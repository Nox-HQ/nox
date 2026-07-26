package core

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/baseline"
)

// Contract tests for the settings the scan pipeline resolves from two sources:
// a ScanOptions field (set by a CLI flag) and a .nox.yaml key. The rule for all
// of them is
//
//	explicit CLI flag  >  .nox.yaml  >  built-in default
//
// and it is asserted here through real scans, because the resolution is inline
// in RunScanContext rather than behind a helper a unit test could call.
//
// See #362 for why this is worth pinning: `output.format` in .nox.yaml overrode
// an explicit `-format` because the resolver compared the flag's VALUE against
// its default, so an explicitly-typed `-format json` looked identical to an
// absent flag. findings.json stopped being written, the CI gate step skipped on
// the missing file, and a skipped step is a green check.
//
// The three settings below are structurally immune to that specific mistake:
// each flag defaults to "", so "absent" has its own representation and config
// fills it in without ever inspecting the value. These tests exist to keep it
// that way — a future default of "." or ".nox/baseline.json" on any of these
// flags would silently reintroduce #362, and would fail here.

// ---------------------------------------------------------------------------
// scan.rules_dir  /  ScanOptions.CustomRulesPath  (--rules)
// ---------------------------------------------------------------------------

const cliRuleYAML = `rules:
  - id: "PREC-CLI"
    version: "1.0"
    description: "rule supplied via --rules"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "CLI_PATTERN_[0-9a-f]{16}"
    file_patterns:
      - "*.txt"
`

const configRuleYAML = `rules:
  - id: "PREC-CONFIG"
    version: "1.0"
    description: "rule supplied via .nox.yaml scan.rules_dir"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "CONFIG_PATTERN_[0-9a-z]{16}"
    file_patterns:
      - "*.txt"
`

// bothPatternsFile contains one line each rule can match, so which rule set was
// loaded is decided purely by precedence, not by the input.
const bothPatternsFile = "CLI_PATTERN_deadbeefcafebabe\nCONFIG_PATTERN_aaaaaaaaaaaaaaaa\n"

func TestCustomRulesPathPrecedence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// useFlag sets ScanOptions.CustomRulesPath (what --rules does);
		// useConfig writes scan.rules_dir into .nox.yaml.
		useFlag    bool
		useConfig  bool
		wantCLI    bool
		wantConfig bool
	}{
		{"neither: no custom rules load", false, false, false, false},
		{"config fills an absent flag", false, true, false, true},
		{"explicit flag, no config", true, false, true, false},
		{"explicit flag beats config", true, true, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, "app.txt"), bothPatternsFile)

			cfgRulesDir := filepath.Join(dir, "config-rules")
			if err := os.Mkdir(cfgRulesDir, 0o755); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(cfgRulesDir, "rules.yaml"), configRuleYAML)

			cliRules := filepath.Join(dir, "cli-rules.yaml")
			mustWrite(t, cliRules, cliRuleYAML)

			if tc.useConfig {
				mustWrite(t, filepath.Join(dir, ".nox.yaml"), "scan:\n  rules_dir: config-rules\n")
			}

			opts := ScanOptions{Offline: true}
			if tc.useFlag {
				opts.CustomRulesPath = cliRules
			}

			res, err := RunScanWithOptions(dir, opts)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got := res.Findings.Findings()

			if hasRule(got, "PREC-CLI") != tc.wantCLI {
				t.Errorf("PREC-CLI present = %v, want %v (flag=%v config=%v)",
					hasRule(got, "PREC-CLI"), tc.wantCLI, tc.useFlag, tc.useConfig)
			}
			if hasRule(got, "PREC-CONFIG") != tc.wantConfig {
				t.Errorf("PREC-CONFIG present = %v, want %v (flag=%v config=%v)",
					hasRule(got, "PREC-CONFIG"), tc.wantConfig, tc.useFlag, tc.useConfig)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// policy.vex_path  /  ScanOptions.VEXPath  (--vex)
// ---------------------------------------------------------------------------

const validVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/precedence",
  "author": "test",
  "timestamp": "2024-01-01T00:00:00Z",
  "statements": []
}`

// TestVEXPathPrecedence decides precedence by which path the pipeline tries to
// load: an explicitly-supplied VEX document that is missing is a hard error,
// while a valid one loads silently. Pointing the two sources at a valid and a
// missing file respectively makes "which source won" observable without needing
// a real vulnerable dependency to waive.
func TestVEXPathPrecedence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		flagPath    string // "" means --vex absent
		configPath  string // "" means policy.vex_path absent
		wantErrPath string // substring of the path the error must name; "" means no error
	}{
		{"neither: no VEX applied", "", "", ""},
		{"config fills an absent flag (valid)", "", "valid.json", ""},
		{"config fills an absent flag (missing → error names the config path)", "", "missing.json", "missing.json"},
		{"explicit flag beats config: flag valid, config missing", "valid.json", "missing.json", ""},
		{"explicit flag beats config: flag missing, config valid", "missing.json", "valid.json", "missing.json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, "app.txt"), "nothing interesting\n")
			mustWrite(t, filepath.Join(dir, "valid.json"), validVEX)
			// missing.json is deliberately never created.

			if tc.configPath != "" {
				mustWrite(t, filepath.Join(dir, ".nox.yaml"),
					"policy:\n  vex_path: \""+tc.configPath+"\"\n")
			}

			opts := ScanOptions{Offline: true, VEXPath: tc.flagPath}
			_, err := RunScanWithOptions(dir, opts)

			switch {
			case tc.wantErrPath == "" && err != nil:
				t.Fatalf("unexpected error (flag=%q config=%q): %v", tc.flagPath, tc.configPath, err)
			case tc.wantErrPath != "" && err == nil:
				t.Fatalf("expected the scan to fail loading %q (flag=%q config=%q), got nil",
					tc.wantErrPath, tc.flagPath, tc.configPath)
			case tc.wantErrPath != "" && !strings.Contains(err.Error(), tc.wantErrPath):
				t.Fatalf("error names the wrong VEX path — the losing source was used.\n got: %v\nwant a path containing %q", err, tc.wantErrPath)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// policy.baseline_path  /  ScanOptions.BaselinePath  (--baseline)
// ---------------------------------------------------------------------------

const baselineRuleYAML = `rules:
  - id: "PREC-BL"
    version: "1.0"
    description: "deterministic finding for baseline precedence"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "TODO"
    file_patterns:
      - "*.go"
`

// TestBaselinePathPrecedence covers the one setting here that CAN express
// "explicit flag whose value equals the built-in default": the baseline path
// falls back to .nox/baseline.json when neither source sets it, and that same
// path can also be passed explicitly on --baseline.
//
// That is #362's shape exactly. A resolver comparing the flag against the
// default path would read `--baseline .nox/baseline.json` as "flag absent" and
// let policy.baseline_path win — suppressing findings the operator had just
// asked to see, silently.
func TestBaselinePathPrecedence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// flagPath / configPath are repo-relative; "" means that source is unset.
		flagPath   string
		configPath string
		// wantSuppressed says whether PREC-BL must come back marked baselined.
		// The two baseline files differ precisely in that: "full.json" contains
		// the finding's fingerprint, "empty.json" and ".nox/baseline.json"
		// contain none.
		wantSuppressed bool
	}{
		{"neither: default .nox/baseline.json (empty) applies, nothing suppressed", "", "", false},
		{"config fills an absent flag", "", "full.json", true},
		{"explicit flag, no config", "full.json", "", true},
		{"explicit flag beats config (flag suppresses)", "full.json", "empty.json", true},
		{"explicit flag beats config (flag does NOT suppress)", "empty.json", "full.json", false},
		// The #362 case: the explicitly-passed path IS the built-in default.
		// It must still win over a config path that would have suppressed.
		{"explicit flag == built-in default path still beats config", ".nox/baseline.json", "full.json", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			rulesFile := filepath.Join(dir, "rules.yaml")
			mustWrite(t, rulesFile, baselineRuleYAML)
			mustWrite(t, filepath.Join(dir, "main.go"), "// TODO: fix\n")

			// Probe scan with no baseline anywhere, to capture the fingerprint.
			probe, err := RunScanWithOptions(dir, ScanOptions{CustomRulesPath: rulesFile, Offline: true})
			if err != nil {
				t.Fatalf("probe scan: %v", err)
			}
			found := probe.Findings.Findings()
			if !hasRule(found, "PREC-BL") {
				t.Fatal("probe scan did not produce PREC-BL")
			}
			if isBaselined(found, "PREC-BL") {
				t.Fatal("probe scan baselined PREC-BL with no baseline in play")
			}

			writeBaseline(t, filepath.Join(dir, "full.json"), baseline.FromFindings(found))
			writeBaseline(t, filepath.Join(dir, "empty.json"), nil)
			// The built-in default location, deliberately empty: reaching it
			// must suppress nothing.
			if err := os.MkdirAll(filepath.Join(dir, ".nox"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeBaseline(t, filepath.Join(dir, ".nox", "baseline.json"), nil)

			if tc.configPath != "" {
				mustWrite(t, filepath.Join(dir, ".nox.yaml"),
					"policy:\n  baseline_path: \""+tc.configPath+"\"\n")
			}

			opts := ScanOptions{CustomRulesPath: rulesFile, Offline: true}
			if tc.flagPath != "" {
				opts.BaselinePath = filepath.Join(dir, tc.flagPath)
			}

			res, err := RunScanWithOptions(dir, opts)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got := res.Findings.Findings()
			if !hasRule(got, "PREC-BL") {
				t.Fatal("PREC-BL disappeared")
			}
			if isBaselined(got, "PREC-BL") != tc.wantSuppressed {
				t.Errorf("PREC-BL baselined = %v, want %v (--baseline %q, policy.baseline_path %q)",
					isBaselined(got, "PREC-BL"), tc.wantSuppressed, tc.flagPath, tc.configPath)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// --staged: the options a staged scan must honour, and the two it must clear
// ---------------------------------------------------------------------------

// TestStagedScanHonoursCustomRulesOverConfig is the core-side half of the
// --staged fix. RunStagedScanWithOptions rebuilds the git index into a temp
// directory and copies .nox.yaml across, so config applies there; the caller's
// options must apply too, and must win.
func TestStagedScanHonoursCustomRulesOverConfig(t *testing.T) {
	t.Parallel()

	// initGitRepo commits what it writes, and a staged scan sees only the
	// index, so the interesting files are written and staged afterwards.
	dir := initGitRepo(t, map[string]string{"README.md": "placeholder\n"})
	stageFiles(t, dir, map[string]string{
		"app.txt":                 bothPatternsFile,
		"config-rules/rules.yaml": configRuleYAML,
		"cli-rules.yaml":          cliRuleYAML,
		".nox.yaml":               "scan:\n  rules_dir: config-rules\n",
	})

	res, err := RunStagedScanWithOptions(dir, ScanOptions{
		CustomRulesPath: filepath.Join(dir, "cli-rules.yaml"),
		Offline:         true,
	})
	if err != nil {
		t.Fatalf("staged scan: %v", err)
	}
	got := res.Findings.Findings()

	if !hasRule(got, "PREC-CLI") {
		t.Error("staged scan dropped the explicit CustomRulesPath: PREC-CLI missing")
	}
	if hasRule(got, "PREC-CONFIG") {
		t.Error("staged scan let .nox.yaml scan.rules_dir beat an explicit CustomRulesPath (#362 shape)")
	}
}

// TestStagedScanClearsGitScopedOptions pins the two options that must NOT be
// forwarded verbatim. Both name git state that does not exist in the temp
// directory the staged scan builds, and both are already implied by --staged:
// the staged set is a changed set and a subset of the tracked set. Forwarding
// them would turn `--staged --tracked-only` into a hard "requires a git
// repository" error about a directory the operator never named.
func TestStagedScanClearsGitScopedOptions(t *testing.T) {
	t.Parallel()

	dir := initGitRepo(t, map[string]string{"README.md": "placeholder\n"})
	stageFiles(t, dir, map[string]string{"app.go": "package main\n"})

	for _, tc := range []struct {
		name string
		opts ScanOptions
	}{
		{"--tracked-only", ScanOptions{TrackedOnly: true, Offline: true}},
		{"--changed-since", ScanOptions{ChangedSince: "HEAD~1", Offline: true}},
		{"both", ScanOptions{TrackedOnly: true, ChangedSince: "HEAD~1", Offline: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RunStagedScanWithOptions(dir, tc.opts); err != nil {
				t.Errorf("staged scan with %s failed: %v", tc.name, err)
			}
		})
	}
}

// stageFiles writes files under dir and stages them without committing, so a
// staged scan has something in the index to look at.
func stageFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		mustWrite(t, full, body)
	}
	cmd := exec.Command("git", "add", "-A")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add -A: %v\n%s", err, out)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func writeBaseline(t *testing.T, path string, entries []baseline.Entry) {
	t.Helper()
	data, err := json.Marshal(baseline.Baseline{SchemaVersion: "1.0.0", Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, string(data))
}
