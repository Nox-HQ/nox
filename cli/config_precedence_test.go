package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
)

// Contract tests for every setting that can be supplied BOTH on the command
// line and in .nox.yaml. The rule under test, for all of them:
//
//	explicit CLI flag  >  .nox.yaml  >  built-in default
//
// Config supplies a value when the flag is ABSENT. It must never override one
// the operator actually typed.
//
// This exists because of #362: `output.format` in .nox.yaml silently overrode an
// explicit `-format` on the command line. The check compared the flag's VALUE to
// its default, so `-format json` — deliberately typed — was indistinguishable
// from "flag absent", and config won. CI ran `nox scan . -format json,sarif` and
// gated on findings.json; two repos set `output.format: sarif`, findings.json was
// never written, the gate step skipped on the missing file, and a skipped step is
// a green check. 20 and 63 findings went ungated, for a long time, with a passing
// build.
//
// The defining case for this bug class is therefore NOT "flag differs from
// config" — it is "flag was explicitly passed with a value that happens to equal
// its own default, and config says something else". A resolver that compares
// against the zero or default value cannot tell those apart. Every table below
// carries that case, marked `explicit == default`.
//
// Coverage map for the dual-source settings, so the gaps are visible:
//
//	output.format      / scan -format        resolveOutputFormat  — output_precedence_test.go
//	output.directory   / scan -output        resolveOutputDir     — output_precedence_test.go
//	scan.rules_dir     / scan -rules         core/scan.go         — core/config_precedence_test.go
//	policy.baseline_path / scan -baseline    core/scan.go         — core/config_precedence_test.go
//	policy.vex_path    / scan -vex           core/scan.go         — core/config_precedence_test.go
//	explain.model      / explain -model      applyExplainDefaults — below
//	explain.base_url   / explain -base-url   applyExplainDefaults — below
//	explain.timeout    / explain -timeout    applyExplainDefaults — below
//	explain.batch_size / explain -batch-size applyExplainDefaults — below
//	explain.output     / explain -output     applyExplainDefaults — below
//	explain.enrich     / explain -enrich     applyExplainDefaults — below
//	explain.plugin_dir / explain -plugin-dir applyExplainDefaults — below
//	plugins.trust_policy / plugin install --trust-policy, --require-verified,
//	                       --require-signature, --allow-unverified
//	                                         resolveTrustPolicy   — below
//
// Two further pairs are one-way and cannot invert, because no flag re-enables
// what either source turns off — there is no --osv and no --auto-install:
//
//	scan.osv.disabled     / scan --no-osv, --offline   (disjunction)
//	plugins.auto_install  / scan --no-auto-install     (conjunction)
//
// If such a flag is ever added, those two become two-sided and need tables here.
//
// explain.api_key_env is config-only (no flag). compliance.framework and the
// whole cache block (cache.disabled/ttl/dir) parse from .nox.yaml and are read
// by nothing — dead config, not a precedence question.

// ---------------------------------------------------------------------------
// explain: seven dual-source settings, resolved by applyExplainDefaults
// ---------------------------------------------------------------------------

// explainConfigFor builds a ScanConfig whose `explain:` block sets exactly one
// field, so each table row isolates a single setting. An empty value means the
// key is absent from .nox.yaml.
func explainConfigFor(t *testing.T, field, value string) *nox.ScanConfig {
	t.Helper()
	var ec nox.ExplainSettings
	switch field {
	case "model":
		ec.Model = value
	case "base-url":
		ec.BaseURL = value
	case "timeout":
		ec.Timeout = value
	case "batch-size":
		if value != "" {
			n, err := strconv.Atoi(value)
			if err != nil {
				t.Fatalf("batch-size config value %q: %v", value, err)
			}
			ec.BatchSize = n
		}
	case "output":
		ec.Output = value
	case "enrich":
		ec.Enrich = value
	case "plugin-dir":
		ec.PluginDir = value
	default:
		t.Fatalf("unknown explain field %q", field)
	}
	return &nox.ScanConfig{Explain: ec}
}

func TestExplainSettingPrecedence(t *testing.T) {
	t.Parallel()

	// Each flag's registered default, restated so the third tier is asserted
	// against a literal rather than against whatever the code happens to do.
	builtin := map[string]string{
		"model":      "gpt-4o",
		"base-url":   "",
		"timeout":    "2m0s",
		"batch-size": "10",
		"output":     "explanations.json",
		"enrich":     "",
		"plugin-dir": "",
	}

	cases := []struct {
		name string
		// flagName is the CLI flag and, implicitly, the .nox.yaml explain key.
		flagName string
		// explicit says whether the flag was passed at all; flagValue is what it
		// was passed. The two are separate on purpose — an explicit flag whose
		// value equals the default is the #362 case, and it cannot be expressed
		// by value alone.
		explicit  bool
		flagValue string
		configVal string // "" means the key is absent from .nox.yaml
		want      string
	}{
		// model — default "gpt-4o"
		{"model: neither, built-in default", "model", false, "", "", "gpt-4o"},
		{"model: config fills an absent flag", "model", false, "", "claude-3-opus", "claude-3-opus"},
		{"model: explicit flag beats config", "model", true, "gpt-4o-mini", "claude-3-opus", "gpt-4o-mini"},
		{"model: explicit == default still beats config", "model", true, "gpt-4o", "claude-3-opus", "gpt-4o"},

		// base-url — default ""
		{"base-url: neither", "base-url", false, "", "", ""},
		{"base-url: config fills an absent flag", "base-url", false, "", "http://localhost:11434", "http://localhost:11434"},
		{"base-url: explicit flag beats config", "base-url", true, "http://proxy:8080", "http://localhost:11434", "http://proxy:8080"},

		// timeout — default 2m, Duration-typed. A resolver comparing against the
		// zero Duration would read an explicit -timeout 2m as absent.
		{"timeout: neither", "timeout", false, "", "", "2m0s"},
		{"timeout: config fills an absent flag", "timeout", false, "", "5m", "5m0s"},
		{"timeout: explicit flag beats config", "timeout", true, "30s", "5m", "30s"},
		{"timeout: explicit == default still beats config", "timeout", true, "2m", "5m", "2m0s"},

		// batch-size — default 10, int-typed. Same hazard against 0 and against 10.
		{"batch-size: neither", "batch-size", false, "", "", "10"},
		{"batch-size: config fills an absent flag", "batch-size", false, "", "20", "20"},
		{"batch-size: explicit flag beats config", "batch-size", true, "5", "20", "5"},
		{"batch-size: explicit == default still beats config", "batch-size", true, "10", "20", "10"},

		// output — default "explanations.json". This is #362's exact shape: a
		// well-known artifact path that a later pipeline step reads.
		{"output: neither", "output", false, "", "", "explanations.json"},
		{"output: config fills an absent flag", "output", false, "", "custom.json", "custom.json"},
		{"output: explicit flag beats config", "output", true, "mine.json", "custom.json", "mine.json"},
		{"output: explicit == default still beats config", "output", true, "explanations.json", "custom.json", "explanations.json"},

		// enrich — default ""
		{"enrich: neither", "enrich", false, "", "", ""},
		{"enrich: config fills an absent flag", "enrich", false, "", "tool1,tool2", "tool1,tool2"},
		{"enrich: explicit flag beats config", "enrich", true, "only-this", "tool1,tool2", "only-this"},

		// plugin-dir — default ""
		{"plugin-dir: neither", "plugin-dir", false, "", "", ""},
		{"plugin-dir: config fills an absent flag", "plugin-dir", false, "", "/opt/plugins", "/opt/plugins"},
		{"plugin-dir: explicit flag beats config", "plugin-dir", true, "/tmp/p", "/opt/plugins", "/tmp/p"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Real registration, not a hand-rolled copy: the flag names, types
			// and defaults under test are the ones runExplain uses. A private
			// copy of the flag set had already drifted from production (it
			// declared -timeout as a string where production registers a
			// Duration), and a test built on a different flag set cannot catch
			// a precedence bug in the real one.
			fs := flag.NewFlagSet("explain", flag.ContinueOnError)
			registerExplainFlags(fs)

			var args []string
			if tc.explicit {
				args = []string{"-" + tc.flagName, tc.flagValue}
			}
			if err := fs.Parse(args); err != nil {
				t.Fatalf("parsing %v: %v", args, err)
			}

			applyExplainDefaults(fs, explainConfigFor(t, tc.flagName, tc.configVal))

			got := fs.Lookup(tc.flagName).Value.String()
			if got != tc.want {
				t.Errorf("-%s explicit=%v value=%q, config %q -> %q, want %q",
					tc.flagName, tc.explicit, tc.flagValue, tc.configVal, got, tc.want)
			}
			// Third tier, asserted independently: with neither source supplying
			// a value the result must be the registered built-in.
			if !tc.explicit && tc.configVal == "" && got != builtin[tc.flagName] {
				t.Errorf("-%s with no flag and no config = %q, want the built-in default %q",
					tc.flagName, got, builtin[tc.flagName])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// plugin install: plugins.trust_policy vs the four trust flags
// ---------------------------------------------------------------------------

// TestTrustPolicyPrecedence covers plugins.trust_policy in .nox.yaml against the
// flags that override it. resolveTrustPolicy reads .nox.yaml from the process
// working directory, so each row runs in its own temp dir.
//
// The asymmetry is deliberate and worth pinning: a project pinning
// `trust_policy: enterprise` asserts that unsigned plugins must not install, and
// an operator flag may relax that — the documented order puts flags first. What
// must not happen is config silently re-tightening or re-loosening a flag that
// was passed.
func TestTrustPolicyPrecedence(t *testing.T) {
	cases := []struct {
		name             string
		configVal        string // "" means no plugins.trust_policy key
		override         string // --trust-policy
		requireVerified  bool   // --require-verified
		requireSignature bool   // --require-signature
		allowUnverified  bool   // --allow-unverified
		want             string
	}{
		{name: "neither: built-in default", want: "default"},
		{name: "config fills absent flags", configVal: "enterprise", want: "enterprise"},
		{name: "config permissive with no flags", configVal: "permissive", want: "permissive"},

		{name: "explicit --trust-policy beats config", configVal: "enterprise", override: "permissive", want: "permissive"},
		// The #362 case. "default" is both a legal --trust-policy value and the
		// built-in fallback: an implementation comparing the override against
		// its own fallback would read this row as "flag not passed" and let
		// config win, silently tightening an operator who asked to relax.
		{name: "explicit --trust-policy == built-in default still beats config", configVal: "enterprise", override: "default", want: "default"},
		{name: "explicit --trust-policy == config value", configVal: "permissive", override: "permissive", want: "permissive"},

		{name: "--allow-unverified beats config", configVal: "enterprise", allowUnverified: true, want: "permissive"},
		{name: "--require-verified beats config", configVal: "permissive", requireVerified: true, want: "enterprise"},
		{name: "--require-signature beats config", configVal: "permissive", requireSignature: true, want: "default"},
		// --require-signature resolves to "default", weaker than the configured
		// "enterprise". The flag still wins: flags come first, and silently
		// upgrading it would be config beating a flag.
		{name: "--require-signature beats a stricter config", configVal: "enterprise", requireSignature: true, want: "default"},

		{name: "config value is normalised", configVal: "  ENTERPRISE  ", want: "enterprise"},
		{name: "flag value is normalised", override: "  PERMISSIVE  ", configVal: "enterprise", want: "permissive"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Chdir is incompatible with t.Parallel; resolveTrustPolicy reads
			// .nox.yaml from the working directory.
			dir := t.TempDir()
			if tc.configVal != "" {
				body := "plugins:\n  trust_policy: \"" + tc.configVal + "\"\n"
				if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(body), 0o644); err != nil {
					t.Fatalf("writing .nox.yaml: %v", err)
				}
			}
			t.Chdir(dir)

			got := resolveTrustPolicy(tc.override, tc.requireVerified, tc.requireSignature, tc.allowUnverified)
			if got != tc.want {
				t.Errorf("resolveTrustPolicy(override=%q, verified=%v, signature=%v, unverified=%v) with config %q = %q, want %q",
					tc.override, tc.requireVerified, tc.requireSignature, tc.allowUnverified, tc.configVal, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// scan --staged: flags must survive the temp-directory round trip
// ---------------------------------------------------------------------------

// TestStagedScanOptionsPreservesFlags pins the wiring that gives
// `nox scan --staged` the operator's flags at all.
//
// The CLI called nox.RunStagedScan(target), which passes ScanOptions{}. The core
// had already been fixed to thread options through RunStagedScanWithOptions, but
// this call site was never updated — so under --staged every flag was dropped
// while .nox.yaml was still copied into the temp directory and honoured. Config
// beat an explicit flag, exactly as in #362, on the path `nox protect` installs
// as a pre-commit hook.
//
// Path-valued options are anchored to the scan target because the staged scan
// runs against a temp copy; a relative path left alone would resolve there and
// silently match nothing.
func TestStagedScanOptionsPreservesFlags(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	in := nox.ScanOptions{
		CustomRulesPath:    "rules/custom.yaml",
		VEXPath:            "waivers/vex.json",
		BaselinePath:       "baseline.json",
		TerraformPlanPath:  "plan.json",
		DisableOSV:         true,
		Offline:            true,
		TrackedOnly:        true,
		NoRespectGitignore: true,
		ChangedSince:       "main",
	}

	got := stagedScanOptions(root, in)

	for _, c := range []struct{ name, got, want string }{
		{"CustomRulesPath", got.CustomRulesPath, filepath.Join(root, "rules", "custom.yaml")},
		{"VEXPath", got.VEXPath, filepath.Join(root, "waivers", "vex.json")},
		{"BaselinePath", got.BaselinePath, filepath.Join(root, "baseline.json")},
		{"TerraformPlanPath", got.TerraformPlanPath, filepath.Join(root, "plan.json")},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want it anchored to the scan target: %q", c.name, c.got, c.want)
		}
	}

	// Booleans must survive untouched. --offline and --no-osv are the
	// zero-network guarantee: dropping them under --staged makes a hook-time
	// scan reach the network after the operator forbade it.
	if !got.DisableOSV || !got.Offline || !got.TrackedOnly || !got.NoRespectGitignore {
		t.Errorf("boolean flags were dropped: %+v", got)
	}
	if got.ChangedSince != "main" {
		t.Errorf("ChangedSince = %q, want %q — clearing it is RunStagedScanWithOptions's job, not the CLI's",
			got.ChangedSince, "main")
	}
}

func TestStagedScanOptionsLeavesAbsoluteAndEmptyPaths(t *testing.T) {
	t.Parallel()

	abs := filepath.Join(t.TempDir(), "rules.yaml")
	got := stagedScanOptions(t.TempDir(), nox.ScanOptions{CustomRulesPath: abs})
	if got.CustomRulesPath != abs {
		t.Errorf("absolute path rewritten: got %q, want %q", got.CustomRulesPath, abs)
	}

	// Empty must stay empty: "" is the sentinel meaning "flag absent", and
	// turning it into the scan root would make every absent path flag look
	// explicitly set — reintroducing #362 from the other direction.
	got = stagedScanOptions(t.TempDir(), nox.ScanOptions{})
	if got.CustomRulesPath != "" || got.VEXPath != "" || got.BaselinePath != "" || got.TerraformPlanPath != "" {
		t.Errorf("absent path flags were given a value: %+v", got)
	}
}

// TestScanStagedHonoursRulesFlagOverConfig is the end-to-end proof, driven
// through run() the way CI drives the binary: the custom rule from --rules must
// fire under --staged, and the rule from .nox.yaml's scan.rules_dir — which the
// staged pipeline copies into its temp directory — must not.
//
// Before the fix this failed with both assertions inverted: CONFIG-001 present,
// CLI-001 absent.
func TestScanStagedHonoursRulesFlagOverConfig(t *testing.T) {
	dir := t.TempDir()
	gitInitOrSkip(t, dir)

	writeFile(t, dir, "app.txt", "CONFIG_PATTERN_aaaaaaaaaaaaaaaa\nCLI_PATTERN_deadbeefcafebabe\n")

	cfgRules := filepath.Join(dir, "config-rules")
	if err := os.Mkdir(cfgRules, 0o755); err != nil {
		t.Fatalf("creating config-rules: %v", err)
	}
	writeFile(t, cfgRules, "rules.yaml", `rules:
  - id: "CONFIG-001"
    version: "1.0"
    description: "Config rule (must not run when --rules is passed)"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "CONFIG_PATTERN_[0-9a-z]{16}"
`)
	writeFile(t, dir, ".nox.yaml", "scan:\n  rules_dir: config-rules\n")

	cliRules := writeFile(t, dir, "cli-rules.yaml", `rules:
  - id: "CLI-001"
    version: "1.0"
    description: "CLI rule"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "CLI_PATTERN_[0-9a-f]{16}"
`)

	runGitOrSkip(t, dir, "add", "-A")

	outDir := filepath.Join(dir, "out")
	run([]string{"--quiet", "--rules", cliRules, "--output", outDir, "scan", "--staged", dir})

	body, err := os.ReadFile(filepath.Join(outDir, "findings.json"))
	if err != nil {
		t.Fatalf("reading findings.json: %v", err)
	}
	got := string(body)

	if !strings.Contains(got, "CLI-001") {
		t.Error("--staged dropped the explicit --rules flag: CLI-001 is missing from findings.json")
	}
	if strings.Contains(got, "CONFIG-001") {
		t.Error("--staged let .nox.yaml scan.rules_dir override an explicit --rules flag (#362 shape): CONFIG-001 fired")
	}
}

func gitInitOrSkip(t *testing.T, dir string) {
	t.Helper()
	runGitOrSkip(t, dir, "init")
	runGitOrSkip(t, dir, "config", "user.email", "test@example.com")
	runGitOrSkip(t, dir, "config", "user.name", "Test User")
}

func runGitOrSkip(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git %v: %v\n%s", args, err, out)
	}
}
