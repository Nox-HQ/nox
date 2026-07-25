package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// writeNoxConfigRequiringWithExclude writes a .nox.yaml declaring both
// scan.exclude patterns and plugins.required.
func writeNoxConfigRequiringWithExclude(t *testing.T, dir string, excludes []string, required ...string) {
	t.Helper()
	body := "scan:\n  exclude:\n"
	for _, e := range excludes {
		body += "    - \"" + e + "\"\n"
	}
	body += "plugins:\n  required:\n"
	for _, r := range required {
		body += "    - " + r + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write .nox.yaml: %v", err)
	}
}

// A plugin's `scan` tool walks the workspace root itself and is handed only
// workspace_root — it never sees `scan.exclude`. So a repo that excludes its
// intentionally-vulnerable fixture corpus (nox's own testdata/precision-suite,
// testdata/metamorphic-corpus, …) had those deliberately-planted findings
// re-surfaced the moment any analysis plugin was required: nox's self-scan went
// from grade A / 3 findings to grade F / 47, and 38 of those 47 were on paths
// .nox.yaml explicitly excludes.
//
// A third-party plugin cannot be trusted to honour an exclusion it is merely
// told about, so the boundary is enforced host-side: plugin findings are
// filtered through the same discovery.IsIgnored matcher the core scan uses, so
// "excluded" means exactly the same thing no matter which analyzer produced
// the finding.
func TestRunScan_PluginFindingsHonourScanExclude(t *testing.T) {
	dir := t.TempDir()
	writeNoxConfigRequiringWithExclude(t, dir,
		[]string{"testdata/", "*.tmpl"}, "nox/taint-analysis")

	setHook(t, func(_ context.Context, target string, _ []string) (*PluginScanOutput, error) {
		mk := func(rule, path string) findings.Finding {
			return findings.NewFinding(
				rule, findings.SeverityHigh, findings.ConfidenceHigh,
				findings.Location{FilePath: path, StartLine: 1, EndLine: 1},
				"plugin finding",
			)
		}
		// Plugins are handed an absolute workspace_root and report absolute
		// paths, so that is what this asserts. (Relative paths are covered
		// too — a plugin may report either.)
		abs := func(rel string) string { return filepath.Join(target, rel) }
		return &PluginScanOutput{Findings: []findings.Finding{
			// Excluded by "testdata/" — an intentionally-vulnerable fixture.
			mk("TAINT-002", abs("testdata/precision-suite/tp_injection.py")),
			// Same, reported relatively.
			mk("TAINT-005", "testdata/metamorphic-corpus/python/ops_cmdi.py"),
			// Excluded by "*.tmpl".
			mk("CONTAINER-001", abs("cli/templates/Dockerfile.tmpl")),
			// Real source — must survive.
			mk("TAINT-004", abs("cli/main.go")),
		}}, nil
	})

	result, err := RunScan(dir)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	byRule := map[string]bool{}
	for _, f := range result.Findings.ActiveFindings() {
		byRule[f.RuleID] = true
	}

	if byRule["TAINT-002"] {
		t.Error("plugin finding on an excluded path (testdata/) was merged; scan.exclude must bind plugins too")
	}
	if byRule["CONTAINER-001"] {
		t.Error("plugin finding on an excluded path (*.tmpl) was merged; scan.exclude must bind plugins too")
	}
	if !byRule["TAINT-004"] {
		t.Error("plugin finding on real source was dropped; only excluded paths may be filtered")
	}
}

// Plugins are handed an absolute workspace_root and report absolute paths,
// while core findings are recorded relative to the scan root. Merging them
// verbatim recorded the same physical file under two different spellings, with
// three consequences:
//
//   - the unused-waiver check groups findings by path, so a file that had both
//     core and plugin findings was evaluated twice, and each group tested ALL
//     the file's waivers against only its own subset — reporting live waivers
//     as "waives X but matched no finding". nox's own Dockerfile produced 4
//     such false degradations the moment the container plugin was enabled.
//   - the v2 fingerprint hashes the path, so a plugin finding's identity
//     embedded an absolute machine path (/Users/<someone>/...) and no baseline
//     could match across machines or in CI.
//   - reports showed local absolute paths next to repo-relative ones.
//
// fingerprint.go's normaliseFilePath says the scanner is the right place to
// make paths repo-relative before they reach the hash; this is that place.
func TestRunScan_PluginFindingPathsAreMadeRootRelative(t *testing.T) {
	dir := t.TempDir()
	writeNoxConfigRequiring(t, dir, "nox/container")

	setHook(t, func(_ context.Context, target string, _ []string) (*PluginScanOutput, error) {
		return &PluginScanOutput{Findings: []findings.Finding{
			findings.NewFinding(
				"CONTAINER-011", findings.SeverityLow, findings.ConfidenceHigh,
				findings.Location{FilePath: filepath.Join(target, "Dockerfile"), StartLine: 1, EndLine: 1},
				"plugin finding with an absolute path",
			),
		}}, nil
	})

	result, err := RunScan(dir)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	for _, f := range result.Findings.ActiveFindings() {
		if f.RuleID != "CONTAINER-011" {
			continue
		}
		if filepath.IsAbs(f.Location.FilePath) {
			t.Errorf("plugin finding kept an absolute path %q; it must be recorded relative to the scan root like core findings",
				f.Location.FilePath)
		}
		if f.Location.FilePath != "Dockerfile" {
			t.Errorf("plugin finding path = %q, want %q", f.Location.FilePath, "Dockerfile")
		}
		return
	}
	t.Fatal("plugin finding CONTAINER-011 not present in results")
}

// Absent any scan.exclude patterns, every plugin finding must survive — the
// filter must not become a silent finding-eater on the common config.
func TestRunScan_PluginFindingsSurviveWithoutExclude(t *testing.T) {
	dir := t.TempDir()
	writeNoxConfigRequiring(t, dir, "nox/taint-analysis")

	setHook(t, func(_ context.Context, _ string, _ []string) (*PluginScanOutput, error) {
		return &PluginScanOutput{Findings: []findings.Finding{
			findings.NewFinding(
				"TAINT-004", findings.SeverityHigh, findings.ConfidenceHigh,
				findings.Location{FilePath: "testdata/x.py", StartLine: 1, EndLine: 1},
				"plugin finding",
			),
		}}, nil
	})

	result, err := RunScan(dir)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	for _, f := range result.Findings.ActiveFindings() {
		if f.RuleID == "TAINT-004" {
			return
		}
	}
	t.Error("plugin finding dropped even though no scan.exclude patterns are configured")
}

// A repository-scoped plugin finding (nox/depconfusion's DEPCONF-002, "no
// private registry config for npm") has no single file to point at, so it
// carries the workspace root as its path. The inline-suppression re-reader
// then tried to os.ReadFile a directory and reported
//
//	[degraded] <repo> could not be re-read to apply inline suppressions: is a directory
//
// on an otherwise healthy scan. The empty-path case was already skipped for
// exactly this reason; a directory is the same thing one step further — there
// are no nox:ignore comments in a directory, so nothing was missed and nothing
// should be reported.
func TestRunScan_RepoScopedFindingDoesNotDegradeSuppressions(t *testing.T) {
	dir := t.TempDir()
	writeNoxConfigRequiring(t, dir, "nox/depconfusion")

	setHook(t, func(_ context.Context, target string, _ []string) (*PluginScanOutput, error) {
		return &PluginScanOutput{Findings: []findings.Finding{
			findings.NewFinding(
				"DEPCONF-002", findings.SeverityMedium, findings.ConfidenceMedium,
				// The plugin reports the workspace root itself.
				findings.Location{FilePath: target, StartLine: 0, EndLine: 0},
				"No private registry configuration found for npm ecosystem",
			),
		}}, nil
	})

	result, err := RunScan(dir)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	for _, d := range result.Degradations {
		if d.Kind == "suppression" {
			t.Errorf("repo-scoped finding produced a suppression degradation: %s", d.Detail)
		}
	}

	// And it is recorded with the canonical repository-scoped path (empty),
	// not the absolute machine path — otherwise the v2 fingerprint hashes
	// /Users/<someone>/... and the finding cannot be baselined anywhere else.
	for _, f := range result.Findings.ActiveFindings() {
		if f.RuleID != "DEPCONF-002" {
			continue
		}
		if f.Location.FilePath != "" {
			t.Errorf("repo-scoped finding path = %q, want \"\" (repository-scoped); an absolute path makes its fingerprint machine-specific",
				f.Location.FilePath)
		}
		return
	}
	t.Fatal("DEPCONF-002 not present in results")
}
