package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/findings"
)

// These tests cover the degradation-reporting and fail-loud behaviour added to
// close a class of bug where nox reported a clean scan without having run the
// check. Each one previously passed silently with exit 0.

func TestRefine_MalformedVEXIsAnError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	vexPath := filepath.Join(dir, "broken.vex.json")
	if err := os.WriteFile(vexPath, []byte("{ this is not valid json"), 0o644); err != nil {
		t.Fatalf("writing vex: %v", err)
	}

	// An operator who passes --vex expects those waivers to be applied. Before
	// this change the load error was discarded, so a typo'd or corrupt document
	// silently applied no waivers at all.
	_, err := RunScanWithOptions(dir, ScanOptions{VEXPath: vexPath, Offline: true})
	if err == nil {
		t.Fatal("expected an error for a malformed VEX document, got nil")
	}
	if !strings.Contains(err.Error(), "VEX") {
		t.Errorf("expected the error to name VEX, got: %v", err)
	}
}

func TestRefine_MissingVEXFileIsAnError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, err := RunScanWithOptions(dir, ScanOptions{
		VEXPath: filepath.Join(dir, "does-not-exist.json"),
		Offline: true,
	})
	if err == nil {
		t.Fatal("expected an error for a missing VEX document, got nil")
	}
}

func TestRefine_MissingTerraformPlanIsAnError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Silently scanning nothing would let a typo'd plan path masquerade as a
	// clean infrastructure review.
	_, err := RunScanWithOptions(dir, ScanOptions{
		TerraformPlanPath: filepath.Join(dir, "no-such-plan.json"),
		Offline:           true,
	})
	if err == nil {
		t.Fatal("expected an error for a missing terraform plan, got nil")
	}
	if !strings.Contains(err.Error(), "terraform") {
		t.Errorf("expected the error to name the terraform plan, got: %v", err)
	}
}

func TestRefine_MalformedTerraformPlanIsAnError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planPath, []byte("not json at all"), 0o644); err != nil {
		t.Fatalf("writing plan: %v", err)
	}

	_, err := RunScanWithOptions(dir, ScanOptions{TerraformPlanPath: planPath, Offline: true})
	if err == nil {
		t.Fatal("expected an error for a malformed terraform plan, got nil")
	}
}

func TestScan_CorruptBaselineIsReportedAsDegradation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// A file the secrets analyzer will flag, so there is something to classify.
	if err := os.WriteFile(filepath.Join(dir, "cfg.env"),
		[]byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n"), 0o644); err != nil {
		t.Fatalf("writing target file: %v", err)
	}

	cfg := "policy:\n  baseline_path: .nox-baseline.json\n"
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".nox-baseline.json"),
		[]byte("{ corrupt"), 0o644); err != nil {
		t.Fatalf("writing baseline: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// A corrupt baseline must not fail the scan — but under baseline_mode it
	// changes what the gate enforces, so it cannot pass unnoticed either.
	if !hasDegradationKind(result, "baseline") {
		t.Errorf("expected a baseline degradation, got %+v", result.Degradations)
	}
}

func TestScan_AbsentBaselineIsNotADegradation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Having no baseline is the normal state before the first
	// `nox baseline write`. Reporting it would train operators to ignore
	// degradation output entirely.
	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if hasDegradationKind(result, "baseline") {
		t.Errorf("absent baseline should be silent, got %+v", result.Degradations)
	}
}

func TestScan_UnparseableLockfileIsReportedAsDegradation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Valid filename so it is classified as a lockfile, invalid content so the
	// parse fails. Every dependency it declares is now absent from CVE matching.
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"),
		[]byte("{ not valid json at all"), 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if !hasDegradationKind(result, "lockfile_parse") {
		t.Errorf("expected a lockfile degradation, got %+v", result.Degradations)
	}
}

func TestScan_CleanScanReportsNoDegradations(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# hello\n"), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Degradations) != 0 {
		t.Errorf("expected no degradations on a clean offline scan, got %+v", result.Degradations)
	}
}

func TestScan_LicensePolicyIsWiredThrough(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// A dependency in the inventory (from the lockfile) whose license the
	// policy denies (from its node_modules manifest). Before this change
	// license.deny parsed cleanly and then produced no findings whatsoever.
	lock := `{"packages":{"node_modules/leftpad":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}
	modDir := filepath.Join(dir, "node_modules", "leftpad")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatalf("creating node_modules: %v", err)
	}
	manifest := `{"name":"leftpad","version":"1.0.0","license":"GPL-3.0"}`
	if err := os.WriteFile(filepath.Join(modDir, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}

	cfg := "license:\n  deny:\n    - GPL-3.0\n"
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var found bool
	for _, f := range result.Findings.Findings() {
		if strings.HasPrefix(f.RuleID, "LIC-") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a LIC-* finding from the configured license policy; license config is not wired through")
	}
}

func hasDegradationKind(result *ScanResult, kind string) bool {
	for _, d := range result.Degradations {
		if string(d.Kind) == kind {
			return true
		}
	}
	return false
}

// TestScan_RedundantLockfileIsNotADegradation guards signal-to-noise. go.sum
// carries nothing go.mod does not, and nox parses go.mod — so reporting it
// would fire on essentially every Go repository, and a warning that fires on
// healthy scans is one operators learn to ignore.
func TestScan_RedundantLockfileIsNotADegradation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.sum"),
		[]byte("github.com/x/y v1.0.0 h1:abc=\n"), 0o644); err != nil {
		t.Fatalf("writing go.sum: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if hasDegradationKind(result, "lockfile_parse") {
		t.Errorf("go.sum is redundant with go.mod and must be silent: %+v", result.Degradations)
	}
}

// TestScan_EveryEcosystemLockfileYieldsDependencies is the end-to-end guarantee
// for the ecosystems that previously scanned clean while nothing was read.
//
// It asserts the operator-visible outcome — packages in the inventory — rather
// than the parser's return value, because the failure was never in a parser: it
// was that no parser was reached at all.
func TestScan_EveryEcosystemLockfileYieldsDependencies(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		file    string
		content string
		pkg     string
	}{
		{"yarn.lock", "# yarn lockfile v1\n\nlodash@^4.17.0:\n  version \"4.17.20\"\n", "lodash"},
		{"pnpm-lock.yaml", "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    dev: false\n", "lodash"},
		{"poetry.lock", "[[package]]\nname = \"django\"\nversion = \"4.2.1\"\n", "django"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0o644); err != nil {
				t.Fatalf("writing %s: %v", tc.file, err)
			}

			result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			var found bool
			for _, p := range result.Inventory.Packages() {
				if p.Name == tc.pkg {
					found = true
				}
			}
			if !found {
				t.Errorf("%s produced no dependencies: %+v", tc.file, result.Inventory.Packages())
			}
			// A parsed lockfile is not a blind spot and must not be reported.
			if hasDegradationKind(result, "lockfile_parse") {
				t.Errorf("%s parsed successfully but was still reported as degraded: %+v",
					tc.file, result.Degradations)
			}
		})
	}
}

// TestScan_MalformedSuppressionExpiryDoesNotWaive is the regression test for a
// waiver that silently became permanent.
//
// The parser discarded the date-parse error while still stripping the expires:
// text from the reason, so `expires:2026-13-01` (month 13) produced a
// suppression with no expiry at all. The operator saw their directive accepted
// and the finding disappear, forever. It failed toward HIDING findings, which
// is the worst direction for a scanner.
//
// This asserts the operator-visible outcome — is the finding reported — rather
// than the parser's internals, because the bug lived in what the caller did
// with the parse result.
func TestScan_MalformedSuppressionExpiryDoesNotWaive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// A file that reliably produces a finding, waived with an invalid date.
	content := "# nox:ignore SEC-652 -- expires:2026-13-01\njenkins_token = \"AbcdefghijklmnopqrstUVWX\"\n"
	if err := os.WriteFile(filepath.Join(dir, "conf.py"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var active bool
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-652" && (f.Status == "" || f.Status == findings.StatusNew) {
			active = true
		}
	}
	if !active {
		t.Error("a waiver with an unparseable expiry suppressed the finding; it must not be applied")
	}
	if !hasDegradationKind(result, "suppression") {
		t.Errorf("the unparseable expiry was not reported to the operator: %+v", result.Degradations)
	}
}

// TestScan_ValidExpiredSuppressionStillReports guards the neighbouring
// behaviour so the fix above cannot be satisfied by breaking expiry entirely.
func TestScan_ValidExpiredSuppressionStillReports(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := "# nox:ignore SEC-652 -- expires:2020-01-01\njenkins_token = \"AbcdefghijklmnopqrstUVWX\"\n"
	if err := os.WriteFile(filepath.Join(dir, "conf.py"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	// An expired waiver is a normal, correctly-parsed state — not a degradation.
	if hasDegradationKind(result, "suppression") {
		t.Errorf("a valid expired waiver should not be reported as degraded: %+v", result.Degradations)
	}
}

// TestScan_ValidUnexpiredSuppressionStillWaives ensures the fix did not break
// the feature it protects.
func TestScan_ValidUnexpiredSuppressionStillWaives(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := "# nox:ignore SEC-652 -- expires:2099-01-01\njenkins_token = \"AbcdefghijklmnopqrstUVWX\"\n"
	if err := os.WriteFile(filepath.Join(dir, "conf.py"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-652" && (f.Status == "" || f.Status == findings.StatusNew) {
			t.Error("a valid unexpired waiver failed to suppress its finding")
		}
	}
}

// TestScan_FailedPluginIsReported covers the guarantee --fail-on-degraded
// advertises in its own help text ("OSV lookup, plugin, lockfile parse").
//
// degrade.Plugin was declared and never emitted, so a required security plugin
// that failed to run produced a clean scan and a passing gate — the precise
// failure the degradation channel exists to prevent, inside the release that
// shipped it.
func TestScan_FailedPluginIsReported(t *testing.T) {
	dir := t.TempDir()
	cfg := "plugins:\n  required:\n    - acme/scanner\n"
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	original := ScanPluginHook
	t.Cleanup(func() { ScanPluginHook = original })

	t.Run("hook error", func(t *testing.T) {
		ScanPluginHook = func(_ context.Context, _ string, _ []string) (*PluginScanOutput, error) {
			return nil, errors.New("plugin host failed to start")
		}
		result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
		if err != nil {
			t.Fatalf("a plugin failure must not abort the scan: %v", err)
		}
		if !hasDegradationKind(result, "plugin") {
			t.Errorf("a failed plugin was not reported: %+v", result.Degradations)
		}
	})

	t.Run("plugin reported as not contributing", func(t *testing.T) {
		// The commoner case: the hook succeeds having run what it could, and
		// reports the required plugins it could not run. No error is returned,
		// so an error-only channel would miss it entirely.
		ScanPluginHook = func(_ context.Context, _ string, _ []string) (*PluginScanOutput, error) {
			return &PluginScanOutput{Degradations: []Degradation{{
				Kind:   degrade.Plugin,
				Detail: `required plugin "acme/scanner" is not installed`,
				Impact: "findings this plugin would have produced are missing from this scan",
			}}}, nil
		}
		result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if !hasDegradationKind(result, "plugin") {
			t.Errorf("an uninstalled required plugin was not reported: %+v", result.Degradations)
		}
	})

	t.Run("healthy plugin stays silent", func(t *testing.T) {
		ScanPluginHook = func(_ context.Context, _ string, _ []string) (*PluginScanOutput, error) {
			return &PluginScanOutput{}, nil
		}
		result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if hasDegradationKind(result, "plugin") {
			t.Errorf("a plugin that ran cleanly must not be reported: %+v", result.Degradations)
		}
	})
}

// TestScan_PathlessFindingIsNotASuppressionDegradation guards against noise on
// healthy scans.
//
// Dependency and plugin findings are often repository-scoped and carry no file
// path. Grouping them for inline-suppression scanning joined "" to the target,
// producing the target DIRECTORY, whose read fails — which was then reported as
// "could not be re-read to apply inline suppressions: is a directory" on scans
// where nothing was actually missed.
//
// A degradation channel that fires on healthy scans is one operators learn to
// ignore, which defeats its entire purpose.
func TestScan_PathlessFindingIsNotASuppressionDegradation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// A lockfile yields VULN/LIC-style findings that may carry no file path,
	// and the license finding below is emitted with an empty FilePath.
	lock := `{"packages":{"node_modules/leftpad":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}
	modDir := filepath.Join(dir, "node_modules", "leftpad")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatalf("creating node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "package.json"),
		[]byte(`{"name":"leftpad","version":"1.0.0","license":"GPL-3.0"}`), 0o644); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"),
		[]byte("license:\n  deny:\n    - GPL-3.0\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Confirm the premise: a finding with no file path was actually produced,
	// or this test would pass vacuously.
	var pathless bool
	for _, f := range result.Findings.Findings() {
		if f.Location.FilePath == "" {
			pathless = true
		}
	}
	if !pathless {
		t.Skip("no path-less finding produced; test premise no longer holds")
	}

	if hasDegradationKind(result, "suppression") {
		t.Errorf("a path-less finding produced a spurious suppression degradation: %+v",
			result.Degradations)
	}
}

// A dedicated nox:ignore applies to the next non-blank line, so a reason that
// wraps onto a second comment line makes the waiver land on that continuation
// comment — the finding below stays reported and nothing said so. The operator
// believed it was waived. An unused waiver is now surfaced.
func TestScan_UnusedSuppressionIsReported(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// The reason wraps, so the directive targets the second comment line.
	content := "# nox:ignore SEC-652 -- this reason wraps onto\n# a second comment line\njenkins_token = \"AbcdefghijklmnopqrstUVWX\"\n"
	if err := os.WriteFile(filepath.Join(dir, "conf.py"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !hasDegradationKind(result, "suppression") {
		t.Errorf("a waiver that suppressed nothing must be reported; got %+v", result.Degradations)
	}
	// And it genuinely did not waive: the finding is still reported.
	var stillReported bool
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-652" && f.Status != findings.StatusSuppressed {
			stillReported = true
		}
	}
	if !stillReported {
		t.Error("expected the finding to remain reported when the waiver missed")
	}
}

// The counterpart: a correctly-placed waiver suppresses its finding and must NOT
// be reported as unused, or the new signal would be noise on every clean repo.
func TestScan_UsedSuppressionIsNotReportedAsUnused(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := "# nox:ignore SEC-652 -- single-line reason\njenkins_token = \"AbcdefghijklmnopqrstUVWX\"\n"
	if err := os.WriteFile(filepath.Join(dir, "conf.py"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if hasDegradationKind(result, "suppression") {
		t.Errorf("a waiver that applied must not be reported as unused: %+v", result.Degradations)
	}
}

// Documentation that demonstrates nox:ignore must not be reported as a pile of
// unused waivers. nox's own README shows the syntax in fenced code blocks whose
// sample secrets are deliberately too short to match a rule, so every example
// waived nothing and was reported — noise, in a file that is behaving correctly.
func TestScan_MarkdownDocExamplesAreNotReportedUnused(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// A doc example in a fence (waives nothing) plus a real finding in the same
	// file, so the file reaches the suppression pass at all.
	md := "# Docs\n\nSuppress like this:\n\n```go\n// nox:ignore SEC-001 -- false positive in test data\nvar testKey = \"AKIAEXAMPLEFAKEKEY\"\n```\n\nA real token below:\n\njenkins_token = \"AbcdefghijklmnopqrstUVWX\"\n"
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(md), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	result, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if hasDegradationKind(result, "suppression") {
		t.Errorf("doc examples in fenced blocks must not be reported as unused waivers: %+v", result.Degradations)
	}
}

// TestScan_SingleFileTargetResolvesRelativePaths guards the file-target case.
//
// A scan target may be a single file (`nox scan main.go`). Relative lookups were
// joined onto that target as if it were a directory, producing paths like
// main.go/.nox/baseline.json and main.go/main.go — neither of which can exist.
// The consequences were not symmetrical: the baseline miss was merely reported,
// but the failed re-read meant the file's nox:ignore comments were never
// applied, so a single-file scan reported findings the operator had waived.
//
// Both halves are asserted here because fixing only the visible one would leave
// the silent one in place.
func TestScan_SingleFileTargetResolvesRelativePaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// The waiver sits on its own line, so it applies to the next non-blank
	// line — the eval() call that AI-009 flags.
	src := "import x\nresponse = get()\n# nox:ignore AI-009 -- reviewed\ndata = eval(response)\n"
	file := filepath.Join(dir, "app.py")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	// Confirm the premise: without the waiver this file really does produce
	// AI-009, or the assertion below would pass vacuously.
	bare := filepath.Join(t.TempDir(), "app.py")
	if err := os.WriteFile(bare, []byte("import x\nresponse = get()\ndata = eval(response)\n"), 0o644); err != nil {
		t.Fatalf("writing control source: %v", err)
	}
	control, err := RunScanWithOptions(bare, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("control scan failed: %v", err)
	}
	var controlHasAI009 bool
	for _, f := range control.Findings.Findings() {
		if f.RuleID == "AI-009" {
			controlHasAI009 = true
		}
	}
	if !controlHasAI009 {
		t.Fatal("premise broken: control file produced no AI-009, so the waiver assertion proves nothing")
	}

	result, err := RunScanWithOptions(file, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// The waiver must be honoured on a file target exactly as on a directory.
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "AI-009" && f.Status != findings.StatusSuppressed {
			t.Errorf("AI-009 reported despite an inline waiver; suppressions were not applied to a file target")
		}
	}

	// And an absent baseline beside a file target is simply absent — not a
	// degradation about a path that could never have existed.
	for _, d := range result.Degradations {
		if strings.Contains(d.Detail, "baseline") || strings.Contains(d.Detail, "inline suppressions") {
			t.Errorf("unexpected degradation on a file target: %s", d.Detail)
		}
	}
}
