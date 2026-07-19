package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// TestScan_UnsupportedLockfileIsNotADegradation guards the signal-to-noise
// property. go.sum and yarn.lock are deliberately not parsed, so reporting them
// as degraded would fire on almost every Go repository — and a warning that
// fires on healthy scans is one operators learn to ignore, which defeats the
// entire point of the channel. It also wrongly tripped --fail-on-degraded.
func TestScan_UnsupportedLockfileIsNotADegradation(t *testing.T) {
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
		t.Errorf("a deliberately unparsed file was reported as degraded: %+v", result.Degradations)
	}
}
