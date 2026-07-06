package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
)

// TestRunScanWithOptions_BaselinePathOverride verifies the restored --baseline
// override (ScanOptions.BaselinePath): it applies a baseline from a NON-default
// location, and without the override the same finding is NOT baselined — proving
// the override is what suppressed it (and that the default .nox/baseline.json
// auto-discovery is not silently in play).
func TestRunScanWithOptions_BaselinePathOverride(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// A custom rule that fires on a TODO comment — a deterministic finding.
	rulesFile := filepath.Join(tmpDir, "custom.yaml")
	rules := `rules:
  - id: "CUSTOM-BL"
    version: "1.0"
    description: "Detect TODO comments"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "TODO"
    file_patterns:
      - "*.go"
`
	if err := os.WriteFile(rulesFile, []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("// TODO: fix\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// First scan (no baseline) — capture the finding and build a baseline from it.
	res, err := RunScanWithOptions(tmpDir, ScanOptions{CustomRulesPath: rulesFile})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := res.Findings.Findings()
	if !hasRule(got, "CUSTOM-BL") {
		t.Fatal("expected the CUSTOM-BL finding on the first scan")
	}
	if isBaselined(got, "CUSTOM-BL") {
		t.Fatal("finding was baselined with no override in play")
	}

	// Write a baseline at a NON-default path (not .nox/baseline.json).
	blPath := filepath.Join(tmpDir, "custom-baseline.json")
	bl := baseline.Baseline{SchemaVersion: "1.0.0", Entries: baseline.FromFindings(got)}
	data, err := json.Marshal(bl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Re-scan WITH the override → the finding must be marked baselined.
	res2, err := RunScanWithOptions(tmpDir, ScanOptions{CustomRulesPath: rulesFile, BaselinePath: blPath})
	if err != nil {
		t.Fatalf("scan with override: %v", err)
	}
	if !isBaselined(res2.Findings.Findings(), "CUSTOM-BL") {
		t.Error("--baseline override did not suppress the finding from the custom path")
	}

	// Control: re-scan WITHOUT the override → not baselined (the custom baseline
	// is not the auto-discovered default, so nothing should be suppressed).
	res3, err := RunScanWithOptions(tmpDir, ScanOptions{CustomRulesPath: rulesFile})
	if err != nil {
		t.Fatalf("control scan: %v", err)
	}
	if isBaselined(res3.Findings.Findings(), "CUSTOM-BL") {
		t.Error("finding baselined WITHOUT the override — override path leaked into default discovery")
	}
}

func hasRule(fs []findings.Finding, ruleID string) bool {
	for i := range fs {
		if fs[i].RuleID == ruleID {
			return true
		}
	}
	return false
}

func isBaselined(fs []findings.Finding, ruleID string) bool {
	for i := range fs {
		if fs[i].RuleID == ruleID && fs[i].Status == findings.StatusBaselined {
			return true
		}
	}
	return false
}
