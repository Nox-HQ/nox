package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// sampleFindingSet returns a FindingSet with two findings added in reverse
// order (rule-002 before rule-001) so tests can verify deterministic sorting.
func sampleFindingSet() *findings.FindingSet {
	fs := findings.NewFindingSet()

	fs.Add(findings.Finding{
		ID:         "f-2",
		RuleID:     "rule-002",
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceHigh,
		Location: findings.Location{
			FilePath:    "pkg/auth/handler.go",
			StartLine:   42,
			EndLine:     42,
			StartColumn: 10,
			EndColumn:   35,
		},
		Message:  "Insecure comparison of secret token",
		Metadata: map[string]string{"category": "crypto"},
	})

	fs.Add(findings.Finding{
		ID:         "f-1",
		RuleID:     "rule-001",
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location: findings.Location{
			FilePath:    "cmd/server/main.go",
			StartLine:   15,
			EndLine:     15,
			StartColumn: 1,
			EndColumn:   40,
		},
		Message:  "Hardcoded credential detected",
		Metadata: map[string]string{"category": "secrets"},
	})

	return fs
}

func TestGenerateProducesValidJSON(t *testing.T) {
	r := NewJSONReporter("0.1.0")
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Generate produced invalid JSON: %v", err)
	}

	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(report.Findings))
	}
}

func TestGenerateContainsCorrectMeta(t *testing.T) {
	r := NewJSONReporter("1.2.3")
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if report.Meta.SchemaVersion != "1.0.0" {
		t.Errorf("expected schema version 1.0.0, got %q", report.Meta.SchemaVersion)
	}
	if report.Meta.ToolName != "nox" {
		t.Errorf("expected tool name nox, got %q", report.Meta.ToolName)
	}
	if report.Meta.ToolVersion != "1.2.3" {
		t.Errorf("expected tool version 1.2.3, got %q", report.Meta.ToolVersion)
	}
	if report.Meta.GeneratedAt == "" {
		t.Error("expected GeneratedAt to be non-empty")
	}
}

func TestGenerateSortsFindingsDeterministically(t *testing.T) {
	r := NewJSONReporter("0.1.0")
	// Findings are added in reverse order (rule-002 before rule-001).
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(report.Findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(report.Findings))
	}

	// After deterministic sorting, rule-001 must come before rule-002.
	if report.Findings[0].RuleID != "rule-001" {
		t.Errorf("expected first finding rule-001, got %q", report.Findings[0].RuleID)
	}
	if report.Findings[1].RuleID != "rule-002" {
		t.Errorf("expected second finding rule-002, got %q", report.Findings[1].RuleID)
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	// Generate twice from the same input and verify the output is identical
	// after stripping the GeneratedAt field which depends on wall-clock time.
	r := NewJSONReporter("0.1.0")

	fs1 := sampleFindingSet()
	data1, err := r.Generate(fs1)
	if err != nil {
		t.Fatalf("first Generate returned error: %v", err)
	}

	fs2 := sampleFindingSet()
	data2, err := r.Generate(fs2)
	if err != nil {
		t.Fatalf("second Generate returned error: %v", err)
	}

	// Unmarshal both, zero out GeneratedAt, re-marshal for comparison.
	var r1, r2 JSONReport
	if err := json.Unmarshal(data1, &r1); err != nil {
		t.Fatalf("unmarshal r1: %v", err)
	}
	if err := json.Unmarshal(data2, &r2); err != nil {
		t.Fatalf("unmarshal r2: %v", err)
	}

	r1.Meta.GeneratedAt = ""
	r2.Meta.GeneratedAt = ""

	norm1, err := json.Marshal(r1)
	if err != nil {
		t.Fatalf("re-marshal r1: %v", err)
	}
	norm2, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("re-marshal r2: %v", err)
	}

	if string(norm1) != string(norm2) {
		t.Errorf("outputs are not deterministic:\n  first:  %s\n  second: %s", norm1, norm2)
	}
}

func TestWriteToFileCreatesValidFile(t *testing.T) {
	r := NewJSONReporter("0.1.0")
	fs := sampleFindingSet()

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	if err := r.WriteToFile(fs, path); err != nil {
		t.Fatalf("WriteToFile returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read written file: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("written file contains invalid JSON: %v", err)
	}

	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings in written file, got %d", len(report.Findings))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("could not stat written file: %v", err)
	}
	// Verify file permissions (masking with 0777 to ignore OS-specific bits).
	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("expected file permissions 0644, got %04o", perm)
	}
}

func TestEmptyFindingSetProducesValidJSON(t *testing.T) {
	r := NewJSONReporter("0.1.0")
	fs := findings.NewFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Generate produced invalid JSON for empty set: %v", err)
	}

	if report.Findings == nil {
		t.Error("expected Findings to be non-nil empty slice, got nil")
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(report.Findings))
	}
}
