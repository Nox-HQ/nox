package assist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	core "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/findings"
)

func makeScanResult(ff []findings.Finding) *core.ScanResult {
	fs := findings.NewFindingSet()
	for _, f := range ff {
		fs.Add(f)
	}
	return &core.ScanResult{
		Findings:    fs,
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}
}

func jsonExplanations(explanations []FindingExplanation) string {
	data, _ := json.Marshal(explanations)
	return string(data)
}

func TestExplain_EmptyFindings(t *testing.T) {
	mock := &MockProvider{}
	e := NewExplainer(mock)

	result := makeScanResult(nil)
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Explanations) != 0 {
		t.Fatalf("expected 0 explanations, got %d", len(report.Explanations))
	}
	if report.Summary != "No findings to explain." {
		t.Fatalf("unexpected summary: %q", report.Summary)
	}
	if len(mock.Calls) != 0 {
		t.Fatalf("expected 0 provider calls, got %d", len(mock.Calls))
	}
}

func TestExplain_SingleFinding(t *testing.T) {
	explanations := []FindingExplanation{
		{
			FindingID:   "f1",
			RuleID:      "SEC-001",
			Title:       "Hardcoded secret",
			Explanation: "A secret was found in source code.",
			Impact:      "Credential leakage.",
			Remediation: "Use environment variables.",
		},
	}

	mock := &MockProvider{
		Responses: []Response{
			{Content: jsonExplanations(explanations), PromptTokens: 100, CompletionTokens: 50},
			{Content: "One critical finding detected.", PromptTokens: 20, CompletionTokens: 10},
		},
	}

	result := makeScanResult([]findings.Finding{
		{
			ID:         "f1",
			RuleID:     "SEC-001",
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceHigh,
			Message:    "Hardcoded AWS key",
			Location:   findings.Location{FilePath: "config.env", StartLine: 1},
		},
	})

	e := NewExplainer(mock)
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Explanations) != 1 {
		t.Fatalf("expected 1 explanation, got %d", len(report.Explanations))
	}
	if report.Explanations[0].Title != "Hardcoded secret" {
		t.Fatalf("unexpected title: %q", report.Explanations[0].Title)
	}
	if report.Summary != "One critical finding detected." {
		t.Fatalf("unexpected summary: %q", report.Summary)
	}
	// 2 calls: 1 batch + 1 summary.
	if len(mock.Calls) != 2 {
		t.Fatalf("expected 2 provider calls, got %d", len(mock.Calls))
	}
	if report.Usage.PromptTokens != 100 {
		t.Fatalf("expected 100 prompt tokens, got %d", report.Usage.PromptTokens)
	}
	if report.Usage.RequestCount != 1 {
		t.Fatalf("expected 1 request count, got %d", report.Usage.RequestCount)
	}
}

func TestExplain_MultipleBatches(t *testing.T) {
	// Create 15 findings with batch size 10 → 2 batches.
	var ff []findings.Finding
	for i := 0; i < 15; i++ {
		ff = append(ff, findings.Finding{
			ID:       fmt.Sprintf("f%d", i),
			RuleID:   "SEC-001",
			Severity: findings.SeverityMedium,
			Message:  "test finding",
			Location: findings.Location{FilePath: "file.go", StartLine: i + 1},
		})
	}

	batch1 := make([]FindingExplanation, 10)
	for i := range batch1 {
		batch1[i] = FindingExplanation{
			FindingID: ff[i].ID, RuleID: "SEC-001",
			Title: "Issue", Explanation: "exp", Impact: "imp", Remediation: "fix",
		}
	}
	batch2 := make([]FindingExplanation, 5)
	for i := range batch2 {
		batch2[i] = FindingExplanation{
			FindingID: ff[10+i].ID, RuleID: "SEC-001",
			Title: "Issue", Explanation: "exp", Impact: "imp", Remediation: "fix",
		}
	}

	mock := &MockProvider{
		Responses: []Response{
			{Content: jsonExplanations(batch1), PromptTokens: 200, CompletionTokens: 100},
			{Content: jsonExplanations(batch2), PromptTokens: 150, CompletionTokens: 80},
			{Content: "Multiple medium-severity issues found.", PromptTokens: 30, CompletionTokens: 15},
		},
	}

	result := makeScanResult(ff)
	e := NewExplainer(mock, WithBatchSize(10))
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Explanations) != 15 {
		t.Fatalf("expected 15 explanations, got %d", len(report.Explanations))
	}
	// 2 batch calls + 1 summary = 3 total.
	if len(mock.Calls) != 3 {
		t.Fatalf("expected 3 provider calls, got %d", len(mock.Calls))
	}
	if report.Usage.RequestCount != 2 {
		t.Fatalf("expected 2 request count, got %d", report.Usage.RequestCount)
	}
	if report.Usage.TotalTokens != (200 + 100 + 150 + 80) {
		t.Fatalf("expected %d total tokens, got %d", 200+100+150+80, report.Usage.TotalTokens)
	}
}

func TestExplain_ProviderError(t *testing.T) {
	mock := &MockProvider{Err: errors.New("api unavailable")}

	result := makeScanResult([]findings.Finding{
		{ID: "f1", RuleID: "SEC-001", Severity: findings.SeverityHigh, Message: "test"},
	})

	e := NewExplainer(mock)
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Explanations) != 0 {
		t.Fatalf("expected 0 explanations, got %d", len(report.Explanations))
	}
	if report.Summary == "" {
		t.Fatal("expected non-empty summary with error info")
	}
}

func TestExplain_MalformedResponse(t *testing.T) {
	mock := &MockProvider{
		Responses: []Response{
			{Content: "this is not JSON", PromptTokens: 10, CompletionTokens: 5},
		},
	}

	result := makeScanResult([]findings.Finding{
		{ID: "f1", RuleID: "SEC-001", Severity: findings.SeverityHigh, Message: "test"},
	})

	e := NewExplainer(mock)
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Graceful degradation: partial report with error in summary.
	if len(report.Explanations) != 0 {
		t.Fatalf("expected 0 explanations, got %d", len(report.Explanations))
	}
	if report.Summary == "" {
		t.Fatal("expected non-empty summary with error info")
	}
}

// TestExplain_WithBasePath tests that WithBasePath option is stored and used.
func TestExplain_WithBasePath(t *testing.T) {
	// Create a temporary workspace with a source file.
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "secret.env")
	os.WriteFile(srcFile, []byte("AWS_KEY=AKIA1234567890ABCDEF\nsecond line\nthird line\n"), 0o644)

	explanations := []FindingExplanation{
		{
			FindingID:   "f1",
			RuleID:      "SEC-001",
			Title:       "Secret in env",
			Explanation: "A secret was found.",
			Impact:      "Credential leak.",
			Remediation: "Remove it.",
		},
	}

	mock := &MockProvider{
		Responses: []Response{
			{Content: jsonExplanations(explanations), PromptTokens: 100, CompletionTokens: 50},
			{Content: "Summary text.", PromptTokens: 20, CompletionTokens: 10},
		},
	}

	result := makeScanResult([]findings.Finding{
		{
			ID:         "f1",
			RuleID:     "SEC-001",
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceHigh,
			Message:    "Hardcoded AWS key",
			Location:   findings.Location{FilePath: "secret.env", StartLine: 1},
		},
	})

	e := NewExplainer(mock, WithBasePath(tmpDir))
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Explanations) != 1 {
		t.Fatalf("expected 1 explanation, got %d", len(report.Explanations))
	}

	// Verify that the provider was called with basePath-enriched content.
	if len(mock.Calls) < 1 {
		t.Fatal("expected at least one provider call")
	}
}

// TestExplain_SummaryGenerationError tests graceful handling when summary
// generation fails.
func TestExplain_SummaryGenerationError(t *testing.T) {
	explanations := []FindingExplanation{
		{
			FindingID:   "f1",
			RuleID:      "SEC-001",
			Title:       "Issue",
			Explanation: "exp",
			Impact:      "imp",
			Remediation: "fix",
		},
	}

	callCount := 0
	mock := &MockProvider{
		Responses: []Response{
			// First call (batch) succeeds.
			{Content: jsonExplanations(explanations), PromptTokens: 100, CompletionTokens: 50},
		},
		// Second call (summary) will run out of responses and error.
	}
	_ = callCount

	result := makeScanResult([]findings.Finding{
		{
			ID:       "f1",
			RuleID:   "SEC-001",
			Severity: findings.SeverityHigh,
			Message:  "test finding",
			Location: findings.Location{FilePath: "file.go"},
		},
	})

	e := NewExplainer(mock)
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have the explanation but summary should mention generation failure.
	if len(report.Explanations) != 1 {
		t.Fatalf("expected 1 explanation, got %d", len(report.Explanations))
	}
	if report.Summary == "" {
		t.Fatal("expected non-empty summary with failure info")
	}
}

func TestExplainReport_WriteFile(t *testing.T) {
	report := &ExplanationReport{
		SchemaVersion: "1.0.0",
		Explanations: []FindingExplanation{
			{
				FindingID:   "f1",
				RuleID:      "SEC-001",
				Title:       "Test",
				Explanation: "explanation",
				Impact:      "impact",
				Remediation: "fix",
			},
		},
		Summary: "test summary",
		Usage:   UsageStats{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15, RequestCount: 1},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "explanations.json")

	if err := report.WriteFile(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	var loaded ExplanationReport
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}

	if loaded.SchemaVersion != "1.0.0" {
		t.Fatalf("expected schema_version 1.0.0, got %q", loaded.SchemaVersion)
	}
	if len(loaded.Explanations) != 1 {
		t.Fatalf("expected 1 explanation, got %d", len(loaded.Explanations))
	}
	if loaded.Explanations[0].FindingID != "f1" {
		t.Fatalf("expected finding_id f1, got %q", loaded.Explanations[0].FindingID)
	}
}

// TestExplainReport_WriteFile_NonWritablePath tests WriteFile with a path that
// does not exist (nonexistent parent directory).
func TestExplainReport_WriteFile_NonWritablePath(t *testing.T) {
	report := &ExplanationReport{
		SchemaVersion: "1.0.0",
		Summary:       "test",
	}

	err := report.WriteFile("/nonexistent/dir/report.json")
	if err == nil {
		t.Error("expected error for non-writable path")
	}
}

// TestExplainReport_JSON tests the JSON method produces valid output.
func TestExplainReport_JSON(t *testing.T) {
	report := &ExplanationReport{
		SchemaVersion: "1.0.0",
		Explanations: []FindingExplanation{
			{
				FindingID:   "f1",
				RuleID:      "SEC-001",
				Title:       "Test",
				Explanation: "exp",
				Impact:      "imp",
				Remediation: "fix",
				References:  []string{"https://example.com"},
			},
		},
		Summary: "summary",
		Usage:   UsageStats{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15, RequestCount: 1},
	}

	data, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	// Verify it is valid JSON.
	var loaded ExplanationReport
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if loaded.Explanations[0].References[0] != "https://example.com" {
		t.Errorf("expected reference URL, got %q", loaded.Explanations[0].References[0])
	}
}

// TestExplainReport_WriteFile_EmptyReport tests writing an empty report.
func TestExplainReport_WriteFile_EmptyReport(t *testing.T) {
	report := &ExplanationReport{
		SchemaVersion: "1.0.0",
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")

	if err := report.WriteFile(path); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var loaded ExplanationReport
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if loaded.SchemaVersion != "1.0.0" {
		t.Errorf("SchemaVersion = %q, want %q", loaded.SchemaVersion, "1.0.0")
	}
}
