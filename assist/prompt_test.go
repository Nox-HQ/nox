package assist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
)

// TestFormatFindings_Empty tests formatFindings with an empty finding list.
func TestFormatFindings_Empty(t *testing.T) {
	got := formatFindings(nil, "", nil, nil)
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

// TestFormatFindings_SingleFinding tests basic formatting of a single finding.
func TestFormatFindings_SingleFinding(t *testing.T) {
	ff := []findings.Finding{
		{
			ID:         "f1",
			RuleID:     "SEC-001",
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceHigh,
			Message:    "Hardcoded secret found",
			Location:   findings.Location{FilePath: "config.env", StartLine: 5},
		},
	}

	got := formatFindings(ff, "", ff, nil)

	if !strings.Contains(got, "Finding ID: f1") {
		t.Error("expected finding ID in output")
	}
	if !strings.Contains(got, "Rule ID: SEC-001") {
		t.Error("expected rule ID in output")
	}
	if !strings.Contains(got, "Severity: high") {
		t.Error("expected severity in output")
	}
	if !strings.Contains(got, "Confidence: high") {
		t.Error("expected confidence in output")
	}
	if !strings.Contains(got, "File: config.env") {
		t.Error("expected file path in output")
	}
	if !strings.Contains(got, "Line: 5") {
		t.Error("expected line number in output")
	}
	if !strings.Contains(got, "Message: Hardcoded secret found") {
		t.Error("expected message in output")
	}
}

// TestFormatFindings_WithMetadata tests formatting with metadata fields.
func TestFormatFindings_WithMetadata(t *testing.T) {
	ff := []findings.Finding{
		{
			ID:       "f1",
			RuleID:   "SEC-001",
			Severity: findings.SeverityMedium,
			Message:  "test",
			Location: findings.Location{FilePath: "file.go"},
			Metadata: map[string]string{
				"secret_type": "aws_key",
				"entropy":     "4.5",
			},
		},
	}

	got := formatFindings(ff, "", ff, nil)

	if !strings.Contains(got, "Metadata secret_type: aws_key") {
		t.Error("expected secret_type metadata in output")
	}
	if !strings.Contains(got, "Metadata entropy: 4.5") {
		t.Error("expected entropy metadata in output")
	}
}

// TestFormatFindings_MultipleFindingsWithSeparator tests that multiple findings
// are separated by "---".
func TestFormatFindings_MultipleFindingsWithSeparator(t *testing.T) {
	ff := []findings.Finding{
		{
			ID:       "f1",
			RuleID:   "SEC-001",
			Severity: findings.SeverityHigh,
			Message:  "First finding",
			Location: findings.Location{FilePath: "file1.go"},
		},
		{
			ID:       "f2",
			RuleID:   "SEC-002",
			Severity: findings.SeverityLow,
			Message:  "Second finding",
			Location: findings.Location{FilePath: "file2.go"},
		},
	}

	got := formatFindings(ff, "", ff, nil)

	if !strings.Contains(got, "---") {
		t.Error("expected separator between findings")
	}
	if !strings.Contains(got, "Finding ID: f1") {
		t.Error("expected first finding ID")
	}
	if !strings.Contains(got, "Finding ID: f2") {
		t.Error("expected second finding ID")
	}
}

// TestFormatFindings_NoStartLine tests that Line is omitted when StartLine is 0.
func TestFormatFindings_NoStartLine(t *testing.T) {
	ff := []findings.Finding{
		{
			ID:       "f1",
			RuleID:   "SEC-001",
			Severity: findings.SeverityInfo,
			Message:  "test",
			Location: findings.Location{FilePath: "file.go", StartLine: 0},
		},
	}

	got := formatFindings(ff, "", ff, nil)

	if strings.Contains(got, "Line:") {
		t.Error("Line should be omitted when StartLine is 0")
	}
}

// TestFormatFindings_WithSourceContext tests source context inclusion when
// basePath points to a real file.
func TestFormatFindings_WithSourceContext(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "app.go")
	content := "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n"
	if err := os.WriteFile(srcFile, []byte(content), 0o644); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	ff := []findings.Finding{
		{
			ID:       "f1",
			RuleID:   "SEC-001",
			Severity: findings.SeverityMedium,
			Message:  "test",
			Location: findings.Location{FilePath: "app.go", StartLine: 3},
		},
	}

	got := formatFindings(ff, tmpDir, ff, nil)

	if !strings.Contains(got, "Source:") {
		t.Error("expected Source: section when basePath is set and file exists")
	}
}

// TestFormatFindings_WithRuleMeta tests that rule metadata (CWE, remediation)
// is included when available in the catalog.
func TestFormatFindings_WithRuleMeta(t *testing.T) {
	ff := []findings.Finding{
		{
			ID:       "f1",
			RuleID:   "SEC-001",
			Severity: findings.SeverityHigh,
			Message:  "test",
			Location: findings.Location{FilePath: "file.go", StartLine: 1},
		},
	}

	cat := map[string]catalog.RuleMeta{
		"SEC-001": {
			ID:          "SEC-001",
			CWE:         "CWE-798",
			Remediation: "Use environment variables instead of hardcoded secrets.",
		},
	}

	got := formatFindings(ff, "", ff, cat)

	if !strings.Contains(got, "CWE: CWE-798") {
		t.Error("expected CWE in output")
	}
	if !strings.Contains(got, "Known Remediation:") {
		t.Error("expected remediation in output")
	}
}

// TestFormatContext_EmptyResult tests formatContext with an empty scan result.
func TestFormatContext_EmptyResult(t *testing.T) {
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	got := formatContext(result)

	if !strings.Contains(got, "Total findings: 0") {
		t.Error("expected 'Total findings: 0'")
	}
	if strings.Contains(got, "Dependencies:") {
		t.Error("should not mention dependencies when none exist")
	}
	if strings.Contains(got, "AI components:") {
		t.Error("should not mention AI components when none exist")
	}
}

// TestFormatContext_WithFindings tests formatContext with findings of various
// severities.
func TestFormatContext_WithFindings(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{ID: "f1", RuleID: "SEC-001", Severity: findings.SeverityCritical, Message: "critical"})
	fs.Add(findings.Finding{ID: "f2", RuleID: "SEC-002", Severity: findings.SeverityHigh, Message: "high"})
	fs.Add(findings.Finding{ID: "f3", RuleID: "SEC-003", Severity: findings.SeverityHigh, Message: "high2"})
	fs.Add(findings.Finding{ID: "f4", RuleID: "SEC-004", Severity: findings.SeverityMedium, Message: "medium"})
	fs.Add(findings.Finding{ID: "f5", RuleID: "SEC-005", Severity: findings.SeverityLow, Message: "low"})
	fs.Add(findings.Finding{ID: "f6", RuleID: "SEC-006", Severity: findings.SeverityInfo, Message: "info"})

	result := &core.ScanResult{
		Findings:    fs,
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	got := formatContext(result)

	if !strings.Contains(got, "Total findings: 6") {
		t.Error("expected 'Total findings: 6'")
	}
	if !strings.Contains(got, "critical: 1") {
		t.Error("expected critical count")
	}
	if !strings.Contains(got, "high: 2") {
		t.Error("expected high count")
	}
	if !strings.Contains(got, "medium: 1") {
		t.Error("expected medium count")
	}
	if !strings.Contains(got, "low: 1") {
		t.Error("expected low count")
	}
	if !strings.Contains(got, "info: 1") {
		t.Error("expected info count")
	}
}

// TestFormatContext_WithDependencies tests formatContext with package inventory.
func TestFormatContext_WithDependencies(t *testing.T) {
	fs := findings.NewFindingSet()

	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "express", Version: "4.18.0", Ecosystem: "npm"})
	inv.Add(deps.Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"})
	inv.Add(deps.Package{Name: "gin", Version: "1.9.0", Ecosystem: "go"})

	result := &core.ScanResult{
		Findings:    fs,
		Inventory:   inv,
		AIInventory: ai.NewInventory(),
	}

	got := formatContext(result)

	if !strings.Contains(got, "Dependencies:") {
		t.Error("expected Dependencies section")
	}
	if !strings.Contains(got, "npm: 2 packages") {
		t.Error("expected npm package count")
	}
	if !strings.Contains(got, "go: 1 packages") {
		t.Error("expected go package count")
	}
}

// TestFormatContext_WithAIComponents tests formatContext with AI inventory.
func TestFormatContext_WithAIComponents(t *testing.T) {
	fs := findings.NewFindingSet()

	aiInv := ai.NewInventory()
	aiInv.Components = append(aiInv.Components, ai.Component{
		Name: "summarizer",
		Type: "prompt",
		Path: "prompts/summarize.txt",
	})
	aiInv.Components = append(aiInv.Components, ai.Component{
		Name: "reviewer",
		Type: "agent",
		Path: "agents/review.yaml",
	})

	result := &core.ScanResult{
		Findings:    fs,
		Inventory:   &deps.PackageInventory{},
		AIInventory: aiInv,
	}

	got := formatContext(result)

	if !strings.Contains(got, "AI components: 2") {
		t.Error("expected 'AI components: 2'")
	}
}

// TestSystemPrompt tests that systemPrompt returns a non-empty string with
// expected content.
func TestSystemPrompt(t *testing.T) {
	got := systemPrompt()

	if got == "" {
		t.Fatal("expected non-empty system prompt")
	}
	if !strings.Contains(got, "security expert") {
		t.Error("expected 'security expert' in system prompt")
	}
	if !strings.Contains(got, "JSON") {
		t.Error("expected 'JSON' in system prompt")
	}
}

// TestSummaryPrompt tests that summaryPrompt produces correct output.
func TestSummaryPrompt(t *testing.T) {
	explanations := []FindingExplanation{
		{RuleID: "SEC-001", Title: "Secret found", Explanation: "A secret in code"},
		{RuleID: "SEC-002", Title: "Insecure config", Explanation: "Missing TLS"},
	}

	got := summaryPrompt(explanations)

	if !strings.Contains(got, "executive summary") {
		t.Error("expected 'executive summary' in prompt")
	}
	if !strings.Contains(got, "SEC-001") {
		t.Error("expected rule ID SEC-001")
	}
	if !strings.Contains(got, "SEC-002") {
		t.Error("expected rule ID SEC-002")
	}
	if !strings.Contains(got, "Secret found") {
		t.Error("expected title 'Secret found'")
	}
}

// TestSummaryPrompt_Empty tests summaryPrompt with no explanations.
func TestSummaryPrompt_Empty(t *testing.T) {
	got := summaryPrompt(nil)

	if !strings.Contains(got, "executive summary") {
		t.Error("expected 'executive summary' in prompt even with no explanations")
	}
}
