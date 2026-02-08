package assist

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	core "github.com/felixgeelhaar/hardline/core"
	"github.com/felixgeelhaar/hardline/core/analyzers/ai"
	"github.com/felixgeelhaar/hardline/core/analyzers/deps"
	"github.com/felixgeelhaar/hardline/core/findings"
)

// mockPluginSource is an in-package test double for PluginSource.
type mockPluginSource struct {
	caps       []PluginCapability
	results    map[string]*PluginToolResult
	errors     map[string]error
	invocations []string
}

func (m *mockPluginSource) Capabilities(_ context.Context) []PluginCapability {
	return m.caps
}

func (m *mockPluginSource) InvokeReadOnly(_ context.Context, toolName string, _ map[string]any, _ string) (*PluginToolResult, error) {
	m.invocations = append(m.invocations, toolName)
	if err, ok := m.errors[toolName]; ok {
		return nil, err
	}
	if r, ok := m.results[toolName]; ok {
		return r, nil
	}
	return nil, errors.New("tool not found: " + toolName)
}

// --- formatPluginContext tests ---

func TestFormatPluginContext_Empty(t *testing.T) {
	got := formatPluginContext(nil)
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}

	got = formatPluginContext([]PluginCapability{})
	if got != "" {
		t.Fatalf("expected empty string for empty slice, got %q", got)
	}
}

func TestFormatPluginContext(t *testing.T) {
	caps := []PluginCapability{
		{
			PluginName:  "vuln-checker",
			PluginVer:   "1.2.0",
			Name:        "vulnerability-scan",
			Description: "Checks packages against vulnerability databases",
			Tools: []PluginTool{
				{Name: "check-cve", Description: "Look up CVE for a package", ReadOnly: true},
				{Name: "apply-patch", Description: "Auto-apply a security patch", ReadOnly: false},
			},
		},
	}

	got := formatPluginContext(caps)

	if !strings.Contains(got, "vuln-checker") {
		t.Error("expected plugin name in output")
	}
	if !strings.Contains(got, "v1.2.0") {
		t.Error("expected plugin version in output")
	}
	if !strings.Contains(got, "vulnerability-scan") {
		t.Error("expected capability name in output")
	}
	if !strings.Contains(got, "check-cve") {
		t.Error("expected tool name in output")
	}
	if !strings.Contains(got, "[read-only]") {
		t.Error("expected [read-only] marker for read-only tool")
	}
	if strings.Contains(got, "apply-patch: Auto-apply a security patch [read-only]") {
		t.Error("non-read-only tool should not have [read-only] marker")
	}
}

// --- formatToolResult tests ---

func TestFormatToolResult(t *testing.T) {
	result := &PluginToolResult{
		ToolName:   "check-cve",
		PluginName: "vuln-checker",
		Output:     `{"cve": "CVE-2024-1234", "severity": "high"}`,
	}

	got := formatToolResult(result)

	if !strings.Contains(got, "check-cve") {
		t.Error("expected tool name in output")
	}
	if !strings.Contains(got, "vuln-checker") {
		t.Error("expected plugin name in output")
	}
	if !strings.Contains(got, "CVE-2024-1234") {
		t.Error("expected output content")
	}
}

func TestFormatToolResult_Nil(t *testing.T) {
	got := formatToolResult(nil)
	if got != "" {
		t.Fatalf("expected empty string for nil result, got %q", got)
	}
}

func TestFormatToolResult_Truncation(t *testing.T) {
	longOutput := strings.Repeat("x", maxToolResultLen+100)
	result := &PluginToolResult{
		ToolName:   "big-tool",
		PluginName: "test-plugin",
		Output:     longOutput,
	}

	got := formatToolResult(result)

	if !strings.Contains(got, "[truncated]") {
		t.Error("expected truncation indicator")
	}
	// The formatted output should not contain the full long string.
	if strings.Contains(got, longOutput) {
		t.Error("expected output to be truncated")
	}
}

func TestFormatToolResult_WithDiagnostics(t *testing.T) {
	result := &PluginToolResult{
		ToolName:    "check-cve",
		PluginName:  "vuln-checker",
		Output:      "ok",
		Diagnostics: []string{"rate limited", "partial data"},
	}

	got := formatToolResult(result)

	if !strings.Contains(got, "Diagnostics:") {
		t.Error("expected diagnostics section")
	}
	if !strings.Contains(got, "rate limited") {
		t.Error("expected first diagnostic")
	}
	if !strings.Contains(got, "partial data") {
		t.Error("expected second diagnostic")
	}
}

// --- Explainer integration tests ---

func TestExplain_WithPluginSource(t *testing.T) {
	caps := []PluginCapability{
		{
			PluginName:  "vuln-checker",
			PluginVer:   "1.0.0",
			Name:        "vuln-scan",
			Description: "CVE lookup",
			Tools: []PluginTool{
				{Name: "check-cve", Description: "Lookup CVEs", ReadOnly: true},
			},
		},
	}

	ps := &mockPluginSource{caps: caps}

	explanations := []FindingExplanation{
		{
			FindingID:   "f1",
			RuleID:      "SEC-001",
			Title:       "Secret",
			Explanation: "Found a secret",
			Impact:      "Leak",
			Remediation: "Remove it",
		},
	}

	mock := &MockProvider{
		Responses: []Response{
			{Content: jsonExplanations(explanations), PromptTokens: 100, CompletionTokens: 50},
			{Content: "Summary text", PromptTokens: 20, CompletionTokens: 10},
		},
	}

	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "f1", RuleID: "SEC-001", Severity: findings.SeverityHigh,
		Message: "test", Location: findings.Location{FilePath: "f.go"},
	})
	result := &core.ScanResult{
		Findings:    fs,
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	e := NewExplainer(mock, WithPluginSource(ps))
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Plugin capabilities should appear in the context message sent to the LLM.
	if len(mock.Calls) < 1 {
		t.Fatal("expected at least one provider call")
	}
	contextMsg := mock.Calls[0][1].Content // Second message (user context)
	if !strings.Contains(contextMsg, "vuln-checker") {
		t.Error("expected plugin name in LLM context message")
	}
	if !strings.Contains(contextMsg, "check-cve") {
		t.Error("expected tool name in LLM context message")
	}

	// Report should include plugin context.
	if report.PluginContext == nil {
		t.Fatal("expected PluginContext to be set")
	}
	if len(report.PluginContext.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(report.PluginContext.Capabilities))
	}
	if report.PluginContext.Capabilities[0] != "vuln-checker.vuln-scan" {
		t.Fatalf("unexpected capability: %q", report.PluginContext.Capabilities[0])
	}
}

func TestExplain_WithEnrichmentTools(t *testing.T) {
	caps := []PluginCapability{
		{
			PluginName: "vuln-checker", PluginVer: "1.0.0",
			Name: "vuln-scan", Description: "CVE lookup",
		},
	}

	ps := &mockPluginSource{
		caps: caps,
		results: map[string]*PluginToolResult{
			"check-cve": {
				ToolName:   "check-cve",
				PluginName: "vuln-checker",
				Output:     `{"cves": ["CVE-2024-5678"]}`,
			},
		},
	}

	explanations := []FindingExplanation{
		{FindingID: "f1", RuleID: "SEC-001", Title: "Issue", Explanation: "exp", Impact: "imp", Remediation: "fix"},
	}

	mock := &MockProvider{
		Responses: []Response{
			{Content: jsonExplanations(explanations), PromptTokens: 100, CompletionTokens: 50},
			{Content: "Summary", PromptTokens: 20, CompletionTokens: 10},
		},
	}

	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "f1", RuleID: "SEC-001", Severity: findings.SeverityHigh,
		Message: "test", Location: findings.Location{FilePath: "f.go"},
	})
	result := &core.ScanResult{
		Findings:    fs,
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	e := NewExplainer(mock, WithPluginSource(ps), WithEnrichmentTools("check-cve"))
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Enrichment output should appear in LLM context.
	contextMsg := mock.Calls[0][1].Content
	if !strings.Contains(contextMsg, "CVE-2024-5678") {
		t.Error("expected enrichment output in LLM context message")
	}

	// Report should record enrichment tools used.
	if report.PluginContext == nil {
		t.Fatal("expected PluginContext to be set")
	}
	if len(report.PluginContext.Enrichments) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(report.PluginContext.Enrichments))
	}
	if report.PluginContext.Enrichments[0] != "check-cve" {
		t.Fatalf("unexpected enrichment: %q", report.PluginContext.Enrichments[0])
	}

	// Verify the tool was actually invoked.
	if len(ps.invocations) != 1 || ps.invocations[0] != "check-cve" {
		t.Fatalf("expected 1 invocation of check-cve, got %v", ps.invocations)
	}
}

func TestExplain_EnrichmentToolError(t *testing.T) {
	caps := []PluginCapability{
		{
			PluginName: "vuln-checker", PluginVer: "1.0.0",
			Name: "vuln-scan", Description: "CVE lookup",
		},
	}

	ps := &mockPluginSource{
		caps:   caps,
		errors: map[string]error{"check-cve": errors.New("connection refused")},
	}

	explanations := []FindingExplanation{
		{FindingID: "f1", RuleID: "SEC-001", Title: "Issue", Explanation: "exp", Impact: "imp", Remediation: "fix"},
	}

	mock := &MockProvider{
		Responses: []Response{
			{Content: jsonExplanations(explanations), PromptTokens: 100, CompletionTokens: 50},
			{Content: "Summary", PromptTokens: 20, CompletionTokens: 10},
		},
	}

	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "f1", RuleID: "SEC-001", Severity: findings.SeverityHigh,
		Message: "test", Location: findings.Location{FilePath: "f.go"},
	})
	scanResult := &core.ScanResult{
		Findings:    fs,
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	e := NewExplainer(mock, WithPluginSource(ps), WithEnrichmentTools("check-cve"))
	report, err := e.Explain(context.Background(), scanResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should still produce explanations despite enrichment failure.
	if len(report.Explanations) != 1 {
		t.Fatalf("expected 1 explanation, got %d", len(report.Explanations))
	}

	// Enrichment should NOT be recorded since it failed.
	if report.PluginContext != nil && len(report.PluginContext.Enrichments) > 0 {
		t.Error("failed enrichments should not be recorded")
	}
}

func TestExplain_NoPluginSource(t *testing.T) {
	explanations := []FindingExplanation{
		{FindingID: "f1", RuleID: "SEC-001", Title: "Issue", Explanation: "exp", Impact: "imp", Remediation: "fix"},
	}

	mock := &MockProvider{
		Responses: []Response{
			{Content: jsonExplanations(explanations), PromptTokens: 100, CompletionTokens: 50},
			{Content: "Summary", PromptTokens: 20, CompletionTokens: 10},
		},
	}

	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "f1", RuleID: "SEC-001", Severity: findings.SeverityHigh,
		Message: "test", Location: findings.Location{FilePath: "f.go"},
	})
	result := &core.ScanResult{
		Findings:    fs,
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	// No WithPluginSource — should work as before.
	e := NewExplainer(mock)
	report, err := e.Explain(context.Background(), result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Explanations) != 1 {
		t.Fatalf("expected 1 explanation, got %d", len(report.Explanations))
	}
	if report.PluginContext != nil {
		t.Error("expected nil PluginContext when no plugin source is set")
	}
}

func TestPluginContextInfo_JSON(t *testing.T) {
	report := &ExplanationReport{
		SchemaVersion: "1.0.0",
		Explanations:  []FindingExplanation{},
		Summary:       "test",
		PluginContext: &PluginContextInfo{
			Capabilities: []string{"vuln-checker.vuln-scan"},
			Enrichments:  []string{"check-cve"},
		},
	}

	data, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON marshalling failed: %v", err)
	}

	var loaded ExplanationReport
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("JSON unmarshalling failed: %v", err)
	}

	if loaded.PluginContext == nil {
		t.Fatal("expected PluginContext in loaded report")
	}
	if len(loaded.PluginContext.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(loaded.PluginContext.Capabilities))
	}
	if len(loaded.PluginContext.Enrichments) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(loaded.PluginContext.Enrichments))
	}
}

func TestPluginContextInfo_OmittedWhenNil(t *testing.T) {
	report := &ExplanationReport{
		SchemaVersion: "1.0.0",
		Explanations:  []FindingExplanation{},
		Summary:       "test",
	}

	data, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON marshalling failed: %v", err)
	}

	if strings.Contains(string(data), "plugin_context") {
		t.Error("expected plugin_context to be omitted when nil")
	}
}
