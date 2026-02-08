package sdk

import (
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

func TestResponse_Empty(t *testing.T) {
	r := NewResponse().Build()
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Findings))
	}
	if len(r.Packages) != 0 {
		t.Errorf("expected 0 packages, got %d", len(r.Packages))
	}
	if len(r.AiComponents) != 0 {
		t.Errorf("expected 0 AI components, got %d", len(r.AiComponents))
	}
	if len(r.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics, got %d", len(r.Diagnostics))
	}
}

func TestResponse_SingleFindingWithLocation(t *testing.T) {
	r := NewResponse().
		Finding("SEC-001", SeverityHigh, ConfidenceHigh, "Hardcoded secret found").
		At("config.yaml", 10, 10).
		Columns(5, 42).
		WithMetadata("pattern", "aws_key").
		WithFingerprint("abc123").
		Done().
		Build()

	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	f := r.Findings[0]
	if f.RuleId != "SEC-001" {
		t.Errorf("RuleId = %q", f.RuleId)
	}
	if f.Severity != pluginv1.Severity_SEVERITY_HIGH {
		t.Errorf("Severity = %v", f.Severity)
	}
	if f.Confidence != pluginv1.Confidence_CONFIDENCE_HIGH {
		t.Errorf("Confidence = %v", f.Confidence)
	}
	if f.Message != "Hardcoded secret found" {
		t.Errorf("Message = %q", f.Message)
	}
	if f.Location == nil {
		t.Fatal("Location should not be nil")
	}
	if f.Location.FilePath != "config.yaml" {
		t.Errorf("FilePath = %q", f.Location.FilePath)
	}
	if f.Location.StartLine != 10 {
		t.Errorf("StartLine = %d", f.Location.StartLine)
	}
	if f.Location.EndLine != 10 {
		t.Errorf("EndLine = %d", f.Location.EndLine)
	}
	if f.Location.StartColumn != 5 {
		t.Errorf("StartColumn = %d", f.Location.StartColumn)
	}
	if f.Location.EndColumn != 42 {
		t.Errorf("EndColumn = %d", f.Location.EndColumn)
	}
	if f.Metadata["pattern"] != "aws_key" {
		t.Errorf("Metadata[pattern] = %q", f.Metadata["pattern"])
	}
	if f.Fingerprint != "abc123" {
		t.Errorf("Fingerprint = %q", f.Fingerprint)
	}
}

func TestResponse_MultipleFindings(t *testing.T) {
	r := NewResponse().
		Finding("SEC-001", SeverityHigh, ConfidenceHigh, "First").
		At("a.go", 1, 1).
		Done().
		Finding("SEC-002", SeverityMedium, ConfidenceMedium, "Second").
		At("b.go", 5, 10).
		Done().
		Build()

	if len(r.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(r.Findings))
	}
	if r.Findings[0].RuleId != "SEC-001" {
		t.Errorf("first finding RuleId = %q", r.Findings[0].RuleId)
	}
	if r.Findings[1].RuleId != "SEC-002" {
		t.Errorf("second finding RuleId = %q", r.Findings[1].RuleId)
	}
}

func TestResponse_FindingWithoutLocation(t *testing.T) {
	r := NewResponse().
		Finding("GEN-001", SeverityInfo, ConfidenceLow, "General info").
		Done().
		Build()

	f := r.Findings[0]
	if f.Location != nil {
		t.Error("Location should be nil when not set")
	}
}

func TestResponse_Package(t *testing.T) {
	r := NewResponse().
		Package("lodash", "4.17.21", "npm").
		Package("requests", "2.28.0", "pypi").
		Build()

	if len(r.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(r.Packages))
	}
	p := r.Packages[0]
	if p.Name != "lodash" {
		t.Errorf("Name = %q", p.Name)
	}
	if p.Version != "4.17.21" {
		t.Errorf("Version = %q", p.Version)
	}
	if p.Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q", p.Ecosystem)
	}
}

func TestResponse_AIComponent(t *testing.T) {
	r := NewResponse().
		AIComponent("gpt-4", "model", "config/ai.yaml").
		Detail("provider", "openai").
		Detail("temperature", "0.7").
		Done().
		Build()

	if len(r.AiComponents) != 1 {
		t.Fatalf("expected 1 AI component, got %d", len(r.AiComponents))
	}
	c := r.AiComponents[0]
	if c.Name != "gpt-4" {
		t.Errorf("Name = %q", c.Name)
	}
	if c.Type != "model" {
		t.Errorf("Type = %q", c.Type)
	}
	if c.Path != "config/ai.yaml" {
		t.Errorf("Path = %q", c.Path)
	}
	if c.Details["provider"] != "openai" {
		t.Errorf("Details[provider] = %q", c.Details["provider"])
	}
	if c.Details["temperature"] != "0.7" {
		t.Errorf("Details[temperature] = %q", c.Details["temperature"])
	}
}

func TestResponse_Diagnostic(t *testing.T) {
	r := NewResponse().
		Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING, "skipped large file", "scanner").
		Build()

	if len(r.Diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(r.Diagnostics))
	}
	d := r.Diagnostics[0]
	if d.Severity != pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING {
		t.Errorf("Severity = %v", d.Severity)
	}
	if d.Message != "skipped large file" {
		t.Errorf("Message = %q", d.Message)
	}
	if d.Source != "scanner" {
		t.Errorf("Source = %q", d.Source)
	}
}

func TestResponse_Full(t *testing.T) {
	r := NewResponse().
		Finding("SEC-001", SeverityCritical, ConfidenceHigh, "Critical finding").
		At("main.go", 42, 42).
		WithMetadata("cwe", "CWE-798").
		Done().
		Package("express", "4.18.0", "npm").
		AIComponent("claude", "model", "agents/config.yaml").
		Detail("version", "3.5").
		Done().
		Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, "scan complete", "engine").
		Build()

	if len(r.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(r.Findings))
	}
	if len(r.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(r.Packages))
	}
	if len(r.AiComponents) != 1 {
		t.Errorf("expected 1 AI component, got %d", len(r.AiComponents))
	}
	if len(r.Diagnostics) != 1 {
		t.Errorf("expected 1 diagnostic, got %d", len(r.Diagnostics))
	}
}
