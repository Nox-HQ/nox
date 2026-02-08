package server

import (
	"encoding/json"
	"testing"

	"github.com/felixgeelhaar/hardline/plugin"
	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
)

func TestSerializePluginList_Empty(t *testing.T) {
	data, err := serializePluginList(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "[]" {
		t.Fatalf("expected empty JSON array, got: %s", data)
	}
}

func TestSerializePluginList_SinglePlugin(t *testing.T) {
	plugins := []plugin.PluginInfo{
		{
			Name:       "test-scanner",
			Version:    "1.0.0",
			APIVersion: "v1",
			Capabilities: []plugin.CapabilityInfo{
				{
					Name:        "scanning",
					Description: "Security scanning",
					Tools: []plugin.ToolInfo{
						{Name: "scan", Description: "Run scan", ReadOnly: true},
					},
					Resources: []plugin.ResourceInfo{
						{URITemplate: "hardline://plugins/test-scanner/results", Name: "results", MimeType: "application/json"},
					},
				},
			},
		},
	}

	data, err := serializePluginList(plugins)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result []pluginListJSON
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(result))
	}
	if result[0].Name != "test-scanner" {
		t.Errorf("name = %q, want %q", result[0].Name, "test-scanner")
	}
	if result[0].Version != "1.0.0" {
		t.Errorf("version = %q, want %q", result[0].Version, "1.0.0")
	}
	if len(result[0].Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(result[0].Capabilities))
	}
	cap := result[0].Capabilities[0]
	if len(cap.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(cap.Tools))
	}
	if cap.Tools[0].Name != "scan" {
		t.Errorf("tool name = %q, want %q", cap.Tools[0].Name, "scan")
	}
	if !cap.Tools[0].ReadOnly {
		t.Error("tool should be read_only")
	}
	if len(cap.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(cap.Resources))
	}
	if cap.Resources[0].URITemplate != "hardline://plugins/test-scanner/results" {
		t.Errorf("resource URI = %q", cap.Resources[0].URITemplate)
	}
}

func TestSerializeInvokeToolResponse_Empty(t *testing.T) {
	resp := &pluginv1.InvokeToolResponse{}
	data, err := serializeInvokeResult(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result invokeResultJSON
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
	if len(result.Packages) != 0 {
		t.Errorf("expected no packages, got %d", len(result.Packages))
	}
}

func TestSerializeInvokeToolResponse_WithFindings(t *testing.T) {
	resp := &pluginv1.InvokeToolResponse{
		Findings: []*pluginv1.Finding{
			{
				Id:         "f-1",
				RuleId:     "SEC-001",
				Severity:   pluginv1.Severity_SEVERITY_HIGH,
				Confidence: pluginv1.Confidence_CONFIDENCE_MEDIUM,
				Location: &pluginv1.Location{
					FilePath:  "src/main.go",
					StartLine: 42,
					EndLine:   42,
				},
				Message:     "hardcoded secret",
				Fingerprint: "fp123",
				Metadata:    map[string]string{"key": "value"},
			},
		},
	}

	data, err := serializeInvokeResult(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result invokeResultJSON
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != "f-1" {
		t.Errorf("ID = %q, want %q", f.ID, "f-1")
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want %q", f.Severity, "high")
	}
	if f.Confidence != "medium" {
		t.Errorf("Confidence = %q, want %q", f.Confidence, "medium")
	}
	if f.Location == nil {
		t.Fatal("expected location")
	}
	if f.Location.FilePath != "src/main.go" {
		t.Errorf("FilePath = %q, want %q", f.Location.FilePath, "src/main.go")
	}
	if f.Location.StartLine != 42 {
		t.Errorf("StartLine = %d, want 42", f.Location.StartLine)
	}
	if f.Metadata["key"] != "value" {
		t.Errorf("Metadata[key] = %q, want %q", f.Metadata["key"], "value")
	}
}

func TestSerializeInvokeToolResponse_WithAllTypes(t *testing.T) {
	resp := &pluginv1.InvokeToolResponse{
		Findings: []*pluginv1.Finding{
			{Id: "f-1", Severity: pluginv1.Severity_SEVERITY_LOW},
		},
		Packages: []*pluginv1.Package{
			{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
		},
		AiComponents: []*pluginv1.AIComponent{
			{Name: "agent", Type: "agent", Path: "agents/main.yaml", Details: map[string]string{"model": "gpt-4"}},
		},
		Diagnostics: []*pluginv1.Diagnostic{
			{Severity: pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING, Message: "deprecated API", Source: "scanner"},
		},
	}

	data, err := serializeInvokeResult(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result invokeResultJSON
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
	if len(result.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(result.Packages))
	}
	if result.Packages[0].Name != "express" {
		t.Errorf("package name = %q, want %q", result.Packages[0].Name, "express")
	}
	if len(result.AIComponents) != 1 {
		t.Errorf("expected 1 AI component, got %d", len(result.AIComponents))
	}
	if result.AIComponents[0].Details["model"] != "gpt-4" {
		t.Errorf("AI component details[model] = %q, want %q", result.AIComponents[0].Details["model"], "gpt-4")
	}
	if len(result.Diagnostics) != 1 {
		t.Errorf("expected 1 diagnostic, got %d", len(result.Diagnostics))
	}
	if result.Diagnostics[0].Severity != "warning" {
		t.Errorf("diagnostic severity = %q, want %q", result.Diagnostics[0].Severity, "warning")
	}
}

func TestResolveToolName_NoAliases(t *testing.T) {
	s := New("0.1.0", nil)
	if got := s.resolveToolName("scanner.scan"); got != "scanner.scan" {
		t.Errorf("resolveToolName() = %q, want %q", got, "scanner.scan")
	}
}

func TestResolveToolName_WithAlias(t *testing.T) {
	s := New("0.1.0", nil, WithAliases(map[string]string{
		"scan": "test-scanner.scan",
	}))

	if got := s.resolveToolName("scan"); got != "test-scanner.scan" {
		t.Errorf("resolveToolName(scan) = %q, want %q", got, "test-scanner.scan")
	}
	if got := s.resolveToolName("other"); got != "other" {
		t.Errorf("resolveToolName(other) = %q, want %q", got, "other")
	}
}

func TestSeverityToString(t *testing.T) {
	tests := []struct {
		input pluginv1.Severity
		want  string
	}{
		{pluginv1.Severity_SEVERITY_CRITICAL, "critical"},
		{pluginv1.Severity_SEVERITY_HIGH, "high"},
		{pluginv1.Severity_SEVERITY_MEDIUM, "medium"},
		{pluginv1.Severity_SEVERITY_LOW, "low"},
		{pluginv1.Severity_SEVERITY_INFO, "info"},
		{pluginv1.Severity_SEVERITY_UNSPECIFIED, "unspecified"},
	}
	for _, tt := range tests {
		if got := severityToString(tt.input); got != tt.want {
			t.Errorf("severityToString(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestConfidenceToString(t *testing.T) {
	tests := []struct {
		input pluginv1.Confidence
		want  string
	}{
		{pluginv1.Confidence_CONFIDENCE_HIGH, "high"},
		{pluginv1.Confidence_CONFIDENCE_MEDIUM, "medium"},
		{pluginv1.Confidence_CONFIDENCE_LOW, "low"},
		{pluginv1.Confidence_CONFIDENCE_UNSPECIFIED, "unspecified"},
	}
	for _, tt := range tests {
		if got := confidenceToString(tt.input); got != tt.want {
			t.Errorf("confidenceToString(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDiagnosticSeverityToString(t *testing.T) {
	tests := []struct {
		input pluginv1.DiagnosticSeverity
		want  string
	}{
		{pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_ERROR, "error"},
		{pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING, "warning"},
		{pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, "info"},
		{pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_UNSPECIFIED, "unspecified"},
	}
	for _, tt := range tests {
		if got := diagnosticSeverityToString(tt.input); got != tt.want {
			t.Errorf("diagnosticSeverityToString(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
