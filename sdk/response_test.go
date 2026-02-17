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

func TestResponse_Graph(t *testing.T) {
	r := NewResponse().
		Graph("resource-deps", "IaC dependency graph").
		Node("vpc-1", NodeKindResource, "aws_vpc.main").
		NodeAt("subnet-1", NodeKindResource, "aws_subnet.pub", "network.tf").
		Edge("subnet-1", "vpc-1", EdgeKindDependsOn).
		Done().
		Build()

	if len(r.Graphs) != 1 {
		t.Fatalf("expected 1 graph, got %d", len(r.Graphs))
	}
	g := r.Graphs[0]
	if g.Name != "resource-deps" {
		t.Errorf("Name = %q", g.Name)
	}
	if g.Description != "IaC dependency graph" {
		t.Errorf("Description = %q", g.Description)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(g.Nodes))
	}
	if g.Nodes[0].Id != "vpc-1" {
		t.Errorf("Node[0].Id = %q", g.Nodes[0].Id)
	}
	if g.Nodes[1].FilePath != "network.tf" {
		t.Errorf("Node[1].FilePath = %q", g.Nodes[1].FilePath)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(g.Edges))
	}
	if g.Edges[0].Source != "subnet-1" || g.Edges[0].Target != "vpc-1" {
		t.Errorf("Edge source=%q target=%q", g.Edges[0].Source, g.Edges[0].Target)
	}
}

func TestResponse_Graph_EdgeLabeled(t *testing.T) {
	r := NewResponse().
		Graph("call-graph", "Function call graph").
		Node("main", NodeKindFunction, "main()").
		Node("auth", NodeKindFunction, "authenticate()").
		EdgeLabeled("main", "auth", EdgeKindCalls, "direct").
		Done().
		Build()

	g := r.Graphs[0]
	if g.Edges[0].Label != "direct" {
		t.Errorf("Edge.Label = %q, want %q", g.Edges[0].Label, "direct")
	}
}

func TestResponse_Graph_NodeWithProps(t *testing.T) {
	r := NewResponse().
		Graph("test", "test graph").
		NodeWithProps("n1", NodeKindData, "user-input", map[string]string{"tainted": "true"}).
		Done().
		Build()

	g := r.Graphs[0]
	if g.Nodes[0].Properties["tainted"] != "true" {
		t.Errorf("Node properties = %v", g.Nodes[0].Properties)
	}
}

func TestResponse_Enrichment(t *testing.T) {
	r := NewResponse().
		Enrichment("fp-abc123", "triage", "False positive").
		Body("This is a **false positive** because the key is a test fixture.").
		WithMetadata("reason", "test_file").
		WithConfidence(ConfidenceHigh).
		Source("ai-triage").
		Done().
		Build()

	if len(r.Enrichments) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(r.Enrichments))
	}
	e := r.Enrichments[0]
	if e.FindingFingerprint != "fp-abc123" {
		t.Errorf("FindingFingerprint = %q", e.FindingFingerprint)
	}
	if e.Kind != "triage" {
		t.Errorf("Kind = %q", e.Kind)
	}
	if e.Title != "False positive" {
		t.Errorf("Title = %q", e.Title)
	}
	if e.Body != "This is a **false positive** because the key is a test fixture." {
		t.Errorf("Body = %q", e.Body)
	}
	if e.Metadata["reason"] != "test_file" {
		t.Errorf("Metadata[reason] = %q", e.Metadata["reason"])
	}
	if e.Confidence != pluginv1.Confidence_CONFIDENCE_HIGH {
		t.Errorf("Confidence = %v", e.Confidence)
	}
	if e.Source != "ai-triage" {
		t.Errorf("Source = %q", e.Source)
	}
}

func TestResponse_MultipleEnrichments(t *testing.T) {
	r := NewResponse().
		Enrichment("fp-1", "triage", "FP").
		Body("false positive").
		Done().
		Enrichment("fp-2", "reachability", "Unreachable").
		Body("code path not reachable").
		Done().
		Build()

	if len(r.Enrichments) != 2 {
		t.Fatalf("expected 2 enrichments, got %d", len(r.Enrichments))
	}
	if r.Enrichments[0].FindingFingerprint != "fp-1" {
		t.Errorf("first enrichment fingerprint = %q", r.Enrichments[0].FindingFingerprint)
	}
	if r.Enrichments[1].Kind != "reachability" {
		t.Errorf("second enrichment kind = %q", r.Enrichments[1].Kind)
	}
}

func TestResponse_FullWithGraphsAndEnrichments(t *testing.T) {
	r := NewResponse().
		Finding("SEC-001", SeverityHigh, ConfidenceHigh, "Secret found").
		At("config.yaml", 10, 10).
		WithFingerprint("fp-1").
		Done().
		Graph("deps", "dependency graph").
		Node("a", NodeKindResource, "vpc").
		Node("b", NodeKindResource, "subnet").
		Edge("b", "a", EdgeKindDependsOn).
		Done().
		Enrichment("fp-1", "triage", "False positive").
		Body("test key").
		Source("triage-plugin").
		Done().
		Build()

	if len(r.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(r.Findings))
	}
	if len(r.Graphs) != 1 {
		t.Errorf("expected 1 graph, got %d", len(r.Graphs))
	}
	if len(r.Enrichments) != 1 {
		t.Errorf("expected 1 enrichment, got %d", len(r.Enrichments))
	}
}

func TestResponse_Empty_NewFields(t *testing.T) {
	r := NewResponse().Build()
	if len(r.Graphs) != 0 {
		t.Errorf("expected 0 graphs, got %d", len(r.Graphs))
	}
	if len(r.Enrichments) != 0 {
		t.Errorf("expected 0 enrichments, got %d", len(r.Enrichments))
	}
}
