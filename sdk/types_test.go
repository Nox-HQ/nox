package sdk

import (
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		name string
		got  pluginv1.Severity
		want pluginv1.Severity
	}{
		{"Critical", SeverityCritical, pluginv1.Severity_SEVERITY_CRITICAL},
		{"High", SeverityHigh, pluginv1.Severity_SEVERITY_HIGH},
		{"Medium", SeverityMedium, pluginv1.Severity_SEVERITY_MEDIUM},
		{"Low", SeverityLow, pluginv1.Severity_SEVERITY_LOW},
		{"Info", SeverityInfo, pluginv1.Severity_SEVERITY_INFO},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

func TestConfidenceConstants(t *testing.T) {
	tests := []struct {
		name string
		got  pluginv1.Confidence
		want pluginv1.Confidence
	}{
		{"High", ConfidenceHigh, pluginv1.Confidence_CONFIDENCE_HIGH},
		{"Medium", ConfidenceMedium, pluginv1.Confidence_CONFIDENCE_MEDIUM},
		{"Low", ConfidenceLow, pluginv1.Confidence_CONFIDENCE_LOW},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

func TestRequestFromProto_NilInput(t *testing.T) {
	req := &pluginv1.InvokeToolRequest{
		ToolName:      "scan",
		WorkspaceRoot: "/workspace",
	}
	tr := RequestFromProto(req)
	if tr.ToolName != "scan" {
		t.Errorf("ToolName = %q, want %q", tr.ToolName, "scan")
	}
	if tr.WorkspaceRoot != "/workspace" {
		t.Errorf("WorkspaceRoot = %q, want %q", tr.WorkspaceRoot, "/workspace")
	}
	if tr.Input == nil {
		t.Fatal("Input should not be nil")
	}
	if len(tr.Input) != 0 {
		t.Errorf("Input should be empty, got %v", tr.Input)
	}
}

func TestRequestFromProto_PopulatedInput(t *testing.T) {
	input, err := structpb.NewStruct(map[string]any{
		"path":    "/src",
		"verbose": true,
		"depth":   float64(3),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &pluginv1.InvokeToolRequest{
		ToolName:      "analyze",
		Input:         input,
		WorkspaceRoot: "/project",
	}
	tr := RequestFromProto(req)
	if tr.ToolName != "analyze" {
		t.Errorf("ToolName = %q, want %q", tr.ToolName, "analyze")
	}
	if tr.WorkspaceRoot != "/project" {
		t.Errorf("WorkspaceRoot = %q, want %q", tr.WorkspaceRoot, "/project")
	}
	if tr.Input["path"] != "/src" {
		t.Errorf("Input[path] = %v, want %q", tr.Input["path"], "/src")
	}
	if tr.Input["verbose"] != true {
		t.Errorf("Input[verbose] = %v, want true", tr.Input["verbose"])
	}
	if tr.Input["depth"] != float64(3) {
		t.Errorf("Input[depth] = %v, want 3", tr.Input["depth"])
	}
}

func TestRequestFromProto_WithScanContext(t *testing.T) {
	sc := &pluginv1.ScanContext{
		Findings: []*pluginv1.Finding{
			{Id: "f-1", RuleId: "SEC-001", Severity: pluginv1.Severity_SEVERITY_HIGH},
		},
		Packages: []*pluginv1.Package{
			{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		},
		AiComponents: []*pluginv1.AIComponent{
			{Name: "gpt-4", Type: "model", Path: "config.yaml"},
		},
	}
	req := &pluginv1.InvokeToolRequest{
		ToolName:    "triage",
		ScanContext: sc,
	}
	tr := RequestFromProto(req)

	if !tr.HasScanContext() {
		t.Fatal("expected HasScanContext() = true")
	}
	if len(tr.Findings()) != 1 {
		t.Errorf("expected 1 finding, got %d", len(tr.Findings()))
	}
	if len(tr.Packages()) != 1 {
		t.Errorf("expected 1 package, got %d", len(tr.Packages()))
	}
	if len(tr.AIComponents()) != 1 {
		t.Errorf("expected 1 AI component, got %d", len(tr.AIComponents()))
	}
}

func TestToolRequest_HasScanContext_Nil(t *testing.T) {
	tr := ToolRequest{ToolName: "scan"}
	if tr.HasScanContext() {
		t.Error("expected HasScanContext() = false for nil context")
	}
	if tr.Findings() != nil {
		t.Error("Findings() should be nil without context")
	}
	if tr.Packages() != nil {
		t.Error("Packages() should be nil without context")
	}
	if tr.AIComponents() != nil {
		t.Error("AIComponents() should be nil without context")
	}
}

func TestToolRequest_InputString(t *testing.T) {
	tr := ToolRequest{
		Input: map[string]any{
			"path":    "/src",
			"verbose": true,
		},
	}
	if got := tr.InputString("path"); got != "/src" {
		t.Errorf("InputString(path) = %q, want %q", got, "/src")
	}
	if got := tr.InputString("verbose"); got != "" {
		t.Errorf("InputString(verbose) should be empty for non-string, got %q", got)
	}
	if got := tr.InputString("missing"); got != "" {
		t.Errorf("InputString(missing) should be empty, got %q", got)
	}
}

func TestNodeKindConstants(t *testing.T) {
	if NodeKindResource != pluginv1.NodeKind_NODE_KIND_RESOURCE {
		t.Errorf("NodeKindResource mismatch")
	}
	if NodeKindFunction != pluginv1.NodeKind_NODE_KIND_FUNCTION {
		t.Errorf("NodeKindFunction mismatch")
	}
	if NodeKindData != pluginv1.NodeKind_NODE_KIND_DATA {
		t.Errorf("NodeKindData mismatch")
	}
	if NodeKindService != pluginv1.NodeKind_NODE_KIND_SERVICE {
		t.Errorf("NodeKindService mismatch")
	}
	if NodeKindPolicy != pluginv1.NodeKind_NODE_KIND_POLICY {
		t.Errorf("NodeKindPolicy mismatch")
	}
}

func TestEdgeKindConstants(t *testing.T) {
	if EdgeKindDependsOn != pluginv1.EdgeKind_EDGE_KIND_DEPENDS_ON {
		t.Errorf("EdgeKindDependsOn mismatch")
	}
	if EdgeKindCalls != pluginv1.EdgeKind_EDGE_KIND_CALLS {
		t.Errorf("EdgeKindCalls mismatch")
	}
	if EdgeKindFlowsTo != pluginv1.EdgeKind_EDGE_KIND_FLOWS_TO {
		t.Errorf("EdgeKindFlowsTo mismatch")
	}
	if EdgeKindExposes != pluginv1.EdgeKind_EDGE_KIND_EXPOSES {
		t.Errorf("EdgeKindExposes mismatch")
	}
	if EdgeKindReferences != pluginv1.EdgeKind_EDGE_KIND_REFERENCES {
		t.Errorf("EdgeKindReferences mismatch")
	}
}
