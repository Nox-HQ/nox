package sdk

import (
	"testing"

	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
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
