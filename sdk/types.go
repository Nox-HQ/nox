package sdk

import (
	"context"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// Severity aliases so plugin authors don't need to import the gen package.
const (
	SeverityCritical = pluginv1.Severity_SEVERITY_CRITICAL
	SeverityHigh     = pluginv1.Severity_SEVERITY_HIGH
	SeverityMedium   = pluginv1.Severity_SEVERITY_MEDIUM
	SeverityLow      = pluginv1.Severity_SEVERITY_LOW
	SeverityInfo     = pluginv1.Severity_SEVERITY_INFO
)

// Confidence aliases so plugin authors don't need to import the gen package.
const (
	ConfidenceHigh   = pluginv1.Confidence_CONFIDENCE_HIGH
	ConfidenceMedium = pluginv1.Confidence_CONFIDENCE_MEDIUM
	ConfidenceLow    = pluginv1.Confidence_CONFIDENCE_LOW
)

// Risk class constants for SafetyRequirements.
const (
	RiskPassive = "passive"
	RiskActive  = "active"
	RiskRuntime = "runtime"
)

// ToolRequest wraps InvokeToolRequest with convenience accessors.
type ToolRequest struct {
	ToolName      string
	Input         map[string]any
	WorkspaceRoot string
}

// ToolHandler is the function signature plugin authors implement per tool.
type ToolHandler func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error)

// RequestFromProto converts a proto InvokeToolRequest into a ToolRequest.
func RequestFromProto(req *pluginv1.InvokeToolRequest) ToolRequest {
	input := make(map[string]any)
	if req.GetInput() != nil {
		input = req.GetInput().AsMap()
	}
	return ToolRequest{
		ToolName:      req.GetToolName(),
		Input:         input,
		WorkspaceRoot: req.GetWorkspaceRoot(),
	}
}
