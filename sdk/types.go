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

// NodeKind aliases for plugin authors.
const (
	NodeKindResource = pluginv1.NodeKind_NODE_KIND_RESOURCE
	NodeKindFunction = pluginv1.NodeKind_NODE_KIND_FUNCTION
	NodeKindData     = pluginv1.NodeKind_NODE_KIND_DATA
	NodeKindService  = pluginv1.NodeKind_NODE_KIND_SERVICE
	NodeKindPolicy   = pluginv1.NodeKind_NODE_KIND_POLICY
)

// EdgeKind aliases for plugin authors.
const (
	EdgeKindDependsOn  = pluginv1.EdgeKind_EDGE_KIND_DEPENDS_ON
	EdgeKindCalls      = pluginv1.EdgeKind_EDGE_KIND_CALLS
	EdgeKindFlowsTo    = pluginv1.EdgeKind_EDGE_KIND_FLOWS_TO
	EdgeKindExposes    = pluginv1.EdgeKind_EDGE_KIND_EXPOSES
	EdgeKindReferences = pluginv1.EdgeKind_EDGE_KIND_REFERENCES
)

// ToolRequest wraps InvokeToolRequest with convenience accessors.
type ToolRequest struct {
	ToolName      string
	Input         map[string]any
	WorkspaceRoot string
	ScanContext   *pluginv1.ScanContext
}

// HasScanContext reports whether scan context was provided.
func (r ToolRequest) HasScanContext() bool {
	return r.ScanContext != nil
}

// Findings returns the findings from the scan context, or nil.
func (r ToolRequest) Findings() []*pluginv1.Finding {
	if r.ScanContext == nil {
		return nil
	}
	return r.ScanContext.GetFindings()
}

// Packages returns the packages from the scan context, or nil.
func (r ToolRequest) Packages() []*pluginv1.Package {
	if r.ScanContext == nil {
		return nil
	}
	return r.ScanContext.GetPackages()
}

// AIComponents returns the AI components from the scan context, or nil.
func (r ToolRequest) AIComponents() []*pluginv1.AIComponent {
	if r.ScanContext == nil {
		return nil
	}
	return r.ScanContext.GetAiComponents()
}

// InputString returns a string parameter from input, or "" if missing.
func (r ToolRequest) InputString(key string) string {
	if v, ok := r.Input[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
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
		ScanContext:   req.GetScanContext(),
	}
}
