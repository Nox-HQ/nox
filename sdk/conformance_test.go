package sdk

import (
	"context"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
)

func TestConformance_ValidPlugin(t *testing.T) {
	manifest := NewManifest("conformance-test", "1.0.0").
		Capability("scanning", "Scan files").
		Tool("scan", "Run scan", true).
		Tool("analyze", "Analyze code", true).
		Done().
		Build()

	srv := NewPluginServer(manifest).
		HandleTool("scan", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().
				Finding("TEST-001", SeverityHigh, ConfidenceHigh, "test finding").
				At("file.go", 1, 1).
				Done().
				Build(), nil
		}).
		HandleTool("analyze", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().
				Package("express", "4.18.0", "npm").
				Build(), nil
		})

	RunConformance(t, srv)
}

func TestConformance_MinimalPlugin_NoTools(t *testing.T) {
	manifest := NewManifest("minimal", "0.1.0").Build()
	srv := NewPluginServer(manifest)

	RunConformance(t, srv)
}

func TestConformance_PluginWithAIComponents(t *testing.T) {
	manifest := NewManifest("ai-scanner", "1.0.0").
		Capability("ai", "AI analysis").
		Tool("detect-ai", "Detect AI components", true).
		Done().
		Build()

	srv := NewPluginServer(manifest).
		HandleTool("detect-ai", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().
				AIComponent("gpt-4", "model", "config.yaml").
				Detail("provider", "openai").
				Done().
				Build(), nil
		})

	RunConformance(t, srv)
}

func TestRunForTrack_CoreAnalysis(t *testing.T) {
	manifest := NewManifest("sast-plugin", "1.0.0").
		Capability("sast", "Static analysis").
		Tool("scan", "Scan for vulnerabilities", true).
		Done().
		Safety(WithRiskClass(RiskPassive)).
		Build()

	srv := NewPluginServer(manifest).
		HandleTool("scan", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().
				Finding("SAST-001", SeverityHigh, ConfidenceHigh, "SQL injection detected").
				At("app.go", 42, 42).
				Done().
				Build(), nil
		})

	RunForTrack(t, srv, registry.TrackCoreAnalysis)
}

func TestRunForTrack_AISecurity(t *testing.T) {
	manifest := NewManifest("ai-scanner", "1.0.0").
		Capability("ai-security", "AI security analysis").
		Tool("detect", "Detect AI security issues", true).
		Done().
		Safety(WithRiskClass(RiskPassive)).
		Build()

	srv := NewPluginServer(manifest).
		HandleTool("detect", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().
				Finding("AI-001", SeverityMedium, ConfidenceMedium, "Prompt injection risk").
				At("prompt.yaml", 10, 15).
				Done().
				AIComponent("gpt-4", "model", "config.yaml").
				Detail("provider", "openai").
				Done().
				Build(), nil
		})

	RunForTrack(t, srv, registry.TrackAISecurity)
}

func TestRunForTrack_DynamicRuntime(t *testing.T) {
	manifest := NewManifest("dast-plugin", "1.0.0").
		Capability("dast", "Dynamic scanning").
		Tool("scan", "DAST scan", false). // not read-only — active track
		Done().
		Safety(
			WithRiskClass(RiskActive),
			WithNeedsConfirmation(),
			WithNetworkHosts("localhost"),
		).
		Build()

	srv := NewPluginServer(manifest).
		HandleTool("scan", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().
				Finding("DAST-001", SeverityHigh, ConfidenceHigh, "XSS detected").
				Done().
				Build(), nil
		})

	RunForTrack(t, srv, registry.TrackDynamicRuntime)
}

func TestRunForTrack_PolicyGovernance(t *testing.T) {
	manifest := NewManifest("policy-gate", "1.0.0").
		Capability("policy", "Policy evaluation").
		Tool("evaluate", "Evaluate policy", true).
		Done().
		Safety(WithRiskClass(RiskPassive)).
		Build()

	srv := NewPluginServer(manifest).
		HandleTool("evaluate", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().Build(), nil
		})

	RunForTrack(t, srv, registry.TrackPolicyGovernance)
}
