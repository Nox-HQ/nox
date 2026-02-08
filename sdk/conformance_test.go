package sdk

import (
	"context"
	"testing"

	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
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
