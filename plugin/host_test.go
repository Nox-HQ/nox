package plugin

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/findings"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

func newTestHost(opts ...HostOption) *Host {
	return NewHost(opts...)
}

// manifestWithSafety returns a manifest with safety requirements
// that violate the default policy (needs network).
func manifestWithViolation() *pluginv1.GetManifestResponse {
	m := validManifest()
	m.Safety = &pluginv1.SafetyRequirements{
		NetworkHosts: []string{"evil.com"},
		RiskClass:    "runtime",
	}
	return m
}

// secondPluginManifest returns a different plugin manifest with a different tool.
func secondPluginManifest() *pluginv1.GetManifestResponse {
	return &pluginv1.GetManifestResponse{
		Name:       "dep-checker",
		Version:    "2.0.0",
		ApiVersion: "v1",
		Capabilities: []*pluginv1.Capability{
			{
				Name: "deps",
				Tools: []*pluginv1.ToolDef{
					{
						Name:     "check-deps",
						ReadOnly: true,
					},
				},
			},
		},
	}
}

func TestHost_NewHost_Defaults(t *testing.T) {
	h := NewHost()
	if h.policy.MaxRiskClass != RiskClassPassive {
		t.Errorf("default policy MaxRiskClass = %q, want %q", h.policy.MaxRiskClass, RiskClassPassive)
	}
	if len(h.Plugins()) != 0 {
		t.Errorf("new host should have no plugins")
	}
	if len(h.AvailableTools()) != 0 {
		t.Errorf("new host should have no tools")
	}
}

func TestHost_RegisterPlugin_Success(t *testing.T) {
	conn := startMockPlugin(t, &mockPluginServer{manifest: validManifest()})
	h := newTestHost()

	err := h.RegisterPlugin(context.Background(), conn)
	if err != nil {
		t.Fatalf("RegisterPlugin() error: %v", err)
	}

	plugins := h.Plugins()
	if len(plugins) != 1 {
		t.Fatalf("len(Plugins()) = %d, want 1", len(plugins))
	}
	if plugins[0].Name != "test-scanner" {
		t.Errorf("plugin name = %q, want %q", plugins[0].Name, "test-scanner")
	}

	tools := h.AvailableTools()
	sort.Strings(tools)
	if len(tools) != 2 {
		t.Fatalf("len(AvailableTools()) = %d, want 2", len(tools))
	}
	if tools[0] != "test-scanner.analyze" {
		t.Errorf("tools[0] = %q, want %q", tools[0], "test-scanner.analyze")
	}
	if tools[1] != "test-scanner.scan" {
		t.Errorf("tools[1] = %q, want %q", tools[1], "test-scanner.scan")
	}
}

func TestHost_RegisterPlugin_SafetyViolation(t *testing.T) {
	conn := startMockPlugin(t, &mockPluginServer{manifest: manifestWithViolation()})
	h := newTestHost()

	err := h.RegisterPlugin(context.Background(), conn)
	if err == nil {
		t.Fatal("expected error for safety violation")
	}

	if len(h.Plugins()) != 0 {
		t.Errorf("rejected plugin should not be in plugins list")
	}
}

func TestHost_RegisterPlugin_HandshakeFailure(t *testing.T) {
	// Create a manifest with wrong API version to trigger handshake failure.
	badManifest := validManifest()
	badManifest.ApiVersion = "v999"
	conn := startMockPlugin(t, &mockPluginServer{manifest: badManifest})
	h := newTestHost()

	err := h.RegisterPlugin(context.Background(), conn)
	if err == nil {
		t.Fatal("expected error for handshake failure")
	}

	if len(h.Plugins()) != 0 {
		t.Errorf("failed plugin should not be in plugins list")
	}
}

func TestHost_InvokeTool_Routes(t *testing.T) {
	// Register two plugins with different tools.
	mock1 := &mockPluginServer{
		manifest: validManifest(), // has "scan" and "analyze"
		invokeFunc: func(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{Id: "from-scanner", RuleId: "SEC-001", Severity: pluginv1.Severity_SEVERITY_HIGH},
				},
			}, nil
		},
	}
	mock2 := &mockPluginServer{
		manifest: secondPluginManifest(), // has "check-deps"
		invokeFunc: func(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Packages: []*pluginv1.Package{
					{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
				},
			}, nil
		},
	}

	conn1 := startMockPlugin(t, mock1)
	conn2 := startMockPlugin(t, mock2)
	h := newTestHost()

	if err := h.RegisterPlugin(context.Background(), conn1); err != nil {
		t.Fatalf("register plugin 1: %v", err)
	}
	if err := h.RegisterPlugin(context.Background(), conn2); err != nil {
		t.Fatalf("register plugin 2: %v", err)
	}

	// Test qualified name.
	resp, err := h.InvokeTool(context.Background(), "test-scanner.scan", nil, "/workspace")
	if err != nil {
		t.Fatalf("InvokeTool(test-scanner.scan) error: %v", err)
	}
	if len(resp.GetFindings()) != 1 || resp.GetFindings()[0].GetId() != "from-scanner" {
		t.Errorf("expected finding from scanner, got %v", resp.GetFindings())
	}

	// Test unqualified name.
	resp2, err := h.InvokeTool(context.Background(), "check-deps", nil, "/workspace")
	if err != nil {
		t.Fatalf("InvokeTool(check-deps) error: %v", err)
	}
	if len(resp2.GetPackages()) != 1 {
		t.Errorf("expected 1 package, got %d", len(resp2.GetPackages()))
	}
}

func TestHost_InvokeTool_UnknownTool(t *testing.T) {
	conn := startMockPlugin(t, &mockPluginServer{manifest: validManifest()})
	h := newTestHost()
	_ = h.RegisterPlugin(context.Background(), conn)

	_, err := h.InvokeTool(context.Background(), "nonexistent", nil, "/workspace")
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestHost_InvokeAll(t *testing.T) {
	// Both plugins have "scan" tool.
	manifest2 := secondPluginManifest()
	manifest2.Capabilities[0].Tools = append(manifest2.Capabilities[0].Tools, &pluginv1.ToolDef{
		Name:     "scan",
		ReadOnly: true,
	})

	mock1 := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{Id: "f1", RuleId: "SEC-001", Severity: pluginv1.Severity_SEVERITY_HIGH},
				},
			}, nil
		},
	}
	mock2 := &mockPluginServer{
		manifest: manifest2,
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{Id: "f2", RuleId: "DEP-001", Severity: pluginv1.Severity_SEVERITY_MEDIUM},
				},
			}, nil
		},
	}

	conn1 := startMockPlugin(t, mock1)
	conn2 := startMockPlugin(t, mock2)

	policy := DefaultPolicy()
	policy.MaxConcurrency = 2
	h := newTestHost(WithPolicy(&policy))

	_ = h.RegisterPlugin(context.Background(), conn1)
	_ = h.RegisterPlugin(context.Background(), conn2)

	responses, err := h.InvokeAll(context.Background(), "scan", nil, "/workspace")
	if err != nil {
		t.Fatalf("InvokeAll() error: %v", err)
	}
	if len(responses) != 2 {
		t.Errorf("len(responses) = %d, want 2", len(responses))
	}
}

func TestHost_MergeResults_Findings(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	resp := &pluginv1.InvokeToolResponse{
		Findings: []*pluginv1.Finding{
			{
				Id:         "f-1",
				RuleId:     "SEC-001",
				Severity:   pluginv1.Severity_SEVERITY_HIGH,
				Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
				Location: &pluginv1.Location{
					FilePath:  "src/main.go",
					StartLine: 42,
				},
				Message:     "test finding",
				Fingerprint: "fp123",
				Metadata:    map[string]string{"key": "value"},
			},
		},
	}

	h.MergeResults("test-plugin", resp, result, "")

	ff := result.Findings.Findings()
	if len(ff) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(ff))
	}
	if ff[0].ID != "f-1" {
		t.Errorf("ID = %q, want %q", ff[0].ID, "f-1")
	}
	if ff[0].Severity != findings.SeverityHigh {
		t.Errorf("Severity = %q, want %q", ff[0].Severity, findings.SeverityHigh)
	}
	if ff[0].Location.FilePath != "src/main.go" {
		t.Errorf("Location.FilePath = %q, want %q", ff[0].Location.FilePath, "src/main.go")
	}
}

func TestHost_MergeResults_Packages(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	resp := &pluginv1.InvokeToolResponse{
		Packages: []*pluginv1.Package{
			{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
			{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		},
	}

	h.MergeResults("test-plugin", resp, result, "")

	pkgs := result.Inventory.Packages()
	if len(pkgs) != 2 {
		t.Fatalf("len(Packages) = %d, want 2", len(pkgs))
	}
	if pkgs[0].Name != "express" {
		t.Errorf("first package = %q, want %q", pkgs[0].Name, "express")
	}
}

func TestHost_MergeResults_AIComponents(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	resp := &pluginv1.InvokeToolResponse{
		AiComponents: []*pluginv1.AIComponent{
			{Name: "agent", Type: "agent", Path: "agents/main.yaml"},
		},
	}

	h.MergeResults("test-plugin", resp, result, "")

	if len(result.AIInventory.Components) != 1 {
		t.Fatalf("len(Components) = %d, want 1", len(result.AIInventory.Components))
	}
	if result.AIInventory.Components[0].Name != "agent" {
		t.Errorf("component name = %q, want %q", result.AIInventory.Components[0].Name, "agent")
	}
}

func TestHost_MergeResults_EmptyResponse(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	h.MergeResults("test-plugin", &pluginv1.InvokeToolResponse{}, result, "")

	if len(result.Findings.Findings()) != 0 {
		t.Error("empty response should not add findings")
	}
	if len(result.Inventory.Packages()) != 0 {
		t.Error("empty response should not add packages")
	}
	if len(result.AIInventory.Components) != 0 {
		t.Error("empty response should not add components")
	}
}

func TestHost_MergeResults_Nil(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	// Should not panic.
	h.MergeResults("test-plugin", nil, result, "")
	h.MergeResults("test-plugin", &pluginv1.InvokeToolResponse{}, nil, "")
}

func TestHost_MergeAllResults(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	responses := []*pluginv1.InvokeToolResponse{
		{
			Findings: []*pluginv1.Finding{
				{Id: "f1", RuleId: "SEC-001", Severity: pluginv1.Severity_SEVERITY_HIGH},
			},
		},
		{
			Findings: []*pluginv1.Finding{
				{Id: "f2", RuleId: "SEC-002", Severity: pluginv1.Severity_SEVERITY_MEDIUM},
			},
			Packages: []*pluginv1.Package{
				{Name: "pkg", Version: "1.0", Ecosystem: "go"},
			},
		},
	}

	h.MergeAllResults(attributed(responses), result, "")

	if len(result.Findings.Findings()) != 2 {
		t.Errorf("len(Findings) = %d, want 2", len(result.Findings.Findings()))
	}
	if len(result.Inventory.Packages()) != 1 {
		t.Errorf("len(Packages) = %d, want 1", len(result.Inventory.Packages()))
	}
}

func TestHost_Diagnostics(t *testing.T) {
	mock := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Diagnostics: []*pluginv1.Diagnostic{
					{
						Severity: pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING,
						Message:  "deprecated API used",
						Source:   "test-scanner",
					},
					{
						Severity: pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO,
						Message:  "scan complete",
					},
				},
			}, nil
		},
	}
	conn := startMockPlugin(t, mock)
	h := newTestHost()
	_ = h.RegisterPlugin(context.Background(), conn)

	_, _ = h.InvokeTool(context.Background(), "scan", nil, "/workspace")

	diags := h.Diagnostics()
	if len(diags) != 2 {
		t.Fatalf("len(Diagnostics) = %d, want 2", len(diags))
	}
	if diags[0].Severity != "warning" {
		t.Errorf("diags[0].Severity = %q, want %q", diags[0].Severity, "warning")
	}
	if diags[0].Message != "deprecated API used" {
		t.Errorf("diags[0].Message = %q", diags[0].Message)
	}
	if diags[1].Source != "test-scanner" {
		t.Errorf("diags[1].Source = %q, want %q", diags[1].Source, "test-scanner")
	}
}

func TestHost_Close(t *testing.T) {
	conn := startMockPlugin(t, &mockPluginServer{manifest: validManifest()})
	h := newTestHost()
	_ = h.RegisterPlugin(context.Background(), conn)

	err := h.Close()
	if err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if len(h.Plugins()) != 0 {
		t.Errorf("plugins should be empty after Close")
	}
	if len(h.AvailableTools()) != 0 {
		t.Errorf("tools should be empty after Close")
	}
}

func TestHost_WithPolicy(t *testing.T) {
	p := Policy{
		MaxRiskClass:     RiskClassRuntime,
		MaxArtifactBytes: 100,
	}
	h := NewHost(WithPolicy(&p))
	if h.policy.MaxRiskClass != RiskClassRuntime {
		t.Errorf("MaxRiskClass = %q, want %q", h.policy.MaxRiskClass, RiskClassRuntime)
	}
	if h.policy.MaxArtifactBytes != 100 {
		t.Errorf("MaxArtifactBytes = %d, want 100", h.policy.MaxArtifactBytes)
	}
}

// manifestWithWriteTool returns a manifest with a non-read-only tool.
func manifestWithWriteTool() *pluginv1.GetManifestResponse {
	return &pluginv1.GetManifestResponse{
		Name:       "writer-plugin",
		Version:    "1.0.0",
		ApiVersion: "v1",
		Capabilities: []*pluginv1.Capability{
			{
				Name: "writing",
				Tools: []*pluginv1.ToolDef{
					{
						Name:        "write-file",
						Description: "Write a file",
						ReadOnly:    false,
					},
					{
						Name:        "read-file",
						Description: "Read a file",
						ReadOnly:    true,
					},
				},
			},
		},
	}
}

func TestHost_ReadOnlyEnforcement_PassiveRejectsWrite(t *testing.T) {
	mock := &mockPluginServer{
		manifest: manifestWithWriteTool(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}
	conn := startMockPlugin(t, mock)

	// Default policy is passive.
	h := newTestHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	// Non-read-only tool should be rejected.
	_, err := h.InvokeTool(context.Background(), "writer-plugin.write-file", nil, "/workspace")
	if err == nil {
		t.Fatal("expected error for non-read-only tool under passive policy")
	}

	// Plugin should be terminated.
	if len(h.Plugins()) != 0 {
		t.Error("plugin should be removed after unauthorized action")
	}

	violations := h.Violations()
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Type != ViolationUnauthorizedAction {
		t.Errorf("violation type = %q, want %q", violations[0].Type, ViolationUnauthorizedAction)
	}
}

func TestHost_ReadOnlyEnforcement_ActiveAllowsWrite(t *testing.T) {
	mock := &mockPluginServer{
		manifest: manifestWithWriteTool(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}
	conn := startMockPlugin(t, mock)

	policy := DefaultPolicy()
	policy.MaxRiskClass = RiskClassActive
	h := newTestHost(WithPolicy(&policy))
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	// Non-read-only tool should be allowed under active policy.
	_, err := h.InvokeTool(context.Background(), "writer-plugin.write-file", nil, "/workspace")
	if err != nil {
		t.Fatalf("expected write tool to be allowed under active policy, got %v", err)
	}

	if len(h.Violations()) != 0 {
		t.Error("no violations expected under active policy")
	}
}

func TestHost_ReadOnlyEnforcement_PassiveAllowsReadOnly(t *testing.T) {
	mock := &mockPluginServer{
		manifest: manifestWithWriteTool(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}
	conn := startMockPlugin(t, mock)

	// Default policy is passive.
	h := newTestHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	// Read-only tool should be allowed under passive policy.
	_, err := h.InvokeTool(context.Background(), "writer-plugin.read-file", nil, "/workspace")
	if err != nil {
		t.Fatalf("expected read-only tool to be allowed under passive policy, got %v", err)
	}
}

func TestHost_SecretRedaction(t *testing.T) {
	mock := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{
						Id:       "f-1",
						RuleId:   "SEC-001",
						Severity: pluginv1.Severity_SEVERITY_HIGH,
						Message:  "Found AKIAIOSFODNN7EXAMPLE in code",
					},
				},
			}, nil
		},
	}
	conn := startMockPlugin(t, mock)
	h := newTestHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	resp, err := h.InvokeTool(context.Background(), "scan", nil, "/workspace")
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	// Secret should be redacted.
	msg := resp.GetFindings()[0].GetMessage()
	if strings.Contains(msg, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key should be redacted, got %q", msg)
	}
	if !strings.Contains(msg, "[REDACTED]") {
		t.Errorf("should contain [REDACTED] placeholder, got %q", msg)
	}

	// Violation should be recorded but plugin should NOT be terminated.
	if len(h.Plugins()) != 1 {
		t.Error("plugin should still be running after secret redaction")
	}

	violations := h.Violations()
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Type != ViolationSecretLeaked {
		t.Errorf("violation type = %q, want %q", violations[0].Type, ViolationSecretLeaked)
	}
}

func TestHost_SecretRedaction_CleanResponse(t *testing.T) {
	mock := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{
						Id:      "f-1",
						Message: "Clean finding with no secrets",
					},
				},
			}, nil
		},
	}
	conn := startMockPlugin(t, mock)
	h := newTestHost()
	_ = h.RegisterPlugin(context.Background(), conn)

	_, err := h.InvokeTool(context.Background(), "scan", nil, "/workspace")
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(h.Violations()) != 0 {
		t.Error("clean response should not produce violations")
	}
}

func TestHost_Violations_ReturnsCopy(t *testing.T) {
	h := newTestHost()

	v1 := h.Violations()
	if len(v1) != 0 {
		t.Error("new host should have no violations")
	}

	// Mutating returned slice should not affect host.
	_ = append(v1, RuntimeViolation{Type: ViolationRateLimit, PluginName: "fake"})
	v2 := h.Violations()
	if len(v2) != 0 {
		t.Error("mutating returned slice should not affect host")
	}
}

func TestHost_RateLimitViolation(t *testing.T) {
	mock := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}
	conn := startMockPlugin(t, mock)

	policy := DefaultPolicy()
	policy.RequestsPerMinute = 1 // Very restrictive: 1 RPM.
	h := newTestHost(WithPolicy(&policy))

	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	// First call uses burst allowance.
	_, err := h.InvokeTool(context.Background(), "scan", nil, "/workspace")
	if err != nil {
		t.Fatalf("first call should succeed: %v", err)
	}

	// Second call should be rate limited (burst = 1, rate = 1/60s).
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = h.InvokeTool(ctx, "scan", nil, "/workspace")
	if err == nil {
		t.Fatal("second call should be rate limited")
	}

	violations := h.Violations()
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Type != ViolationRateLimit {
		t.Errorf("violation type = %q, want %q", violations[0].Type, ViolationRateLimit)
	}

	// Plugin should be terminated.
	if len(h.Plugins()) != 0 {
		t.Error("plugin should be removed after rate limit violation")
	}
}

func TestHost_ConfigBasedPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".nox.yaml")
	data := `
plugin_policy:
  max_risk_class: active
  requests_per_minute: 100
  bandwidth_mb_per_minute: 5
  tool_timeout_seconds: 10
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	policy := cfg.PluginPolicy.ToPolicy()
	if policy.MaxRiskClass != RiskClassActive {
		t.Errorf("MaxRiskClass = %q, want %q", policy.MaxRiskClass, RiskClassActive)
	}
	if policy.RequestsPerMinute != 100 {
		t.Errorf("RequestsPerMinute = %d, want 100", policy.RequestsPerMinute)
	}
	if policy.BandwidthBytesPerMin != 5*1024*1024 {
		t.Errorf("BandwidthBytesPerMin = %d, want %d", policy.BandwidthBytesPerMin, 5*1024*1024)
	}

	// Create a host with the config-based policy.
	h := NewHost(WithPolicy(&policy))
	if h.policy.MaxRiskClass != RiskClassActive {
		t.Errorf("host policy MaxRiskClass = %q, want %q", h.policy.MaxRiskClass, RiskClassActive)
	}
}

func TestHost_BandwidthViolation(t *testing.T) {
	mock := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			// Return a response with a large message to exhaust bandwidth.
			bigMsg := strings.Repeat("x", 1024*1024) // 1 MB message
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{Id: "f-1", Message: bigMsg},
				},
			}, nil
		},
	}
	conn := startMockPlugin(t, mock)

	policy := DefaultPolicy()
	policy.BandwidthBytesPerMin = 100 // 100 bytes/min — will be exceeded.
	h := newTestHost(WithPolicy(&policy))

	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	_, err := h.InvokeTool(context.Background(), "scan", nil, "/workspace")
	if err == nil {
		t.Fatal("expected error for bandwidth violation")
	}

	violations := h.Violations()
	foundBandwidth := false
	for _, v := range violations {
		if v.Type == ViolationBandwidth {
			foundBandwidth = true
			break
		}
	}
	if !foundBandwidth {
		t.Error("expected bandwidth violation")
	}

	// Plugin should be terminated.
	if len(h.Plugins()) != 0 {
		t.Error("plugin should be removed after bandwidth violation")
	}
}

func TestHost_InvokeAll_RateLimitedPlugin(t *testing.T) {
	// Plugin 1: will be rate-limited.
	mock1 := &mockPluginServer{
		manifest: validManifest(), // has "scan"
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{Id: "f1", RuleId: "SEC-001", Severity: pluginv1.Severity_SEVERITY_HIGH},
				},
			}, nil
		},
	}

	// Plugin 2: also has "scan", should succeed.
	manifest2 := secondPluginManifest()
	manifest2.Capabilities[0].Tools = append(manifest2.Capabilities[0].Tools, &pluginv1.ToolDef{
		Name:     "scan",
		ReadOnly: true,
	})
	mock2 := &mockPluginServer{
		manifest: manifest2,
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{Id: "f2", RuleId: "DEP-001", Severity: pluginv1.Severity_SEVERITY_MEDIUM},
				},
			}, nil
		},
	}

	conn1 := startMockPlugin(t, mock1)
	conn2 := startMockPlugin(t, mock2)

	policy := DefaultPolicy()
	policy.MaxConcurrency = 1 // Sequential so we control ordering.
	policy.RequestsPerMinute = 1
	h := newTestHost(WithPolicy(&policy))

	if err := h.RegisterPlugin(context.Background(), conn1); err != nil {
		t.Fatalf("register plugin 1: %v", err)
	}
	if err := h.RegisterPlugin(context.Background(), conn2); err != nil {
		t.Fatalf("register plugin 2: %v", err)
	}

	// First InvokeAll: both plugins use their burst allowance.
	responses, err := h.InvokeAll(context.Background(), "scan", nil, "/workspace")
	if err != nil {
		t.Fatalf("first InvokeAll: %v", err)
	}
	if len(responses) != 2 {
		t.Fatalf("first InvokeAll: expected 2 responses, got %d", len(responses))
	}

	// Second InvokeAll with tight timeout: rate-limited plugins get violations.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	responses2, err := h.InvokeAll(ctx, "scan", nil, "/workspace")
	if err != nil {
		t.Fatalf("second InvokeAll: %v", err)
	}

	// Some plugins may have been rate-limited and removed.
	// At minimum, violations should exist for rate-limited plugins.
	violations := h.Violations()
	rateLimitViolations := 0
	for _, v := range violations {
		if v.Type == ViolationRateLimit {
			rateLimitViolations++
		}
	}

	// The total of responses + violations should account for all plugins.
	// Either a plugin responded successfully or was rate-limited.
	total := len(responses2) + rateLimitViolations
	if total == 0 {
		t.Error("expected at least one response or violation from second InvokeAll")
	}

	// Diagnostics should record the violations.
	diags := h.Diagnostics()
	foundRateLimitDiag := false
	for _, d := range diags {
		if strings.Contains(d.Message, "rate_limit_exceeded") {
			foundRateLimitDiag = true
			break
		}
	}
	if rateLimitViolations > 0 && !foundRateLimitDiag {
		t.Error("rate limit violation should produce a diagnostic")
	}
}

func TestHost_MergeResults_Graphs(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	resp := &pluginv1.InvokeToolResponse{
		Graphs: []*pluginv1.Graph{
			{
				Name:        "resource-deps",
				Description: "IaC dependencies",
				Nodes: []*pluginv1.GraphNode{
					{Id: "vpc-1", Kind: pluginv1.NodeKind_NODE_KIND_RESOURCE, Label: "aws_vpc"},
					{Id: "subnet-1", Kind: pluginv1.NodeKind_NODE_KIND_RESOURCE, Label: "aws_subnet"},
				},
				Edges: []*pluginv1.GraphEdge{
					{Source: "subnet-1", Target: "vpc-1", Kind: pluginv1.EdgeKind_EDGE_KIND_DEPENDS_ON},
				},
			},
		},
	}

	h.MergeResults("test-plugin", resp, result, "")

	if len(result.Graphs) != 1 {
		t.Fatalf("expected 1 graph, got %d", len(result.Graphs))
	}
	if result.Graphs[0].Name != "resource-deps" {
		t.Errorf("graph name = %q", result.Graphs[0].Name)
	}
	if len(result.Graphs[0].Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(result.Graphs[0].Nodes))
	}
	if len(result.Graphs[0].Edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(result.Graphs[0].Edges))
	}
}

func TestHost_MergeResults_Enrichments(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	resp := &pluginv1.InvokeToolResponse{
		Enrichments: []*pluginv1.Enrichment{
			{
				FindingFingerprint: "fp-abc",
				Kind:               "triage",
				Title:              "False positive",
				Body:               "Test key detected",
				Source:             "triage-plugin",
				Confidence:         pluginv1.Confidence_CONFIDENCE_HIGH,
			},
		},
	}

	h.MergeResults("test-plugin", resp, result, "")

	if len(result.Enrichments) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(result.Enrichments))
	}
	e := result.Enrichments[0]
	if e.FindingFingerprint != "fp-abc" {
		t.Errorf("FindingFingerprint = %q", e.FindingFingerprint)
	}
	if e.Kind != "triage" {
		t.Errorf("Kind = %q", e.Kind)
	}
	if e.Source != "triage-plugin" {
		t.Errorf("Source = %q", e.Source)
	}
}

func TestHost_MergeResults_GraphsAndEnrichments_Empty(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	h.MergeResults("test-plugin", &pluginv1.InvokeToolResponse{}, result, "")

	if len(result.Graphs) != 0 {
		t.Error("empty response should not add graphs")
	}
	if len(result.Enrichments) != 0 {
		t.Error("empty response should not add enrichments")
	}
}

// manifestWithPostScanTool returns a manifest with a tool that requires scan context.
func manifestWithPostScanTool() *pluginv1.GetManifestResponse {
	return &pluginv1.GetManifestResponse{
		Name:       "post-scan-plugin",
		Version:    "1.0.0",
		ApiVersion: "v1",
		Capabilities: []*pluginv1.Capability{
			{
				Name: "triage",
				Tools: []*pluginv1.ToolDef{
					{
						Name:                "ai-triage",
						Description:         "Triage findings using AI",
						ReadOnly:            true,
						RequiresScanContext: true,
					},
				},
			},
		},
	}
}

func TestHost_InvokePostScan_Success(t *testing.T) {
	var capturedCtx *pluginv1.ScanContext
	mock := &mockPluginServer{
		manifest: manifestWithPostScanTool(),
		invokeFunc: func(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			capturedCtx = req.GetScanContext()
			return &pluginv1.InvokeToolResponse{
				Enrichments: []*pluginv1.Enrichment{
					{
						FindingFingerprint: "fp-123",
						Kind:               "triage",
						Title:              "False positive",
						Source:             "post-scan-plugin",
						Confidence:         pluginv1.Confidence_CONFIDENCE_HIGH,
					},
				},
				Graphs: []*pluginv1.Graph{
					{
						Name: "call-graph",
						Nodes: []*pluginv1.GraphNode{
							{Id: "fn-a", Kind: pluginv1.NodeKind_NODE_KIND_FUNCTION, Label: "funcA"},
							{Id: "fn-b", Kind: pluginv1.NodeKind_NODE_KIND_FUNCTION, Label: "funcB"},
						},
						Edges: []*pluginv1.GraphEdge{
							{Source: "fn-a", Target: "fn-b", Kind: pluginv1.EdgeKind_EDGE_KIND_CALLS},
						},
					},
				},
			}, nil
		},
	}

	conn := startMockPlugin(t, mock)
	h := newTestHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	// Build initial scan result with a finding.
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}
	result.Findings.Add(findings.Finding{
		ID:          "f-1",
		RuleID:      "SEC-001",
		Severity:    findings.SeverityHigh,
		Message:     "test finding",
		Fingerprint: "fp-123",
	})

	err := h.InvokePostScan(context.Background(), result, "/workspace")
	if err != nil {
		t.Fatalf("InvokePostScan: %v", err)
	}

	// ScanContext should have been populated with findings.
	if capturedCtx == nil {
		t.Fatal("ScanContext was not passed to post-scan tool")
	}
	if len(capturedCtx.GetFindings()) != 1 {
		t.Errorf("expected 1 finding in context, got %d", len(capturedCtx.GetFindings()))
	}

	// Enrichments from post-scan should be merged.
	if len(result.Enrichments) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(result.Enrichments))
	}
	if result.Enrichments[0].FindingFingerprint != "fp-123" {
		t.Errorf("enrichment fingerprint = %q", result.Enrichments[0].FindingFingerprint)
	}

	// Graphs from post-scan should be merged.
	if len(result.Graphs) != 1 {
		t.Fatalf("expected 1 graph, got %d", len(result.Graphs))
	}
	if result.Graphs[0].Name != "call-graph" {
		t.Errorf("graph name = %q", result.Graphs[0].Name)
	}
	if len(result.Graphs[0].Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(result.Graphs[0].Nodes))
	}
}

func TestHost_InvokePostScan_NoPostScanTools(t *testing.T) {
	// Register a normal plugin with no post-scan tools.
	mock := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			t.Error("InvokeTool should not be called when no post-scan tools exist")
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}

	conn := startMockPlugin(t, mock)
	h := newTestHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	err := h.InvokePostScan(context.Background(), result, "/workspace")
	if err != nil {
		t.Fatalf("InvokePostScan: %v", err)
	}

	if len(result.Enrichments) != 0 {
		t.Error("no enrichments expected when no post-scan tools")
	}
}

func TestHost_InvokePostScan_ToolError(t *testing.T) {
	mock := &mockPluginServer{
		manifest: manifestWithPostScanTool(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return nil, context.DeadlineExceeded
		},
	}

	conn := startMockPlugin(t, mock)
	h := newTestHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	// Should not return error; tool failures become diagnostics.
	err := h.InvokePostScan(context.Background(), result, "/workspace")
	if err != nil {
		t.Fatalf("InvokePostScan should not return error for tool failure: %v", err)
	}

	diags := h.Diagnostics()
	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic for failed tool, got %d", len(diags))
	}
	if !strings.Contains(diags[0].Message, "post-scan tool") {
		t.Errorf("diagnostic message = %q, expected post-scan failure message", diags[0].Message)
	}
}

func TestEstimateResponseSize_WithGraphsAndEnrichments(t *testing.T) {
	resp := &pluginv1.InvokeToolResponse{
		Graphs: []*pluginv1.Graph{
			{
				Name:        "dep-graph",
				Description: "Dependencies",
				Nodes: []*pluginv1.GraphNode{
					{Id: "a", Label: "nodeA", FilePath: "/path/a.go", Properties: map[string]string{"k": "v"}},
					{Id: "b", Label: "nodeB"},
				},
				Edges: []*pluginv1.GraphEdge{
					{Source: "a", Target: "b", Label: "uses", Properties: map[string]string{"weight": "1"}},
				},
			},
		},
		Enrichments: []*pluginv1.Enrichment{
			{
				FindingFingerprint: "fp-abc",
				Kind:               "triage",
				Title:              "Test enrichment",
				Body:               "This is the body",
				Source:             "test",
				Metadata:           map[string]string{"key": "value"},
			},
		},
	}

	size := estimateResponseSize(resp)
	if size <= 0 {
		t.Errorf("expected positive size, got %d", size)
	}

	// Verify specific contributions.
	emptySize := estimateResponseSize(&pluginv1.InvokeToolResponse{})
	if emptySize != 0 {
		t.Errorf("empty response size = %d, want 0", emptySize)
	}
}

func TestHost_MergeAllResults_WithGraphsAndEnrichments(t *testing.T) {
	h := newTestHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	responses := []*pluginv1.InvokeToolResponse{
		{
			Graphs: []*pluginv1.Graph{
				{Name: "g1"},
			},
			Enrichments: []*pluginv1.Enrichment{
				{FindingFingerprint: "fp-1", Kind: "triage"},
			},
		},
		{
			Graphs: []*pluginv1.Graph{
				{Name: "g2"},
			},
		},
	}

	h.MergeAllResults(attributed(responses), result, "")

	if len(result.Graphs) != 2 {
		t.Errorf("expected 2 graphs, got %d", len(result.Graphs))
	}
	if len(result.Enrichments) != 1 {
		t.Errorf("expected 1 enrichment, got %d", len(result.Enrichments))
	}
}

// attributed wraps bare responses for tests written before InvokeAll began
// carrying the producing plugin's name alongside each response.
func attributed(responses []*pluginv1.InvokeToolResponse) []AttributedResponse {
	out := make([]AttributedResponse, 0, len(responses))
	for _, r := range responses {
		out = append(out, AttributedResponse{PluginName: "test-plugin", Response: r})
	}
	return out
}

// TestHost_MergeResults_PluginCannotSuppressCoreFinding reproduces the attack
// end to end: a plugin claims a core finding's fingerprint, hoping Deduplicate
// (first-wins) will drop the core finding in favour of its own. Before
// fingerprints were recomputed host-side this erased the core finding
// outright — the scan reported the plugin's benign entry and nothing else.
func TestHost_MergeResults_PluginCannotSuppressCoreFinding(t *testing.T) {
	h := NewHost()
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}

	coreFinding := findings.Finding{
		RuleID:   "SEC-001",
		Severity: findings.SeverityCritical,
		Message:  "Hardcoded AWS key",
		Location: findings.Location{FilePath: "app/config.go", StartLine: 12},
	}
	result.Findings.Add(coreFinding)

	stored := result.Findings.Findings()[0].Fingerprint
	if stored == "" {
		t.Fatal("expected the core finding to have a fingerprint")
	}

	// The plugin claims the core finding's fingerprint verbatim.
	h.MergeResults("evil-plugin", &pluginv1.InvokeToolResponse{
		Findings: []*pluginv1.Finding{{
			RuleId:      "PLG-001",
			Severity:    pluginv1.Severity_SEVERITY_INFO,
			Message:     "nothing to see here",
			Fingerprint: stored,
			Location:    &pluginv1.Location{FilePath: "app/config.go", StartLine: 12},
		}},
	}, result, "")

	result.Findings.Deduplicate()

	items := result.Findings.Findings()
	if len(items) != 2 {
		t.Fatalf("expected both findings to survive dedup, got %d", len(items))
	}

	var foundCore bool
	for _, f := range items {
		if f.RuleID == "SEC-001" && f.Severity == findings.SeverityCritical {
			foundCore = true
		}
	}
	if !foundCore {
		t.Error("the core critical finding was suppressed by the plugin's claimed fingerprint")
	}
}

// TestHost_InvokePostScan_EnforcesReadOnlyGate is the regression test for a
// bypass of nox's core safety promise.
//
// InvokePostScan called the gRPC client directly, applying no policy at all, so
// a plugin declaring a non-read-only tool with requires_scan_context ran it
// regardless of the passive default. nox/remediate ships exactly that shape —
// apply_code, which modifies source — meaning "nox never auto-applies fixes"
// was bypassable by a registry plugin.
//
// This asserts the outcome that matters: the tool does not execute.
func TestHost_InvokePostScan_EnforcesReadOnlyGate(t *testing.T) {
	var invoked bool

	mock := &mockPluginServer{
		manifest: &pluginv1.GetManifestResponse{
			Name:       "mutating-plugin",
			Version:    "1.0.0",
			ApiVersion: HostAPIVersion,
			Capabilities: []*pluginv1.Capability{{
				Name: "remediation",
				Tools: []*pluginv1.ToolDef{{
					Name:                "apply_code",
					Description:         "Rewrites source files",
					ReadOnly:            false,
					RequiresScanContext: true,
				}},
			}},
		},
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			invoked = true
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}

	conn := startMockPlugin(t, mock)
	// DefaultPolicy is passive, which is what an operator gets without opting in.
	h := newTestHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}
	if err := h.InvokePostScan(context.Background(), result, t.TempDir()); err != nil {
		t.Fatalf("InvokePostScan should not abort the scan: %v", err)
	}

	if invoked {
		t.Error("a non-read-only post-scan tool executed under a passive policy — the read-only gate is bypassed")
	}

	var reported bool
	for _, d := range h.Diagnostics() {
		if strings.Contains(d.Message, "apply_code") {
			reported = true
		}
	}
	if !reported {
		t.Error("the blocked post-scan tool was not reported as a diagnostic")
	}
}

// TestHost_InvokePostScan_AllowsWhenOperatorOptsIn confirms the gate is a
// policy decision and not a hard ban: an operator who raises max_risk_class
// gets the tool they asked for.
func TestHost_InvokePostScan_AllowsWhenOperatorOptsIn(t *testing.T) {
	var invoked bool

	mock := &mockPluginServer{
		manifest: &pluginv1.GetManifestResponse{
			Name:       "mutating-plugin",
			Version:    "1.0.0",
			ApiVersion: HostAPIVersion,
			Capabilities: []*pluginv1.Capability{{
				Name: "remediation",
				Tools: []*pluginv1.ToolDef{{
					Name:                "apply_code",
					ReadOnly:            false,
					RequiresScanContext: true,
				}},
			}},
		},
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			invoked = true
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}

	conn := startMockPlugin(t, mock)
	active := DefaultPolicy()
	active.MaxRiskClass = RiskClassActive
	h := newTestHost(WithPolicy(&active))
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}
	if err := h.InvokePostScan(context.Background(), result, t.TempDir()); err != nil {
		t.Fatalf("InvokePostScan: %v", err)
	}

	if !invoked {
		t.Error("an operator who opted in to active risk class did not get the tool they configured")
	}
}

// TestHost_InvokePostScan_RefusalDoesNotKillSiblings covers a false block that
// enforcing post-scan policy introduced.
//
// The host — not a caller — enumerates every requires_scan_context tool and
// invokes them all. Treating a refusal as a terminating RuntimeViolation
// therefore punished a well-behaved plugin for a tool it never asked to run,
// and took its READ-ONLY siblings down with it: they then failed with
// "plugin not ready".
//
// A plugin shipping a passive plan_code alongside an active apply_code is the
// exact shape the SDK docs recommend, so the cascade would have hit the
// recommended layout. The blocked tool must be skipped, not fatal.
func TestHost_InvokePostScan_RefusalDoesNotKillSiblings(t *testing.T) {
	var ran []string

	mock := &mockPluginServer{
		manifest: &pluginv1.GetManifestResponse{
			Name:       "mixed-plugin",
			Version:    "1.0.0",
			ApiVersion: HostAPIVersion,
			Capabilities: []*pluginv1.Capability{{
				Name: "remediation",
				Tools: []*pluginv1.ToolDef{
					// Write tool declared FIRST, so a cascade would take out
					// everything after it.
					{Name: "apply_code", ReadOnly: false, RequiresScanContext: true},
					{Name: "plan_code", ReadOnly: true, RequiresScanContext: true},
					{Name: "verify_code", ReadOnly: true, RequiresScanContext: true},
				},
			}},
		},
		invokeFunc: func(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			ran = append(ran, req.GetToolName())
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}

	conn := startMockPlugin(t, mock)
	h := newTestHost() // passive default
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}
	if err := h.InvokePostScan(context.Background(), result, t.TempDir()); err != nil {
		t.Fatalf("InvokePostScan: %v", err)
	}

	for _, tool := range ran {
		if tool == "apply_code" {
			t.Error("the non-read-only tool ran under a passive policy")
		}
	}

	for _, want := range []string{"plan_code", "verify_code"} {
		var found bool
		for _, tool := range ran {
			if tool == want {
				found = true
			}
		}
		if !found {
			t.Errorf("read-only tool %q did not run; blocking a sibling terminated the plugin", want)
		}
	}

	if len(h.Plugins()) != 1 {
		t.Error("the plugin was terminated for a tool the host chose to invoke")
	}
}

// TestEveryInvocationPathIsGated catches an invocation path that reaches a
// plugin without passing the policy gate.
//
// This is the guard for a real bypass: enforcement was extracted into
// authorizeTool with a comment saying "any new invocation path must go through
// here", and InvokeAll — the path `nox scan` actually uses — did not. It
// re-inlined only some of the checks, so a tool declaring requirements its
// policy forbids was blocked on one path and admitted on the shipping one.
//
// The property is structural, not behavioural, so it is checked structurally:
// the raw gRPC client may only be reached from a function that is itself gated.
// A behavioural test would have to guess which path a future author adds.
func TestEveryInvocationPathIsGated(t *testing.T) {
	t.Parallel()

	// Functions permitted to call the raw client. Each is small, and each is
	// reached only after authorizeTool. Adding a name here is a deliberate
	// assertion that the caller gates first.
	gatedCallers := map[string]bool{
		"invokeRequest": true, // plugin.go — callers gate; see InvokePostScan
		"InvokeTool":    true, // plugin.go — callers gate; see Host.InvokeTool
	}

	for _, file := range []string{"host.go", "plugin.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}

		var current string
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(line, "func ") {
				current = funcName(line)
			}
			if !strings.Contains(line, ".client.InvokeTool(") {
				continue
			}
			if !gatedCallers[current] {
				t.Errorf("%s:%d: %s calls the raw plugin client directly. "+
					"Every invocation must pass through Host.authorizeTool first — "+
					"a path that skips it runs plugin tools with no policy, no rate limit "+
					"and no secret redaction. Route it through the gate, or add it to "+
					"gatedCallers if its callers gate.", file, i+1, current)
			}
		}
	}
}

// TestHostInvocationEntryPointsCallAuthorize checks the other direction: every
// exported Host method that reaches a plugin names the gate.
func TestHostInvocationEntryPointsCallAuthorize(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("host.go")
	if err != nil {
		t.Fatalf("reading host.go: %v", err)
	}

	// Exported Host methods that invoke plugin tools.
	entryPoints := []string{"InvokeTool", "InvokeAll", "InvokePostScan"}
	text := string(src)

	for _, name := range entryPoints {
		marker := "func (h *Host) " + name + "("
		start := strings.Index(text, marker)
		if start < 0 {
			t.Errorf("%s no longer exists; update this test's list of entry points", name)
			continue
		}
		end := strings.Index(text[start:], "\n}\n")
		if end < 0 {
			end = len(text) - start
		}
		body := text[start : start+end]

		if !strings.Contains(body, "authorizeTool") && !strings.Contains(body, "authorizeToolWithoutTermination") {
			t.Errorf("Host.%s invokes plugin tools without calling the authorization gate", name)
		}
		if !strings.Contains(body, "processResponse") {
			t.Errorf("Host.%s delivers plugin output without calling processResponse, "+
				"so responses are neither bandwidth-checked nor secret-redacted", name)
		}
	}
}

// funcName extracts the identifier from a Go function declaration line.
func funcName(line string) string {
	rest := strings.TrimPrefix(line, "func ")
	if strings.HasPrefix(rest, "(") {
		if idx := strings.Index(rest, ") "); idx >= 0 {
			rest = rest[idx+2:]
		}
	}
	if idx := strings.Index(rest, "("); idx >= 0 {
		return rest[:idx]
	}
	return rest
}
