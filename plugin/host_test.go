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
	h := newTestHost(WithPolicy(policy))

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

	h.MergeResults(resp, result)

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

	h.MergeResults(resp, result)

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

	h.MergeResults(resp, result)

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

	h.MergeResults(&pluginv1.InvokeToolResponse{}, result)

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
	h.MergeResults(nil, result)
	h.MergeResults(&pluginv1.InvokeToolResponse{}, nil)
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

	h.MergeAllResults(responses, result)

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
	h := NewHost(WithPolicy(p))
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
	h := newTestHost(WithPolicy(policy))
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
	v1 = append(v1, RuntimeViolation{Type: ViolationRateLimit, PluginName: "fake"})
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
	h := newTestHost(WithPolicy(policy))

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
	h := NewHost(WithPolicy(policy))
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
	h := newTestHost(WithPolicy(policy))

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
	h := newTestHost(WithPolicy(policy))

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
