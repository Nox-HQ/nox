package plugin

import (
	"context"
	"sort"
	"testing"

	"github.com/felixgeelhaar/hardline/core"
	"github.com/felixgeelhaar/hardline/core/analyzers/ai"
	"github.com/felixgeelhaar/hardline/core/analyzers/deps"
	"github.com/felixgeelhaar/hardline/core/findings"
	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
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
