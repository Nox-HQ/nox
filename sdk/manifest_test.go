package sdk

import (
	"testing"
)

func TestManifest_Minimal(t *testing.T) {
	m := NewManifest("test-plugin", "1.0.0").Build()
	if m.Name != "test-plugin" {
		t.Errorf("Name = %q, want %q", m.Name, "test-plugin")
	}
	if m.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", m.Version, "1.0.0")
	}
	if m.ApiVersion != "v1" {
		t.Errorf("ApiVersion = %q, want %q", m.ApiVersion, "v1")
	}
	if len(m.Capabilities) != 0 {
		t.Errorf("Capabilities should be empty, got %d", len(m.Capabilities))
	}
	if m.Safety != nil {
		t.Error("Safety should be nil for minimal manifest")
	}
}

func TestManifest_OneCapabilityOneTool(t *testing.T) {
	m := NewManifest("scanner", "2.0.0").
		Capability("scanning", "File scanning").
		Tool("scan-files", "Scan files for secrets", true).
		Done().
		Build()

	if len(m.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(m.Capabilities))
	}
	cap := m.Capabilities[0]
	if cap.Name != "scanning" {
		t.Errorf("cap.Name = %q, want %q", cap.Name, "scanning")
	}
	if cap.Description != "File scanning" {
		t.Errorf("cap.Description = %q, want %q", cap.Description, "File scanning")
	}
	if len(cap.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(cap.Tools))
	}
	tool := cap.Tools[0]
	if tool.Name != "scan-files" {
		t.Errorf("tool.Name = %q, want %q", tool.Name, "scan-files")
	}
	if tool.Description != "Scan files for secrets" {
		t.Errorf("tool.Description = %q", tool.Description)
	}
	if !tool.ReadOnly {
		t.Error("tool.ReadOnly should be true")
	}
}

func TestManifest_MultipleCapabilities(t *testing.T) {
	m := NewManifest("multi", "1.0.0").
		Capability("cap-a", "First").
		Tool("tool-a", "Tool A", true).
		Done().
		Capability("cap-b", "Second").
		Tool("tool-b", "Tool B", false).
		Done().
		Build()

	if len(m.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(m.Capabilities))
	}
	if m.Capabilities[0].Name != "cap-a" {
		t.Errorf("first cap name = %q", m.Capabilities[0].Name)
	}
	if m.Capabilities[1].Name != "cap-b" {
		t.Errorf("second cap name = %q", m.Capabilities[1].Name)
	}
}

func TestManifest_CapabilityWithToolsAndResources(t *testing.T) {
	m := NewManifest("full", "1.0.0").
		Capability("analysis", "Analysis capability").
		Tool("analyze", "Run analysis", true).
		Tool("fix", "Apply fix", false).
		Resource("plugin://results/{id}", "results", "Scan results", "application/json").
		Done().
		Build()

	cap := m.Capabilities[0]
	if len(cap.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(cap.Tools))
	}
	if len(cap.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(cap.Resources))
	}
	res := cap.Resources[0]
	if res.UriTemplate != "plugin://results/{id}" {
		t.Errorf("UriTemplate = %q", res.UriTemplate)
	}
	if res.Name != "results" {
		t.Errorf("Name = %q", res.Name)
	}
	if res.MimeType != "application/json" {
		t.Errorf("MimeType = %q", res.MimeType)
	}
}

func TestManifest_SafetyOptions(t *testing.T) {
	m := NewManifest("net-plugin", "1.0.0").
		Safety(
			WithNetworkHosts("api.example.com", "cdn.example.com"),
			WithNetworkCIDRs("10.0.0.0/8"),
			WithFilePaths("/tmp", "/var/data"),
			WithEnvVars("API_KEY", "SECRET"),
			WithRiskClass(RiskActive),
			WithNeedsConfirmation(),
			WithMaxArtifactBytes(1024*1024),
		).
		Build()

	s := m.Safety
	if s == nil {
		t.Fatal("Safety should not be nil")
	}
	if len(s.NetworkHosts) != 2 || s.NetworkHosts[0] != "api.example.com" {
		t.Errorf("NetworkHosts = %v", s.NetworkHosts)
	}
	if len(s.NetworkCidrs) != 1 || s.NetworkCidrs[0] != "10.0.0.0/8" {
		t.Errorf("NetworkCidrs = %v", s.NetworkCidrs)
	}
	if len(s.FilePaths) != 2 || s.FilePaths[0] != "/tmp" {
		t.Errorf("FilePaths = %v", s.FilePaths)
	}
	if len(s.EnvVars) != 2 || s.EnvVars[0] != "API_KEY" {
		t.Errorf("EnvVars = %v", s.EnvVars)
	}
	if s.RiskClass != "active" {
		t.Errorf("RiskClass = %q, want %q", s.RiskClass, "active")
	}
	if !s.NeedsConfirmation {
		t.Error("NeedsConfirmation should be true")
	}
	if s.MaxArtifactBytes != 1024*1024 {
		t.Errorf("MaxArtifactBytes = %d", s.MaxArtifactBytes)
	}
}

func TestManifest_BuildIdempotent(t *testing.T) {
	b := NewManifest("idem", "1.0.0").
		Capability("cap", "A capability").
		Tool("tool", "A tool", true).
		Done()

	first := b.Build()
	second := b.Build()

	if first.Name != second.Name {
		t.Error("Build should be idempotent: Name mismatch")
	}
	if len(first.Capabilities) != len(second.Capabilities) {
		t.Error("Build should be idempotent: Capabilities length mismatch")
	}
}
