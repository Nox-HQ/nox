package plugin

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".nox.yaml")
	data := `
plugin_policy:
  allowed_network_hosts:
    - "*.example.com"
    - api.github.com
  allowed_file_paths:
    - /workspace
  max_risk_class: active
  max_artifact_mb: 50
  max_concurrency: 4
  tool_timeout_seconds: 60
  requests_per_minute: 120
  bandwidth_mb_per_minute: 10
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if len(cfg.PluginPolicy.AllowedNetworkHosts) != 2 {
		t.Errorf("AllowedNetworkHosts = %v, want 2 entries", cfg.PluginPolicy.AllowedNetworkHosts)
	}
	if cfg.PluginPolicy.MaxRiskClass != "active" {
		t.Errorf("MaxRiskClass = %q, want %q", cfg.PluginPolicy.MaxRiskClass, "active")
	}
	if cfg.PluginPolicy.MaxArtifactMB != 50 {
		t.Errorf("MaxArtifactMB = %d, want 50", cfg.PluginPolicy.MaxArtifactMB)
	}
	if cfg.PluginPolicy.RequestsPerMinute != 120 {
		t.Errorf("RequestsPerMinute = %d, want 120", cfg.PluginPolicy.RequestsPerMinute)
	}
	if cfg.PluginPolicy.BandwidthMBPerMinute != 10 {
		t.Errorf("BandwidthMBPerMinute = %d, want 10", cfg.PluginPolicy.BandwidthMBPerMinute)
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/.nox.yaml")
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if cfg == nil {
		t.Fatal("missing file should return default config")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".nox.yaml")
	if err := os.WriteFile(path, []byte("invalid: yaml: [[["), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("invalid YAML should return error")
	}
}

func TestPluginPolicyConfig_ToPolicy(t *testing.T) {
	cfg := PluginPolicyConfig{
		AllowedNetworkHosts:  []string{"*.example.com"},
		MaxRiskClass:         "active",
		MaxArtifactMB:        50,
		MaxConcurrency:       4,
		ToolTimeoutSeconds:   60,
		RequestsPerMinute:    120,
		BandwidthMBPerMinute: 10,
	}

	p := cfg.ToPolicy()

	if len(p.AllowedNetworkHosts) != 1 || p.AllowedNetworkHosts[0] != "*.example.com" {
		t.Errorf("AllowedNetworkHosts = %v", p.AllowedNetworkHosts)
	}
	if p.MaxRiskClass != RiskClassActive {
		t.Errorf("MaxRiskClass = %q, want %q", p.MaxRiskClass, RiskClassActive)
	}
	if p.MaxArtifactBytes != 50*1024*1024 {
		t.Errorf("MaxArtifactBytes = %d, want %d", p.MaxArtifactBytes, 50*1024*1024)
	}
	if p.MaxConcurrency != 4 {
		t.Errorf("MaxConcurrency = %d, want 4", p.MaxConcurrency)
	}
	if p.ToolInvocationTimeout != 60*time.Second {
		t.Errorf("ToolInvocationTimeout = %v, want 60s", p.ToolInvocationTimeout)
	}
	if p.RequestsPerMinute != 120 {
		t.Errorf("RequestsPerMinute = %d, want 120", p.RequestsPerMinute)
	}
	if p.BandwidthBytesPerMin != 10*1024*1024 {
		t.Errorf("BandwidthBytesPerMin = %d, want %d", p.BandwidthBytesPerMin, 10*1024*1024)
	}
}

func TestPluginPolicyConfig_ToPolicy_ZeroValues(t *testing.T) {
	cfg := PluginPolicyConfig{}
	p := cfg.ToPolicy()
	def := DefaultPolicy()

	if p.MaxRiskClass != def.MaxRiskClass {
		t.Errorf("zero config MaxRiskClass = %q, want default %q", p.MaxRiskClass, def.MaxRiskClass)
	}
	if p.MaxArtifactBytes != def.MaxArtifactBytes {
		t.Errorf("zero config MaxArtifactBytes = %d, want default %d", p.MaxArtifactBytes, def.MaxArtifactBytes)
	}
	if p.ToolInvocationTimeout != def.ToolInvocationTimeout {
		t.Errorf("zero config ToolInvocationTimeout = %v, want default %v", p.ToolInvocationTimeout, def.ToolInvocationTimeout)
	}
	if p.RequestsPerMinute != 0 {
		t.Errorf("zero config RequestsPerMinute = %d, want 0", p.RequestsPerMinute)
	}
	if p.BandwidthBytesPerMin != 0 {
		t.Errorf("zero config BandwidthBytesPerMin = %d, want 0", p.BandwidthBytesPerMin)
	}
}
