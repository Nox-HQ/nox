package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadScanConfig_NotFound(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("expected no error for missing .nox.yaml, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Scan.Exclude) != 0 {
		t.Errorf("expected empty exclude list, got %v", cfg.Scan.Exclude)
	}
	if len(cfg.Scan.Rules.Disable) != 0 {
		t.Errorf("expected empty disable list, got %v", cfg.Scan.Rules.Disable)
	}
	if cfg.Output.Format != "" {
		t.Errorf("expected empty format, got %q", cfg.Output.Format)
	}
}

func TestLoadScanConfig_Valid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  exclude:
    - "plugin-repos/"
    - "dist/"
    - "*.test.js"
  rules:
    disable:
      - "AI-008"
      - "SEC-003"
    severity_override:
      SEC-001: medium
      AI-002: low
output:
  format: sarif
  directory: reports
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Exclude patterns.
	if len(cfg.Scan.Exclude) != 3 {
		t.Fatalf("expected 3 exclude patterns, got %d", len(cfg.Scan.Exclude))
	}
	if cfg.Scan.Exclude[0] != "plugin-repos/" {
		t.Errorf("exclude[0] = %q, want %q", cfg.Scan.Exclude[0], "plugin-repos/")
	}
	if cfg.Scan.Exclude[2] != "*.test.js" {
		t.Errorf("exclude[2] = %q, want %q", cfg.Scan.Exclude[2], "*.test.js")
	}

	// Rule disable.
	if len(cfg.Scan.Rules.Disable) != 2 {
		t.Fatalf("expected 2 disabled rules, got %d", len(cfg.Scan.Rules.Disable))
	}
	if cfg.Scan.Rules.Disable[0] != "AI-008" {
		t.Errorf("disable[0] = %q, want %q", cfg.Scan.Rules.Disable[0], "AI-008")
	}

	// Severity overrides.
	if len(cfg.Scan.Rules.SeverityOverride) != 2 {
		t.Fatalf("expected 2 severity overrides, got %d", len(cfg.Scan.Rules.SeverityOverride))
	}
	if cfg.Scan.Rules.SeverityOverride["SEC-001"] != "medium" {
		t.Errorf("severity_override[SEC-001] = %q, want %q", cfg.Scan.Rules.SeverityOverride["SEC-001"], "medium")
	}
	if cfg.Scan.Rules.SeverityOverride["AI-002"] != "low" {
		t.Errorf("severity_override[AI-002] = %q, want %q", cfg.Scan.Rules.SeverityOverride["AI-002"], "low")
	}

	// Output settings.
	if cfg.Output.Format != "sarif" {
		t.Errorf("format = %q, want %q", cfg.Output.Format, "sarif")
	}
	if cfg.Output.Directory != "reports" {
		t.Errorf("directory = %q, want %q", cfg.Output.Directory, "reports")
	}
}

func TestLoadScanConfig_Partial(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  exclude:
    - "vendor/"
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Scan.Exclude) != 1 {
		t.Fatalf("expected 1 exclude pattern, got %d", len(cfg.Scan.Exclude))
	}
	if cfg.Scan.Exclude[0] != "vendor/" {
		t.Errorf("exclude[0] = %q, want %q", cfg.Scan.Exclude[0], "vendor/")
	}

	// Unset sections should be zero-valued.
	if len(cfg.Scan.Rules.Disable) != 0 {
		t.Errorf("expected empty disable list, got %v", cfg.Scan.Rules.Disable)
	}
	if cfg.Output.Format != "" {
		t.Errorf("expected empty format, got %q", cfg.Output.Format)
	}
}

func TestLoadScanConfig_ExplainSettings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `explain:
  api_key_env: ANTHROPIC_API_KEY
  model: claude-sonnet-4-5-20250929
  base_url: http://localhost:11434/v1
  timeout: 30s
  batch_size: 5
  output: my-explanations.json
  enrich: sast.scan,deps.check
  plugin_dir: ./plugins
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Explain.APIKeyEnv != "ANTHROPIC_API_KEY" {
		t.Errorf("api_key_env = %q, want %q", cfg.Explain.APIKeyEnv, "ANTHROPIC_API_KEY")
	}
	if cfg.Explain.Model != "claude-sonnet-4-5-20250929" {
		t.Errorf("model = %q, want %q", cfg.Explain.Model, "claude-sonnet-4-5-20250929")
	}
	if cfg.Explain.BaseURL != "http://localhost:11434/v1" {
		t.Errorf("base_url = %q, want %q", cfg.Explain.BaseURL, "http://localhost:11434/v1")
	}
	if cfg.Explain.Timeout != "30s" {
		t.Errorf("timeout = %q, want %q", cfg.Explain.Timeout, "30s")
	}
	if cfg.Explain.BatchSize != 5 {
		t.Errorf("batch_size = %d, want %d", cfg.Explain.BatchSize, 5)
	}
	if cfg.Explain.Output != "my-explanations.json" {
		t.Errorf("output = %q, want %q", cfg.Explain.Output, "my-explanations.json")
	}
	if cfg.Explain.Enrich != "sast.scan,deps.check" {
		t.Errorf("enrich = %q, want %q", cfg.Explain.Enrich, "sast.scan,deps.check")
	}
	if cfg.Explain.PluginDir != "./plugins" {
		t.Errorf("plugin_dir = %q, want %q", cfg.Explain.PluginDir, "./plugins")
	}
}

func TestLoadScanConfig_Invalid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  exclude: [[[invalid yaml
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadScanConfig(dir)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadScanConfig_EntropyConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  entropy:
    threshold: 5.5
    hex_threshold: 5.0
    base64_threshold: 5.8
    require_context: false
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Scan.Entropy.Threshold != 5.5 {
		t.Errorf("threshold = %f, want 5.5", cfg.Scan.Entropy.Threshold)
	}
	if cfg.Scan.Entropy.HexThreshold != 5.0 {
		t.Errorf("hex_threshold = %f, want 5.0", cfg.Scan.Entropy.HexThreshold)
	}
	if cfg.Scan.Entropy.Base64Threshold != 5.8 {
		t.Errorf("base64_threshold = %f, want 5.8", cfg.Scan.Entropy.Base64Threshold)
	}
	if cfg.Scan.Entropy.RequireContext == nil {
		t.Fatal("require_context should not be nil")
	}
	if *cfg.Scan.Entropy.RequireContext != false {
		t.Errorf("require_context = %v, want false", *cfg.Scan.Entropy.RequireContext)
	}
}

func TestLoadScanConfig_ReadFileError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	noxPath := filepath.Join(dir, ".nox.yaml")

	// Create .nox.yaml as a directory so ReadFile returns a non-ENOENT error.
	if err := os.Mkdir(noxPath, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := LoadScanConfig(dir)
	if err == nil {
		t.Fatal("expected error when .nox.yaml is a directory, got nil")
	}
}

func TestLoadScanConfig_EntropyConfig_Defaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  exclude:
    - "vendor/"
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// When not specified, zero values should be returned.
	if cfg.Scan.Entropy.Threshold != 0 {
		t.Errorf("threshold = %f, want 0 (unset)", cfg.Scan.Entropy.Threshold)
	}
	if cfg.Scan.Entropy.HexThreshold != 0 {
		t.Errorf("hex_threshold = %f, want 0 (unset)", cfg.Scan.Entropy.HexThreshold)
	}
	if cfg.Scan.Entropy.Base64Threshold != 0 {
		t.Errorf("base64_threshold = %f, want 0 (unset)", cfg.Scan.Entropy.Base64Threshold)
	}
	if cfg.Scan.Entropy.RequireContext != nil {
		t.Errorf("require_context = %v, want nil (unset)", cfg.Scan.Entropy.RequireContext)
	}
}
