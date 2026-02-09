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
