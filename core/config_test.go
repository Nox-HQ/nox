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

func TestLoadScanConfig_ExcludeArtifactTypes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  exclude_artifact_types:
    - artifact_types:
        - lockfile
        - container
      paths:
        - "vendor/"
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Scan.ExcludeArtifactTypes) != 1 {
		t.Fatalf("expected 1 exclude_artifact_types entry, got %d", len(cfg.Scan.ExcludeArtifactTypes))
	}
	if len(cfg.Scan.ExcludeArtifactTypes[0].ArtifactTypes) != 2 {
		t.Fatalf("expected 2 artifact types, got %d", len(cfg.Scan.ExcludeArtifactTypes[0].ArtifactTypes))
	}
	if cfg.Scan.ExcludeArtifactTypes[0].ArtifactTypes[0] != "lockfile" {
		t.Errorf("artifact_types[0] = %q, want %q", cfg.Scan.ExcludeArtifactTypes[0].ArtifactTypes[0], "lockfile")
	}
}

func TestLoadScanConfig_AnalyzerRules(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  analyzer_rules:
    - analyzer: deps
      rules:
        - "VULN-001"
        - "VULN-002"
      paths:
        - "**/node_modules/**"
        - "**/test/**"
      action: disable
    - analyzer: secrets
      paths:
        - "**/*.test.js"
      action: skip_analyzer
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Scan.AnalyzerRules) != 2 {
		t.Fatalf("expected 2 analyzer_rules, got %d", len(cfg.Scan.AnalyzerRules))
	}
	if cfg.Scan.AnalyzerRules[0].Analyzer != "deps" {
		t.Errorf("analyzer_rules[0].analyzer = %q, want %q", cfg.Scan.AnalyzerRules[0].Analyzer, "deps")
	}
	if cfg.Scan.AnalyzerRules[0].Action != "disable" {
		t.Errorf("analyzer_rules[0].action = %q, want %q", cfg.Scan.AnalyzerRules[0].Action, "disable")
	}
	if len(cfg.Scan.AnalyzerRules[0].Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(cfg.Scan.AnalyzerRules[0].Rules))
	}
}

func TestLoadScanConfig_ConditionalSeverity(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  conditional_severity:
    - rules:
        - "SEC-005"
        - "SEC-006"
      paths:
        - "**/config/**"
        - "**/*.config.js"
      severity: low
    - rules:
        - "VULN-*"
      paths:
        - "**/node_modules/**"
      severity: info
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Scan.ConditionalSeverity) != 2 {
		t.Fatalf("expected 2 conditional_severity entries, got %d", len(cfg.Scan.ConditionalSeverity))
	}
	if cfg.Scan.ConditionalSeverity[0].Severity != "low" {
		t.Errorf("severity = %q, want %q", cfg.Scan.ConditionalSeverity[0].Severity, "low")
	}
	if len(cfg.Scan.ConditionalSeverity[1].Rules) != 1 {
		t.Errorf("expected 1 rule pattern, got %d", len(cfg.Scan.ConditionalSeverity[1].Rules))
	}
	if cfg.Scan.ConditionalSeverity[1].Rules[0] != "VULN-*" {
		t.Errorf("rule[0] = %q, want %q", cfg.Scan.ConditionalSeverity[1].Rules[0], "VULN-*")
	}
}

func TestResolveGeneratedPaths(t *testing.T) {
	t.Parallel()

	// Default: returns the built-in set.
	def := GeneratedPathsConfig{}.ResolveGeneratedPaths()
	if len(def) == 0 {
		t.Fatal("default generated paths must be non-empty")
	}
	hasLock := false
	for _, g := range def {
		if g == "package-lock.json" {
			hasLock = true
		}
	}
	if !hasLock {
		t.Error("default set should include package-lock.json")
	}

	// Disabled: nil.
	if got := (GeneratedPathsConfig{Disabled: true}).ResolveGeneratedPaths(); got != nil {
		t.Errorf("disabled should resolve to nil, got %v", got)
	}

	// Extend: default + extra.
	ext := GeneratedPathsConfig{Extend: []string{"gen/**"}}.ResolveGeneratedPaths()
	if len(ext) != len(def)+1 || ext[len(ext)-1] != "gen/**" {
		t.Errorf("extend should append to defaults, got %v", ext)
	}

	// Override: exactly the given set, defaults ignored.
	ovr := GeneratedPathsConfig{Override: []string{"only.json"}, Extend: []string{"ignored"}}.ResolveGeneratedPaths()
	if len(ovr) != 1 || ovr[0] != "only.json" {
		t.Errorf("override should replace defaults and ignore extend, got %v", ovr)
	}
}

func TestResolveNoiseDirs(t *testing.T) {
	t.Parallel()
	def := GeneratedPathsConfig{}.ResolveNoiseDirs()
	has := func(s string) bool {
		for _, d := range def {
			if d == s {
				return true
			}
		}
		return false
	}
	if !has("tests") || !has("fixtures") || !has("examples") {
		t.Errorf("default noise dirs missing expected segments: %v", def)
	}
	if got := (GeneratedPathsConfig{Disabled: true}).ResolveNoiseDirs(); got != nil {
		t.Errorf("disabled should resolve to nil, got %v", got)
	}
	ovr := GeneratedPathsConfig{OverrideDirs: []string{"only"}}.ResolveNoiseDirs()
	if len(ovr) != 1 || ovr[0] != "only" {
		t.Errorf("override_dirs should replace defaults, got %v", ovr)
	}
}

func TestMatchesNonProductionPath(t *testing.T) {
	t.Parallel()

	globs := NonProductionPathGlobs()
	cases := []struct {
		path string
		want bool
	}{
		// ** spans zero or more segments, at any depth.
		{"test/a.py", true},
		{"src/test/a.py", true},
		{"a/b/test/c/d.py", true},
		{"tests/foo.go", true},
		{"pkg/tests/foo.go", true},
		{"examples/foo.py", true},
		{"example/foo.py", true},
		{"deep/nested/examples/x/y.py", true},
		{"docs/guide.md", true},
		{"vendor/github.com/x/y.go", true},
		{"node_modules/react/index.js", true},
		{"web/dist/app.js", true},
		{"out/build/thing.o", true},
		{"pkg/generated/api.go", true},
		{"src/__mocks__/fs.js", true},
		{"testdata/fixture.json", true},
		{"pkg/testdata/x.bin", true},
		// Single-segment / basename globs.
		{"foo_test.go", true},
		{"pkg/handler_test.go", true},
		{"assets/jquery.min.js", true},
		{"a/b/c/vendor.min.js", true},
		// Case-insensitive on segments.
		{"Tests/Foo.go", true},
		{"src/TEST/x.py", true},
		{"Examples/Foo.py", true},
		// Production paths — must NOT match.
		{"src/foo.py", false},
		{"internal/app/handler.go", false},
		{"main.go", false},
		{"cmd/nox/main.go", false},
		// "test" only matches as a whole segment, not a substring.
		{"src/latest/x.py", false},
		{"src/contest.go", false},
	}
	for _, tc := range cases {
		if got := MatchesNonProductionPath(tc.path, globs); got != tc.want {
			t.Errorf("MatchesNonProductionPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestMatchesNonProductionPath_Empty(t *testing.T) {
	t.Parallel()

	if MatchesNonProductionPath("", NonProductionPathGlobs()) {
		t.Error("empty path must not match")
	}
	if MatchesNonProductionPath("test/a.py", nil) {
		t.Error("empty glob set must not match")
	}
}

func TestContextDowngradeEnabled_DefaultsOn(t *testing.T) {
	t.Parallel()

	var s ScanSettings // ContextDowngrade nil
	if !s.ContextDowngradeEnabled() {
		t.Error("unset context_downgrade must default to enabled")
	}
	off := false
	s.ContextDowngrade = &off
	if s.ContextDowngradeEnabled() {
		t.Error("context_downgrade:false must disable")
	}
	on := true
	s.ContextDowngrade = &on
	if !s.ContextDowngradeEnabled() {
		t.Error("context_downgrade:true must enable")
	}
}

func TestLoadScanConfig_ContextDowngrade(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	yaml := "scan:\n  context_downgrade: false\n"
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Scan.ContextDowngrade == nil {
		t.Fatal("expected context_downgrade to be parsed, got nil")
	}
	if cfg.Scan.ContextDowngradeEnabled() {
		t.Error("context_downgrade:false must resolve to disabled")
	}
}
