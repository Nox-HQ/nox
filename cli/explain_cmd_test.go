package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	nox "github.com/nox-hq/nox/core"
)

func TestRunExplain_NoPath(t *testing.T) {
	code := run([]string{"explain"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for explain without path, got %d", code)
	}
}

func TestRunExplain_MissingAPIKey(t *testing.T) {
	// Ensure OPENAI_API_KEY is not set for this test.
	t.Setenv("OPENAI_API_KEY", "")

	dir := t.TempDir()
	code := run([]string{"explain", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing API key, got %d", code)
	}
}

func TestRunExplain_InvalidPath(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")

	code := runExplain([]string{"/nonexistent/path/xyz123"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid path, got %d", code)
	}
}

func TestRunExplain_InvalidFlag(t *testing.T) {
	code := runExplain([]string{"--invalid-flag"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid flag, got %d", code)
	}
}

func TestRunExplain_FlagParsing(t *testing.T) {
	// Test that flags can appear after the path.
	t.Setenv("OPENAI_API_KEY", "")

	dir := t.TempDir()
	// "nox explain . --model gpt-4o" - flags after positional arg.
	// Without API key, this should fail at the API key check, proving
	// that path parsing and flag extraction worked.
	code := runExplain([]string{dir, "--model", "gpt-4o"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing API key, got %d", code)
	}
}

func TestRunExplain_BaseURLBypassesAPIKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")

	dir := t.TempDir()
	// Create clean file so scan succeeds.
	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// With --base-url set, the API key check should be bypassed,
	// but scan with no findings should return 0.
	code := runExplain([]string{"--base-url", "http://localhost:11434/v1", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no findings with base-url, got %d", code)
	}
}

func TestRunExplain_CustomAPIKeyEnv(t *testing.T) {
	// Ensure the default key is not set.
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("MY_CUSTOM_KEY", "")

	dir := t.TempDir()
	// Create .nox.yaml with custom API key env.
	noxYAML := `explain:
  api_key_env: MY_CUSTOM_KEY
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(noxYAML), 0o644); err != nil {
		t.Fatalf("writing .nox.yaml: %v", err)
	}

	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Should fail because MY_CUSTOM_KEY is not set.
	code := runExplain([]string{dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing custom API key, got %d", code)
	}
}

func TestApplyExplainDefaults_OverridesUnsetFlags(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("model", "gpt-4o", "")
	fs.String("base-url", "", "")
	fs.String("timeout", "2m", "")
	fs.Int("batch-size", 10, "")
	fs.String("output", "explanations.json", "")
	fs.String("enrich", "", "")
	fs.String("plugin-dir", "", "")

	// Parse no args (all defaults).
	fs.Parse([]string{})

	cfg := &nox.ScanConfig{
		Explain: nox.ExplainSettings{
			Model:     "claude-3-opus",
			BaseURL:   "http://localhost:11434",
			Timeout:   "5m",
			BatchSize: 20,
			Output:    "custom-output.json",
			Enrich:    "tool1,tool2",
			PluginDir: "/opt/plugins",
		},
	}

	applyExplainDefaults(fs, cfg)

	// Verify config values were applied.
	var modelVal, baseURLVal, timeoutVal, outputVal, enrichVal, pluginDirVal string
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "model":
			modelVal = f.Value.String()
		case "base-url":
			baseURLVal = f.Value.String()
		case "timeout":
			timeoutVal = f.Value.String()
		case "output":
			outputVal = f.Value.String()
		case "enrich":
			enrichVal = f.Value.String()
		case "plugin-dir":
			pluginDirVal = f.Value.String()
		}
	})

	if modelVal != "claude-3-opus" {
		t.Errorf("model = %q, want %q", modelVal, "claude-3-opus")
	}
	if baseURLVal != "http://localhost:11434" {
		t.Errorf("base-url = %q, want %q", baseURLVal, "http://localhost:11434")
	}
	if timeoutVal != "5m" {
		t.Errorf("timeout = %q, want %q", timeoutVal, "5m")
	}
	if outputVal != "custom-output.json" {
		t.Errorf("output = %q, want %q", outputVal, "custom-output.json")
	}
	if enrichVal != "tool1,tool2" {
		t.Errorf("enrich = %q, want %q", enrichVal, "tool1,tool2")
	}
	if pluginDirVal != "/opt/plugins" {
		t.Errorf("plugin-dir = %q, want %q", pluginDirVal, "/opt/plugins")
	}
}

func TestApplyExplainDefaults_DoesNotOverrideCLIFlags(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("model", "gpt-4o", "")
	fs.String("base-url", "", "")
	fs.String("timeout", "2m", "")
	fs.Int("batch-size", 10, "")
	fs.String("output", "explanations.json", "")
	fs.String("enrich", "", "")
	fs.String("plugin-dir", "", "")

	// Parse with explicit flags.
	fs.Parse([]string{"--model", "gpt-4o-mini", "--output", "my-output.json"})

	cfg := &nox.ScanConfig{
		Explain: nox.ExplainSettings{
			Model:  "claude-3-opus",
			Output: "config-output.json",
		},
	}

	applyExplainDefaults(fs, cfg)

	// CLI flags should not be overridden.
	modelVal := ""
	outputVal := ""
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "model":
			modelVal = f.Value.String()
		case "output":
			outputVal = f.Value.String()
		}
	})

	if modelVal != "gpt-4o-mini" {
		t.Errorf("model should not be overridden: got %q", modelVal)
	}
	if outputVal != "my-output.json" {
		t.Errorf("output should not be overridden: got %q", outputVal)
	}
}

func TestApplyExplainDefaults_EmptyConfig(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("model", "gpt-4o", "")
	fs.String("base-url", "", "")
	fs.Parse([]string{})

	cfg := &nox.ScanConfig{}
	applyExplainDefaults(fs, cfg)

	// Nothing should be changed with empty config.
	visited := 0
	fs.Visit(func(f *flag.Flag) { visited++ })
	if visited != 0 {
		t.Errorf("expected no flags visited with empty config, got %d", visited)
	}
}

func TestRunExplain_NoFindingsNoExplain(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")

	dir := t.TempDir()
	// Create clean file so scan has no findings.
	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runExplain([]string{dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no findings, got %d", code)
	}
}

func TestRunExplain_ScanFailsOnBadPath(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")

	code := runExplain([]string{"/nonexistent/abc123"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for scan failure, got %d", code)
	}
}

func TestRunExplain_WithAllFlags(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")

	dir := t.TempDir()
	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outputFile := filepath.Join(dir, "output.json")
	code := runExplain([]string{
		"--model", "gpt-4o",
		"--batch-size", "5",
		"--output", outputFile,
		"--timeout", "30s",
		dir,
	})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no findings, got %d", code)
	}
}

func TestRunExplain_WithEnrichFlag(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")

	dir := t.TempDir()
	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runExplain([]string{"--enrich", "tool1,tool2", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no findings, got %d", code)
	}
}

func TestRunExplain_LoadConfigError(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")

	dir := t.TempDir()
	// Create invalid .nox.yaml.
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte("invalid: yaml: ["), 0o644); err != nil {
		t.Fatalf("writing .nox.yaml: %v", err)
	}

	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runExplain([]string{dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for config load error, got %d", code)
	}
}
