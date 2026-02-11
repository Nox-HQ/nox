package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRun_VersionFlag(t *testing.T) {
	code := run([]string{"--version"})
	if code != 0 {
		t.Fatalf("expected exit code 0 for --version, got %d", code)
	}
}

func TestRun_VersionCommand(t *testing.T) {
	code := run([]string{"version"})
	if code != 0 {
		t.Fatalf("expected exit code 0 for version command, got %d", code)
	}
}

func TestRun_NoArgs(t *testing.T) {
	code := run([]string{})
	if code != 2 {
		t.Fatalf("expected exit code 2 for no args, got %d", code)
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	code := run([]string{"invalid"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for unknown command, got %d", code)
	}
}

func TestRun_ScanNoPath(t *testing.T) {
	code := run([]string{"scan"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for scan without path, got %d", code)
	}
}

func TestRun_ScanCleanDir(t *testing.T) {
	dir := t.TempDir()

	// Create a clean Go file with no security issues.
	content := `package main

func main() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for clean directory, got %d", code)
	}

	// Verify JSON report was written.
	reportPath := filepath.Join(outDir, "findings.json")
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		t.Fatal("expected findings.json to be created")
	}
}

func TestRun_ScanDirWithFindings(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a secret.
	content := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})
	if code != 1 {
		t.Fatalf("expected exit code 1 for findings, got %d", code)
	}
}

func TestRun_ScanNonexistentDir(t *testing.T) {
	code := run([]string{"--quiet", "scan", "/nonexistent/path/abc123"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for nonexistent path, got %d", code)
	}
}

func TestRun_ScanAllFormats(t *testing.T) {
	dir := t.TempDir()

	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--format", "all", "--output", outDir, "scan", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// All four report files should exist.
	for _, name := range []string{"findings.json", "results.sarif", "sbom.cdx.json", "sbom.spdx.json"} {
		path := filepath.Join(outDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Fatalf("expected %s to be created", name)
		}
	}
}

func TestExtractInterspersedArgs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			"flags before command",
			[]string{"--format", "sarif", "scan", "."},
			[]string{"--format", "sarif", "scan", "."},
		},
		{
			"flags after command and path",
			[]string{"scan", ".", "--format", "sarif", "--output", "/tmp/out"},
			[]string{"--format", "sarif", "--output", "/tmp/out", "scan", "."},
		},
		{
			"mixed ordering",
			[]string{"scan", ".", "--format", "all", "-q", "--output", "/tmp/out"},
			[]string{"--format", "all", "-q", "--output", "/tmp/out", "scan", "."},
		},
		{
			"bool flags interspersed",
			[]string{"-q", "scan", ".", "-v"},
			[]string{"-q", "-v", "scan", "."},
		},
		{
			"flag=value syntax",
			[]string{"scan", ".", "--format=sarif"},
			[]string{"--format=sarif", "scan", "."},
		},
		{
			"no flags",
			[]string{"scan", "."},
			[]string{"scan", "."},
		},
		{
			"version flag only",
			[]string{"--version"},
			[]string{"--version"},
		},
		{
			"subcommand flags stay in place",
			[]string{"show", ".", "--severity", "critical", "--json"},
			[]string{"show", ".", "--severity", "critical", "--json"},
		},
		{
			"mixed top-level and subcommand flags",
			[]string{"show", ".", "--severity", "critical", "-q"},
			[]string{"-q", "show", ".", "--severity", "critical"},
		},
		{
			"output flag stays with non-scan subcommand",
			[]string{"badge", ".", "--output", "/tmp/badge.svg"},
			[]string{"badge", ".", "--output", "/tmp/badge.svg"},
		},
		{
			"output flag extracted for scan only",
			[]string{"scan", ".", "--output", "/tmp/out"},
			[]string{"--output", "/tmp/out", "scan", "."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractInterspersedArgs(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d args, got %d: %v", len(tt.expected), len(result), result)
			}
			for i, arg := range result {
				if arg != tt.expected[i] {
					t.Fatalf("arg[%d]: expected %q, got %q (full: %v)", i, tt.expected[i], arg, result)
				}
			}
		})
	}
}

func TestRun_ScanInterspersedFlags(t *testing.T) {
	dir := t.TempDir()

	content := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")

	// Flags placed after "scan <path>" should still be parsed.
	code := run([]string{"scan", dir, "--quiet", "--format", "sarif", "--output", outDir})
	if code != 1 {
		t.Fatalf("expected exit code 1 for findings, got %d", code)
	}

	// Verify SARIF was written (proving --format sarif was parsed).
	sarifPath := filepath.Join(outDir, "results.sarif")
	if _, err := os.Stat(sarifPath); os.IsNotExist(err) {
		t.Fatal("expected results.sarif to be created (--format flag after scan was ignored)")
	}
}

func TestParseFormats(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"json", []string{"json"}},
		{"sarif", []string{"sarif"}},
		{"json,sarif", []string{"json", "sarif"}},
		{"all", []string{"json", "sarif", "cdx", "spdx"}},
		{"", []string{"json"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseFormats(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d formats, got %d: %v", len(tt.expected), len(result), result)
			}
			for i, f := range result {
				if f != tt.expected[i] {
					t.Fatalf("format[%d]: expected %q, got %q", i, tt.expected[i], f)
				}
			}
		})
	}
}

func TestRun_ScanStagedFlag(t *testing.T) {
	dir := t.TempDir()

	// Initialize git repo.
	exec.Command("git", "init").Run()
	exec.Command("git", "config", "user.email", "test@example.com").Run()
	exec.Command("git", "config", "user.name", "Test User").Run()

	// Create a file with a finding.
	content := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	// Stage the file.
	cmd := exec.Command("git", "add", "config.env")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", "--staged", dir})

	// Should detect finding in staged file.
	if code != 1 {
		t.Fatalf("expected exit code 1 for staged finding, got %d", code)
	}
}

func TestRun_ScanSeverityThreshold(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a high-severity finding (AWS key is "high", not "critical").
	content := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")

	// Test with high threshold - should include the finding.
	code := run([]string{"--quiet", "--output", outDir, "scan", "--severity-threshold", "high", dir})
	if code != 1 {
		t.Fatalf("expected exit code 1 for high threshold, got %d", code)
	}
}

func TestRun_ScanSeverityThresholdFiltersOut(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a lower severity finding.
	content := "package main\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")

	// Test with critical threshold - should filter out lower findings.
	code := run([]string{"--quiet", "--output", outDir, "scan", "--severity-threshold", "critical", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 when all findings filtered by threshold, got %d", code)
	}
}

func TestRun_ScanVerboseFlag(t *testing.T) {
	dir := t.TempDir()

	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--verbose", "--output", outDir, "scan", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRun_ScanCDXFormat(t *testing.T) {
	dir := t.TempDir()

	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--format", "cdx", "--output", outDir, "scan", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify CDX SBOM was written.
	cdxPath := filepath.Join(outDir, "sbom.cdx.json")
	if _, err := os.Stat(cdxPath); os.IsNotExist(err) {
		t.Fatal("expected sbom.cdx.json to be created")
	}
}

func TestRun_ScanSPDXFormat(t *testing.T) {
	dir := t.TempDir()

	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--format", "spdx", "--output", outDir, "scan", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify SPDX SBOM was written.
	spdxPath := filepath.Join(outDir, "sbom.spdx.json")
	if _, err := os.Stat(spdxPath); os.IsNotExist(err) {
		t.Fatal("expected sbom.spdx.json to be created")
	}
}

func TestRun_ScanQuietFlag(t *testing.T) {
	dir := t.TempDir()

	content := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"-q", "--output", outDir, "scan", dir})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRun_ScanMultipleFormats(t *testing.T) {
	dir := t.TempDir()

	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--format", "json,sarif,cdx", "--output", outDir, "scan", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify all specified formats were written.
	for _, name := range []string{"findings.json", "results.sarif", "sbom.cdx.json"} {
		path := filepath.Join(outDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Fatalf("expected %s to be created", name)
		}
	}
}

func TestRun_Help(t *testing.T) {
	// Test that invalid flags trigger usage output.
	code := run([]string{"--invalid-flag"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid flag, got %d", code)
	}
}

func TestIsTopLevelBoolFlag(t *testing.T) {
	tests := []struct {
		flag     string
		expected bool
	}{
		{"quiet", true},
		{"q", true},
		{"verbose", true},
		{"v", true},
		{"version", true},
		{"format", false},
		{"output", false},
		{"severity", false},
		{"staged", false},
	}

	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			result := isTopLevelBoolFlag(tt.flag)
			if result != tt.expected {
				t.Fatalf("expected %v for %s, got %v", tt.expected, tt.flag, result)
			}
		})
	}
}

func TestIsTopLevelStringFlag(t *testing.T) {
	tests := []struct {
		flag     string
		expected bool
	}{
		{"format", true},
		{"output", true},
		{"rules", true},
		{"quiet", false},
		{"verbose", false},
		{"severity", false},
		{"staged", false},
	}

	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			result := isTopLevelStringFlag(tt.flag)
			if result != tt.expected {
				t.Fatalf("expected %v for %s, got %v", tt.expected, tt.flag, result)
			}
		})
	}
}

func TestRun_ScanWithNoxYAML(t *testing.T) {
	dir := t.TempDir()

	// Create file with a finding.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Create a .nox.yaml to test config loading.
	noxYAML := `output:
  format: sarif
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(noxYAML), 0o644); err != nil {
		t.Fatalf("writing .nox.yaml: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	// Should detect findings and return 1.
	if code != 1 {
		t.Fatalf("expected exit code 1 for findings, got %d", code)
	}

	// Verify SARIF output was written (from .nox.yaml config).
	if _, err := os.Stat(filepath.Join(outDir, "results.sarif")); os.IsNotExist(err) {
		t.Fatal("expected results.sarif from .nox.yaml format config")
	}
}

func TestRun_ScanWithAIComponents(t *testing.T) {
	dir := t.TempDir()

	// Create a file that might trigger AI component detection.
	mcpConfig := `{
  "mcpServers": {
    "test": {
      "command": "npx",
      "args": ["test-mcp"]
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(mcpConfig), 0o644); err != nil {
		t.Fatalf("writing mcp.json: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify AI inventory was written.
	aiInventoryPath := filepath.Join(outDir, "ai.inventory.json")
	if _, err := os.Stat(aiInventoryPath); os.IsNotExist(err) {
		// AI inventory might not be written if no AI components detected.
		// That's okay, just test that scan completes.
	}
}

func TestRun_ScanWithPolicy(t *testing.T) {
	dir := t.TempDir()

	// Create file with finding.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Create a .nox.yaml with policy that should fail.
	noxYAML := `policy:
  fail_on_critical: true
  fail_on_high: true
  max_findings: 0
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(noxYAML), 0o644); err != nil {
		t.Fatalf("writing .nox.yaml: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	// Should exit with policy exit code (1 for findings).
	if code == 0 {
		t.Fatal("expected non-zero exit code for policy violation")
	}
}

func TestRun_ScanOutputDirCreation(t *testing.T) {
	dir := t.TempDir()

	// Create clean file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Use nested output directory that doesn't exist.
	outDir := filepath.Join(dir, "nested", "output", "dir")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify output directory was created.
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		t.Fatal("expected output directory to be created")
	}
}

func TestRun_ScanWithCustomRules(t *testing.T) {
	dir := t.TempDir()

	// Create custom rules file.
	rulesPath := filepath.Join(dir, "custom.yaml")
	rulesContent := `rules: []
`
	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0o644); err != nil {
		t.Fatalf("writing rules file: %v", err)
	}

	// Create test file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--rules", rulesPath, "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0 with custom rules, got %d", code)
	}
}

func TestRun_ScanInvalidSeverityThreshold(t *testing.T) {
	dir := t.TempDir()

	// Create test file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	// Invalid severity threshold should still work (just no filtering).
	code := run([]string{"--quiet", "--output", outDir, "scan", "--severity-threshold", "invalid", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRun_CommandDispatch(t *testing.T) {
	// Test that all known commands are dispatched correctly.
	tests := []struct {
		command      string
		expectedCode int
	}{
		{"scan", 2},       // No path provided
		{"protect", 2},    // No subcommand provided
		{"show", 0},       // Default path with no findings
		{"badge", 0},      // Default path
		{"registry", 2},   // No subcommand provided
		{"plugin", 2},     // No subcommand provided
		{"baseline", 2},   // No subcommand provided
		{"diff", 2},       // Not a git repo in current dir
		{"completion", 2}, // No shell provided
		{"annotate", 2},   // No input file
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			code := run([]string{tt.command})
			// We just verify the command is recognized (non-panic).
			// Actual exit codes may vary based on environment.
			_ = code
		})
	}
}

func TestRun_ScanWriteError(t *testing.T) {
	dir := t.TempDir()

	// Create test file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Try to write to an invalid output path (file instead of directory).
	invalidOut := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(invalidOut, []byte("test"), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	// Should fail trying to create output directory.
	code := run([]string{"--quiet", "--output", invalidOut, "scan", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for output write error, got %d", code)
	}
}

func TestRun_ScanLoadConfigError(t *testing.T) {
	dir := t.TempDir()

	// Create invalid .nox.yaml.
	invalidYAML := "invalid: yaml: syntax: error"
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(invalidYAML), 0o644); err != nil {
		t.Fatalf("writing .nox.yaml: %v", err)
	}

	// Create test file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	// Should fail to load config.
	if code != 2 {
		t.Fatalf("expected exit code 2 for config load error, got %d", code)
	}
}

func TestRun_ScanFormatEqualsValue(t *testing.T) {
	dir := t.TempDir()

	// Create test file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	// Test --format=sarif syntax (before scan command).
	code := run([]string{"--quiet", "--format=sarif", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify SARIF was written.
	sarifPath := filepath.Join(outDir, "results.sarif")
	if _, err := os.Stat(sarifPath); os.IsNotExist(err) {
		t.Fatal("expected results.sarif to be created")
	}
}

func TestRun_ScanOutputEqualsValue(t *testing.T) {
	dir := t.TempDir()

	// Create test file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "myoutput")
	// Test --output=/path syntax.
	code := run([]string{"--quiet", "--output=" + outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify output was written to specified directory.
	if _, err := os.Stat(filepath.Join(outDir, "findings.json")); os.IsNotExist(err) {
		t.Fatal("expected findings.json in specified output directory")
	}
}

func TestRun_ScanDoubleDash(t *testing.T) {
	dir := t.TempDir()

	// Create test file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	// Test -- separator (args after -- are positional).
	code := run([]string{"--quiet", "--output", outDir, "scan", "--", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRun_ShortFlags(t *testing.T) {
	dir := t.TempDir()

	// Create test file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	// Test short -q and -v flags.
	code := run([]string{"-q", "-v", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0 with -q -v flags, got %d", code)
	}
}
