package main

import (
	"os"
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
