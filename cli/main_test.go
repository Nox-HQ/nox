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
