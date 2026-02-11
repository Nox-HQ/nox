package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Test comprehensive scan scenarios to increase runScan coverage.

func TestRunScan_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0 for empty directory, got %d", code)
	}

	// Should still produce reports.
	if _, err := os.Stat(filepath.Join(outDir, "findings.json")); os.IsNotExist(err) {
		t.Fatal("expected findings.json even for empty directory")
	}
}

func TestRunScan_OnlyComments(t *testing.T) {
	dir := t.TempDir()

	// Create file with only comments.
	comments := "# This is a comment\n# Another comment\n"
	if err := os.WriteFile(filepath.Join(dir, "script.sh"), []byte(comments), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunScan_BinaryFile(t *testing.T) {
	dir := t.TempDir()

	// Create a binary file.
	binary := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}
	if err := os.WriteFile(filepath.Join(dir, "binary.bin"), binary, 0o644); err != nil {
		t.Fatalf("writing binary file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0 for binary file, got %d", code)
	}
}

func TestRunScan_LargeFile(t *testing.T) {
	dir := t.TempDir()

	// Create a large-ish file.
	content := make([]byte, 10000)
	for i := range content {
		content[i] = byte('a' + (i % 26))
	}
	if err := os.WriteFile(filepath.Join(dir, "large.txt"), content, 0o644); err != nil {
		t.Fatalf("writing large file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunScan_NestedDirectories(t *testing.T) {
	dir := t.TempDir()

	// Create nested directory structure.
	nestedDir := filepath.Join(dir, "a", "b", "c", "d")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("creating nested dirs: %v", err)
	}

	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(nestedDir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing nested file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunScan_MultipleFindings(t *testing.T) {
	dir := t.TempDir()

	// Create multiple files with findings.
	secret1 := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	secret2 := "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
	secret3 := "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n"

	if err := os.WriteFile(filepath.Join(dir, "config1.env"), []byte(secret1), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config2.env"), []byte(secret2), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config3.env"), []byte(secret3), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	// Should detect multiple findings.
	if code != 1 {
		t.Fatalf("expected exit code 1 for multiple findings, got %d", code)
	}
}

func TestRunScan_WithDependencies(t *testing.T) {
	dir := t.TempDir()

	// Create a package.json with dependencies.
	packageJSON := `{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(packageJSON), 0o644); err != nil {
		t.Fatalf("writing package.json: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--format", "cdx", "--output", outDir, "scan", dir})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify SBOM was created.
	sbomPath := filepath.Join(outDir, "sbom.cdx.json")
	if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
		t.Fatal("expected sbom.cdx.json to be created")
	}
}

func TestRunScan_MixedContent(t *testing.T) {
	dir := t.TempDir()

	// Create a mix of clean and vulnerable files.
	clean := "package main\n\nfunc main() {}\n"
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"

	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", dir})

	// Should detect the secret.
	if code != 1 {
		t.Fatalf("expected exit code 1 for mixed content with findings, got %d", code)
	}
}
