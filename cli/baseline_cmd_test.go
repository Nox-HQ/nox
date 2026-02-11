package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/baseline"
)

func TestRunBaseline_NoArgs(t *testing.T) {
	code := runBaseline([]string{})
	if code != 2 {
		t.Fatalf("expected exit code 2 for no args, got %d", code)
	}
}

func TestRunBaseline_UnknownSubcommand(t *testing.T) {
	code := runBaseline([]string{"invalid"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for unknown subcommand, got %d", code)
	}
}

func TestRunBaseline_Write(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a secret to get findings.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	baselinePath := filepath.Join(dir, "test-baseline.json")
	code := runBaseline([]string{"write", "--output", baselinePath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify baseline file exists.
	if _, err := os.Stat(baselinePath); os.IsNotExist(err) {
		t.Fatal("expected baseline file to be created")
	}

	// Verify baseline can be loaded and has entries.
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	if bl.Len() == 0 {
		t.Fatal("expected baseline to have entries")
	}
}

func TestRunBaseline_WriteDefaultPath(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a finding.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runBaseline([]string{"write", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify default baseline path exists.
	defaultPath := baseline.DefaultPath(dir)
	if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
		t.Fatal("expected baseline file at default path")
	}
}

func TestRunBaseline_WriteCleanDir(t *testing.T) {
	dir := t.TempDir()

	// Create a clean file with no findings.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	baselinePath := filepath.Join(dir, "baseline.json")
	code := runBaseline([]string{"write", "--output", baselinePath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Baseline should exist but be empty.
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	if bl.Len() != 0 {
		t.Fatalf("expected empty baseline, got %d entries", bl.Len())
	}
}

func TestRunBaseline_WriteScanError(t *testing.T) {
	code := runBaseline([]string{"write", "/nonexistent/path/xyz123"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for scan error, got %d", code)
	}
}

func TestRunBaseline_Update(t *testing.T) {
	dir := t.TempDir()

	// Create initial finding.
	secret1 := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config1.env"), []byte(secret1), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Write initial baseline.
	baselinePath := filepath.Join(dir, "baseline.json")
	code := runBaseline([]string{"write", "--output", baselinePath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for write, got %d", code)
	}

	initialBL, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading initial baseline: %v", err)
	}
	initialCount := initialBL.Len()

	// Add a new finding with different content to get a different fingerprint.
	secret2 := "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
	if err := os.WriteFile(filepath.Join(dir, "config2.env"), []byte(secret2), 0o644); err != nil {
		t.Fatalf("writing second test file: %v", err)
	}

	// Update baseline.
	code = runBaseline([]string{"update", "--baseline", baselinePath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for update, got %d", code)
	}

	// Verify baseline has more entries.
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	if bl.Len() <= initialCount {
		t.Fatalf("expected baseline to have more than %d entries, got %d", initialCount, bl.Len())
	}
}

func TestRunBaseline_UpdateDefaultPath(t *testing.T) {
	dir := t.TempDir()

	// Create initial baseline.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runBaseline([]string{"write", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for write, got %d", code)
	}

	// Update using default path.
	code = runBaseline([]string{"update", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for update, got %d", code)
	}
}

func TestRunBaseline_UpdateScanError(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")

	// Create a baseline.
	bl := &baseline.Baseline{}
	if err := bl.Save(baselinePath); err != nil {
		t.Fatalf("saving baseline: %v", err)
	}

	// Try to update with nonexistent path.
	code := runBaseline([]string{"update", "--baseline", baselinePath, "/nonexistent/path/xyz123"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for scan error, got %d", code)
	}
}

func TestRunBaseline_UpdateLoadError(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "invalid.json")

	// Write invalid JSON to baseline file.
	if err := os.WriteFile(baselinePath, []byte("invalid json{"), 0o644); err != nil {
		t.Fatalf("writing invalid baseline: %v", err)
	}

	code := runBaseline([]string{"update", "--baseline", baselinePath, dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for load error, got %d", code)
	}
}

func TestRunBaseline_Show(t *testing.T) {
	dir := t.TempDir()

	// Create findings and baseline.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runBaseline([]string{"write", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for write, got %d", code)
	}

	// Show baseline.
	code = runBaseline([]string{"show", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for show, got %d", code)
	}
}

func TestRunBaseline_ShowEmpty(t *testing.T) {
	dir := t.TempDir()

	// Create empty baseline.
	bl := &baseline.Baseline{}
	if err := bl.Save(baseline.DefaultPath(dir)); err != nil {
		t.Fatalf("saving baseline: %v", err)
	}

	code := runBaseline([]string{"show", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for empty baseline, got %d", code)
	}
}

func TestRunBaseline_ShowLoadError(t *testing.T) {
	dir := t.TempDir()

	// Write invalid JSON to baseline file.
	baselinePath := baseline.DefaultPath(dir)
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0o755); err != nil {
		t.Fatalf("creating .nox dir: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte("invalid json{"), 0o644); err != nil {
		t.Fatalf("writing invalid baseline: %v", err)
	}

	code := runBaseline([]string{"show", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for load error, got %d", code)
	}
}
