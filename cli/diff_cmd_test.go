package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDiff_NonGitRepo(t *testing.T) {
	dir := t.TempDir()

	code := runDiff([]string{dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for non-git repo, got %d", code)
	}
}

func TestRunDiff_NoChangedFiles(t *testing.T) {
	dir := t.TempDir()

	// Initialize git repo.
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	// Configure git user.
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = dir
	_ = cmd.Run()
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = dir
	_ = cmd.Run()

	// Create initial commit.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// No changes since HEAD.
	code := runDiff([]string{"--base", "HEAD", "--head", "HEAD", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no changes, got %d", code)
	}
}

func TestRunDiff_WithChangedFiles(t *testing.T) {
	dir := t.TempDir()

	// Initialize git repo.
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	// Configure git user.
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = dir
	_ = cmd.Run()
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = dir
	_ = cmd.Run()

	// Create initial commit with clean file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// Create a new file with a finding.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" // nox:ignore SEC-001 -- test fixture
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "add config")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// Run diff comparing HEAD~1 to HEAD.
	code := runDiff([]string{"--base", "HEAD~1", "--head", "HEAD", dir})
	if code != 1 {
		t.Fatalf("expected exit code 1 for findings, got %d", code)
	}
}

func TestRunDiff_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	// Initialize git repo.
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	// Configure git user.
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = dir
	_ = cmd.Run()
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = dir
	_ = cmd.Run()

	// Create initial commit.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// Add file with finding.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" // nox:ignore SEC-001 -- test fixture
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "add config")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// Capture stdout for JSON output validation.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runDiff([]string{"--base", "HEAD~1", "--head", "HEAD", "--json", dir})

	w.Close()
	os.Stdout = oldStdout

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if code != 1 {
		t.Fatalf("expected exit code 1 for findings, got %d", code)
	}

	// Validate JSON output.
	var result []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("expected JSON output to contain findings")
	}
}

func TestRunDiff_DefaultPath(t *testing.T) {
	dir := t.TempDir()

	// Initialize git repo in temp dir.
	cmd := exec.Command("git", "init", "-b", "main")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	// Configure git user.
	for _, args := range [][]string{
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test User"},
	} {
		cmd = exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
		_ = cmd.Run()
	}

	// Create initial commit.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	if err := cmd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// Change to the temp dir and run diff without path arg.
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// Use explicit --base HEAD to avoid relying on a "main" branch name
	// (the three-dot diff syntax requires a valid ref that git can resolve).
	code := runDiff([]string{"--base", "HEAD", "--head", "HEAD"})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no changes, got %d", code)
	}
}

func TestRunDiff_CustomRules(t *testing.T) {
	dir := t.TempDir()

	// Initialize git repo.
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	// Configure git user.
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = dir
	_ = cmd.Run()
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = dir
	_ = cmd.Run()

	// Create initial commit.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// Create custom rules file (empty).
	rulesPath := filepath.Join(dir, "custom-rules.yaml")
	rulesContent := `rules: []
`
	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0o644); err != nil {
		t.Fatalf("writing rules file: %v", err)
	}

	// Run diff with custom rules.
	// Use explicit --base HEAD to avoid relying on a "main" branch existing.
	code := runDiff([]string{"--rules", rulesPath, "--base", "HEAD", "--head", "HEAD", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no changes, got %d", code)
	}
}

func TestRunDiff_InvalidBase(t *testing.T) {
	dir := t.TempDir()

	// Initialize git repo.
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	// Configure git user.
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = dir
	_ = cmd.Run()
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = dir
	_ = cmd.Run()

	// Create initial commit.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// Run diff with invalid base ref.
	code := runDiff([]string{"--base", "nonexistent-branch", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid base ref, got %d", code)
	}
}

func TestRunDiff_ScanError(t *testing.T) {
	dir := t.TempDir()

	// Initialize git repo.
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	// Configure git user.
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = dir
	_ = cmd.Run()
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = dir
	_ = cmd.Run()

	// Create initial commit.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// Try to run diff on nonexistent subdirectory.
	code := runDiff([]string{filepath.Join(dir, "nonexistent")})
	if code != 2 {
		t.Fatalf("expected exit code 2 for scan error, got %d", code)
	}
}

func TestRunDiff_ViaRunCommand(t *testing.T) {
	// Change to a non-git temp directory so that runDiff's default target "."
	// is not inside the project's own git repo.
	dir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// Test that diff command is recognized and fails for non-git directory.
	code := run([]string{"diff"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for diff without git repo, got %d", code)
	}
}
