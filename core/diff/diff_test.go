package diff

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRun_NotGitRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := Run(dir, Options{})
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
	if err.Error() != "not a git repository" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_EmptyOptions(t *testing.T) {
	// Verify defaults are applied.
	opts := Options{}
	if opts.Base != "" {
		t.Fatalf("expected empty base, got: %s", opts.Base)
	}
	if opts.Head != "" {
		t.Fatalf("expected empty head, got: %s", opts.Head)
	}
}

func TestFinding_JSONTags(t *testing.T) {
	f := Finding{
		RuleID:   "SEC-001",
		Severity: "high",
		File:     "main.go",
		Line:     10,
		Message:  "test",
	}
	if f.RuleID != "SEC-001" {
		t.Fatalf("unexpected rule ID: %s", f.RuleID)
	}
}

func TestRun_NoChangedFiles(t *testing.T) {
	dir := setupDiffGitRepo(t)

	result, err := Run(dir, Options{Base: "main", Head: "main"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.ChangedFiles) != 0 {
		t.Errorf("expected 0 changed files, got %d", len(result.ChangedFiles))
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.Base != "main" {
		t.Errorf("expected base 'main', got %q", result.Base)
	}
	if result.Head != "main" {
		t.Errorf("expected head 'main', got %q", result.Head)
	}
}

func TestRun_WithChangedFiles(t *testing.T) {
	dir := setupDiffGitRepo(t)

	// Create a feature branch with a secret.
	runGitCmd(t, dir, "git", "checkout", "-b", "feature")
	secretFile := filepath.Join(dir, "secret.go")
	if err := os.WriteFile(secretFile, []byte("package main\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n"), 0o644); err != nil {
		t.Fatalf("writing secret file: %v", err)
	}
	runGitCmd(t, dir, "git", "add", "secret.go")
	runGitCmd(t, dir, "git", "commit", "-m", "add secret")

	result, err := Run(dir, Options{Base: "main", Head: "feature"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.ChangedFiles) != 1 {
		t.Fatalf("expected 1 changed file, got %d: %v", len(result.ChangedFiles), result.ChangedFiles)
	}
	if result.ChangedFiles[0] != "secret.go" {
		t.Errorf("expected changed file 'secret.go', got %q", result.ChangedFiles[0])
	}

	// Should detect the AWS key in the changed file.
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "SEC-001" && f.File == "secret.go" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SEC-001 finding in changed secret.go")
	}
}

func TestRun_ChangedFilesError(t *testing.T) {
	dir := setupDiffGitRepo(t)

	// Use a nonexistent base ref — ChangedFiles will fail.
	_, err := Run(dir, Options{Base: "nonexistent-branch-xyz", Head: "main"})
	if err == nil {
		t.Fatal("expected error for invalid base ref, got nil")
	}
}

func TestRun_DefaultOptions(t *testing.T) {
	dir := setupDiffGitRepo(t)

	// Create a feature branch so HEAD differs from main.
	runGitCmd(t, dir, "git", "checkout", "-b", "feature")
	cleanFile := filepath.Join(dir, "clean.go")
	if err := os.WriteFile(cleanFile, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("writing clean file: %v", err)
	}
	runGitCmd(t, dir, "git", "add", "clean.go")
	runGitCmd(t, dir, "git", "commit", "-m", "add clean file")

	// Run with empty options — should use defaults "main" and "HEAD".
	result, err := Run(dir, Options{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result.Base != "main" {
		t.Errorf("expected default base 'main', got %q", result.Base)
	}
	if result.Head != "HEAD" {
		t.Errorf("expected default head 'HEAD', got %q", result.Head)
	}
}

// setupDiffGitRepo creates a temp dir with a git repo and initial commit.
func setupDiffGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGitCmd(t, dir, "git", "init", "-b", "main")
	runGitCmd(t, dir, "git", "config", "user.email", "test@test.com")
	runGitCmd(t, dir, "git", "config", "user.name", "Test")

	readme := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readme, []byte("# Test\n"), 0o644); err != nil {
		t.Fatalf("writing README: %v", err)
	}
	runGitCmd(t, dir, "git", "add", ".")
	runGitCmd(t, dir, "git", "commit", "-m", "initial")
	return dir
}

func runGitCmd(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}
