package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIsGitRepo_True(t *testing.T) {
	dir := setupGitRepo(t)
	if !IsGitRepo(dir) {
		t.Fatal("expected true for git repo")
	}
}

func TestIsGitRepo_False(t *testing.T) {
	dir := t.TempDir()
	if IsGitRepo(dir) {
		t.Fatal("expected false for non-git dir")
	}
}

func TestRepoRoot(t *testing.T) {
	dir := setupGitRepo(t)
	root, err := RepoRoot(dir)
	if err != nil {
		t.Fatalf("RepoRoot: %v", err)
	}

	// Compare resolved paths for portability.
	resolvedDir, _ := filepath.EvalSymlinks(dir)
	resolvedRoot, _ := filepath.EvalSymlinks(root)
	if resolvedRoot != resolvedDir {
		t.Fatalf("expected root %s, got %s", resolvedDir, resolvedRoot)
	}
}

func TestCurrentBranch(t *testing.T) {
	dir := setupGitRepo(t)
	branch, err := CurrentBranch(dir)
	if err != nil {
		t.Fatalf("CurrentBranch: %v", err)
	}
	// Initial branch is usually "main" or "master" depending on git config.
	if branch == "" {
		t.Fatal("expected non-empty branch name")
	}
}

func TestChangedFiles(t *testing.T) {
	dir := setupGitRepo(t)

	// Create a branch, add a file, commit.
	run(t, dir, "git", "checkout", "-b", "feature")
	writeFile(t, filepath.Join(dir, "new.txt"), "hello")
	run(t, dir, "git", "add", "new.txt")
	run(t, dir, "git", "commit", "-m", "add new.txt")

	changed, err := ChangedFiles(dir, "main", "feature")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}

	if len(changed) != 1 || changed[0] != "new.txt" {
		t.Fatalf("expected [new.txt], got %v", changed)
	}
}

func TestChangedFiles_NoChanges(t *testing.T) {
	dir := setupGitRepo(t)

	changed, err := ChangedFiles(dir, "main", "main")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}

	if len(changed) != 0 {
		t.Fatalf("expected no changes, got %v", changed)
	}
}

func TestMergeBase(t *testing.T) {
	dir := setupGitRepo(t)

	// The merge base of main with itself should be the same commit.
	mb, err := MergeBase(dir, "main", "main")
	if err != nil {
		t.Fatalf("MergeBase: %v", err)
	}
	if mb == "" {
		t.Fatal("expected non-empty merge base")
	}
}

// setupGitRepo creates a temp dir with a git repo and an initial commit.
func setupGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init", "-b", "main")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")

	writeFile(t, filepath.Join(dir, "README.md"), "# Test")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "initial")
	return dir
}

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
