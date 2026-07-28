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

func TestStagedFiles(t *testing.T) {
	dir := setupGitRepo(t)

	// Stage two new files.
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")
	run(t, dir, "git", "add", "a.txt", "b.txt")

	staged, err := StagedFiles(dir)
	if err != nil {
		t.Fatalf("StagedFiles: %v", err)
	}

	if len(staged) != 2 {
		t.Fatalf("expected 2 staged files, got %d: %v", len(staged), staged)
	}

	expected := map[string]bool{"a.txt": true, "b.txt": true}
	for _, f := range staged {
		if !expected[f] {
			t.Fatalf("unexpected staged file: %s", f)
		}
	}
}

func TestStagedFiles_NoStaged(t *testing.T) {
	dir := setupGitRepo(t)

	staged, err := StagedFiles(dir)
	if err != nil {
		t.Fatalf("StagedFiles: %v", err)
	}

	if len(staged) != 0 {
		t.Fatalf("expected no staged files, got %v", staged)
	}
}

func TestStagedContent(t *testing.T) {
	dir := setupGitRepo(t)

	// Write and stage a file.
	writeFile(t, filepath.Join(dir, "secret.env"), "API_KEY=staged_value")
	run(t, dir, "git", "add", "secret.env")

	// Now modify the working tree version (but do not stage it).
	writeFile(t, filepath.Join(dir, "secret.env"), "API_KEY=working_tree_value")

	// StagedContent should return the staged version, not the working tree.
	content, err := StagedContent(dir, "secret.env")
	if err != nil {
		t.Fatalf("StagedContent: %v", err)
	}

	got := string(content)
	if got != "API_KEY=staged_value" {
		t.Fatalf("expected staged content %q, got %q", "API_KEY=staged_value", got)
	}
}

func TestStagedContent_SubDir(t *testing.T) {
	dir := setupGitRepo(t)

	// Write a file in a subdirectory and stage it.
	subDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("creating subdir: %v", err)
	}
	writeFile(t, filepath.Join(subDir, "app.yaml"), "key: value")
	run(t, dir, "git", "add", "config/app.yaml")

	content, err := StagedContent(dir, "config/app.yaml")
	if err != nil {
		t.Fatalf("StagedContent: %v", err)
	}

	if string(content) != "key: value" {
		t.Fatalf("expected %q, got %q", "key: value", string(content))
	}
}

func TestTrackedFiles(t *testing.T) {
	dir := setupGitRepo(t) // starts with a tracked README.md

	// A directory ignored by .gitignore, but with a file force-added (tracked).
	writeFile(t, filepath.Join(dir, ".gitignore"), "mobile/\n")
	if err := os.MkdirAll(filepath.Join(dir, "mobile"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "mobile", "app.go"), "package m")
	writeFile(t, filepath.Join(dir, "mobile", "ignored.go"), "package m")
	run(t, dir, "git", "add", ".gitignore", "README.md")
	run(t, dir, "git", "add", "-f", "mobile/app.go") // force-track despite ignore
	run(t, dir, "git", "commit", "-m", "add tracked file under ignored dir")

	tracked, err := TrackedFiles(dir)
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	got := map[string]bool{}
	for _, f := range tracked {
		got[f] = true
	}
	// The force-added file is tracked even though mobile/ is gitignored —
	// this is exactly what git ls-files reports, and why the scanner must
	// cover it (#142).
	if !got["mobile/app.go"] {
		t.Errorf("expected tracked mobile/app.go, got %v", tracked)
	}
	if !got[".gitignore"] || !got["README.md"] {
		t.Errorf("expected .gitignore and README.md tracked, got %v", tracked)
	}
	if got["mobile/ignored.go"] {
		t.Error("mobile/ignored.go was never added — it must not be tracked")
	}
}

// TestTrackedFiles_Submodules verifies tracked-only scans reach into an
// initialized submodule (roadmap 1.2). Without --recurse-submodules, git
// ls-files reports the submodule only as a gitlink, so its scannable content
// would be invisible to a tracked-only scan even though a normal walk sees it.
func TestTrackedFiles_Submodules(t *testing.T) {
	// A separate repo that will become the submodule.
	subRemote := t.TempDir()
	run(t, subRemote, "git", "init", "-b", "main")
	run(t, subRemote, "git", "config", "user.email", "test@test.com")
	run(t, subRemote, "git", "config", "user.name", "Test")
	writeFile(t, filepath.Join(subRemote, "lib.go"), "package lib")
	run(t, subRemote, "git", "add", ".")
	run(t, subRemote, "git", "commit", "-m", "sub initial")

	super := setupGitRepo(t)
	// Local submodule add needs protocol.file.allow=always on modern git.
	run(t, super, "git", "-c", "protocol.file.allow=always", "submodule", "add", subRemote, "vendor/sub")
	run(t, super, "git", "commit", "-m", "add submodule")

	tracked, err := TrackedFiles(super)
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	got := map[string]bool{}
	for _, f := range tracked {
		got[f] = true
	}
	if !got["vendor/sub/lib.go"] {
		t.Errorf("expected submodule file vendor/sub/lib.go in tracked set, got %v", tracked)
	}
}

func TestTrackedFiles_InvalidRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := TrackedFiles(dir)
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
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
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir,
		// Git may fork `gc --auto` on commit, which keeps writing into
		// .git/objects after the command returns. t.TempDir cleanup then races
		// it and RemoveAll fails with "directory not empty", failing a test
		// that had already passed. Disabling auto-maintenance removes the race.
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=gc.auto", "GIT_CONFIG_VALUE_0=0",
		"GIT_CONFIG_KEY_1=maintenance.auto", "GIT_CONFIG_VALUE_1=false")
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

// ---------------------------------------------------------------------------
// Error path tests
// ---------------------------------------------------------------------------

func TestChangedFiles_InvalidRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := ChangedFiles(dir, "main", "HEAD")
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
	}
}

func TestRepoRoot_InvalidRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := RepoRoot(dir)
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
	}
}

func TestCurrentBranch_InvalidRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := CurrentBranch(dir)
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
	}
}

func TestMergeBase_InvalidRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := MergeBase(dir, "a", "b")
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
	}
}

func TestStagedFiles_InvalidRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := StagedFiles(dir)
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
	}
}

func TestStagedContent_NonexistentFile(t *testing.T) {
	dir := setupGitRepo(t)
	_, err := StagedContent(dir, "nonexistent.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent staged file, got nil")
	}
}

func TestSplitLines_Empty(t *testing.T) {
	result := splitLines("")
	if result != nil {
		t.Errorf("expected nil for empty string, got %v", result)
	}
}

func TestSplitLines_Whitespace(t *testing.T) {
	result := splitLines("   \n  ")
	if result != nil {
		t.Errorf("expected nil for whitespace-only string, got %v", result)
	}
}

func TestSplitLines_SingleLine(t *testing.T) {
	result := splitLines("hello\n")
	if len(result) != 1 || result[0] != "hello" {
		t.Errorf("expected [hello], got %v", result)
	}
}

func TestSplitLines_MultipleLines(t *testing.T) {
	result := splitLines("a\nb\nc\n")
	if len(result) != 3 {
		t.Errorf("expected 3 lines, got %d: %v", len(result), result)
	}
}
