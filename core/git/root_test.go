package git

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootCommitIsStableAcrossLaterCommits(t *testing.T) {
	dir := setupGitRepo(t)
	first, err := RootCommit(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(gitOut(t, dir, "rev-list", "--max-parents=0", "HEAD"))
	if first != want {
		t.Fatalf("RootCommit = %q, want %q", first, want)
	}
	writeFile(t, filepath.Join(dir, "later.txt"), "x")
	run(t, dir, "git", "add", "later.txt")
	run(t, dir, "git", "commit", "-m", "later")
	if again, _ := RootCommit(dir); again != first {
		t.Fatalf("root moved with a new commit: %q -> %q", first, again)
	}
}

// The case that matters in CI: a depth-1 checkout's boundary commit is HEAD,
// a new "root" every run.
func TestRootCommitRefusesAShallowClone(t *testing.T) {
	src := setupGitRepo(t)
	writeFile(t, filepath.Join(src, "second.txt"), "x")
	run(t, src, "git", "add", "second.txt")
	run(t, src, "git", "commit", "-m", "second")

	clone := filepath.Join(t.TempDir(), "shallow")
	run(t, t.TempDir(), "git", "clone", "-q", "--depth", "1", "file://"+src, clone)
	if _, err := RootCommit(clone); !errors.Is(err, ErrShallowClone) {
		t.Fatalf("shallow clone: err = %v, want ErrShallowClone", err)
	}
}

// Unrelated histories merged: the answer is the smallest root, whichever
// order git lists them in.
func TestRootCommitOfMergedHistoriesIsTheSmallest(t *testing.T) {
	dir := setupGitRepo(t)
	run(t, dir, "git", "checkout", "-q", "--orphan", "other")
	writeFile(t, filepath.Join(dir, "other.txt"), "y")
	run(t, dir, "git", "add", "other.txt")
	run(t, dir, "git", "commit", "-q", "-m", "other root")
	run(t, dir, "git", "checkout", "-q", "main")
	run(t, dir, "git", "merge", "-q", "--allow-unrelated-histories", "-m", "join", "other")

	roots := strings.Fields(gitOut(t, dir, "rev-list", "--max-parents=0", "HEAD"))
	if len(roots) != 2 {
		t.Fatalf("setup: %d roots, want 2", len(roots))
	}
	want := roots[0]
	if roots[1] < want {
		want = roots[1]
	}
	if got, err := RootCommit(dir); err != nil || got != want {
		t.Fatalf("RootCommit = %q, %v; want %q", got, err, want)
	}
}

func TestRootCommitOutsideARepositoryFails(t *testing.T) {
	if _, err := RootCommit(t.TempDir()); err == nil {
		t.Fatal("no error outside a repository")
	}
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := runGit(dir, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
