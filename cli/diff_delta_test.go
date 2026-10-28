package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// diffGit runs git in dir with a hermetic identity and fails the test on error.
func diffGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("git %v unavailable: %v: %s", args, err, out)
	}
	return string(out)
}

func writeAll(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// `nox diff` is a delta: over two real commits it lists what the second commit
// introduced and what it removed, and is silent about a finding that was there
// before and is still there, including one that merely moved down the file.
func TestRunDiff_IsADeltaOverTwoCommits(t *testing.T) {
	dir := t.TempDir()
	diffGit(t, dir, "init", "-b", "main")

	const keyOld = "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" // nox:ignore SEC-001 -- test fixture

	const keyGone = "AWS_KEY=AKIAJ5ZQ7XM2K9PLRD3A\n" // nox:ignore SEC-001 -- test fixture

	const keyNew = "AWS_KEY=AKIAV4NHT8QWE6YCBU2S\n" // nox:ignore SEC-001 -- test fixture
	writeAll(t, dir, map[string]string{"kept.env": keyOld, "gone.env": keyGone, "README.md": "# app\n"})
	diffGit(t, dir, "add", ".")
	diffGit(t, dir, "commit", "-m", "base")

	// The second commit: remove one secret, add another, and push the kept
	// secret down the file by prepending blank lines.
	if err := os.Remove(filepath.Join(dir, "gone.env")); err != nil {
		t.Fatal(err)
	}
	writeAll(t, dir, map[string]string{"added.env": keyNew, "kept.env": "\n\n\n\n" + keyOld})
	diffGit(t, dir, "add", "-A")
	diffGit(t, dir, "commit", "-m", "head")

	// An uncommitted file must survive: the command reads refs, never the tree.
	writeAll(t, dir, map[string]string{"scratch.txt": "uncommitted\n"})

	var code int
	out := captureStdout(t, func() {
		code = runDiff([]string{"--base", "HEAD~1", "--head", "HEAD", "--offline", dir})
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (the head introduced a secret)\n%s", code, out)
	}
	newSection, resolved, ok := strings.Cut(out, "Resolved (no longer present)")
	if !ok {
		t.Fatalf("no resolved section:\n%s", out)
	}
	if !strings.Contains(newSection, "added.env") {
		t.Errorf("the new secret is not listed as new:\n%s", out)
	}
	if !strings.Contains(resolved, "gone.env") {
		t.Errorf("the removed secret is not listed as resolved:\n%s", out)
	}
	if strings.Contains(out, "kept.env") {
		t.Errorf("a secret that only moved down its file is listed:\n%s", out)
	}

	if _, err := os.Stat(filepath.Join(dir, "scratch.txt")); err != nil {
		t.Errorf("the working tree was touched: %v", err)
	}
	if n := strings.Count(strings.TrimSpace(diffGit(t, dir, "worktree", "list")), "\n"); n != 0 {
		t.Errorf("a git worktree was left behind")
	}
	if st := diffGit(t, dir, "status", "--porcelain"); strings.TrimSpace(st) != "?? scratch.txt" {
		t.Errorf("git status changed: %q", st)
	}
}

// With nothing introduced the command exits 0 and says so, however many files
// the commit touched.
func TestRunDiff_NothingNewExitsZero(t *testing.T) {
	dir := t.TempDir()
	diffGit(t, dir, "init", "-b", "main")
	const key = "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" // nox:ignore SEC-001 -- test fixture
	writeAll(t, dir, map[string]string{"kept.env": key})
	diffGit(t, dir, "add", ".")
	diffGit(t, dir, "commit", "-m", "base")
	writeAll(t, dir, map[string]string{"kept.env": "\n\n" + key})
	diffGit(t, dir, "add", "-A")
	diffGit(t, dir, "commit", "-m", "move")

	var code int
	out := captureStdout(t, func() {
		code = runDiff([]string{"--base", "HEAD~1", "--head", "HEAD", "--offline", dir})
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "Nothing new and nothing resolved") {
		t.Errorf("output should say nothing changed:\n%s", out)
	}
}

// scan --previous leads with what changed and lists the old findings only as
// part of the assessment that follows; without --previous nothing is added.
func TestScanPrevious_LeadsWithTheChange(t *testing.T) {
	dir := t.TempDir()
	const keyOld = "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" // nox:ignore SEC-001 -- test fixture

	const keyNew = "AWS_KEY=AKIAV4NHT8QWE6YCBU2S\n" // nox:ignore SEC-001 -- test fixture
	writeAll(t, dir, map[string]string{"old.env": keyOld})
	prevOut := t.TempDir()
	if code := runScan([]string{dir, "--offline"}, "json", prevOut, "", true, false); code == 2 {
		t.Fatal("first scan failed")
	}
	writeAll(t, dir, map[string]string{"new.env": keyNew})

	var code int
	out := captureStdout(t, func() {
		code = runScan([]string{dir, "--offline", "--previous", filepath.Join(prevOut, "findings.json")}, "json", t.TempDir(), "", false, false)
	})
	if code == 2 {
		t.Fatalf("scan failed:\n%s", out)
	}
	since := strings.Index(out, "Since the previous run:")
	assessment := strings.Index(out, "Nox Security Assessment")
	if since < 0 || assessment < 0 || since > assessment {
		t.Fatalf("the change section must lead the assessment:\n%s", out)
	}
	section := out[since:assessment]
	if !strings.Contains(section, "new.env") || strings.Contains(section, "old.env") {
		t.Errorf("the change section should name new.env only:\n%s", section)
	}

	plain := captureStdout(t, func() {
		runScan([]string{dir, "--offline"}, "json", t.TempDir(), "", false, false)
	})
	if strings.Contains(plain, "Since ") {
		t.Errorf("without --previous the output must not change:\n%s", plain)
	}
}

// A previous file that is absent is a first run, said on stderr; one that is
// present and broken is an error, never an empty history.
func TestScanPrevious_MissingIsFirstRunCorruptIsError(t *testing.T) {
	dir := t.TempDir()
	writeAll(t, dir, map[string]string{"a.txt": "hello\n"})
	if code := runScan([]string{dir, "--offline", "--previous", filepath.Join(dir, "nope.json")}, "json", t.TempDir(), "", true, false); code == 2 {
		t.Error("a missing previous file must not fail the scan")
	}
	bad := filepath.Join(t.TempDir(), "findings.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runScan([]string{dir, "--offline", "--previous", bad}, "json", t.TempDir(), "", true, false); code != 2 {
		t.Errorf("a corrupt previous file exited %d, want 2", code)
	}
}
