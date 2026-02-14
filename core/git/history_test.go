package git

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWalkHistory_BasicTraversal(t *testing.T) {
	dir := setupGitRepo(t)

	// Add two more commits beyond the initial one.
	writeFile(t, filepath.Join(dir, "secret.txt"), "AWS_SECRET_ACCESS_KEY=abc123")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "add secret")

	writeFile(t, filepath.Join(dir, "config.yaml"), "password: hunter2")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "add config")

	var diffs []HistoryDiff
	err := WalkHistory(dir, WalkHistoryOptions{}, func(d HistoryDiff) error {
		diffs = append(diffs, d)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkHistory: %v", err)
	}

	// 3 commits: initial (README.md), secret.txt, config.yaml — at least 3 diffs.
	if len(diffs) < 3 {
		t.Fatalf("expected at least 3 diffs, got %d", len(diffs))
	}

	// Verify all diffs have non-empty commit info.
	for i, d := range diffs {
		if d.Commit.SHA == "" {
			t.Errorf("diff[%d]: empty SHA", i)
		}
		if d.Commit.Author == "" {
			t.Errorf("diff[%d]: empty Author", i)
		}
		if d.Commit.Email == "" {
			t.Errorf("diff[%d]: empty Email", i)
		}
		if d.Commit.Date.IsZero() {
			t.Errorf("diff[%d]: zero Date", i)
		}
		if d.Commit.Message == "" {
			t.Errorf("diff[%d]: empty Message", i)
		}
		if d.FilePath == "" {
			t.Errorf("diff[%d]: empty FilePath", i)
		}
		if len(d.Content) == 0 {
			t.Errorf("diff[%d]: empty Content", i)
		}
	}

	// Verify that diffs are in chronological order (oldest first).
	for i := 1; i < len(diffs); i++ {
		if diffs[i].Commit.Date.Before(diffs[i-1].Commit.Date) {
			// Allow equal dates (same-second commits), just not strictly before.
			if !diffs[i].Commit.Date.Equal(diffs[i-1].Commit.Date) {
				t.Errorf("diff[%d] date %v is before diff[%d] date %v",
					i, diffs[i].Commit.Date, i-1, diffs[i-1].Commit.Date)
			}
		}
	}

	// Verify we see the expected file paths.
	paths := make(map[string]bool)
	for _, d := range diffs {
		paths[d.FilePath] = true
	}
	for _, want := range []string{"README.md", "secret.txt", "config.yaml"} {
		if !paths[want] {
			t.Errorf("expected to see file %q in diffs", want)
		}
	}
}

func TestWalkHistory_MaxDepth(t *testing.T) {
	dir := setupGitRepo(t)

	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "second")

	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "third")

	// Walk only the first 2 commits (oldest first due to --reverse).
	var diffs []HistoryDiff
	err := WalkHistory(dir, WalkHistoryOptions{MaxDepth: 2}, func(d HistoryDiff) error {
		diffs = append(diffs, d)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkHistory: %v", err)
	}

	// We should only see files from the first 2 commits.
	shas := make(map[string]bool)
	for _, d := range diffs {
		shas[d.Commit.SHA] = true
	}
	if len(shas) > 2 {
		t.Fatalf("expected at most 2 unique commits, got %d", len(shas))
	}

	// b.txt should NOT appear (that is the 3rd commit).
	for _, d := range diffs {
		if d.FilePath == "b.txt" {
			t.Fatal("b.txt should not appear with MaxDepth=2")
		}
	}
}

func TestWalkHistory_SinceBookmark(t *testing.T) {
	dir := setupGitRepo(t)

	// Record the SHA of the initial commit as the bookmark.
	bookmark := getHEAD(t, dir)

	writeFile(t, filepath.Join(dir, "after.txt"), "after bookmark")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "after bookmark")

	var diffs []HistoryDiff
	err := WalkHistory(dir, WalkHistoryOptions{Since: bookmark}, func(d HistoryDiff) error {
		diffs = append(diffs, d)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkHistory: %v", err)
	}

	// Only the commit after the bookmark should appear.
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].FilePath != "after.txt" {
		t.Fatalf("expected after.txt, got %s", diffs[0].FilePath)
	}

	// The bookmark commit itself should NOT appear.
	if diffs[0].Commit.SHA == bookmark {
		t.Fatal("bookmark commit should not appear in results")
	}
}

func TestWalkHistory_EmptyRepo(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "git", "init", "-b", "main")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")

	var diffs []HistoryDiff
	err := WalkHistory(dir, WalkHistoryOptions{}, func(d HistoryDiff) error {
		diffs = append(diffs, d)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkHistory on empty repo: %v", err)
	}
	if len(diffs) != 0 {
		t.Fatalf("expected 0 diffs on empty repo, got %d", len(diffs))
	}
}

func TestWalkHistory_DeletedFiles(t *testing.T) {
	dir := setupGitRepo(t)

	writeFile(t, filepath.Join(dir, "temp.txt"), "temporary")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "add temp")

	run(t, dir, "git", "rm", "temp.txt")
	run(t, dir, "git", "commit", "-m", "delete temp")

	var diffs []HistoryDiff
	err := WalkHistory(dir, WalkHistoryOptions{}, func(d HistoryDiff) error {
		diffs = append(diffs, d)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkHistory: %v", err)
	}

	// The delete commit should NOT produce a diff for temp.txt.
	// temp.txt should appear once (the add), but never from the delete commit.
	deleteCommitFiles := make(map[string]bool)
	for _, d := range diffs {
		if d.Commit.Message == "delete temp" {
			deleteCommitFiles[d.FilePath] = true
		}
	}
	if deleteCommitFiles["temp.txt"] {
		t.Fatal("deleted file temp.txt should not appear in diff for the delete commit")
	}

	// temp.txt should appear from the add commit.
	found := false
	for _, d := range diffs {
		if d.FilePath == "temp.txt" && d.Commit.Message == "add temp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("temp.txt should appear from the 'add temp' commit")
	}
}

func TestWalkHistory_BinaryFilesSkipped(t *testing.T) {
	dir := setupGitRepo(t)

	// Create a binary file with null bytes.
	binPath := filepath.Join(dir, "image.bin")
	if err := os.WriteFile(binPath, []byte{0x89, 0x50, 0x4E, 0x47, 0x00, 0x00, 0x00}, 0o644); err != nil {
		t.Fatalf("writing binary file: %v", err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "add binary")

	var diffs []HistoryDiff
	err := WalkHistory(dir, WalkHistoryOptions{}, func(d HistoryDiff) error {
		diffs = append(diffs, d)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkHistory: %v", err)
	}

	// Binary file should be skipped.
	for _, d := range diffs {
		if d.FilePath == "image.bin" {
			t.Fatal("binary file image.bin should be skipped")
		}
	}
}

func TestWalkHistory_CallbackError(t *testing.T) {
	dir := setupGitRepo(t)

	sentinel := errors.New("stop walking")
	err := WalkHistory(dir, WalkHistoryOptions{}, func(d HistoryDiff) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got: %v", err)
	}
}

func TestWalkHistory_ModifiedFiles(t *testing.T) {
	dir := setupGitRepo(t)

	// Modify README.md in a second commit.
	writeFile(t, filepath.Join(dir, "README.md"), "# Updated")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "update readme")

	var diffs []HistoryDiff
	err := WalkHistory(dir, WalkHistoryOptions{}, func(d HistoryDiff) error {
		diffs = append(diffs, d)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkHistory: %v", err)
	}

	// README.md should appear twice: once in the initial, once in the update.
	count := 0
	for _, d := range diffs {
		if d.FilePath == "README.md" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected README.md in 2 diffs, got %d", count)
	}
}

func TestWalkHistory_InvalidRepo(t *testing.T) {
	// Use a plain temp dir that is NOT a git repo.
	dir := t.TempDir()
	err := WalkHistory(dir, WalkHistoryOptions{}, func(d HistoryDiff) error {
		t.Fatal("callback should not be called for invalid repo")
		return nil
	})
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
	}
}

func TestWalkHistory_BranchOption(t *testing.T) {
	dir := setupGitRepo(t)

	// Create a second branch with a file.
	run(t, dir, "git", "checkout", "-b", "feature")
	writeFile(t, filepath.Join(dir, "feature.txt"), "feature content")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "feature commit")

	// Walk only the feature branch.
	var diffs []HistoryDiff
	err := WalkHistory(dir, WalkHistoryOptions{Branch: "feature"}, func(d HistoryDiff) error {
		diffs = append(diffs, d)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkHistory: %v", err)
	}

	// Should see feature.txt from the feature branch.
	found := false
	for _, d := range diffs {
		if d.FilePath == "feature.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected feature.txt in diffs when walking feature branch")
	}
}

func TestParseNullSeparatedPaths_Empty(t *testing.T) {
	result := parseNullSeparatedPaths("")
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
}

func TestParseNullSeparatedPaths_MetadataOnly(t *testing.T) {
	// Metadata line with no path following it.
	result := parseNullSeparatedPaths(":100644 100644 abc def M\x00")
	if len(result) != 0 {
		t.Errorf("expected 0 paths when path is empty, got %v", result)
	}
}

func TestParseNullSeparatedPaths_SingleFile(t *testing.T) {
	input := ":100644 100644 abc def M\x00file.go\x00"
	result := parseNullSeparatedPaths(input)
	if len(result) != 1 || result[0] != "file.go" {
		t.Errorf("expected [file.go], got %v", result)
	}
}

func TestListCommits_MaxDepthTruncation(t *testing.T) {
	dir := setupGitRepo(t)

	// Add two more commits.
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "second")

	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "third")

	// Request only 1 commit.
	shas, err := listCommits(dir, WalkHistoryOptions{MaxDepth: 1})
	if err != nil {
		t.Fatalf("listCommits: %v", err)
	}
	if len(shas) != 1 {
		t.Fatalf("expected 1 SHA, got %d", len(shas))
	}
}

func TestListCommits_SinceBookmark(t *testing.T) {
	dir := setupGitRepo(t)
	bookmark := getHEAD(t, dir)

	writeFile(t, filepath.Join(dir, "new.txt"), "new")
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "after bookmark")

	shas, err := listCommits(dir, WalkHistoryOptions{Since: bookmark})
	if err != nil {
		t.Fatalf("listCommits: %v", err)
	}
	if len(shas) != 1 {
		t.Fatalf("expected 1 SHA after bookmark, got %d", len(shas))
	}
}

func TestCommitInfo_ValidCommit(t *testing.T) {
	dir := setupGitRepo(t)
	sha := getHEAD(t, dir)

	info, err := commitInfo(dir, sha)
	if err != nil {
		t.Fatalf("commitInfo: %v", err)
	}
	if info.SHA != sha {
		t.Errorf("expected SHA %q, got %q", sha, info.SHA)
	}
	if info.Author == "" {
		t.Error("expected non-empty author")
	}
	if info.Email == "" {
		t.Error("expected non-empty email")
	}
	if info.Date.IsZero() {
		t.Error("expected non-zero date")
	}
	if info.Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestCommitInfo_InvalidSHA(t *testing.T) {
	dir := setupGitRepo(t)
	_, err := commitInfo(dir, "0000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected error for invalid SHA, got nil")
	}
}

func TestChangedFilesForCommit_InitialCommit(t *testing.T) {
	dir := setupGitRepo(t)
	sha := getHEAD(t, dir)

	files, err := changedFilesForCommit(dir, sha)
	if err != nil {
		t.Fatalf("changedFilesForCommit: %v", err)
	}

	// Initial commit should include README.md.
	found := false
	for _, f := range files {
		if f == "README.md" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected README.md in initial commit, got %v", files)
	}
}

func TestFileAtCommit_ValidFile(t *testing.T) {
	dir := setupGitRepo(t)
	sha := getHEAD(t, dir)

	content, err := fileAtCommit(dir, sha, "README.md")
	if err != nil {
		t.Fatalf("fileAtCommit: %v", err)
	}
	if string(content) != "# Test" {
		t.Errorf("expected '# Test', got %q", string(content))
	}
}

func TestFileAtCommit_NonexistentFile(t *testing.T) {
	dir := setupGitRepo(t)
	sha := getHEAD(t, dir)

	_, err := fileAtCommit(dir, sha, "nonexistent.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

// getHEAD returns the full SHA of the current HEAD.
func getHEAD(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v\n%s", err, out)
	}
	return string(bytes.TrimSpace(out))
}
