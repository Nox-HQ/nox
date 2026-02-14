// Package git provides Git operations via os/exec for diff and PR workflows.
package git

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ChangedFiles returns the list of files changed between base and head refs.
func ChangedFiles(repoRoot, base, head string) ([]string, error) {
	args := []string{"diff", "--name-only", base + "..." + head}
	out, err := runGit(repoRoot, args...)
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	return splitLines(out), nil
}

// IsGitRepo returns true if path is inside a git repository.
func IsGitRepo(path string) bool {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// RepoRoot returns the top-level directory of the git repository.
func RepoRoot(path string) (string, error) {
	out, err := runGit(path, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	root := strings.TrimSpace(out)
	return filepath.Clean(root), nil
}

// CurrentBranch returns the current branch name.
func CurrentBranch(repoRoot string) (string, error) {
	out, err := runGit(repoRoot, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git current branch: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// MergeBase returns the best common ancestor between two refs.
func MergeBase(repoRoot, ref1, ref2 string) (string, error) {
	out, err := runGit(repoRoot, "merge-base", ref1, ref2)
	if err != nil {
		return "", fmt.Errorf("git merge-base: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// StagedFiles returns the list of staged file paths (added, copied, modified,
// renamed) relative to the repository root. Only files in the git index that
// differ from HEAD are returned, which is exactly what will be committed.
func StagedFiles(repoRoot string) ([]string, error) {
	out, err := runGit(repoRoot, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
	if err != nil {
		return nil, fmt.Errorf("git diff --cached: %w", err)
	}
	return splitLines(out), nil
}

// StagedContent returns the staged (index) version of a file. This reads from
// the git index rather than the working tree, ensuring pre-commit hooks scan
// exactly what will be committed.
func StagedContent(repoRoot, path string) ([]byte, error) {
	out, err := runGit(repoRoot, "show", ":"+path)
	if err != nil {
		return nil, fmt.Errorf("git show :%s: %w", path, err)
	}
	return []byte(out), nil
}

func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func splitLines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
