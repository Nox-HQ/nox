package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// CommitInfo holds metadata about a single commit.
type CommitInfo struct {
	SHA     string
	Author  string
	Email   string
	Date    time.Time
	Message string
}

// HistoryDiff represents a single file change in a commit.
type HistoryDiff struct {
	Commit   CommitInfo
	FilePath string
	Content  []byte // the full file content at that commit
}

// WalkHistoryOptions configures history traversal.
type WalkHistoryOptions struct {
	MaxDepth int    // max commits to traverse (0 = unlimited)
	Branch   string // branch to walk (default: HEAD)
	Since    string // bookmark commit SHA to start after (for incremental)
}

// WalkHistory traverses git history and calls fn for each added/modified file.
// It uses git rev-list to enumerate commits and git show to extract file content.
// Returns early if fn returns an error.
func WalkHistory(repoRoot string, opts WalkHistoryOptions, fn func(HistoryDiff) error) error {
	shas, err := listCommits(repoRoot, opts)
	if err != nil {
		return fmt.Errorf("walk history: list commits: %w", err)
	}
	if len(shas) == 0 {
		return nil
	}

	for _, sha := range shas {
		info, err := commitInfo(repoRoot, sha)
		if err != nil {
			return fmt.Errorf("walk history: commit info %s: %w", sha, err)
		}

		files, err := changedFilesForCommit(repoRoot, sha)
		if err != nil {
			return fmt.Errorf("walk history: changed files %s: %w", sha, err)
		}

		for _, path := range files {
			content, err := fileAtCommit(repoRoot, sha, path)
			if err != nil {
				// File may not be readable (submodule, etc.); skip.
				continue
			}

			// Skip binary files (files containing null bytes).
			if bytes.ContainsRune(content, 0) {
				continue
			}

			if err := fn(HistoryDiff{
				Commit:   info,
				FilePath: path,
				Content:  content,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

// listCommits returns commit SHAs in chronological order (oldest first).
// When MaxDepth is set, the list is truncated to the first N commits
// (oldest first) so that incremental scanning processes history from
// the beginning.
func listCommits(repoRoot string, opts WalkHistoryOptions) ([]string, error) {
	branch := opts.Branch
	if branch == "" {
		branch = "HEAD"
	}

	args := []string{"rev-list", "--reverse"}

	if opts.Since != "" {
		// Walk commits reachable from branch but not from Since (exclusive).
		args = append(args, branch, "^"+opts.Since)
	} else {
		args = append(args, branch)
	}

	out, err := runGit(repoRoot, args...)
	if err != nil {
		// Empty repo or no commits: rev-list returns non-zero.
		if strings.Contains(err.Error(), "unknown revision") ||
			strings.Contains(err.Error(), "bad default revision") {
			return nil, nil
		}
		return nil, err
	}

	lines := splitLines(out)

	// Truncate to MaxDepth oldest commits.
	if opts.MaxDepth > 0 && len(lines) > opts.MaxDepth {
		lines = lines[:opts.MaxDepth]
	}

	return lines, nil
}

// commitInfo retrieves metadata for a single commit using a format string.
func commitInfo(repoRoot, sha string) (CommitInfo, error) {
	// Use a record separator that will not appear in commit messages.
	const delim = "\x1e"
	format := strings.Join([]string{"%H", "%an", "%ae", "%at", "%s"}, delim)

	out, err := runGit(repoRoot, "log", "-1", "--format="+format, sha)
	if err != nil {
		return CommitInfo{}, err
	}

	parts := strings.SplitN(strings.TrimSpace(out), delim, 5)
	if len(parts) < 5 {
		return CommitInfo{}, fmt.Errorf("unexpected git log output: %q", out)
	}

	ts, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return CommitInfo{}, fmt.Errorf("parsing commit timestamp %q: %w", parts[3], err)
	}

	return CommitInfo{
		SHA:     parts[0],
		Author:  parts[1],
		Email:   parts[2],
		Date:    time.Unix(ts, 0).UTC(),
		Message: parts[4],
	}, nil
}

// changedFilesForCommit returns files added, copied, modified, or renamed in a commit.
// For the initial commit (no parent), --root is used.
func changedFilesForCommit(repoRoot, sha string) ([]string, error) {
	// Try with diff-tree for normal commits first.
	out, err := runGit(repoRoot, "diff-tree", "--no-commit-id", "-r",
		"--diff-filter=ACMR", "-z", sha)
	if err != nil {
		return nil, err
	}

	// If empty, this may be the initial commit — use --root.
	if strings.TrimSpace(out) == "" {
		out, err = runGit(repoRoot, "diff-tree", "--root", "--no-commit-id", "-r",
			"--diff-filter=ACMR", "-z", sha)
		if err != nil {
			return nil, err
		}
	}

	return parseNullSeparatedPaths(out), nil
}

// parseNullSeparatedPaths extracts file paths from git diff-tree -z output.
// The -z format produces lines like: ":old_mode new_mode old_hash new_hash status\0path\0"
// We need to extract only the path fields.
func parseNullSeparatedPaths(raw string) []string {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, "\x00")
	var paths []string

	for i := 0; i < len(parts); i++ {
		part := parts[i]
		if part == "" {
			continue
		}
		// Lines starting with ":" are metadata; the next element is the path.
		if strings.HasPrefix(part, ":") {
			if i+1 < len(parts) && parts[i+1] != "" {
				paths = append(paths, parts[i+1])
				i++ // skip the path element
			}
		}
	}

	return paths
}

// fileAtCommit retrieves the full content of a file at a specific commit.
func fileAtCommit(repoRoot, sha, path string) ([]byte, error) {
	out, err := runGitBytes(repoRoot, "show", sha+":"+path)
	if err != nil {
		return nil, fmt.Errorf("git show %s:%s: %w", sha, path, err)
	}
	return out, nil
}

// runGitBytes is like runGit but returns raw bytes instead of a string.
// This is necessary for binary-safe content retrieval.
func runGitBytes(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}
