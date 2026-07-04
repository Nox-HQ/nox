package discovery

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// LoadGitignore reads ignore patterns from the standard set of locations git
// itself consults: every .gitignore from the scan target up to the repo
// root (so `nox scan apps/api` still honors the project-root .gitignore
// that lists `node_modules/`), the optional .noxignore convenience file,
// the per-repo .git/info/exclude, and the global excludesfile (resolved
// from $XDG_CONFIG_HOME/git/ignore or ~/.config/git/ignore).
//
// Missing files are treated as empty. If no enclosing .git directory is
// found, only the target's own .gitignore + .noxignore are loaded.
func LoadGitignore(root string) ([]string, error) {
	var patterns []string

	absTarget, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	repoRoot := findRepoRoot(absTarget)

	// Walk the ancestor chain from the repo root down to (but not
	// including) the target, loading each .gitignore. Parent patterns
	// apply to paths underneath them, which is the standard git
	// semantic. Loading top-down means a deeper .gitignore can override
	// with negation (`!`) patterns.
	if repoRoot != "" && repoRoot != absTarget {
		for _, dir := range ancestorChain(repoRoot, absTarget) {
			p, err := loadIgnoreFile(filepath.Join(dir, ".gitignore"))
			if err != nil {
				return nil, err
			}
			patterns = append(patterns, p...)
		}
	}

	for _, name := range []string{".gitignore", ".noxignore"} {
		p, err := loadIgnoreFile(filepath.Join(root, name))
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, p...)
	}

	// info/exclude lives at the repo root. In a linked worktree `.git` is a
	// gitdir-pointer file (not a directory), and git keeps info/exclude in the
	// shared common dir — so resolve the real path rather than blindly joining
	// `.git/info/exclude`, which would ENOTDIR and discard every pattern above.
	gitInfoDir := absTarget
	if repoRoot != "" {
		gitInfoDir = repoRoot
	}
	if excludePath := gitInfoExcludePath(gitInfoDir); excludePath != "" {
		p, err := loadIgnoreFile(excludePath)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, p...)
	}

	if globalPath := globalGitignorePath(); globalPath != "" {
		gp, err := loadIgnoreFile(globalPath)
		if err == nil {
			patterns = append(patterns, gp...)
		}
	}

	return patterns, nil
}

// findRepoRoot walks upward from an absolute start path looking for the
// first directory containing a `.git` entry (file or directory —
// submodules use a file). Returns the empty string when no enclosing
// repo is found, leaving the caller to fall back to target-only loading.
func findRepoRoot(absStart string) string {
	abs := absStart
	for {
		if _, err := os.Stat(filepath.Join(abs, ".git")); err == nil {
			return abs
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return ""
		}
		abs = parent
	}
}

// gitInfoExcludePath resolves the path to git's info/exclude file for the
// repository rooted at repoRoot, handling both shapes of `.git`:
//
//   - a directory (normal checkout): <repoRoot>/.git/info/exclude
//   - a file (linked worktree or submodule): the file holds a
//     `gitdir: <path>` pointer. git stores info/exclude in the repo's shared
//     *common* dir, which <gitdir>/commondir points to, so all worktrees see
//     the same excludes. Falls back to <gitdir>/info/exclude when no
//     commondir marker is present.
//
// Returns "" when there is no `.git` entry, leaving the caller to load only
// the .gitignore/.noxignore chain.
func gitInfoExcludePath(repoRoot string) string {
	gitPath := filepath.Join(repoRoot, ".git")
	info, err := os.Stat(gitPath)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		return filepath.Join(gitPath, "info", "exclude")
	}

	// `.git` is a file: follow the gitdir pointer, then the commondir.
	gitDir := parseGitdirPointer(gitPath)
	if gitDir == "" {
		return ""
	}
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(repoRoot, gitDir)
	}
	commonDir := gitDir
	if data, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		if cd := strings.TrimSpace(string(data)); cd != "" {
			if !filepath.IsAbs(cd) {
				cd = filepath.Join(gitDir, cd)
			}
			commonDir = filepath.Clean(cd)
		}
	}
	return filepath.Join(commonDir, "info", "exclude")
}

// parseGitdirPointer reads a `.git` pointer file and returns the gitdir path
// it names, or "" if the file is unreadable or malformed.
func parseGitdirPointer(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(line, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(line, prefix))
}

// ancestorChain returns the directories between absRoot and absLeaf,
// in top-down order, starting with absRoot and excluding absLeaf. Both
// inputs must be absolute. Returns nil if absLeaf is not under absRoot.
func ancestorChain(absRoot, absLeaf string) []string {
	rel, err := filepath.Rel(absRoot, absLeaf)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil
	}
	if rel == "." {
		return nil
	}
	out := []string{absRoot}
	cur := absRoot
	parts := strings.Split(filepath.ToSlash(rel), "/")
	// Drop the final component so absLeaf isn't included.
	for _, p := range parts[:len(parts)-1] {
		if p == "" || p == "." {
			continue
		}
		cur = filepath.Join(cur, p)
		out = append(out, cur)
	}
	return out
}

// globalGitignorePath resolves the global git ignore file location, checking
// XDG_CONFIG_HOME first, then the conventional ~/.config/git/ignore.
func globalGitignorePath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "git", "ignore")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "git", "ignore")
}

// LoadNestedGitignore reads a .gitignore file from dir and returns the parsed
// patterns. Nested gitignores apply only to paths under their containing
// directory; callers must scope checks accordingly.
func LoadNestedGitignore(dir string) ([]string, error) {
	return loadIgnoreFile(filepath.Join(dir, ".gitignore"))
}

func loadIgnoreFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		// A missing file — or a path whose parent turned out to be a file
		// rather than a directory (ENOTDIR: e.g. `.git/info/exclude` in a
		// worktree where `.git` is a gitdir pointer) — simply contributes no
		// patterns. Anything else is a real error worth surfacing.
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close() //nolint:errcheck // best-effort close on read-only file

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return patterns, nil
}

// IsIgnored reports whether a relative path matches any of the provided
// gitignore patterns. It supports basic gitignore semantics:
//   - Exact name matches (e.g. "node_modules")
//   - Wildcard patterns via filepath.Match (e.g. "*.log")
//   - Directory-only patterns ending with "/" (e.g. "vendor/")
//   - Negation patterns prefixed with "!" that un-ignore a path
//
// The .git directory is always ignored regardless of patterns.
func IsIgnored(path string, patterns []string) bool {
	// .git is always ignored.
	if isGitPath(path) {
		return true
	}

	ignored := false
	for _, pattern := range patterns {
		neg := false
		p := pattern

		// Handle negation.
		if strings.HasPrefix(p, "!") {
			neg = true
			p = strings.TrimPrefix(p, "!")
		}

		if matchPattern(path, p) {
			ignored = !neg
		}
	}

	return ignored
}

// isGitPath reports whether path is inside the .git directory.
func isGitPath(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		if part == ".git" {
			return true
		}
	}
	return false
}

// matchPattern checks whether a relative path matches a single gitignore
// pattern. It handles directory patterns (trailing /) and wildcards.
func matchPattern(path, pattern string) bool {
	// Normalise to forward slashes for consistent matching.
	path = filepath.ToSlash(path)
	pattern = filepath.ToSlash(pattern)

	dirOnly := strings.HasSuffix(pattern, "/")
	if dirOnly {
		pattern = strings.TrimSuffix(pattern, "/")
	}

	// Split path into components to allow matching against any segment.
	parts := strings.Split(path, "/")

	// Handle root-anchored patterns (leading "/").
	// In gitignore, "/foo" means "match foo only at the repo root".
	if strings.HasPrefix(pattern, "/") {
		pattern = strings.TrimPrefix(pattern, "/")
		if dirOnly {
			return strings.HasPrefix(path, pattern+"/") || path == pattern
		}
		matched, _ := filepath.Match(pattern, path)
		return matched
	}

	// If the pattern contains a slash it must match from the repo root.
	if strings.Contains(pattern, "/") {
		if dirOnly {
			// Must match a prefix of the path.
			return strings.HasPrefix(path, pattern+"/") || path == pattern
		}
		matched, _ := filepath.Match(pattern, path)
		return matched
	}

	// Pattern without slash: match against any path component.
	for i, part := range parts {
		matched, _ := filepath.Match(pattern, part)
		if !matched {
			continue
		}
		// If the pattern is directory-only, only match if this component
		// is not the final segment (i.e. something comes after it).
		if dirOnly && i == len(parts)-1 {
			continue
		}
		return true
	}

	return false
}
