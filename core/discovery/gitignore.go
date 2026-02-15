package discovery

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// LoadGitignore reads a .gitignore file from root and returns the parsed
// patterns. If no .gitignore exists, it returns an empty slice and nil error.
func LoadGitignore(root string) ([]string, error) {
	p := filepath.Join(root, ".gitignore")

	patterns, err := loadIgnoreFile(p)
	if err != nil {
		return nil, err
	}

	noxignorePath := filepath.Join(root, ".noxignore")
	noxPatterns, err := loadIgnoreFile(noxignorePath)
	if err != nil {
		return nil, err
	}

	patterns = append(patterns, noxPatterns...)
	return patterns, nil
}

func loadIgnoreFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
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
