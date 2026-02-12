// Package deps — malicious package detection for dependency scanning.
//
// This file implements typosquatting detection (comparing package names against
// a curated list of popular packages) and known-malicious package lookup. Both
// checks are driven by embedded data files that ship with the Nox binary,
// keeping the scanner fully offline-capable.
package deps

import (
	"embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed data/popular_npm.txt data/popular_pypi.txt data/known_malicious.json
var dataFS embed.FS

// popularPackages holds lazy-loaded popular package names per ecosystem.
var (
	popularOnce sync.Once
	popularPkgs map[string][]string // ecosystem → list of names
)

// maliciousPackages holds lazy-loaded known malicious package names per ecosystem.
var (
	maliciousOnce sync.Once
	maliciousPkgs map[string]map[string]struct{} // ecosystem → set of names
)

// loadPopular reads the embedded popular package lists. It is called exactly
// once via sync.Once to avoid repeated file I/O.
func loadPopular() {
	popularPkgs = make(map[string][]string)

	files := map[string]string{
		"npm":  "data/popular_npm.txt",
		"pypi": "data/popular_pypi.txt",
	}

	for eco, path := range files {
		data, err := dataFS.ReadFile(path)
		if err != nil {
			continue
		}
		var names []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			names = append(names, line)
		}
		popularPkgs[eco] = names
	}
}

// loadMalicious reads the embedded known malicious package list. It is called
// exactly once via sync.Once to avoid repeated file I/O and JSON parsing.
func loadMalicious() {
	maliciousPkgs = make(map[string]map[string]struct{})

	data, err := dataFS.ReadFile("data/known_malicious.json")
	if err != nil {
		return
	}

	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	for eco, names := range raw {
		set := make(map[string]struct{}, len(names))
		for _, n := range names {
			set[strings.ToLower(n)] = struct{}{}
		}
		maliciousPkgs[eco] = set
	}
}

// LevenshteinDistance computes the edit distance between two strings using the
// standard dynamic-programming algorithm. The edit distance is the minimum
// number of single-character insertions, deletions, or substitutions required
// to transform string a into string b.
func LevenshteinDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use a single row and reuse it to reduce memory from O(m*n) to O(min(m,n)).
	if la < lb {
		a, b = b, a
		la, lb = lb, la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost

			minVal := del
			if ins < minVal {
				minVal = ins
			}
			if sub < minVal {
				minVal = sub
			}
			curr[j] = minVal
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

// DetectTyposquatting checks if a package name is suspiciously similar to a
// popular package in the given ecosystem. It returns the name of the popular
// package and true if a potential typosquat is detected.
//
// An exact match (the package IS the popular package) returns ("", false)
// because the real package is not a typosquat. Only supported ecosystems
// (npm, pypi) are checked; all others return ("", false).
//
// The threshold parameter controls the maximum Levenshtein distance that is
// still considered suspicious. A value of 2 is recommended for general use.
func DetectTyposquatting(name, ecosystem string, threshold int) (string, bool) {
	popularOnce.Do(loadPopular)

	names, ok := popularPkgs[ecosystem]
	if !ok {
		return "", false
	}

	lowerName := strings.ToLower(name)

	for _, popular := range names {
		lowerPopular := strings.ToLower(popular)

		// Exact match — not a typosquat, it is the real package.
		if lowerName == lowerPopular {
			return "", false
		}

		dist := LevenshteinDistance(lowerName, lowerPopular)
		if dist > 0 && dist <= threshold {
			return popular, true
		}
	}

	return "", false
}

// IsKnownMalicious checks if a package with the given name and ecosystem
// appears in the curated list of known malicious packages. Matching is
// case-insensitive.
func IsKnownMalicious(name, ecosystem string) bool {
	maliciousOnce.Do(loadMalicious)

	set, ok := maliciousPkgs[ecosystem]
	if !ok {
		return false
	}

	_, found := set[strings.ToLower(name)]
	return found
}
