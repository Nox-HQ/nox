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
	"fmt"
	"strings"
	"sync"
)

//go:embed data/popular_npm.txt data/popular_pypi.txt data/known_malicious.json
var dataFS embed.FS

// dataLoadErrs records embedded-dataset load failures.
//
// These datasets drive typosquatting and known-malicious-package detection. If
// one fails to load, the corresponding check returns no findings and the scan
// reports success — for a supply-chain scanner, the worst possible silent
// failure: the check that exists to catch active attacks says "clean" when it
// never loaded its data. Writes happen inside sync.Once, reads after it.
var dataLoadErrs []string

// dataLoadFailures returns the embedded-dataset load failures seen so far.
// Callers must have triggered the relevant sync.Once first.
func dataLoadFailures() []string {
	out := make([]string, len(dataLoadErrs))
	copy(out, dataLoadErrs)
	return out
}

// popularPackages holds lazy-loaded popular package names per ecosystem.
var (
	popularOnce sync.Once
	popularPkgs map[string][]string // ecosystem → list of names
	// popularSet is the same data as a normalized membership set per ecosystem,
	// so DetectTyposquatting can answer "is this name itself a popular package?"
	// in O(1) BEFORE doing any distance comparison.
	popularSet map[string]map[string]struct{}
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
	popularSet = make(map[string]map[string]struct{})

	files := map[string]string{
		"npm":  "data/popular_npm.txt",
		"pypi": "data/popular_pypi.txt",
	}

	for eco, path := range files {
		data, err := dataFS.ReadFile(path)
		if err != nil {
			dataLoadErrs = append(dataLoadErrs,
				fmt.Sprintf("popular-package list for %s (%s) could not be read: %v", eco, path, err))
			continue
		}
		var names []string
		set := make(map[string]struct{})
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			names = append(names, line)
			set[normalizeDistName(line)] = struct{}{}
		}
		popularPkgs[eco] = names
		popularSet[eco] = set
	}
}

// loadMalicious reads the embedded known malicious package list. It is called
// exactly once via sync.Once to avoid repeated file I/O and JSON parsing.
func loadMalicious() {
	maliciousPkgs = make(map[string]map[string]struct{})

	data, err := dataFS.ReadFile("data/known_malicious.json")
	if err != nil {
		dataLoadErrs = append(dataLoadErrs,
			fmt.Sprintf("known-malicious package list could not be read: %v", err))
		return
	}

	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		dataLoadErrs = append(dataLoadErrs,
			fmt.Sprintf("known-malicious package list could not be parsed: %v", err))
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
// still considered suspicious. A value of 2 is recommended for general use; it
// is automatically tightened to 1 for short names (see below).
func DetectTyposquatting(name, ecosystem string, threshold int) (string, bool) {
	popularOnce.Do(loadPopular)

	names, ok := popularPkgs[ecosystem]
	if !ok {
		return "", false
	}

	lowerName := normalizeDistName(name)

	// Exact match FIRST: if the package IS itself a popular package, it is not a
	// typosquat — regardless of how close some OTHER popular name happens to be.
	// Checking this only inside the distance loop (as before) was order-
	// dependent: "vue" would match "vuex" at distance 1 and be flagged before
	// the loop ever reached the exact "vue" entry. This false-positived every
	// popular package with a near neighbour (vue, zod, ms, ajv, …).
	if set, ok := popularSet[ecosystem]; ok {
		if _, isPopular := set[lowerName]; isPopular {
			return "", false
		}
	}

	// Short names have many spurious neighbours at distance 2 (e.g. "abc" is
	// distance 2 from hundreds of three-letter names). Require an exact single-
	// character typo for short names to keep precision high.
	effThreshold := threshold
	if len(lowerName) <= 4 && effThreshold > 1 {
		effThreshold = 1
	}

	for _, popular := range names {
		lowerPopular := normalizeDistName(popular)
		if lowerName == lowerPopular {
			continue
		}
		dist := LevenshteinDistance(lowerName, lowerPopular)
		if dist > 0 && dist <= effThreshold {
			return popular, true
		}
	}

	return "", false
}

// normalizeDistName canonicalizes a distribution name per PEP 503: lowercase
// and collapse any run of "-", "_", or "." to a single "-". This makes
// equivalent spellings (huggingface_hub, huggingface-hub) compare equal.
func normalizeDistName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	prevSep := false
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return strings.Trim(b.String(), "-")
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
