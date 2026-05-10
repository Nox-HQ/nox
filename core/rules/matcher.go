package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// MatchResult describes a single match of a rule pattern within file content.
type MatchResult struct {
	Line      int
	Column    int
	MatchText string
}

// Matcher is the interface that all pattern-matching strategies must satisfy.
// Implementations receive raw file content and a pointer to the triggering
// rule, and return zero or more match results.
type Matcher interface {
	Match(content []byte, rule *Rule) []MatchResult
}

// RegexMatcher implements Matcher using compiled regular expressions. It
// caches compiled patterns to avoid redundant compilation across calls.
type RegexMatcher struct {
	mu    sync.Mutex
	cache map[string]*regexp.Regexp
}

// NewRegexMatcher returns a RegexMatcher with an initialised pattern cache.
func NewRegexMatcher() *RegexMatcher {
	return &RegexMatcher{
		cache: make(map[string]*regexp.Regexp),
	}
}

// compile returns a compiled regexp for the given pattern, using the cache
// when possible.
func (m *RegexMatcher) compile(pattern string) (*regexp.Regexp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if re, ok := m.cache[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compiling pattern %q: %w", pattern, err)
	}
	m.cache[pattern] = re
	return re, nil
}

// Match finds all occurrences of the rule pattern in content and returns
// their positions as MatchResult values with 1-based line and column numbers.
// When rule.Metadata["secret_shape"] == "true", matches are post-filtered to
// require a secret-shaped value: minimum Shannon entropy, restricted charset,
// and rejection of obvious non-secret patterns (camelCase identifiers,
// version strings, file paths, all-lowercase dictionary words). The minimum
// entropy threshold defaults to 3.0 and can be overridden via
// rule.Metadata["min_entropy"].
func (m *RegexMatcher) Match(content []byte, rule *Rule) []MatchResult {
	re, err := m.compile(rule.Pattern)
	if err != nil {
		return nil
	}

	// Pre-compute line start offsets for O(1) line/column lookup.
	lines := bytes.SplitAfter(content, []byte("\n"))
	lineStarts := make([]int, len(lines))
	offset := 0
	for i, line := range lines {
		lineStarts[i] = offset
		offset += len(line)
	}

	matches := re.FindAllIndex(content, -1)
	results := make([]MatchResult, 0, len(matches))

	for _, loc := range matches {
		startOffset := loc[0]
		endOffset := loc[1]

		// Binary search is unnecessary for typical file sizes; a linear scan
		// from the last known position would be faster for sequential matches,
		// but correctness is the priority here.
		line := findLine(lineStarts, startOffset)
		col := startOffset - lineStarts[line] + 1 // 1-based column

		results = append(results, MatchResult{
			Line:      line + 1, // 1-based line number
			Column:    col,
			MatchText: string(content[startOffset:endOffset]),
		})
	}

	if rule.Metadata["secret_shape"] == "true" {
		results = filterBySecretShape(results, rule)
	}
	if rule.Metadata["publisher_allowlist"] != "" {
		results = filterByPublisherAllowlist(results, rule)
	}
	return results
}

// filterByPublisherAllowlist drops matches whose `<publisher>/<name>@<ref>`
// reference belongs to a trusted publisher. Used by IAC-013 to silence
// findings on first-party GitHub actions (actions/*, github/*) that ship
// immutable releases via tagged refs and are managed by Dependabot.
//
// The allowlist is read from rule.Metadata["publisher_allowlist"] as a
// comma-separated list (e.g. "actions,github"). Comparison is case-
// insensitive and ignores surrounding whitespace.
func filterByPublisherAllowlist(in []MatchResult, rule *Rule) []MatchResult {
	raw := rule.Metadata["publisher_allowlist"]
	if raw == "" {
		return in
	}
	allowed := make(map[string]struct{})
	for p := range strings.SplitSeq(raw, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			allowed[p] = struct{}{}
		}
	}
	out := in[:0]
	for _, r := range in {
		pub := extractPublisher(r.MatchText)
		if pub != "" {
			if _, ok := allowed[strings.ToLower(pub)]; ok {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// extractPublisher returns the publisher segment of a `uses: <pub>/<name>@<ref>`
// match text, or "" when the match doesn't follow that shape.
func extractPublisher(text string) string {
	// Strip the `uses:` prefix and surrounding whitespace.
	idx := strings.Index(strings.ToLower(text), "uses:")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(text[idx+len("uses:"):])
	slash := strings.Index(rest, "/")
	if slash <= 0 {
		return ""
	}
	return rest[:slash]
}

// filterBySecretShape rejects matches whose text doesn't look like a real
// secret. Used by vendor-name secret rules with loose regex patterns
// (e.g. `[a-zA-Z0-9]{20}`) that would otherwise fire on identifier
// substrings, README example text, or other non-secret content.
func filterBySecretShape(in []MatchResult, rule *Rule) []MatchResult {
	minEntropy := 3.0
	if v, ok := rule.Metadata["min_entropy"]; ok {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			minEntropy = parsed
		}
	}
	out := in[:0]
	for _, r := range in {
		if !isSecretShape(r.MatchText, minEntropy) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// isSecretShape returns true if text has the entropy/character profile of a
// real secret rather than a code identifier or human-readable string.
func isSecretShape(text string, minEntropy float64) bool {
	if len(text) < 12 {
		return false
	}
	if isLikelyNotSecret(text) {
		return false
	}
	if ShannonEntropy(text) < minEntropy {
		return false
	}
	return true
}

// findLine returns the 0-based line index for the given byte offset using a
// linear scan over the precomputed line start offsets.
func findLine(lineStarts []int, offset int) int {
	for i := len(lineStarts) - 1; i >= 0; i-- {
		if lineStarts[i] <= offset {
			return i
		}
	}
	return 0
}

// stubMatcher is a placeholder for matcher types that are not yet implemented
// (jsonpath, yamlpath, heuristic). It always returns nil.
type stubMatcher struct{}

// Match is a no-op implementation that always returns nil for unimplemented
// matcher types (jsonpath, yamlpath, heuristic).
func (s *stubMatcher) Match(_ []byte, _ *Rule) []MatchResult {
	return nil
}

// MatcherRegistry maps matcher type strings to their Matcher implementations.
type MatcherRegistry struct {
	matchers map[string]Matcher
}

// NewMatcherRegistry returns an empty registry.
func NewMatcherRegistry() *MatcherRegistry {
	return &MatcherRegistry{
		matchers: make(map[string]Matcher),
	}
}

// Register associates a matcher type string with a Matcher implementation.
func (r *MatcherRegistry) Register(matcherType string, m Matcher) {
	r.matchers[matcherType] = m
}

// Get returns the Matcher for the given type string, or nil if none is
// registered.
func (r *MatcherRegistry) Get(matcherType string) Matcher {
	return r.matchers[matcherType]
}

// NewDefaultMatcherRegistry returns a registry pre-populated with the
// built-in matchers: RegexMatcher for "regex" and stubs for the remaining
// types.
func NewDefaultMatcherRegistry() *MatcherRegistry {
	r := NewMatcherRegistry()
	r.Register("regex", NewRegexMatcher())
	r.Register("entropy", &EntropyMatcher{})
	r.Register("jsonpath", &stubMatcher{})
	r.Register("yamlpath", &stubMatcher{})
	r.Register("heuristic", &stubMatcher{})
	return r
}
