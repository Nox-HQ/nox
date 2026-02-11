package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"sync"
)

// MatchResult describes a single match of a rule pattern within file content.
type MatchResult struct {
	Line      int
	Column    int
	MatchText string
}

// Matcher is the interface that all pattern-matching strategies must satisfy.
// Implementations receive raw file content and the triggering rule, and return
// zero or more match results.
type Matcher interface {
	Match(content []byte, rule Rule) []MatchResult
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
func (m *RegexMatcher) Match(content []byte, rule Rule) []MatchResult {
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
	return results
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

func (s *stubMatcher) Match(_ []byte, _ Rule) []MatchResult {
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
