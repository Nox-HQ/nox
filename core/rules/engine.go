package rules

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/nox-hq/nox/core/findings"
)

// Engine ties a RuleSet and a MatcherRegistry together to scan file content
// and produce findings.
type Engine struct {
	rules    *RuleSet
	matchers *MatcherRegistry
}

// NewEngine creates an Engine with the given rules and the default matcher
// registry.
func NewEngine(rules *RuleSet) *Engine {
	return &Engine{
		rules:    rules,
		matchers: NewDefaultMatcherRegistry(),
	}
}

// Rules returns the engine's RuleSet.
func (e *Engine) Rules() *RuleSet { return e.rules }

// ScanFile runs every applicable rule against the given file content and
// returns the resulting findings. A rule applies if its FilePatterns list is
// empty (matches everything) or if at least one of its patterns matches the
// supplied path using filepath.Match semantics.
func (e *Engine) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	var out []findings.Finding

	// Pre-compute a lowercase copy of content for keyword filtering.
	var contentLower []byte
	for _, rule := range e.rules.Rules() {
		if !fileMatchesRule(path, rule) {
			continue
		}

		if len(rule.Keywords) > 0 {
			if contentLower == nil {
				contentLower = bytes.ToLower(content)
			}
			if !containsAnyKeyword(contentLower, rule.Keywords) {
				continue
			}
		}

		matcher := e.matchers.Get(rule.MatcherType)
		if matcher == nil {
			return nil, fmt.Errorf("no matcher registered for type %q (rule %s)", rule.MatcherType, rule.ID)
		}

		results := matcher.Match(content, rule)
		for _, mr := range results {
			loc := findings.Location{
				FilePath:    path,
				StartLine:   mr.Line,
				EndLine:     mr.Line,
				StartColumn: mr.Column,
				EndColumn:   mr.Column + len(mr.MatchText),
			}

			f := findings.Finding{
				ID:         fmt.Sprintf("%s:%s:%d", rule.ID, path, mr.Line),
				RuleID:     rule.ID,
				Severity:   rule.Severity,
				Confidence: rule.Confidence,
				Location:   loc,
				Message:    rule.Description,
				Metadata:   rule.Metadata,
			}
			// Fingerprint is computed by FindingSet.Add, but we also set it
			// here so callers who do not use FindingSet still get a stable
			// fingerprint.
			f.Fingerprint = findings.ComputeFingerprint(f.RuleID, f.Location, mr.MatchText)

			out = append(out, f)
		}
	}
	return out, nil
}

// containsAnyKeyword returns true if content contains at least one of the
// keywords. Both content and keywords must be lowercase.
func containsAnyKeyword(contentLower []byte, keywords []string) bool {
	for _, kw := range keywords {
		if bytes.Contains(contentLower, []byte(kw)) {
			return true
		}
	}
	return false
}

// fileMatchesRule returns true if the file path matches at least one of the
// rule's FilePatterns, or if the rule has no file patterns (applies to all
// files).
func fileMatchesRule(path string, rule Rule) bool {
	if len(rule.FilePatterns) == 0 {
		return true
	}
	// Match against both the full path and the base name so that patterns
	// like "*.go" work as expected even when path contains directories.
	base := filepath.Base(path)
	for _, pattern := range rule.FilePatterns {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}
	return false
}
