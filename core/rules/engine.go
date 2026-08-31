package rules

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

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
// supplied path using filepath.Match semantics. Binary files (containing null
// bytes in the first 512 bytes) are skipped to avoid false positives from
// compiled binaries that embed rule patterns.
func (e *Engine) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	if isBinary(content) {
		return nil, nil
	}

	var out []findings.Finding

	// Pre-compute a lowercase copy of content for keyword filtering.
	var contentLower []byte
	// Lazily split lines for the comment / context precision filters.
	var lines []string
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
			// Post-match predicate: the rule inspects its own match text and
			// vetoes it. Runs before the line-windowed filters because it is
			// the cheapest of the three and needs no line splitting.
			if rule.ValidateMatch != nil && !rule.ValidateMatch(mr.MatchText) {
				continue
			}

			// Precision filters: drop matches in comments or defensive
			// contexts when the rule opts in. Lines are computed lazily.
			if rule.IgnoreInComments || len(rule.ExcludeContextKeywords) > 0 ||
				len(rule.RequireContextKeywords) > 0 {
				if lines == nil {
					lines = splitLines(content)
				}
				if rule.IgnoreInComments && lineIsComment(lines, mr.Line) {
					continue
				}
				if len(rule.ExcludeContextKeywords) > 0 &&
					codeContextHasKeyword(lines, mr.Line, contextWindow, rule.ExcludeContextKeywords) {
					continue
				}
				// Positive context requirement: the vendor name must be near
				// the match, not merely somewhere in the file.
				if len(rule.RequireContextKeywords) > 0 &&
					!contextHasKeyword(lines, mr.Line, contextWindow, rule.RequireContextKeywords) {
					continue
				}
			}

			loc := findings.Location{
				FilePath:    path,
				StartLine:   mr.Line,
				EndLine:     mr.Line,
				StartColumn: mr.Column,
				EndColumn:   mr.Column + len(mr.MatchText),
			}

			f := findings.Finding{
				RuleID:     rule.ID,
				Severity:   rule.Severity,
				Confidence: rule.Confidence,
				Location:   loc,
				Message:    rule.Description,
				// Per-finding copy, never the rule's shared map. Downstream
				// passes write per-finding keys (GHA context, the
				// original-severity downgrade trail), and assigning
				// rule.Metadata directly meant one finding's write mutated the
				// single shared instance and contaminated every other finding
				// of the same rule — including findings in unrelated files.
				Metadata: copyMetadata(rule.Metadata),
			}
			// A structural result was decided by PARSING the document, not by
			// matching text against a span. That difference is the whole
			// reason the structural path exists, so it travels with the
			// finding: the rule engine has no reasoning store and must not
			// grow one, and the analyzer that owns the evidence seam turns
			// this sentence into a deterministic claim.
			if mr.Structural != "" {
				if f.Metadata == nil {
					f.Metadata = map[string]string{}
				}
				f.Metadata[StructuralClaimKey] = mr.Structural
			}
			// Fingerprint is computed by FindingSet.Add, but we also set it
			// here so callers who do not use FindingSet still get a stable
			// fingerprint.
			f.Fingerprint = findings.ComputeFingerprint(f.RuleID, f.Location, mr.MatchText)
			// A rule that absorbed a retired ID also carries that ID's
			// identity here, so waivers written before the retirement keep
			// matching. See RetiredRule.
			if len(rule.Retires) > 0 {
				if lines == nil {
					lines = splitLines(content)
				}
				f.RetiredRuleIDs, f.AliasFingerprints = retiredIdentities(rule, lineAt(lines, mr.Line), f.Location)
			}
			fpShort := f.Fingerprint
			if len(fpShort) > 12 {
				fpShort = fpShort[:12]
			}
			f.ID = f.RuleID + "-" + fpShort

			out = append(out, f)
		}
	}
	return out, nil
}

// contextWindow is the number of lines above and below a match that
// ExcludeContextKeywords inspects for a defensive context.
const contextWindow = 4

// splitLines splits content into lines without a trailing-newline empty entry.
func splitLines(content []byte) []string {
	return strings.Split(string(content), "\n")
}

// lineAt returns the 1-based line, or "" when it is out of range.
func lineAt(lines []string, line1 int) string {
	idx := line1 - 1
	if idx < 0 || idx >= len(lines) {
		return ""
	}
	return lines[idx]
}

// commentPrefixes are the leading tokens that mark a line as a comment across
// the languages nox scans (Go, JS/TS, Python, YAML, shell, C-style).
var commentPrefixes = []string{"//", "#", "*", "/*", "<!--", ";", "--"}

// lineIsComment reports whether the 1-based line is a comment line.
func lineIsComment(lines []string, line1 int) bool {
	idx := line1 - 1
	if idx < 0 || idx >= len(lines) {
		return false
	}
	trimmed := strings.TrimSpace(lines[idx])
	for _, p := range commentPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// copyMetadata returns a shallow copy of a rule's metadata so each finding owns
// its own map. Returns nil for an empty source, matching the previous behaviour
// for rules that carry no metadata.
func copyMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// contextHasKeyword reports whether any keyword appears within ±window lines of
// the 1-based match line. Keywords are matched case-insensitively.
// codeContextHasKeyword is contextHasKeyword restricted to lines that are not
// wholly comments.
//
// Exclusion keywords are evidence that the surrounding CODE is defensive — a
// detector, a corpus, a guardrail. Prose is not that evidence, and honouring it
// gives the scanner a second suppression channel that leaves no trace: no
// nox:ignore, no audit trail, and no "waives X but matched no finding" when it
// goes stale.
//
// Measured on nox's own tree: a comment reading "attack payload, not tool
// metadata" silenced MCP-009 entirely, because its keyword list contains
// "payload". Anyone can disable that rule by writing an ordinary sentence near
// the code, and nothing in the output says so.
//
// Suppression by prose already exists and is audited. It is spelled
// nox:ignore.
func codeContextHasKeyword(lines []string, line1, window int, keywords []string) bool {
	idx := line1 - 1
	start := max(idx-window, 0)
	end := min(idx+window, len(lines)-1)
	for i := start; i <= end; i++ {
		if lineIsComment(lines, i+1) {
			continue
		}
		lower := strings.ToLower(lines[i])
		for _, kw := range keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				return true
			}
		}
	}
	return false
}

func contextHasKeyword(lines []string, line1, window int, keywords []string) bool {
	idx := line1 - 1
	start := max(idx-window, 0)
	end := min(idx+window, len(lines)-1)
	for i := start; i <= end; i++ {
		lower := strings.ToLower(lines[i])
		for _, kw := range keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				return true
			}
		}
	}
	return false
}

// containsAnyKeyword returns true if content contains at least one of the
// keywords. Content must be lowercase; keywords are lowered automatically.
func containsAnyKeyword(contentLower []byte, keywords []string) bool {
	for _, kw := range keywords {
		if bytes.Contains(contentLower, []byte(strings.ToLower(kw))) {
			return true
		}
	}
	return false
}

// fileMatchesRule returns true if the file path matches at least one of the
// rule's FilePatterns (or all files when none are set) AND does not match any
// of the rule's IgnoreFilePatterns. Ignore patterns take precedence over
// allow patterns so well-known noisy files (lockfiles, checksums) can be
// skipped even when the include list otherwise matches.
func fileMatchesRule(path string, rule *Rule) bool {
	base := filepath.Base(path)

	for _, pattern := range rule.IgnoreFilePatterns {
		if matched, _ := filepath.Match(pattern, path); matched {
			return false
		}
		if matched, _ := filepath.Match(pattern, base); matched {
			return false
		}
	}

	if len(rule.FilePatterns) == 0 {
		return true
	}
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

// isBinary reports whether content appears to be a binary file by checking for
// null bytes in the first 512 bytes. Text files (source, config, YAML, JSON)
// do not contain null bytes, so this is a reliable heuristic that prevents
// false positives when scanning compiled binaries that embed rule patterns.
func isBinary(content []byte) bool {
	limit := 512
	if len(content) < limit {
		limit = len(content)
	}
	for _, b := range content[:limit] {
		if b == 0 {
			return true
		}
	}
	return false
}
