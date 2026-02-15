// Package findings defines the canonical security findings model used across
// all Nox analyzers and reporters. Every scanner produces Finding values
// which are collected into a FindingSet for deduplication, sorting, and
// downstream consumption by report formatters (SARIF, SBOM, etc.).
package findings

import (
	"path/filepath"
	"sort"
	"strings"
)

// Severity indicates how critical a finding is. The values are ordered from
// most to least severe and are compatible with SARIF level mappings.
type Severity string

// Severity level constants ordered from most to least severe.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Status indicates the disposition of a finding relative to baselines and
// inline suppressions.
type Status string

// Finding status values used by the scan pipeline.
const (
	StatusNew                   Status = "new"
	StatusBaselined             Status = "baselined"
	StatusSuppressed            Status = "suppressed"
	StatusVEXNotAffected        Status = "vex_not_affected"
	StatusVEXUnderInvestigation Status = "vex_under_investigation"
	StatusVEXFixed              Status = "vex_fixed"
)

// IsActive returns true if the finding should be reported (not suppressed,
// baselined, or marked not affected/fixed via VEX).
func (s Status) IsActive() bool {
	switch s {
	case StatusSuppressed, StatusBaselined, StatusVEXNotAffected, StatusVEXFixed:
		return false
	}
	return true
}

// Confidence expresses how certain the scanner is that the finding is a true
// positive rather than a false positive.
type Confidence string

// Confidence level constants for finding certainty.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Location pinpoints where a finding was detected within a source file. The
// fields map directly to the SARIF physicalLocation / region model so that
// report generation can consume them without translation.
type Location struct {
	FilePath    string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
}

// Finding is a single security observation produced by an analyzer. It is the
// canonical unit of output for the entire Nox pipeline.
type Finding struct {
	ID          string
	RuleID      string
	Severity    Severity
	Confidence  Confidence
	Location    Location
	Message     string
	Fingerprint string
	Metadata    map[string]string
	Status      Status `json:"Status,omitempty"`
}

// FindingSet is an ordered, deduplicated collection of findings. It is the
// primary data structure passed between pipeline stages.
type FindingSet struct {
	items []Finding
}

// NewFindingSet returns an empty FindingSet ready for use.
func NewFindingSet() *FindingSet {
	return &FindingSet{}
}

// Add appends a finding to the set. If the finding has an empty Fingerprint,
// one is computed automatically from RuleID, Location, and Message so that
// every finding in the set is always fingerprintable.
//
//nolint:gocritic // Findings are passed by value throughout the pipeline for simplicity.
func (fs *FindingSet) Add(f Finding) {
	if f.Fingerprint == "" {
		f.Fingerprint = ComputeFingerprint(f.RuleID, f.Location, f.Message)
	}
	fs.items = append(fs.items, f)
}

// Deduplicate removes findings that share the same Fingerprint, keeping only
// the first occurrence. Call this after all findings have been added and before
// producing output.
func (fs *FindingSet) Deduplicate() {
	seen := make(map[string]struct{}, len(fs.items))
	unique := make([]Finding, 0, len(fs.items))
	for i := range fs.items {
		finding := fs.items[i]
		if _, exists := seen[finding.Fingerprint]; exists {
			continue
		}
		seen[finding.Fingerprint] = struct{}{}
		unique = append(unique, finding)
	}
	fs.items = unique
}

// SortDeterministic orders findings by RuleID, then FilePath, then StartLine.
// This guarantees stable, reproducible output regardless of the order in which
// analyzers emit their results.
func (fs *FindingSet) SortDeterministic() {
	sort.Slice(fs.items, func(i, j int) bool {
		a, b := fs.items[i], fs.items[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Location.FilePath != b.Location.FilePath {
			return a.Location.FilePath < b.Location.FilePath
		}
		return a.Location.StartLine < b.Location.StartLine
	})
}

// RemoveByRuleIDs removes all findings whose RuleID matches any of the given IDs.
func (fs *FindingSet) RemoveByRuleIDs(ids []string) {
	if len(ids) == 0 {
		return
	}
	disabled := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		disabled[id] = struct{}{}
	}
	kept := make([]Finding, 0, len(fs.items))
	for i := range fs.items {
		finding := fs.items[i]
		if _, skip := disabled[finding.RuleID]; !skip {
			kept = append(kept, finding)
		}
	}
	fs.items = kept
}

// OverrideSeverity changes the severity for all findings with the given rule ID.
func (fs *FindingSet) OverrideSeverity(ruleID string, severity Severity) {
	for i := range fs.items {
		if fs.items[i].RuleID == ruleID {
			fs.items[i].Severity = severity
		}
	}
}

// SetStatus sets the status of the finding at the given index.
func (fs *FindingSet) SetStatus(i int, s Status) {
	if i >= 0 && i < len(fs.items) {
		fs.items[i].Status = s
	}
}

// CountByStatus returns a count of findings grouped by status.
// Findings with an empty status are counted under StatusNew.
func (fs *FindingSet) CountByStatus() map[Status]int {
	counts := make(map[Status]int)
	for i := range fs.items {
		finding := fs.items[i]
		s := finding.Status
		if s == "" {
			s = StatusNew
		}
		counts[s]++
	}
	return counts
}

// ActiveFindings returns findings that are not suppressed, baselined, or VEX-excluded.
func (fs *FindingSet) ActiveFindings() []Finding {
	var active []Finding
	for i := range fs.items {
		finding := fs.items[i]
		if !finding.Status.IsActive() {
			continue
		}
		active = append(active, finding)
	}
	return active
}

// Findings returns the current slice of findings. The caller must not modify
// the returned slice.
func (fs *FindingSet) Findings() []Finding {
	return fs.items
}

// RemoveByRuleIDsAndPaths removes findings that match both the given rule IDs
// AND any of the given path patterns. This enables granular exclusion based on
// rule + path combinations (e.g., disable VULN rules only for node_modules).
func (fs *FindingSet) RemoveByRuleIDsAndPaths(ruleIDs, paths []string) {
	if len(ruleIDs) == 0 && len(paths) == 0 {
		return
	}
	ruleSet := make(map[string]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		ruleSet[id] = struct{}{}
	}
	kept := make([]Finding, 0, len(fs.items))
	for i := range fs.items {
		finding := fs.items[i]
		skipRule := false
		if len(ruleIDs) > 0 {
			_, skipRule = ruleSet[finding.RuleID]
		}
		skipPath := false
		if len(paths) > 0 {
			skipPath = matchAnyPattern(finding.Location.FilePath, paths)
		}
		// Keep if EITHER rule or path doesn't match the exclusion criteria.
		// Skip only if BOTH rule and path match (both are true).
		if !skipRule || !skipPath {
			kept = append(kept, finding)
		}
	}
	fs.items = kept
}

func matchAnyPattern(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
		if strings.HasPrefix(pattern, "*") {
			rest := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(path, rest) || strings.HasSuffix(filepath.Base(path), rest) {
				return true
			}
		}
		if matchPathPattern(path, pattern) {
			return true
		}
	}
	return false
}

func matchPathPattern(path, pattern string) bool {
	pathParts := strings.Split(path, "/")
	patternParts := strings.Split(pattern, "/")

	if len(patternParts) > len(pathParts) {
		return false
	}

	for i, part := range patternParts {
		if part == "*" || part == "**" {
			continue
		}
		if i >= len(pathParts) {
			return false
		}
		if matched, _ := filepath.Match(part, pathParts[i]); !matched {
			return false
		}
	}
	return true
}

// OverrideSeverityByRuleIDAndPath changes the severity of findings that match
// both the given rule ID and path pattern.
func (fs *FindingSet) OverrideSeverityByRuleIDAndPath(ruleID, pathPattern string, severity Severity) {
	for i := range fs.items {
		finding := &fs.items[i]
		if finding.RuleID == ruleID && matchAnyPattern(finding.Location.FilePath, []string{pathPattern}) {
			finding.Severity = severity
		}
	}
}

// OverrideSeverityByRulePatternsAndPaths changes the severity of findings that match
// any of the given rule patterns (with wildcard support) AND any of the given path patterns.
// This enables conditional severity overrides (e.g., downgrade all VULN-* findings in node_modules to info). // nox:ignore SEC-659 -- false positive: "Split" in function name
func (fs *FindingSet) OverrideSeverityByRulePatternsAndPaths(rulePatterns, pathPatterns []string, severity Severity) {
	for i := range fs.items {
		finding := &fs.items[i]
		if matchRulePatterns(finding.RuleID, rulePatterns) && matchAnyPattern(finding.Location.FilePath, pathPatterns) {
			finding.Severity = severity
		}
	}
}

func matchRulePatterns(ruleID string, patterns []string) bool {
	for _, pattern := range patterns {
		if ruleID == pattern {
			return true
		}
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			mid := strings.TrimSuffix(strings.TrimPrefix(pattern, "*"), "*")
			if strings.Contains(ruleID, mid) {
				return true
			}
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(ruleID, prefix) {
				return true
			}
		}
	}
	return false
}
