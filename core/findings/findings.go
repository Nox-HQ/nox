// Package findings defines the canonical security findings model used across
// all Nox analyzers and reporters. Every scanner produces Finding values
// which are collected into a FindingSet for deduplication, sorting, and
// downstream consumption by report formatters (SARIF, SBOM, etc.).
package findings

import (
	"sort"
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
		switch finding.Status {
		case StatusSuppressed, StatusBaselined, StatusVEXNotAffected, StatusVEXFixed:
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
