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
	for _, f := range fs.items {
		if _, exists := seen[f.Fingerprint]; exists {
			continue
		}
		seen[f.Fingerprint] = struct{}{}
		unique = append(unique, f)
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

// Findings returns the current slice of findings. The caller must not modify
// the returned slice.
func (fs *FindingSet) Findings() []Finding {
	return fs.items
}
