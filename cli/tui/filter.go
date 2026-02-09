package tui

import (
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// severityOrder defines the cycle order for the severity filter toggle.
var severityOrder = []findings.Severity{
	findings.SeverityCritical,
	findings.SeverityHigh,
	findings.SeverityMedium,
	findings.SeverityLow,
	findings.SeverityInfo,
}

// filterState tracks the active filter configuration.
type filterState struct {
	severityIdx int    // -1 = all, 0..4 = specific severity
	search      string // free-text search query
	searching   bool   // true when search input is active
}

func newFilterState() filterState {
	return filterState{severityIdx: -1}
}

// cycleSeverity advances the severity filter to the next level.
func (f *filterState) cycleSeverity() {
	f.severityIdx++
	if f.severityIdx >= len(severityOrder) {
		f.severityIdx = -1
	}
}

// activeSeverity returns the current severity filter, or empty string for "all".
func (f *filterState) activeSeverity() string {
	if f.severityIdx < 0 {
		return "all"
	}
	return string(severityOrder[f.severityIdx])
}

// matchesFinding returns true if the finding passes all active filters.
func (f *filterState) matchesFinding(finding findings.Finding) bool {
	// Severity filter.
	if f.severityIdx >= 0 {
		if finding.Severity != severityOrder[f.severityIdx] {
			return false
		}
	}

	// Search filter.
	if f.search != "" {
		q := strings.ToLower(f.search)
		if !strings.Contains(strings.ToLower(finding.RuleID), q) &&
			!strings.Contains(strings.ToLower(finding.Location.FilePath), q) &&
			!strings.Contains(strings.ToLower(finding.Message), q) &&
			!strings.Contains(strings.ToLower(finding.ID), q) {
			return false
		}
	}

	return true
}

// filterFindings returns findings that pass the active filters.
func (f *filterState) filterFindings(all []findings.Finding) []findings.Finding {
	var result []findings.Finding
	for _, finding := range all {
		if f.matchesFinding(finding) {
			result = append(result, finding)
		}
	}
	return result
}
