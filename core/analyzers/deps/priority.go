package deps

import (
	"strconv"

	"github.com/nox-hq/nox-core/vulnsource"
)

// addPriorityMetadata records NOX Intelligence's ranking of the advisory
// (nox_priority) on the finding: the score, the rule and band that decided it,
// the reason, and the EPSS inputs, so a report re-renders the same ordering and
// a reader can see why. A ranking of the advisory, not of this application's
// exposure to it, and never a reason to hide or demote a finding.
func addPriorityMetadata(meta map[string]string, r *vulnsource.Record) {
	p := r.Priority
	if p == nil || p.Rule == "" {
		return
	}
	meta["priority_score"] = strconv.FormatFloat(p.Score, 'g', -1, 64)
	meta["priority_rule"] = p.Rule
	meta["priority_band"] = p.Band
	if p.Why != "" {
		meta["priority_why"] = p.Why
	}
	if p.EPSS != nil {
		meta["priority_epss"] = strconv.FormatFloat(*p.EPSS, 'g', -1, 64)
	}
	if p.EPSSPercentile != nil {
		meta["priority_epss_percentile"] = strconv.FormatFloat(*p.EPSSPercentile, 'g', -1, 64)
	}
}
