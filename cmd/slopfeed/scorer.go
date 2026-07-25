package main

import (
	"fmt"
	"math"

	"github.com/nox-hq/nox/core/analyzers/slop/feed"
)

// neighbourBoost lifts the risk of names that are also classic typosquat lures
// (likely-emitted AND a lure). Composition names get no boost.
func neighbourBoost(prior float64, pattern string) float64 {
	switch pattern {
	case "typo":
		return math.Min(1.0, prior+0.08)
	case "obvious":
		return math.Min(1.0, prior+0.04)
	default:
		return prior
	}
}

// tierFor buckets a risk score. A score below 0.50 is not high-likelihood
// enough to assert as a predictive target and is dropped by the caller.
func tierFor(score float64) string {
	switch {
	case score >= 0.80:
		return feed.TierCritical
	case score >= 0.65:
		return feed.TierHigh
	case score >= 0.50:
		return feed.TierMedium
	default:
		return ""
	}
}

// scoreSquattable turns a candidate that was re-verified UNREGISTERED into a
// feed entry. It returns ok=false for anything that must not be written: a
// candidate that is not unregistered (never accuse a registered package) or one
// whose risk falls below the medium tier. verifiedAt is the date the 404 was
// confirmed (stamped into the entry so the claim is time-bound and honest).
func scoreSquattable(c candidate, r checkResult, verifiedAt string) (feed.Entry, bool) {
	if r.verdict != unregistered {
		return feed.Entry{}, false
	}
	risk := round3(neighbourBoost(c.prior, c.pattern))
	tier := tierFor(risk)
	if tier == "" {
		return feed.Entry{}, false
	}
	reason := fmt.Sprintf(
		"UNREGISTERED (404 confirmed twice on %s) and matches a high-likelihood "+
			"hallucination pattern [%s]: %s. An attacker could register this name "+
			"today and capture installs of hallucinated `%s`.",
		verifiedAt, c.pattern, c.reason, c.name,
	)
	return feed.Entry{
		Name:       c.name,
		Ecosystem:  c.ecosystem,
		Pattern:    c.pattern,
		NeighborOf: c.neighborOf,
		Risk:       risk,
		Tier:       tier,
		Reason:     reason,
		VerifiedAt: verifiedAt,
	}, true
}
