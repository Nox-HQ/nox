package reasoning

import (
	"strings"

	"github.com/nox-hq/nox-core/evidence"
)

// ObservationKind classifies how a rule established its match, so a synthesised
// claim carries the strength the rule actually earned rather than a uniform
// guess.
//
// The three answers are taken from the kernel's own definitions of the kinds,
// not invented here:
//
//   - KindStatic is documented as "deterministic static analysis established it
//     (a taint path, a resolved version range)". TAINT-* rules come from the
//     dataflow engine and VULN-* from a resolved version match, so both are
//     exactly the two examples that definition names.
//   - KindHeuristic is documented as "a pattern matched. The weakest claim nox
//     makes." Every other family is a regex over bytes, so that is what they
//     are, whatever confidence the analyzer attached.
//
// The default is the weaker kind, deliberately. Under-claiming a rule's
// strength costs a promotion that a later refinement can restore;
// over-claiming it puts weight behind a pattern match that nothing checked,
// which is the failure the strength ladder exists to prevent.
func ObservationKind(ruleID string) evidence.Kind {
	switch {
	case strings.HasPrefix(ruleID, "TAINT-"), strings.HasPrefix(ruleID, "VULN-"):
		return evidence.KindStatic
	default:
		return evidence.KindHeuristic
	}
}

// Observed records the claim that a rule matched — the supporting half of a
// candidate's ledger, opposite the refutations the refiners file against it.
//
// analyzerConfidence is the analyzer's own high|medium|low label. It is carried
// as an attribute rather than folded into the kind, because the two are
// different assertions and C5 retires one of them: the kind says how the claim
// was established, the label says how sure its author felt. Keeping the label
// as data is what lets a later stage compare the two and find where they
// disagree; folding it in now would destroy the comparison before it could be
// made.
//
// One thing this deliberately does NOT do: a VULN finding backed by an OSV
// advisory is not recorded as KindPublicAdvisory. The advisory is evidence
// about a PACKAGE, and this claim is about a CANDIDATE — attaching an
// advisory's authority to a finding's subject is precisely the cross-subject
// aggregation typed subjects exist to prevent. The package subject and its
// advisory claim belong to Track G.
func (s *Store) Observed(subject evidence.Subject, ruleID, analyzerConfidence, tool string) {
	var attrs map[string]string
	if analyzerConfidence != "" {
		attrs = map[string]string{"analyzer_confidence": analyzerConfidence}
	}
	s.Support(subject, ObservationKind(ruleID), "nox-scan", tool,
		"rule "+ruleID+" matched at this location", attrs)
}
