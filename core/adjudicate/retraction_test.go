package adjudicate_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/adjudicate"
)

// retracted returns a claim that has been withdrawn.
func retracted(c evidence.Claim) evidence.Claim {
	c.Status = evidence.StatusRetracted
	return c
}

// Milestone 3.4: a withdrawn claim stops contributing.
//
// The lifecycle ships in the kernel and the intel path honours it. What was
// never asserted is that the SCAN path does — that a claim retracted after it
// was filed stops moving the verdict rather than merely being labelled.
//
// The distinction matters because a retraction is the mechanism by which a
// mistake gets corrected: an advisory withdrawn, a producer disavowing an
// observation. A ledger that renders "withdrawn" while still counting the claim
// has recorded the correction and ignored it.
func TestARetractedClaimStopsContributing(t *testing.T) {
	strong := supporting(evidence.KindPublicAdvisory, "an advisory affects this")

	var live evidence.Ledger
	live.Add(strong)
	liveConfidence := adjudicate.Adjudicate(live, candidate).Confidence

	var withdrawn evidence.Ledger
	withdrawn.Add(retracted(strong))
	withdrawnConfidence := adjudicate.Adjudicate(withdrawn, candidate).Confidence

	if liveConfidence == withdrawnConfidence {
		t.Errorf("a retracted advisory produced the same confidence as a live one (%s). "+
			"A retraction is how a mistake gets corrected; a ledger that records the "+
			"correction and still counts the claim has ignored it.", liveConfidence)
	}
}

// The rationale never cites a claim that carries no weight.
//
// A LOW verdict justified by "the exploit reproduced under the determinism
// gate" — retracted, weighing nothing — reads as a bug in the verdict, and the
// reader cannot tell which half to believe.
func TestTheRationaleNeverCitesARetractedClaim(t *testing.T) {
	var l evidence.Ledger
	l.Add(retracted(supporting(evidence.KindControlledReproduction,
		"the exploit reproduced under the determinism gate")))
	l.Add(supporting(evidence.KindHeuristic, "a pattern matched"))

	rationale := adjudicate.Adjudicate(l, candidate).Rationale
	if strings.Contains(rationale, "reproduced under the determinism gate") {
		t.Errorf("the rationale cites a retracted claim: %q", rationale)
	}
	if !strings.Contains(rationale, "a pattern matched") {
		t.Errorf("the rationale does not name the claim that actually carried the "+
			"verdict: %q", rationale)
	}
}

// A retracted REFUTATION also stops contributing, so withdrawing a refutation
// restores the finding rather than leaving it suppressed by an argument nobody
// stands behind any more.
func TestARetractedRefutationStopsSuppressing(t *testing.T) {
	support := supporting(evidence.KindStatic, "the value has the shape of a live token")

	var withRefutation evidence.Ledger
	withRefutation.Add(support)
	withRefutation.Add(refuting(evidence.KindStatic, "the value is a documented placeholder"))

	var refutationWithdrawn evidence.Ledger
	refutationWithdrawn.Add(support)
	refutationWithdrawn.Add(retracted(refuting(evidence.KindStatic,
		"the value is a documented placeholder")))

	a := adjudicate.Adjudicate(withRefutation, candidate)
	b := adjudicate.Adjudicate(refutationWithdrawn, candidate)
	if a.Confidence == b.Confidence && a.Conflicted == b.Conflicted {
		t.Errorf("withdrawing a refutation changed nothing (confidence %s, conflicted %v "+
			"both ways). A refutation nobody stands behind any more must stop "+
			"suppressing.", a.Confidence, a.Conflicted)
	}
}
