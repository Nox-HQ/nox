package intel_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/intel"
)

func proposition() intel.ResearchProposition {
	return intel.ResearchProposition{
		Ecosystem: "Go", Package: "golang.org/x/crypto", Advisory: "GO-2026-9999",
		AffectedSymbols:  []string{"golang.org/x/crypto/ssh"},
		TriggerCondition: "a client presents a crafted key exchange",
		KnownEntryPoints: []string{"ssh.NewServerConn"},
		PoCHypothesis:    "a malformed KEX packet bypasses the source-address check",
		Maturity:         intel.MaturityReproduced,
	}
}

// TestIntelEvidenceIsAboutThePackageAndNothingElse is Milestone M's invariant.
//
// Intel provides evidence; it does not decide what affects a repository. Every
// proposition is about a PACKAGE — a thing in the world, independent of anyone's
// code. Whether it applies here is a different proposition, about a candidate or
// a flow in this repository, and only local analysis can establish it.
//
// core/reasoning already refuses to record an advisory as evidence about a
// candidate and left the package side unbuilt. Aggregation is per-subject, so
// filing against a distinct subject is the mechanism — not a convention — that
// keeps a researcher's confidence about a library from becoming confidence
// about somebody's code.
func TestIntelEvidenceIsAboutThePackageAndNothingElse(t *testing.T) {
	claims := proposition().Claims("nox-intel", "2026-08-31T00:00:00Z")
	if len(claims) == 0 {
		t.Fatal("a proposition produced no claims")
	}
	want := intel.PackageSubject("Go", "golang.org/x/crypto")
	for _, c := range claims {
		if c.Subject != want {
			t.Errorf("a claim is filed against %v, not the package", c.Subject)
		}
		if c.Subject.Kind != evidence.SubjectPackage {
			t.Errorf("claim subject kind is %q; anything but package lets intel's "+
				"authority reach a local proposition", c.Subject.Kind)
		}
	}

	// The decisive check: this evidence must not raise confidence about a
	// candidate in the scanned repository, whatever its strength.
	candidate := evidence.Subject{Kind: evidence.SubjectCandidate, ID: "VULN-001@go.mod:1"}
	l := evidence.Ledger{Claims: claims}
	if got := l.ConfidenceAbout(candidate); got != evidence.ConfidenceLow {
		t.Errorf("a maintainer-grade intel claim about a package raised confidence "+
			"about a local candidate to %s. Intel would then be deciding what "+
			"affects a repository it has never seen", got)
	}
	// And it must raise confidence about the package, or it is carrying nothing.
	if got := l.ConfidenceAbout(want); got == evidence.ConfidenceLow {
		t.Error("a controlled-reproduction claim did not raise confidence even about " +
			"the package it is explicitly about")
	}
}

// TestMaturityCannotBeUpgradedByConfidence. The ladder exists so an unpublished
// finding can help before OSV can, without pretending to certainty. A hypothesis
// entering a ledger at advisory strength would defeat the whole point.
func TestMaturityCannotBeUpgradedByConfidence(t *testing.T) {
	p := proposition()
	p.Maturity = intel.MaturityHypothesis
	claims := p.Claims("nox-intel", "t")
	if len(claims) == 0 {
		t.Fatal("no claims")
	}
	if claims[0].Kind == evidence.KindPublicAdvisory ||
		claims[0].Kind == evidence.KindMaintainerConfirmed {
		t.Errorf("a research hypothesis entered the ledger at %q", claims[0].Kind)
	}

	// An unrecognised rung must not be read generously.
	p.Maturity = intel.Maturity("very-confident-honestly")
	claims = p.Claims("nox-intel", "t")
	if claims[0].Kind != evidence.KindHeuristic {
		t.Errorf("an unrecognised maturity entered at %q; a vocabulary this build "+
			"does not understand is not evidence of anything", claims[0].Kind)
	}
}

// TestRefutationsSurviveTransport. A source that forwards only what supports its
// conclusion cannot be checked. The polarity model exists so disagreement
// survives the wire.
func TestRefutationsSurviveTransport(t *testing.T) {
	p := proposition()
	p.Refutations = []string{"the maintainer disputes that the check is reachable"}
	var refuting int
	for _, c := range p.Claims("nox-intel", "t") {
		if c.Refutes() {
			refuting++
		}
	}
	if refuting != 1 {
		t.Errorf("%d refuting claims; a disputed proposition arrived as though "+
			"nobody had disputed it", refuting)
	}
}

// TestAppliesLocallyReturnsQuestions. Intel can say a symbol is dangerous; only
// the local build can say whether it is referenced. A source that answered
// these would be deciding what affects a repository it has never seen.
func TestAppliesLocallyReturnsQuestions(t *testing.T) {
	for _, q := range proposition().AppliesLocally() {
		if !strings.HasSuffix(q, "?") {
			t.Errorf("%q is not a question. This method exists to hand work back "+
				"to local analysis, not to answer it", q)
		}
	}
	// Even a proposition with nothing specific still asks something local.
	bare := intel.ResearchProposition{Ecosystem: "npm", Package: "left-pad"}
	if len(bare.AppliesLocally()) == 0 {
		t.Error("a bare proposition asks nothing locally, so it would be applied " +
			"without any local test at all")
	}
}
