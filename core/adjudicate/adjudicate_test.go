package adjudicate_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/adjudicate"
)

var candidate = evidence.Subject{Kind: evidence.SubjectCandidate, ID: "SEC-003@app/creds.py:1:16"}

func supporting(kind evidence.Kind, statement string) evidence.Claim {
	return evidence.Claim{
		Kind: kind, Statement: statement, Subject: candidate,
		Provenance: evidence.Provenance{Source: "nox-scan", Tool: "secrets"},
	}
}

func refuting(kind evidence.Kind, statement string) evidence.Claim {
	c := supporting(kind, statement)
	c.Polarity = evidence.PolarityRefutes
	return c
}

// TestAScanNeverClaimsExploitability is the honesty rule. nox does not execute
// the code it scans, so no static finding may present as anything but
// POTENTIAL — and saying POTENTIAL out loud is the point, because a finding
// that stays silent about it reads as a stronger claim than it is.
func TestAScanNeverClaimsExploitability(t *testing.T) {
	for _, kind := range []evidence.Kind{
		evidence.KindHeuristic, evidence.KindStatic, evidence.KindSourceConfirmed,
		evidence.KindControlledReproduction, evidence.KindPublicAdvisory,
	} {
		var l evidence.Ledger
		l.Add(supporting(kind, "established somehow"))
		v := adjudicate.Adjudicate(l, candidate)
		if v.Exploitability != evidence.Potential {
			t.Errorf("a %s claim with no attack run produced %s, want POTENTIAL",
				kind, v.Exploitability)
		}
	}
}

// TestRationaleNeverAssertsSafety mirrors the kernel's own guard. §25 is
// explicit that nox reports "not reproduced" or "prevented under the
// strategies tested", never "safe" — and a rationale is exactly the free-text
// field where a careless "looks fine" would be written.
func TestRationaleNeverAssertsSafety(t *testing.T) {
	ledgers := []evidence.Ledger{
		{},
		{Claims: []evidence.Claim{supporting(evidence.KindHeuristic, "a pattern matched")}},
		{Claims: []evidence.Claim{refuting(evidence.KindStatic, "the value is a placeholder")}},
		{Claims: []evidence.Claim{
			supporting(evidence.KindStatic, "taint reaches the sink"),
			refuting(evidence.KindStatic, "a sanitizer dominates the path"),
		}},
	}
	banned := []string{"safe", "secure", "no risk", "not vulnerable", "clean"}
	for i, l := range ledgers {
		got := strings.ToLower(adjudicate.Adjudicate(l, candidate).Rationale)
		for _, word := range banned {
			if strings.Contains(got, word) {
				t.Errorf("ledger %d produced a rationale asserting safety (%q contains %q)",
					i, got, word)
			}
		}
		if got == "" {
			t.Errorf("ledger %d produced an empty rationale", i)
		}
	}
}

// TestConfidenceFollowsTheEvidence covers the arithmetic the verdict inherits
// from the kernel, at the level a caller sees it.
func TestConfidenceFollowsTheEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims []evidence.Claim
		want   evidence.Confidence
	}{
		{"nothing recorded", nil, evidence.ConfidenceLow},
		{"a bare pattern match", []evidence.Claim{
			supporting(evidence.KindHeuristic, "a pattern matched")}, evidence.ConfidenceLow},
		{"deterministic analysis", []evidence.Claim{
			supporting(evidence.KindStatic, "taint path resolved")}, evidence.ConfidenceMedium},
		{"refuted by something stronger", []evidence.Claim{
			supporting(evidence.KindHeuristic, "a pattern matched"),
			refuting(evidence.KindStatic, "every argument is constant")}, evidence.ConfidenceLow},
		{"refuted by something weaker", []evidence.Claim{
			supporting(evidence.KindStatic, "taint path resolved"),
			refuting(evidence.KindHeuristic, "looks like test code")}, evidence.ConfidenceMedium},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := evidence.Ledger{Claims: tc.claims}
			if got := adjudicate.Adjudicate(l, candidate).Confidence; got != tc.want {
				t.Errorf("confidence = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestConflictIsReportedNotResolved. Two producers disagreeing at equal
// strength is worth surfacing; collapsing it to a number is how a disagreement
// becomes invisible.
func TestConflictIsReportedNotResolved(t *testing.T) {
	l := evidence.Ledger{Claims: []evidence.Claim{
		supporting(evidence.KindStatic, "taint reaches the sink"),
		refuting(evidence.KindStatic, "a sanitizer dominates the path"),
	}}
	v := adjudicate.Adjudicate(l, candidate)
	if !v.Conflicted {
		t.Error("equally strong contradictory claims were not reported as a conflict")
	}
	if !strings.Contains(v.Rationale, "conflict") {
		t.Errorf("rationale %q does not mention the conflict", v.Rationale)
	}
}

// TestUnknownAnalyzerLabelIsNotTreatedAsMiddling. A label this build does not
// understand is not evidence of anything, and reading it as medium confidence
// would let a typo look like a considered judgement.
func TestUnknownAnalyzerLabelIsNotTreatedAsMiddling(t *testing.T) {
	for _, label := range []string{"", "High", "critical", "unknown", "  high"} {
		if got := adjudicate.ConfidenceFrom(label); got != evidence.ConfidenceLow {
			t.Errorf("ConfidenceFrom(%q) = %s, want LOW", label, got)
		}
	}
	if got := adjudicate.ConfidenceFrom("high"); got != evidence.ConfidenceHigh {
		t.Errorf("ConfidenceFrom(\"high\") = %s, want HIGH", got)
	}
}

// TestDivergenceDirection pins which way round "overclaimed" means, because
// getting it backwards would invert the one number C5 depends on.
func TestDivergenceDirection(t *testing.T) {
	for _, tc := range []struct {
		label           string
		adjudicated     evidence.Confidence
		wantDiverged    bool
		wantOverclaimed bool
	}{
		{"high", evidence.ConfidenceLow, true, true},
		{"high", evidence.ConfidenceHigh, false, false},
		{"low", evidence.ConfidenceHigh, true, false},
		{"medium", evidence.ConfidenceLow, true, true},
		{"low", evidence.ConfidenceLow, false, false},
	} {
		diverged, over := adjudicate.Diverged(tc.label, tc.adjudicated)
		if diverged != tc.wantDiverged || over != tc.wantOverclaimed {
			t.Errorf("Diverged(%q, %s) = (%v, %v), want (%v, %v)",
				tc.label, tc.adjudicated, diverged, over, tc.wantDiverged, tc.wantOverclaimed)
		}
	}
}

// TestConflictIsNotAnExploitabilityState is the C3 decision, held as an
// assertion.
//
// The roadmap asked for equal contradictory strength to surface as
// INCONCLUSIVE. It must not: INCONCLUSIVE means execution occurred and could
// not decide, a static scan executes nothing, and one state cannot carry both
// meanings without a reader losing the ability to tell them apart. The
// intelligence service derives exploitability from the same kernel function, so
// the ambiguity would not stay in this repository.
func TestConflictIsNotAnExploitabilityState(t *testing.T) {
	l := evidence.Ledger{Claims: []evidence.Claim{
		supporting(evidence.KindStatic, "taint reaches the sink"),
		refuting(evidence.KindStatic, "a sanitizer dominates the path"),
	}}
	v := adjudicate.Adjudicate(l, candidate)
	if !v.Conflicted {
		t.Fatal("the fixture does not conflict; the rest of this test is vacuous")
	}
	if v.Exploitability != evidence.Potential {
		t.Errorf("a conflicted static verdict reported exploitability %q, want POTENTIAL. "+
			"Conflict is a property of the evidence, not a point on the validation "+
			"ladder; routing it into the lifecycle makes INCONCLUSIVE mean both "+
			"\"we attacked it and could not tell\" and \"we attacked nothing\"",
			v.Exploitability)
	}
}

// TestConflictForReportsThePairThatTied. A report saying only "these disagree"
// sends a person looking through the whole ledger for the disagreement. Naming
// the two statements is the difference between a signal and a chore.
func TestConflictForReportsThePairThatTied(t *testing.T) {
	l := evidence.Ledger{Claims: []evidence.Claim{
		supporting(evidence.KindHeuristic, "a weak corroboration nobody should act on"),
		supporting(evidence.KindStatic, "taint reaches the sink"),
		refuting(evidence.KindStatic, "a sanitizer dominates the path"),
	}}
	c, ok := adjudicate.ConflictFor(l, candidate)
	if !ok {
		t.Fatal("ConflictFor declined a ledger the kernel calls conflicted")
	}
	if c.Strength != evidence.KindStatic {
		t.Errorf("Strength = %q, want static: the tie is between the STRONGEST claim of "+
			"each polarity, and reporting the weaker one describes a disagreement that "+
			"did not decide anything", c.Strength)
	}
	if c.Supporting != "taint reaches the sink" {
		t.Errorf("Supporting = %q; the heuristic was reported instead of the claim that tied",
			c.Supporting)
	}
	if c.Refuting != "a sanitizer dominates the path" {
		t.Errorf("Refuting = %q", c.Refuting)
	}
	if c.Subject != candidate {
		t.Errorf("Subject = %v, want %v", c.Subject, candidate)
	}
}

// TestConflictForCannotManufactureAConflict. A caller that asks for a conflict
// report about an agreeing ledger must be told no, not handed a half-filled
// struct: a Conflict in a scan result is a claim that two producers disagreed,
// and one nobody disagreed about is a fabricated disagreement.
func TestConflictForCannotManufactureAConflict(t *testing.T) {
	for name, l := range map[string]evidence.Ledger{
		"empty":        {},
		"support only": {Claims: []evidence.Claim{supporting(evidence.KindStatic, "reaches the sink")}},
		"refute only":  {Claims: []evidence.Claim{refuting(evidence.KindStatic, "sanitized")}},
		"unequal": {Claims: []evidence.Claim{
			supporting(evidence.KindControlledReproduction, "the exploit reproduced under the determinism gate"),
			refuting(evidence.KindHeuristic, "the name looks like a placeholder"),
		}},
	} {
		if c, ok := adjudicate.ConflictFor(l, candidate); ok {
			t.Errorf("%s: reported a conflict (%+v) where the evidence does not tie", name, c)
		}
	}
}

// TestStrongerEvidenceWinsAndDeterminismIsNotOverturnable pins the two
// composition rules C3 states, in the direction each can fail, with the exact
// confidence rather than a bound.
//
// The first case is the one with teeth. A heuristic that could demote a
// deterministic claim would let a guess retire a proof, which is the failure
// the strength ladder exists to make impossible — and an assertion phrased as
// "not high" would pass even if it had.
func TestStrongerEvidenceWinsAndDeterminismIsNotOverturnable(t *testing.T) {
	proofVersusGuess := evidence.Ledger{Claims: []evidence.Claim{
		supporting(evidence.KindControlledReproduction, "the exploit reproduced under the determinism gate"),
		refuting(evidence.KindHeuristic, "the identifier name contains 'example'"),
	}}
	v := adjudicate.Adjudicate(proofVersusGuess, candidate)
	if v.Conflicted {
		t.Error("a heuristic refutation tied with a reproduction; a guess must not draw with a proof")
	}
	if v.Confidence != evidence.ConfidenceConfirmed {
		t.Errorf("confidence = %q, want CONFIRMED: a heuristic refutation demoted a "+
			"deterministic support, which is a guess retiring a proof", v.Confidence)
	}

	guessVersusProof := evidence.Ledger{Claims: []evidence.Claim{
		supporting(evidence.KindHeuristic, "a pattern matched"),
		refuting(evidence.KindControlledReproduction, "a controlled reproduction showed the sink is unreachable"),
	}}
	v = adjudicate.Adjudicate(guessVersusProof, candidate)
	if v.Conflicted {
		t.Error("a heuristic support tied with a reproduction refuting it")
	}
	if v.Confidence != evidence.ConfidenceLow {
		t.Errorf("confidence = %q, want LOW: a pattern match is a heuristic however "+
			"strongly it is contradicted, and inflating it either way misreports "+
			"what was established", v.Confidence)
	}
}

// TestVerdictsAreStableForThisVersion is the enforcement behind
// adjudicate.Version, and therefore behind replay meaning anything.
//
// The replay contract is "same ledger + same adjudicator version = same
// verdict". Nothing makes that true by itself: Version is a constant somebody
// has to remember to bump, and the failure mode is silent — adjudication
// improves, the constant stays, and every stored artifact now disagrees with
// the code while claiming to be comparable. A reader cannot tell that from a
// regression.
//
// So the pairs below are pinned. Change what Adjudicate returns for any of them
// and this fails with the exact field that moved. If the change is intended,
// bump Version and update the table in the same commit — which is the point,
// because those two edits belong together and nothing else forces it.
//
// The kernel's derivation is covered too, not just the code in this file:
// confidence aggregation and DeriveExploitability both feed these verdicts, so
// a kernel bump that moves one shows up here as well.
func TestVerdictsAreStableForThisVersion(t *testing.T) {
	if adjudicate.Version != "1" {
		t.Fatalf("adjudicate.Version is %q; this table was pinned against %q. "+
			"Re-derive the expectations below deliberately rather than editing "+
			"until it passes", adjudicate.Version, "1")
	}

	cases := []struct {
		name           string
		ledger         evidence.Ledger
		exploitability evidence.Exploitability
		confidence     evidence.Confidence
		conflicted     bool
		rationale      string
	}{
		{
			name:           "no evidence",
			ledger:         evidence.Ledger{},
			exploitability: evidence.Potential,
			confidence:     evidence.ConfidenceLow,
			rationale:      "no evidence was recorded about this subject",
		},
		{
			name:           "one heuristic",
			ledger:         evidence.Ledger{Claims: []evidence.Claim{supporting(evidence.KindHeuristic, "a pattern matched")}},
			exploitability: evidence.Potential,
			confidence:     evidence.ConfidenceLow,
			rationale:      "a pattern matched (heuristic); confidence LOW",
		},
		{
			name:           "static support",
			ledger:         evidence.Ledger{Claims: []evidence.Claim{supporting(evidence.KindStatic, "the checksum verifies")}},
			exploitability: evidence.Potential,
			confidence:     evidence.ConfidenceMedium,
			rationale:      "the checksum verifies (static); confidence MEDIUM",
		},
		{
			name: "static support, static refutation",
			ledger: evidence.Ledger{Claims: []evidence.Claim{
				supporting(evidence.KindStatic, "taint reaches the sink"),
				refuting(evidence.KindStatic, "a sanitizer dominates the path"),
			}},
			exploitability: evidence.Potential,
			confidence:     evidence.ConfidenceLow,
			conflicted:     true,
			rationale:      "evidence conflicts at equal strength; " + evidence.Describe(evidence.Potential),
		},
		{
			name: "reproduction beats a heuristic refutation",
			ledger: evidence.Ledger{Claims: []evidence.Claim{
				supporting(evidence.KindControlledReproduction, "the exploit reproduced under the determinism gate"),
				refuting(evidence.KindHeuristic, "the identifier name contains 'example'"),
			}},
			exploitability: evidence.Potential,
			confidence:     evidence.ConfidenceConfirmed,
			rationale: "the exploit reproduced under the determinism gate (controlled_reproduction); " +
				"confidence CONFIRMED",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := adjudicate.Adjudicate(tc.ledger, candidate)
			if got.Exploitability != tc.exploitability {
				t.Errorf("exploitability = %q, want %q", got.Exploitability, tc.exploitability)
			}
			if got.Confidence != tc.confidence {
				t.Errorf("confidence = %q, want %q", got.Confidence, tc.confidence)
			}
			if got.Conflicted != tc.conflicted {
				t.Errorf("conflicted = %v, want %v", got.Conflicted, tc.conflicted)
			}
			if got.Rationale != tc.rationale {
				t.Errorf("rationale =\n  %q\nwant\n  %q\nThe rationale is part of the "+
					"verdict: it is the sentence a person read and acted on, and a replay "+
					"that reproduced the labels but not the explanation has not reproduced "+
					"what they saw", got.Rationale, tc.rationale)
			}
		})
	}
}
