// Package adjudicate turns a ledger of claims about one subject into a
// security verdict.
//
// It exists because two analyzers could previously pronounce incompatible
// verdicts on the same code and leave the developer to decide who was right.
// Each authored its own Confidence directly onto its findings, from its own
// private sense of how sure it felt, and nothing reconciled them or could
// have: there was no shared record of what either had actually established.
//
// The judgement is made in ONE place, from evidence, by explicit state
// transitions. Not by a risk equation — a single number computed from weighted
// inputs is unarguable in the worst way, because it cannot be shown to be
// wrong about any particular step. A verdict a developer can dispute is worth
// more than one they can only accept.
//
// # What is deliberately not here
//
// Composition ACROSS subjects. A package being affected and a call path being
// unreachable are both true and neither outranks the other; combining them
// needs to know what is being decided. This package adjudicates ONE subject at
// a time, which is what the evidence kernel can support soundly.
package adjudicate

import (
	"fmt"

	"github.com/nox-hq/nox-core/evidence"
)

// Verdict is what the evidence about one subject supports.
type Verdict struct {
	// Exploitability is the lifecycle state. For a static scan it is always
	// POTENTIAL, and saying so explicitly is the point: nox reports a condition
	// it has not attempted to exploit, and a finding that stays silent about
	// that reads as a stronger claim than it is.
	Exploitability evidence.Exploitability `json:"exploitability"`
	// Confidence is what the ledger supports, which is not necessarily what the
	// analyzer that produced the finding believed.
	Confidence evidence.Confidence `json:"confidence"`
	// Conflicted is true when support and refutation are equally strong: the
	// evidence does not decide, as distinct from deciding against.
	Conflicted bool `json:"conflicted,omitempty"`
	// Rationale is the one-line reading a person gets. It never asserts safety
	// — see evidence.Describe, and §25 of the exploit-validation PRD.
	Rationale string `json:"rationale"`
}

// Adjudicate derives the verdict the ledger supports about subject.
//
// Exploitability comes from evidence.DeriveExploitability rather than being
// re-derived here, deliberately. That function is the one definition of what
// each state means, shared with the intelligence service, and a second
// implementation in the scanner is exactly the drift the kernel exists to
// prevent — it would not fail any test, it would just quietly disagree.
//
// A scan constructs no attack path and executes nothing, so the RunOutcome it
// reports is empty and the honest answer is POTENTIAL. That is not a
// placeholder to be improved: it is the true state of a finding nobody has
// tried to exploit, and Track G is what will move some of them off it.
//
// # Why a conflict is not INCONCLUSIVE
//
// The roadmap asked for equal contradictory strength to surface as
// INCONCLUSIVE. It must not, and the reason is in the kernel: Exploitability is
// a DYNAMIC-VALIDATION lifecycle, and INCONCLUSIVE means specifically that
// execution occurred and the evidence was insufficient to decide. A static scan
// executes nothing, so routing a static disagreement there would make one state
// mean two incompatible things — "we attacked it and could not tell" and "we
// attacked nothing and two producers disagree" — with no way for a reader to
// know which. The intelligence service derives exploitability from the same
// function, so that ambiguity would cross a repository boundary as well.
//
// Neither does the kernel need a new state. Conflict is not a point on the
// exploitability ladder at all; it is a property of the evidence, orthogonal to
// how far validation got. A finding can be POTENTIAL and conflicted, or
// CONFIRMED and conflicted, and collapsing the two axes loses that. So conflict
// stays its own field — and the work of C3 is to stop throwing that field away
// between here and the scan result.
func Adjudicate(l evidence.Ledger, subject evidence.Subject) Verdict {
	state := evidence.DeriveExploitability(evidence.RunOutcome{}, &l)
	confidence := l.ConfidenceAbout(subject)
	conflicted := l.Conflict(subject)

	return Verdict{
		Exploitability: state,
		Confidence:     confidence,
		Conflicted:     conflicted,
		Rationale:      rationale(l, subject, state, confidence, conflicted),
	}
}

// rationale explains the verdict in one line, naming what carried it.
func rationale(l evidence.Ledger, subject evidence.Subject, state evidence.Exploitability,
	confidence evidence.Confidence, conflicted bool) string {
	if l.Len() == 0 {
		return "no evidence was recorded about this subject"
	}
	if conflicted {
		return fmt.Sprintf("evidence conflicts at equal strength; %s", evidence.Describe(state))
	}

	sub := l.About(subject)
	// StrongestLive, not Strongest: this sentence explains the verdict, so it
	// must name a claim that contributed to it. A LOW verdict justified by "the
	// exploit reproduced under the determinism gate" — retracted, weighing
	// nothing — reads as a bug in the verdict, and the reader cannot tell which
	// half to believe. Strongest stays the audit-trail accessor.
	strongest, ok := sub.StrongestLive()
	if !ok {
		return evidence.Describe(state)
	}
	return fmt.Sprintf("%s (%s); confidence %s", strongest.Statement, strongest.Kind, confidence)
}

// Divergence records a finding whose analyzer-authored confidence disagrees
// with what its evidence supports.
//
// It was built as the measurement C5 needed before analyzer-authored
// confidence could be retired. The measurement was taken and C5 decided the
// other way, so this is now a standing report rather than a one-off: the two
// confidences are different quantities, both are kept, and where they disagree
// is output instead of being resolved.
//
// # What the measurement showed
//
// Retiring Confidence in favour of the adjudicated value does not recalibrate
// the scale — it removes the top of it. The kernel puts HIGH at strength 70
// (source_confirmed, controlled_reproduction, public_advisory) and a static
// scan's strongest claim is KindStatic at 40. On the precision suite the flip
// took `--min-confidence high` from 11 findings to zero, and it would be zero
// on every project permanently, because analysing harder does not produce
// strength 70; executing something or someone else reporting it does.
//
// A filter that always returns nothing is indistinguishable from a clean
// repository. So the analyzer keeps authorship of Confidence — which the
// precision suite says is well calibrated, 37 true positives and no false ones
// — and the evidence gets Finding.EvidenceConfidence to disagree in.
// TestTheFlipWouldHaveEmptiedTheTopOfTheScale keeps that number executable.
//
// # How to read the number, and how not to
//
// On the precision suite, 15 of 37 findings diverge and every one is the
// analyzer claiming MORE than the evidence supports. That is a real signal and
// it is not the signal it first looks like.
//
// It is tempting to read it as "the analyzers over-claim on 41% of findings".
// The more accurate reading is that they UNDER-RECORD. A secrets rule matching
// a well-formed AWS key ID has done more than match a pattern — it checked a
// provider-specific format, a length, a character class, often an entropy
// threshold — and recorded exactly one KindHeuristic claim saying "a pattern
// matched", because that is all the shim knows how to say. The analyzer's
// "high" is not obviously wrong; the ledger behind it is obviously thin.
//
// The fix is therefore NOT to weigh pattern matches more heavily. A regex
// match is a heuristic however specific it is, and inflating the kind would
// put strength behind the one thing on the ladder that earns none.
//
// This comment used to continue "the fix is for the checks the analyzers
// already perform to become claims", and that was measured and found wrong.
// Recording those checks — E3 — took the corpus from 37 supporting claims to
// 61 and left the divergence at exactly 15. It could not have done anything
// else: aggregation takes the STRONGEST supporting claim, every one of those
// checks is a heuristic, and three heuristics are still a heuristic. The
// independence promotion cannot apply either, since they all come from one
// producer; counting them as independent would be the "one project scanning
// itself a hundred times" fallacy with the numbers changed.
//
// So the number moves on evidence of a different KIND, not more of the same.
// Several providers encode a checksum in the token itself, and verifying one
// is deterministic — that is the path, and it needs a verifiable test vector
// before it is written, because unverified checksum logic would put false
// deterministic claims in the ledger and that is worse than the silence.
//
// What E3 did buy is explanation: a finding's ledger now says what nox checked
// before believing it, not only what would have made it stop.
//
// So the number measures the gap between what nox knows and what nox can
// currently record AS EVIDENCE. That gap is worth having a number for; it is
// not evidence that the analyzers are wrong — and C5 is where acting as though
// it were would have done real damage.
type Divergence struct {
	Fingerprint string              `json:"fingerprint"`
	RuleID      string              `json:"rule_id"`
	Analyzer    evidence.Confidence `json:"analyzer_confidence"`
	Adjudicated evidence.Confidence `json:"adjudicated_confidence"`
	// Overclaimed is true when the analyzer was MORE confident than the
	// evidence supports. It is the direction that matters: an analyzer
	// under-claiming costs a promotion, an analyzer over-claiming puts a
	// developer's time behind something nothing established.
	Overclaimed bool `json:"overclaimed"`
}

// ConfidenceFrom maps an analyzer's high|medium|low label onto the evidence
// scale so the two can be compared at all.
//
// An unrecognised label maps to LOW rather than to a middle value. A label this
// build does not understand is not evidence of anything, and treating it as
// medium confidence would let a typo look like a considered judgement.
func ConfidenceFrom(label string) evidence.Confidence {
	switch label {
	case "high":
		return evidence.ConfidenceHigh
	case "medium":
		return evidence.ConfidenceMedium
	case "low":
		return evidence.ConfidenceLow
	default:
		return evidence.ConfidenceLow
	}
}

// Diverged reports whether the two confidences disagree, and whether the
// analyzer claimed more than the evidence supports.
func Diverged(analyzerLabel string, adjudicated evidence.Confidence) (diverged, overclaimed bool) {
	a := ConfidenceFrom(analyzerLabel)
	if a == adjudicated {
		return false, false
	}
	return true, a.AtLeast(adjudicated) && a != adjudicated
}

// Conflict records a finding whose evidence contradicts itself at equal
// strength: something supports it and something refutes it, and neither
// outranks the other.
//
// It is reported rather than resolved. A conflict is a disagreement between two
// producers about the same subject, and the one thing nox must not do with it
// is pick a winner silently — that is the behaviour the whole evidence spine
// exists to replace. An operator who can see that the AI analyzer and the
// secrets analyzer disagree about one line can go and look; an operator handed
// whichever verdict happened to be computed last cannot.
//
// # It does not fire today, and that is worth stating precisely
//
// On every committed corpus this is empty, and not by luck. A refuted candidate
// is DROPPED before any supporting claim is recorded, and a surviving one is
// corroborated on a separate path — so the two polarities do not meet. The one
// place they do meet is the checksum verifier, which files a KindStatic
// refutation against a candidate whose supports are KindHeuristic, and 40 does
// not equal 10.
//
// So conflict is currently unreachable rather than merely unobserved, and the
// distinction matters: an unreachable check and a working one look identical
// from the outside, which is precisely how "we never exercised it" gets
// reported as "it holds". What makes it reachable is a SECOND producer filing
// claims about a subject the scanner already has an opinion on — the
// intelligence service under Track H, or a plugin. That is exactly when a
// silently discarded conflict would start hiding a real disagreement, and it is
// why this is wired now, while it costs nothing, rather than then.
//
// TestConflictIsUnreachableUntilASecondProducerExists holds that reasoning to
// the corpus, so the day it stops being true, something says so.
type Conflict struct {
	Fingerprint string           `json:"fingerprint"`
	RuleID      string           `json:"rule_id"`
	Subject     evidence.Subject `json:"subject"`
	// Strength is the kind at which the two sides tied. It is the useful half
	// of the report: a tie between two heuristics is a coin-flip nobody should
	// act on, and a tie between two deterministic claims means one of the
	// producers is wrong about something checkable.
	Strength evidence.Kind `json:"strength"`
	// Supporting and Refuting are the two statements that tied, so the report
	// says what the disagreement IS rather than only that there is one.
	Supporting string `json:"supporting"`
	Refuting   string `json:"refuting"`
}

// ConflictFor builds the report for a subject the ledger says is conflicted.
// It returns ok=false when the ledger does not in fact conflict, so a caller
// cannot manufacture a conflict report by asking for one.
func ConflictFor(l evidence.Ledger, subject evidence.Subject) (Conflict, bool) {
	if !l.Conflict(subject) {
		return Conflict{}, false
	}
	sub := l.About(subject)
	support, hasSupport := strongestWhere(sub, evidence.Claim.Supports)
	refutation, hasRefutation := strongestWhere(sub, evidence.Claim.Refutes)
	if !hasSupport || !hasRefutation {
		// Unreachable via Ledger.Conflict, which requires both. Returning
		// ok=false rather than a half-filled report keeps that true if the
		// kernel's definition ever widens.
		return Conflict{}, false
	}
	return Conflict{
		Subject:    subject,
		Strength:   support.Kind,
		Supporting: support.Statement,
		Refuting:   refutation.Statement,
	}, true
}

// strongestWhere returns the strongest claim matching pol. It mirrors the
// kernel's own selection so the pair this reports is the pair the kernel
// compared when it called the subject conflicted — reporting a different pair
// would describe a disagreement that did not decide anything.
func strongestWhere(l evidence.Ledger, pol func(evidence.Claim) bool) (evidence.Claim, bool) {
	var best evidence.Claim
	var found bool
	for _, c := range l.Claims {
		if !pol(c) {
			continue
		}
		if !found || c.Kind.Strength() > best.Kind.Strength() {
			best, found = c, true
		}
	}
	return best, found
}

// Version identifies the adjudication logic that produced a verdict.
//
// It is the second half of the replay contract: the same ledger and the same
// adjudicator version must yield the same verdict. Without it, a replay that
// disagrees with the stored result is ambiguous — the evidence could have been
// mis-serialised, or adjudication could simply have improved since — and a
// reader has no way to tell a regression from an upgrade.
//
// # When to bump it
//
// Whenever Adjudicate can return a different Verdict for an input it has seen
// before. That includes changes inside evidence.DeriveExploitability and the
// kernel's confidence aggregation, because this version covers the whole
// derivation, not just the code in this file. A rationale reworded is a change:
// the rationale is part of the verdict a person read and acted on.
//
// TestVerdictsAreStableForThisVersion is the enforcement. It pins a set of
// ledgers to their verdicts, so changing the logic without bumping this fails
// with the exact pair that moved, and bumping it without changing the logic
// fails too.
const Version = "1"
