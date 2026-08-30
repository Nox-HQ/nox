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
	strongest, ok := sub.Strongest()
	if !ok {
		return evidence.Describe(state)
	}
	return fmt.Sprintf("%s (%s); confidence %s", strongest.Statement, strongest.Kind, confidence)
}

// Divergence records a finding whose analyzer-authored confidence disagrees
// with what its evidence supports.
//
// This is the measurement C5 needs before analyzer-authored confidence can be
// retired. Retiring it on the argument that evidence "should" be better is a
// bet; retiring it having counted where the two disagree and in which
// direction is a decision.
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
// put strength behind the one thing on the ladder that earns none. The fix is
// for the checks the analyzers already perform to become claims — which is
// what the E track builds, and what will move these findings up honestly.
//
// Until then this number measures the gap between what nox knows and what nox
// records. That gap is worth having a number for; it is not evidence that the
// analyzers are wrong.
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
