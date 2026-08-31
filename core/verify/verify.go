// Package verify is the vocabulary a verification producer speaks, chosen so
// the domain model outlives the technology that produced it.
//
// A constraint solver is one evidence producer. So is a fuzzer, a symbolic
// executor, a runtime attack adapter, a unit-level harness, a proof-of-concept
// runner and a property checker. Coupling nox's verdicts to any one of their
// vocabularies — SAT and UNSAT most obviously — would make the domain model a
// hostage to a tool choice that has not been made yet, and would have to be
// unpicked the first time a second producer disagreed about what its own words
// meant.
//
// # This is a separate axis, not a widening of Exploitability
//
// evidence.Exploitability is a lifecycle: how far dynamic validation of a
// finding has got. A verification result is a different question — what one
// producer established about one proposition, under one model. Track C3
// rejected folding conflict into Exploitability for exactly this reason, and
// the reasoning carries: INCONCLUSIVE already means "execution occurred and
// could not decide", and a state meaning two things leaves a reader unable to
// tell which applies. Conflict got its own field; so does this.
//
// # What a result may never say
//
// A solver returning UNSAT has refuted a PATH under a model, an abstraction and
// a set of bounds. It has not refuted the finding. Nothing in this package can
// express "refutes the finding", because the only refuting outcome is named
// InfeasibleWithinScope and it carries the scope that bounds it — the same
// asymmetry core/reach enforces, for the same reason: a universal claim is only
// as good as the search behind it.
package verify

import (
	"fmt"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/reach"
)

// Outcome is what one producer established about one proposition.
type Outcome string

const (
	// Feasible — the condition can be satisfied, under the stated model. It
	// SUPPORTS the proposition; it does not confirm anything above it.
	Feasible Outcome = "FEASIBLE"
	// InfeasibleWithinScope — the condition could not be satisfied under the
	// stated model, abstraction and bounds. Named at length on purpose: there
	// is no way to say "infeasible" without saying within what.
	InfeasibleWithinScope Outcome = "INFEASIBLE_WITHIN_SCOPE"
	// Observed — something happened and was recorded. Not yet a judgement about
	// whether it matters.
	Observed Outcome = "OBSERVED"
	// Violated — a stated security invariant was broken. Stronger than
	// Observed, weaker than Reproduced.
	Violated Outcome = "VIOLATED"
	// Reproduced — it recurred under a determinism gate.
	Reproduced Outcome = "REPRODUCED"
	// Unknown — the producer could not tell. The honest default, and the only
	// outcome an incomplete model may reach for a negative.
	Unknown Outcome = "UNKNOWN"
)

// Valid reports whether o is a defined outcome.
func (o Outcome) Valid() bool {
	switch o {
	case Feasible, InfeasibleWithinScope, Observed, Violated, Reproduced, Unknown:
		return true
	}
	return false
}

// Refutes reports whether this outcome argues against its proposition. Only one
// outcome does, and it is the one carrying its scope in its name.
func (o Outcome) Refutes() bool { return o == InfeasibleWithinScope }

// Result is one producer's finding about one proposition.
//
// Subject is required and is the whole point: a result is about a path, a flow,
// a trigger condition — never about "the finding". Attaching a solver's answer
// to a finding is how UNSAT on one path becomes "not vulnerable".
type Result struct {
	// Producer names what established this — "z3", "afl", "nox-attack" — so a
	// reader can weigh it and a second producer can disagree attributably.
	Producer string `json:"producer"`
	// Subject is the proposition, typed.
	Subject evidence.Subject `json:"subject"`
	// Outcome is what was established.
	Outcome Outcome `json:"outcome"`
	// Scope is the model, abstraction and bounds it holds under, reusing the
	// same object reachability results carry. A verification answer and a
	// reachability answer are bounded the same way and by the same kinds of
	// thing; two scope types would drift.
	Scope reach.Scope `json:"scope"`
	// Detail is the producer's own words.
	Detail string `json:"detail"`
}

// Verify records an outcome, refusing the ones that cannot be stated.
//
// A negative — InfeasibleWithinScope — requires a scope with no limitations,
// exactly as reach.Refute does. A model that could not resolve a dispatch has
// not shown the condition unsatisfiable; it has shown its own search came up
// empty, which is Unknown. The second return is false when the outcome was
// downgraded, so a caller cannot get the stronger claim by not looking.
func Verify(producer string, subject evidence.Subject, outcome Outcome, scope reach.Scope, detail string) (Result, bool) {
	r := Result{Producer: producer, Subject: subject, Outcome: outcome, Scope: scope, Detail: detail}
	if !outcome.Valid() || subject.Zero() {
		// An unattributed result aggregates with every other unattributed one,
		// which is how a solver's answer about a path reaches a finding.
		r.Outcome = Unknown
		return r, false
	}
	if outcome.Refutes() && !scope.Complete() {
		r.Outcome = Unknown
		r.Detail = detail + " (downgraded: " + scope.Describe() + ")"
		return r, false
	}
	return r, true
}

// Claim converts a result into evidence, at a kind that reflects what the
// producer actually did.
//
// A solver's answer is KindStatic: it is a machine-checkable statement about a
// model, which is more than a heuristic and less than an execution. Only
// something that actually ran and recurred earns KindControlledReproduction,
// and only the Reproduced outcome maps to it — which is why a solver cannot
// reach CONFIRMED however confident it is.
func (r Result) Claim(observedAt string) (evidence.Claim, bool) {
	var kind evidence.Kind
	polarity := evidence.PolaritySupports
	switch r.Outcome {
	case Reproduced:
		kind = evidence.KindControlledReproduction
	case Violated, Observed:
		kind = evidence.KindStatic
	case Feasible:
		kind = evidence.KindStatic
	case InfeasibleWithinScope:
		kind, polarity = evidence.KindStatic, evidence.PolarityRefutes
	default:
		// Unknown produces no claim. A producer that could not tell has not
		// contributed evidence, and filing an empty one would make the ledger
		// look busier than the enquiry was.
		return evidence.Claim{}, false
	}
	return evidence.Claim{
		Kind:      kind,
		Subject:   r.Subject,
		Polarity:  polarity,
		Statement: r.Statement(),
		Provenance: evidence.Provenance{
			Source: r.Producer, SourceID: r.Producer, ObservedAt: observedAt,
		},
	}, true
}

// Statement is the sentence a person reads. It never drops the scope from a
// negative, because the scope is what makes the negative true.
func (r Result) Statement() string {
	switch r.Outcome {
	case InfeasibleWithinScope:
		return fmt.Sprintf("%s found no satisfying assignment within its model (%s)",
			r.Producer, r.Scope.Describe())
	case Unknown:
		return fmt.Sprintf("%s could not determine this (%s)", r.Producer, r.Scope.Describe())
	default:
		return fmt.Sprintf("%s established %s (%s)", r.Producer, r.Outcome, r.Scope.Describe())
	}
}
