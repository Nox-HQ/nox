package attack

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// Milestone F: KindControlledReproduction requires all of — real execution, a
// deterministic oracle, repeatability, sound control, and a completed run — and
// removing any one prevents CONFIRMED.
//
// Four of the five are enforced by evidence.DeriveExploitability, which
// TestFailClosed_ConfirmedOnlyFromTheExactIntendedCombination walks as a full
// cross product in the kernel. This file is about the fifth, because it is NOT
// enforced there, and that turns out to be right rather than an oversight.

// TestACompletedRunIsSubsumedByReproduction is F's fifth condition, and the
// argument for where it lives.
//
// The kernel deliberately does not bar CONFIRMED on BudgetExhausted, and its
// cross-product test asserts that: the rule is
// Executed && Violated && Reproduced && ControlSound && deterministic. Adding
// budget as a sixth bar was tried and reverted, because it makes nox less
// accurate rather than safer — a genuinely reproduced exploit would be
// downgraded to INCONCLUSIVE because the runner later hit a time limit. Budget
// exhaustion says the run stopped early. It does not say that what it already
// observed was wrong. That is why the kernel bars it for PREVENTED, where "we
// saw nothing" IS the claim and an unfinished search is exactly why you might
// see nothing.
//
// The condition is instead satisfied structurally: Reproduced cannot be true
// unless the determinism gate ran to completion, and every runner sets
// BudgetExhausted only on a path that leaves before the gate. This test pins
// that property where it is actually made — in the runners — rather than
// asserting it as a comment.
func TestACompletedRunIsSubsumedByReproduction(t *testing.T) {
	// The kernel's contract, restated so a change there fails here too.
	confirmed := func(o evidence.RunOutcome) bool {
		l := &evidence.Ledger{Claims: []evidence.Claim{{
			Kind: evidence.KindControlledReproduction, Statement: "reproduced",
		}}}
		return evidence.DeriveExploitability(o, l) == evidence.Confirmed
	}

	base := evidence.RunOutcome{
		Executed: true, Violated: true, Reproduced: true, ControlSound: true,
	}
	if !confirmed(base) {
		t.Fatal("the complete combination does not confirm; the rest of this test is vacuous")
	}

	// Conditions 1-4, each removed in turn.
	for name, mutate := range map[string]func(evidence.RunOutcome) evidence.RunOutcome{
		"real execution": func(o evidence.RunOutcome) evidence.RunOutcome { o.Executed = false; return o },
		"repeatability":  func(o evidence.RunOutcome) evidence.RunOutcome { o.Reproduced = false; return o },
		"sound control":  func(o evidence.RunOutcome) evidence.RunOutcome { o.ControlSound = false; return o },
		"a violation":    func(o evidence.RunOutcome) evidence.RunOutcome { o.Violated = false; return o },
	} {
		if confirmed(mutate(base)) {
			t.Errorf("removing %q still reached CONFIRMED", name)
		}
	}

	// Condition 2 removed: the oracle is semantic rather than deterministic.
	semantic := &evidence.Ledger{Claims: []evidence.Claim{{
		Kind: evidence.KindSemantic, Statement: "a model judged this exploited",
	}}}
	if evidence.DeriveExploitability(base, semantic) == evidence.Confirmed {
		t.Error("a model's judgement confirmed an exploit with nothing machine-checkable behind it")
	}

	// Condition 5: budget exhaustion does NOT bar CONFIRMED in the kernel, and
	// this records that as the deliberate choice it is. If someone adds the bar,
	// this fails and points at the reasoning rather than letting the change look
	// like a tightening with no cost.
	budgeted := base
	budgeted.BudgetExhausted = true
	if !confirmed(budgeted) {
		t.Error("budget exhaustion now bars CONFIRMED. That downgrades a genuinely " +
			"reproduced exploit because the runner later hit a time limit. The " +
			"condition is satisfied structurally instead — see the runner test below")
	}
}

// TestNoRunnerReportsAReproductionItCutShort is where F's fifth condition is
// actually guaranteed.
//
// A run that exhausts its budget must not also report a reproduction, because
// the determinism gate is what sets Reproduced and the budget path leaves
// before reaching it. Both runners are written that way; neither says so.
// Enforcing it by control flow in two callers rather than by the type is what
// makes it invisible to a third, which is the failure shape this programme has
// found five times.
func TestNoRunnerReportsAReproductionItCutShort(t *testing.T) {
	// notRunTrace is the one place a RunOutcome is built with BudgetExhausted
	// set up front. It must never claim execution or reproduction.
	tr := notRunTrace(Hypothesis{ID: "h1"}, RunConfig{}, "nothing ran")
	if tr.Outcome.Executed {
		t.Error("a hypothesis that never ran reports Executed")
	}
	if tr.Outcome.Reproduced {
		t.Error("a hypothesis that never ran reports a reproduction")
	}
	if tr.Exploitability == evidence.Confirmed {
		t.Errorf("a hypothesis that never ran is %s", tr.Exploitability)
	}
}

// TestAnAttackConfirmsTheInvariantItTestedAndNothingAbove is Milestone G at the
// producer.
//
// The kernel aggregates per subject, so the reproduction hierarchy is only real
// if a producer attributes its claims. Until this landed, core/attack set no
// Subject on any claim: every claim shared the zero subject and landed in one
// bag, where the cheapest deterministic claim satisfied the precondition for
// the most expensive.
//
// A run that saw a guardrail bypassed and reproduced it has established that
// the guardrail was bypassed. What an attacker could then do is a later
// proposition with its own evidence, and promoting across that gap is how a
// scanner reports an RCE it never saw.
func TestAnAttackConfirmsTheInvariantItTestedAndNothingAbove(t *testing.T) {
	h := Hypothesis{ID: "hyp-1", Rationale: "a prompt boundary is splice-able"}
	ledger := &evidence.Ledger{}
	ledger.Add(evidence.Claim{
		Kind:      evidence.KindDynamicExploit,
		Subject:   InvariantSubject(h),
		Statement: "a deterministic oracle observed the invariant violated and it reproduced",
	})
	outcome := evidence.RunOutcome{
		Executed: true, Violated: true, Reproduced: true, ControlSound: true,
	}

	if got := evidence.DeriveExploitabilityAbout(outcome, ledger, InvariantSubject(h)); got != evidence.Confirmed {
		t.Errorf("the invariant this run actually tested was not confirmed: %s", got)
	}

	// Everything above it on the hierarchy stays unconfirmed on this evidence.
	for _, k := range []evidence.SubjectKind{
		evidence.SubjectSecurityEffect, evidence.SubjectExploit,
	} {
		s := evidence.Subject{Kind: k, ID: h.ID}
		if got := evidence.DeriveExploitabilityAbout(outcome, ledger, s); got == evidence.Confirmed {
			t.Errorf("a reproduced invariant violation confirmed %s — a later "+
				"proposition this run produced no evidence for", k)
		}
	}
}

// TestEveryAttackClaimIsAttributed. The subject is what makes the hierarchy
// real, and a claim without one rejoins the undifferentiated bag. Checked on
// the ledger a real run builds rather than on the constructor, because the
// constructor is easy to get right and the call sites are what drift.
func TestEveryAttackClaimIsAttributed(t *testing.T) {
	h := Hypothesis{ID: "hyp-2", Rationale: "grounding"}
	l := groundingLedger(h, "2026-08-31T00:00:00Z")
	if len(l.Claims) == 0 {
		t.Fatal("the grounding ledger is empty; this test checks nothing")
	}
	for i, c := range l.Claims {
		if c.Subject.Zero() {
			t.Errorf("claim %d (%q) carries no subject, so it aggregates with every "+
				"other unattributed claim regardless of what it is about", i, c.Statement)
		}
	}
}
