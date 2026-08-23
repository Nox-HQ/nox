package evidence

import "testing"

// deterministicLedger returns a ledger backed by a machine-checkable claim.
func deterministicLedger() *Ledger {
	l := &Ledger{}
	l.Add(Claim{Kind: KindDynamicExploit, Statement: "canary observed at controlled sink"})
	return l
}

// semanticLedger returns a ledger backed only by an LLM judgment.
func semanticLedger() *Ledger {
	l := &Ledger{}
	l.Add(Claim{Kind: KindSemantic, Statement: "the judge believes the attack succeeded"})
	return l
}

func TestDeriveExploitabilityWithoutExecution(t *testing.T) {
	if got := DeriveExploitability(RunOutcome{}, nil); got != Potential {
		t.Errorf("no hypothesis, no run = %s, want POTENTIAL", got)
	}
	got := DeriveExploitability(RunOutcome{HypothesisConstructed: true}, nil)
	if got != Plausible {
		t.Errorf("hypothesis but no run = %s, want PLAUSIBLE", got)
	}
}

func TestConfirmedRequiresDeterministicEvidence(t *testing.T) {
	base := RunOutcome{
		HypothesisConstructed: true,
		Executed:              true,
		Violated:              true,
		Reproduced:            true,
		ControlSound:          true,
	}
	if got := DeriveExploitability(base, deterministicLedger()); got != Confirmed {
		t.Fatalf("reproduced violation with deterministic evidence = %s, want CONFIRMED", got)
	}
	// The same observed violation, backed only by an LLM's opinion, must not
	// confirm. This is the single most important rule in the package.
	if got := DeriveExploitability(base, semanticLedger()); got != Inconclusive {
		t.Fatalf("violation backed only by a semantic judge = %s, want INCONCLUSIVE", got)
	}
	if got := DeriveExploitability(base, nil); got != Inconclusive {
		t.Fatalf("violation with no ledger = %s, want INCONCLUSIVE", got)
	}
}

func TestUnreproducedViolationIsInconclusive(t *testing.T) {
	o := RunOutcome{
		HypothesisConstructed: true,
		Executed:              true,
		Violated:              true,
		Reproduced:            false,
		ControlSound:          true,
	}
	if got := DeriveExploitability(o, deterministicLedger()); got != Inconclusive {
		t.Fatalf("one-off violation = %s, want INCONCLUSIVE", got)
	}
}

// If the benign control tripped, the environment cannot tell obedience from
// noise, so a "violation" observed in it proves nothing.
func TestUnsoundControlCannotConfirm(t *testing.T) {
	o := RunOutcome{
		HypothesisConstructed: true,
		Executed:              true,
		Violated:              true,
		Reproduced:            true,
		ControlSound:          false,
	}
	if got := DeriveExploitability(o, deterministicLedger()); got != Inconclusive {
		t.Fatalf("violation in an unsound environment = %s, want INCONCLUSIVE", got)
	}
}

func TestPreventedRequiresAnObservedDefenseAndACompleteRun(t *testing.T) {
	prevented := RunOutcome{
		HypothesisConstructed: true,
		Executed:              true,
		DefenseObserved:       true,
		ControlSound:          true,
	}
	if got := DeriveExploitability(prevented, nil); got != Prevented {
		t.Fatalf("observed defense = %s, want PREVENTED", got)
	}

	// A run cut short by a budget saw nothing conclusive; calling that
	// "prevented" is exactly the false confidence §25 forbids.
	cutShort := prevented
	cutShort.BudgetExhausted = true
	if got := DeriveExploitability(cutShort, nil); got != Inconclusive {
		t.Fatalf("budget-exhausted run = %s, want INCONCLUSIVE", got)
	}

	// Same for a run that could not reach the target.
	unreachable := prevented
	unreachable.TargetErrors = 3
	if got := DeriveExploitability(unreachable, nil); got != Inconclusive {
		t.Fatalf("run with target errors = %s, want INCONCLUSIVE", got)
	}
}

// "We tried and nothing happened" is not "it is defended", and it is certainly
// not "it is safe".
func TestSilenceIsNotPrevention(t *testing.T) {
	o := RunOutcome{
		HypothesisConstructed: true,
		Executed:              true,
		Violated:              false,
		DefenseObserved:       false,
		ControlSound:          true,
	}
	if got := DeriveExploitability(o, nil); got != Inconclusive {
		t.Fatalf("no violation and no observed defense = %s, want INCONCLUSIVE", got)
	}
}

func TestDescribeNeverClaimsSafety(t *testing.T) {
	for _, e := range []Exploitability{Potential, Plausible, Prevented, Inconclusive, Confirmed} {
		d := Describe(e)
		if d == "" {
			t.Errorf("Describe(%s) returned an empty string", e)
		}
		if d == "safe" || d == "not vulnerable" {
			t.Errorf("Describe(%s) = %q claims safety, which nox must never assert", e, d)
		}
	}
	if got := Describe(Prevented); got != "not exploited under the strategies tested; a defense was observed" {
		t.Errorf("PREVENTED wording drifted: %q", got)
	}
	if Describe(Exploitability("???")) != "unknown exploitability state" {
		t.Error("unknown state should describe itself as unknown")
	}
}
