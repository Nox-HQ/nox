package attack

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// Milestone 4.2: PREVENTED is reachable only from a POSITIVE observation, and
// absence of evidence must never produce it.
//
// PREVENTED is the most dangerous state nox can emit, more so than CONFIRMED.
// A wrong CONFIRMED sends somebody to look at code that turns out to be fine —
// wasteful, and self-correcting the moment they look. A wrong PREVENTED tells
// them a defence holds, and nobody looks again. "We attacked it and saw
// nothing" and "a defence stopped the attack" produce identical silence, and
// only the second is a claim.
//
// CONFIRMED has a full cross-product contract in the kernel and a producer-side
// one in confirmed_contract_test.go. This is the matching pair for PREVENTED,
// which had e2e coverage for particular failures — a wrong route, an erroring
// target — but nothing walking the combination.
func TestPreventedRequiresAnObservedDefence(t *testing.T) {
	prevented := func(o evidence.RunOutcome) bool {
		return evidence.DeriveExploitability(o, &evidence.Ledger{}) == evidence.Prevented
	}

	// The complete combination: the run happened, finished, was sound, saw no
	// violation, and a defence was actually observed.
	base := evidence.RunOutcome{
		Executed: true, ControlSound: true, DefenseObserved: true,
	}
	if !prevented(base) {
		t.Fatal("the complete combination does not reach PREVENTED; the rest of this " +
			"test is vacuous")
	}

	for name, mutate := range map[string]func(evidence.RunOutcome) evidence.RunOutcome{
		// The one that matters most: no defence was seen. The run simply found
		// nothing, which is not the same sentence.
		"an observed defence": func(o evidence.RunOutcome) evidence.RunOutcome {
			o.DefenseObserved = false
			return o
		},
		// Nothing ran. A scan is permanently in this state.
		"real execution": func(o evidence.RunOutcome) evidence.RunOutcome {
			o.Executed = false
			return o
		},
		// The environment could not tell obedience from echo, so it could not
		// tell a defence from a coincidence either.
		"sound control": func(o evidence.RunOutcome) evidence.RunOutcome {
			o.ControlSound = false
			return o
		},
		// The search stopped early. An unfinished search is exactly why you
		// might see nothing, which is why the kernel bars budget here and not
		// for CONFIRMED.
		"a completed run": func(o evidence.RunOutcome) evidence.RunOutcome {
			o.BudgetExhausted = true
			return o
		},
		// The probes never reached the code. Neither is evidence a fix holds.
		"a reachable target": func(o evidence.RunOutcome) evidence.RunOutcome {
			o.TargetErrors = 1
			return o
		},
	} {
		t.Run(name, func(t *testing.T) {
			if prevented(mutate(base)) {
				t.Errorf("PREVENTED without %s — absence of evidence became evidence of "+
					"a defence, and a defence nobody saw is the one verdict that stops "+
					"anybody looking again", name)
			}
		})
	}
}

// A violation outranks a defence. Seeing both means the attack got through,
// whatever else also happened.
func TestAnObservedViolationIsNeverPrevented(t *testing.T) {
	o := evidence.RunOutcome{
		Executed: true, ControlSound: true, DefenseObserved: true, Violated: true,
	}
	if got := evidence.DeriveExploitability(o, &evidence.Ledger{}); got == evidence.Prevented {
		t.Error("a run that observed the invariant violated reported PREVENTED")
	}
}

// A scan can never reach PREVENTED, and this is the assertion that keeps
// milestone 4.1 from having quietly widened what a scan may claim.
//
// Adjudication now runs on every scan rather than only on those recording
// reasoning. That is safe precisely because the state is derived from the run
// outcome, and a scan's outcome has Executed false — so POTENTIAL is the only
// reachable value. If that ever stops being true, a scan would start emitting
// verdicts about defences it never tested.
func TestAScanOutcomeCannotReachPreventedOrConfirmed(t *testing.T) {
	var scanOutcome evidence.RunOutcome // exactly what core/scan passes

	// Even handed the strongest possible ledger.
	ledger := &evidence.Ledger{Claims: []evidence.Claim{{
		Kind:      evidence.KindControlledReproduction,
		Statement: "reproduced",
	}}}

	got := evidence.DeriveExploitability(scanOutcome, ledger)
	if got == evidence.Prevented || got == evidence.Confirmed {
		t.Fatalf("a scan's run outcome reached %s. nox executes nothing during a scan, "+
			"so no state above POTENTIAL is honest, and 4.1 writes this value onto "+
			"every finding.", got)
	}
	if got != evidence.Potential {
		t.Errorf("a scan's run outcome reached %s, want POTENTIAL", got)
	}
}
