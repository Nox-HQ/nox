package verify_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/reach"
	"github.com/nox-hq/nox/core/verify"
)

func path() evidence.Subject {
	return evidence.Subject{Kind: evidence.SubjectCallPath, ID: "main→handler→exec"}
}

func model() reach.Scope {
	return reach.Scope{Analysis: "z3", Capability: capability.Taint, BuildID: "m1"}
}

// TestUNSATRefutesAPathAndNeverAFinding is Milestone E's central rule.
//
// A solver returning UNSAT has refuted a PATH under a model, an abstraction and
// a set of bounds. It has not refuted the finding, and there must be no way to
// say that it has. The subject is required, so a result cannot be filed against
// nothing and reach everything by sharing the zero subject.
func TestUNSATRefutesAPathAndNeverAFinding(t *testing.T) {
	r, ok := verify.Verify("z3", path(), verify.InfeasibleWithinScope, model(),
		"no satisfying assignment")
	if !ok {
		t.Fatalf("a complete model could not state a negative: %+v", r)
	}
	c, made := r.Claim("2026-08-31T00:00:00Z")
	if !made {
		t.Fatal("a refuting result produced no claim")
	}
	if !c.Refutes() {
		t.Error("an infeasibility result does not refute")
	}
	if c.Subject != path() {
		t.Errorf("the claim is filed against %v, not the path it is about", c.Subject)
	}
	if c.Kind == evidence.KindControlledReproduction {
		t.Error("a solver's answer was recorded at reproduction strength; nothing ran")
	}

	// An unattributed result is refused: it would aggregate with every other
	// unattributed claim, which is how a solver's answer about a path reaches a
	// finding.
	if _, ok := verify.Verify("z3", evidence.Subject{}, verify.InfeasibleWithinScope, model(), "x"); ok {
		t.Error("a result with no subject was accepted; it aggregates with everything")
	}
}

// TestANegativeNeedsACompleteModel. Same asymmetry as core/reach, for the same
// reason: UNSAT on the paths a bounded model explored is not "no path exists".
func TestANegativeNeedsACompleteModel(t *testing.T) {
	bounded := model()
	bounded.Limitations = []reach.Limitation{reach.BoundedLoops}

	r, ok := verify.Verify("z3", path(), verify.InfeasibleWithinScope, bounded, "unsat")
	if ok {
		t.Error("a bounded model stated an unqualified negative")
	}
	if r.Outcome != verify.Unknown {
		t.Errorf("the downgraded outcome is %q, want UNKNOWN", r.Outcome)
	}
	if !strings.Contains(r.Detail, "downgraded") {
		t.Errorf("the downgrade is silent: %q", r.Detail)
	}

	// The positive direction is unaffected: finding a satisfying assignment is
	// existential, and a bounded search that found one still found one.
	if _, ok := verify.Verify("z3", path(), verify.Feasible, bounded, "sat"); !ok {
		t.Error("a bounded model was blocked from reporting a path it did find")
	}
}

// TestOnlyExecutionEarnsReproductionStrength. A solver is confident about a
// model, not about the world, so no outcome it can produce may reach the kind
// that carries CONFIRMED.
func TestOnlyExecutionEarnsReproductionStrength(t *testing.T) {
	for _, o := range []verify.Outcome{
		verify.Feasible, verify.InfeasibleWithinScope, verify.Observed, verify.Violated,
	} {
		r, _ := verify.Verify("z3", path(), o, model(), "d")
		c, made := r.Claim("t")
		if made && c.Kind == evidence.KindControlledReproduction {
			t.Errorf("outcome %s reached reproduction strength without anything running", o)
		}
	}
	repro, _ := verify.Verify("nox-attack", path(), verify.Reproduced, model(), "d")
	c, _ := repro.Claim("t")
	if c.Kind != evidence.KindControlledReproduction {
		t.Errorf("a reproduction was recorded at %q", c.Kind)
	}
}

// TestUnknownFilesNoClaim. A producer that could not tell has not contributed
// evidence, and an empty claim makes a ledger look busier than the enquiry was.
func TestUnknownFilesNoClaim(t *testing.T) {
	r, _ := verify.Verify("z3", path(), verify.Unknown, model(), "timeout")
	if _, made := r.Claim("t"); made {
		t.Error("an UNKNOWN outcome filed a claim")
	}
	if !strings.Contains(r.Statement(), "could not determine") {
		t.Errorf("statement %q does not say the producer could not tell", r.Statement())
	}
}

// TestNoStatementAssertsSafety, and no negative drops its scope — the scope is
// what makes a negative true.
func TestNoStatementAssertsSafety(t *testing.T) {
	banned := []string{"safe", "secure", "no risk", "not vulnerable", "prevented", "clean"}
	for _, o := range []verify.Outcome{
		verify.Feasible, verify.InfeasibleWithinScope, verify.Observed,
		verify.Violated, verify.Reproduced, verify.Unknown,
	} {
		r := verify.Result{Producer: "p", Subject: path(), Outcome: o, Scope: model()}
		got := strings.ToLower(r.Statement())
		for _, w := range banned {
			if strings.Contains(got, w) {
				t.Errorf("%s says %q, which contains %q", o, got, w)
			}
		}
		if o.Refutes() && !strings.Contains(got, "z3") {
			t.Errorf("a negative dropped its scope: %q", got)
		}
	}
}
