package catalog

import "testing"

// TestBuiltinRulesAreCoherent applies the load-time check to the rules that
// never pass through the loader.
//
// validateRule guards YAML rules. Every built-in is a Go struct built in
// package init, so nothing validated them at all: a built-in could declare a
// subject precondition the matcher never reads, or a span nobody implements,
// and the only symptom would be a rule that quietly finds nothing.
//
// Measured when this landed: 1531 rules, 55 on the absence matcher, 31 of
// those structural, 2 carrying a subject precondition — and zero incoherent.
// The counts are asserted below because a check that runs over no absence
// rules passes for the wrong reason.
func TestBuiltinRulesAreCoherent(t *testing.T) {
	total, absence, structural := 0, 0, 0

	for _, rs := range allRuleSets() {
		for _, r := range rs.Rules() {
			total++
			if r.MatcherType == "absence" {
				absence++
			}
			if len(r.AbsenceResourceTypes) > 0 {
				structural++
			}
			if err := r.CheckCoherence(); err != nil {
				t.Errorf("%v", err)
			}
		}
	}

	// Floors, not equalities: rules are added constantly, and an equality here
	// would fail on every unrelated rule PR. What must never happen is the
	// count collapsing, which would mean this test walked a set with nothing
	// in it to check.
	if total < 1000 {
		t.Errorf("walked %d rules; the catalog is far smaller than expected, so this check "+
			"is passing over the wrong input", total)
	}
	if absence < 20 {
		t.Errorf("only %d absence rules seen; the absence clauses are the ones with teeth "+
			"and they are not being exercised", absence)
	}
	if structural < 10 {
		t.Errorf("only %d structural absence rules seen; the structural/text split is what "+
			"CheckCoherence exists to police", structural)
	}
}
