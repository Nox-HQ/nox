package attack

import (
	"context"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// Milestone J: directed active verification, measured by hypotheses resolved
// per unit of verification effort — not by coverage.
//
// The direction already exists: Run consumes a plan of grounded hypotheses and
// fires probes toward each. What was missing is the accounting, because a
// coverage number cannot distinguish a harness that fired a million probes and
// confirmed nothing from one that fired three and confirmed one. These tests
// run the real HTTP harness (e2e_test.go) and check the accounting against it.

// TestResolutionIsThreeValued. A hypothesis is confirmed, refuted, or left
// inconclusive, and the third is the honest majority rather than a failure.
// Counting only confirmations would make the harness look worse the more
// careful it was.
func TestResolutionIsThreeValued(t *testing.T) {
	cfg := e2eCfg("/vuln")
	cs := MintCanaries(cfg.Seed)
	srv := e2eApp(t, cs)

	res, err := Run(context.Background(), piPlan(t), e2eTarget(srv.URL), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	resolutions := res.Resolutions()
	if len(resolutions) == 0 {
		t.Fatal("the run produced no resolutions to account for")
	}
	// Every resolution's attempt count is the effort that hypothesis cost, and
	// a confirmed one must have cost at least one probe — a confirmation from
	// zero attempts would be a verdict with no verification behind it.
	var confirmed int
	for _, r := range resolutions {
		if r.Outcome == ResolvedConfirmed {
			confirmed++
			if r.Attempts == 0 {
				t.Errorf("%s is confirmed with zero attempts; a verdict with no "+
					"verification behind it", r.HypothesisID)
			}
		}
	}
	if confirmed == 0 {
		t.Fatal("the vulnerable route confirmed nothing; the metric has nothing to measure")
	}
}

// TestEfficiencyMeasuresResolutionNotCoverage is the metric itself.
//
// attempts-per-resolution is the headline: a lower number is a harness that
// decides more per probe. The vulnerable route resolves at least one hypothesis,
// so the ratio is finite and positive; a run that decided nothing reports
// Resolved=0 rather than a divided value that reads as success.
func TestEfficiencyMeasuresResolutionNotCoverage(t *testing.T) {
	cfg := e2eCfg("/vuln")
	cs := MintCanaries(cfg.Seed)
	srv := e2eApp(t, cs)

	res, err := Run(context.Background(), piPlan(t), e2eTarget(srv.URL), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	e := res.Efficiency()

	if e.Hypotheses == 0 {
		t.Fatal("no hypotheses accounted for")
	}
	if e.Attempts == 0 {
		t.Error("the run reports zero verification effort while resolving hypotheses")
	}
	if e.Resolved == 0 {
		t.Fatal("the vulnerable route resolved nothing")
	}
	if e.Confirmed+e.Refuted != e.Resolved {
		t.Errorf("resolved (%d) is not confirmed+refuted (%d+%d)",
			e.Resolved, e.Confirmed, e.Refuted)
	}
	if e.Confirmed+e.Refuted+e.Inconclusive+e.NotRun != e.Hypotheses {
		t.Error("the outcomes do not sum to the hypothesis count; something is uncounted")
	}
	if apr := e.AttemptsPerResolution(); apr <= 0 {
		t.Errorf("attempts-per-resolution is %v with a resolution present", apr)
	}
	t.Logf("directed verification: %d hypotheses, %d attempts, %d resolved "+
		"(%d confirmed, %d refuted), %.1f attempts/resolution",
		e.Hypotheses, e.Attempts, e.Resolved, e.Confirmed, e.Refuted,
		e.AttemptsPerResolution())
}

// TestNothingResolvedReportsSoRatherThanDividing. A run that decides nothing
// must be legible as such, not as a zero or an infinity that a caller might
// read as a clean result.
func TestNothingResolvedReportsSoRatherThanDividing(t *testing.T) {
	// The wrong route: 404 to every probe, so nox reaches no code and resolves
	// nothing. This is the shape of the bug where a suite printed "fix holds"
	// for a target it never touched.
	cfg := e2eCfg("/does-not-exist")
	cs := MintCanaries(cfg.Seed)
	srv := e2eApp(t, cs)

	res, err := Run(context.Background(), piPlan(t), e2eTarget(srv.URL), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	e := res.Efficiency()
	if e.Confirmed != 0 {
		t.Errorf("a route that was never reached confirmed %d hypotheses", e.Confirmed)
	}
	if apr := e.AttemptsPerResolution(); apr != 0 {
		t.Errorf("attempts-per-resolution is %v when nothing resolved; the caller "+
			"must read Resolved=%d, not a divided value", apr, e.Resolved)
	}
}

// TestPreventedIsRefutedNotConfirmedAndNotClean. PREVENTED is the kernel's word
// for an observed defense: the objective was not reachable, so the hypothesis
// is refuted — resolved, in the negative — but the run must never read it as
// "the target is secure".
func TestPreventedIsRefutedNotConfirmed(t *testing.T) {
	tr := &Trace{
		HypothesisID: "h", Exploitability: evidence.Prevented,
		Outcome:  evidence.RunOutcome{Executed: true, DefenseObserved: true},
		Attempts: []Attempt{{}},
	}
	if got := resolutionOf(tr); got != ResolvedRefuted {
		t.Errorf("a PREVENTED trace resolved as %q, want refuted", got)
	}

	// And an inconclusive execution is inconclusive, never refuted-by-default.
	inc := &Trace{
		HypothesisID: "h2", Exploitability: evidence.Inconclusive,
		Outcome: evidence.RunOutcome{Executed: true},
	}
	if got := resolutionOf(inc); got != ResolvedInconclusive {
		t.Errorf("an inconclusive run resolved as %q; treating it as decided is how "+
			"a harness reports progress it did not make", got)
	}

	// A hypothesis that never executed is not-run, not inconclusive: it cost
	// nothing and should not dilute the effort denominator.
	notRun := &Trace{HypothesisID: "h3", Exploitability: evidence.Potential}
	if got := resolutionOf(notRun); got != ResolvedNotRun {
		t.Errorf("an unexecuted hypothesis resolved as %q, want not_run", got)
	}
}
