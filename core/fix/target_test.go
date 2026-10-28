package fix

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// fakeChecker answers from a table keyed by candidate version.
type fakeChecker map[string][]Residual

func (f fakeChecker) Remaining(_ context.Context, _, _, v string) ([]Residual, error) {
	return f[v], nil
}

type errChecker struct{}

func (errChecker) Remaining(context.Context, string, string, string) ([]Residual, error) {
	return nil, errors.New("offline")
}

func axiosOld() []findings.Finding {
	// axios 0.21.1: every advisory that affects it names a fix on the 0.x line;
	// the highest is 0.33.0. GHSA-9fr6 and GHSA-x97p were introduced in 0.27.2
	// and 0.28.0, so 0.21.1 is not affected and its findings never mention them.
	return []findings.Finding{
		vuln("npm", "axios", "0.21.1", "0.21.2"),
		vuln("npm", "axios", "0.21.1", "0.28.0"),
		vuln("npm", "axios", "0.21.1", "0.33.0"),
	}
}

// Counterexample: without a Checker the plan stops at 0.33.0, a version that is
// itself still vulnerable to two advisories.
func TestPlanWithoutCheckerStopsAtStillVulnerableTarget(t *testing.T) {
	plan := PlanUpgrades(axiosOld(), Options{})
	if len(plan.Actions) != 1 || plan.Actions[0].To != "0.33.0" {
		t.Fatalf("got %+v", plan.Actions)
	}
}

func TestPlanChoosesLowestVersionClearingAllAdvisories(t *testing.T) {
	c := fakeChecker{"0.33.0": {{ID: "GHSA-9fr6", FixedIn: "0.34.0"}, {ID: "GHSA-x97p", FixedIn: "0.34.0"}}}
	plan := PlanUpgrades(axiosOld(), Options{Checker: c})
	if len(plan.Actions) != 1 || plan.Actions[0].To != "0.34.0" {
		t.Fatalf("want 0.34.0, got %+v held=%+v", plan.Actions, plan.Held)
	}
	if plan.Actions[0].Remaining != nil || plan.Actions[0].Unverified {
		t.Errorf("a cleared target carries no residue: %+v", plan.Actions[0])
	}
}

// The target moves one named fix at a time, so it is the lowest that clears
// everything, not the highest version that exists.
func TestPlanFollowsChainOfResidualAdvisories(t *testing.T) {
	c := fakeChecker{
		"0.33.0": {{ID: "A", FixedIn: "0.34.0"}},
		"0.34.0": {{ID: "B", FixedIn: "0.35.1"}},
	}
	plan := PlanUpgrades(axiosOld(), Options{Checker: c})
	if len(plan.Actions) != 1 || plan.Actions[0].To != "0.35.1" {
		t.Fatalf("got %+v", plan.Actions)
	}
}

// No version inside the policy clears everything: the move is held, and says
// what would remain in policy and what clears it.
func TestPlanHoldsWhenOnlyAMajorBumpClears(t *testing.T) {
	c := fakeChecker{"0.33.0": {{ID: "GHSA-9fr6", FixedIn: "1.20.0"}}}
	plan := PlanUpgrades(axiosOld(), Options{Checker: c})
	if len(plan.Actions) != 0 || len(plan.Held) != 1 || plan.MajorSkipped != 1 {
		t.Fatalf("want one held move, got actions=%+v held=%+v", plan.Actions, plan.Held)
	}
	h := plan.Held[0]
	if h.To != "1.20.0" || h.PolicyTarget != "0.33.0" || !reflect.DeepEqual(h.Remaining, []string{"GHSA-9fr6"}) {
		t.Errorf("held move should name the clearing version and the residue: %+v", h)
	}
	with := PlanUpgrades(axiosOld(), Options{Checker: c, IncludeMajor: true})
	if len(with.Actions) != 1 || with.Actions[0].To != "1.20.0" || with.Actions[0].PolicyTarget != "" {
		t.Errorf("--include-major should apply the clearing version: %+v", with.Actions)
	}
}

// An advisory with no published fix cannot be cleared by any version; the move
// still happens and says what is left.
func TestPlanReportsAdvisoriesNoVersionClears(t *testing.T) {
	c := fakeChecker{"0.33.0": {{ID: "GHSA-unfixed"}}}
	plan := PlanUpgrades(axiosOld(), Options{Checker: c})
	if len(plan.Actions) != 1 || plan.Actions[0].To != "0.33.0" ||
		!reflect.DeepEqual(plan.Actions[0].Remaining, []string{"GHSA-unfixed"}) {
		t.Fatalf("got %+v", plan.Actions)
	}
}

// An unreachable source must not read as "clears everything".
func TestPlanMarksUnverifiedWhenCheckerFails(t *testing.T) {
	plan := PlanUpgrades(axiosOld(), Options{Checker: errChecker{}})
	if len(plan.Actions) != 1 || !plan.Actions[0].Unverified || plan.Actions[0].To != "0.33.0" {
		t.Fatalf("got %+v", plan.Actions)
	}
}
