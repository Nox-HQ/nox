package fix

import "context"

// Residual is an advisory that still affects a candidate version.
type Residual struct {
	// ID is the advisory identifier.
	ID string
	// FixedIn is the version that closes it for the candidate, or "" when no
	// fix is published for the branch the candidate is on.
	FixedIn string
}

// Checker answers what a candidate version of a package is still vulnerable to.
//
// The findings PlanUpgrades is given describe the INSTALLED version. An
// advisory that was introduced after the installed version (axios 0.27.2 and
// 0.28.0 introduce two) is not among them, yet it affects the version the
// planner is about to move to. Without asking, the first target the findings
// name can be one that is itself still vulnerable, and only a re-scan after
// the upgrade finds out. A nil Checker keeps the planner offline and pure.
type Checker interface {
	Remaining(ctx context.Context, ecosystem, pkg, version string) ([]Residual, error)
}

// maxTargetSteps bounds the search. Each step moves to a strictly higher
// version, so it terminates anyway; the bound is for a source that keeps
// inventing advisories.
const maxTargetSteps = 8

// resolution is the outcome of searching for a version that clears everything.
type resolution struct {
	// Target is the lowest version found that clears every known advisory, or
	// the best reachable one when Remaining is non-empty.
	Target string
	// PolicyTarget and PolicyRemaining are set when the search had to cross a
	// major boundary: the highest version before the crossing and the
	// advisories that would still affect it.
	PolicyTarget    string
	PolicyRemaining []string
	// Remaining are advisories that affect Target and have no fix to move to.
	Remaining []string
	// Unverified is set when the Checker failed, so Target is only what the
	// installed version's findings name.
	Unverified bool
}

// resolveTarget starts from the fix the installed version's findings name and
// raises it, one named fix at a time, until the Checker reports nothing left.
// Every step is a version some advisory itself names as fixed, so the result is
// the lowest such version that clears all of them.
func resolveTarget(ctx context.Context, c Checker, eco, pkg, from, initial string) resolution {
	res := resolution{Target: initial}
	if c == nil {
		return res
	}
	policyOpen := true
	for step := 0; step < maxTargetSteps; step++ {
		rem, err := c.Remaining(ctx, eco, pkg, res.Target)
		if err != nil {
			res.Unverified = true
			return res
		}
		if len(rem) == 0 {
			res.Remaining = nil
			return res
		}
		var fixes, ids []string
		for _, r := range rem {
			ids = append(ids, r.ID)
			if r.FixedIn != "" {
				fixes = append(fixes, r.FixedIn)
			}
		}
		next := BestFix(fixes)
		if next == "" || !IsUpgrade(res.Target, next) {
			res.Remaining = ids
			return res
		}
		if policyOpen && IsMajorBump(from, next) {
			res.PolicyTarget, res.PolicyRemaining = res.Target, ids
			policyOpen = false
		}
		res.Target = next
	}
	return res
}
