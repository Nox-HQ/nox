package secrets

import (
	"math/rand"
	"strings"
	"testing"
)

// The equivalence test is only as strong as the branches its random sets
// reach. This counts each kind of suppression the reference produces over
// the same generator and fails if any is absent, so a generator change that
// stops exercising a branch cannot silently weaken the oracle.
func TestDedupEquivalenceSetsReachEveryBranch(t *testing.T) {
	spec := NewAnalyzer().spec
	ruleIDs := []string{
		"SEC-371", "SEC-952", "SEC-100", "SEC-105", "SEC-084", "SEC-251",
		"SEC-003", "SEC-017", "SEC-216", "SEC-001", "SEC-508",
		"SEC-018", "SEC-030", "SEC-023", "SEC-007",
		"SEC-073", "SEC-085", "SEC-082", "SEC-183", "SEC-005", "SEC-469",
		"SEC-161", "SEC-162", "SEC-163",
	}
	r := rand.New(rand.NewSource(827))
	counts := map[string]int{}
	for c := 0; c < 4000; c++ {
		content, lines := equivalenceContent(r)
		in := equivalenceFindings(r, lines, ruleIDs)
		_, dropped := refDedupBySpecificity(cloneFindings(in), spec, content)
		for _, d := range dropped {
			switch {
			case strings.HasPrefix(d.reason, "two JWT owners overlap"):
				counts["jwt-owner tie-break"]++
			case strings.HasPrefix(d.reason, "the matched token's prefix") && d.dropped == d.survivor:
				counts["anchor self-drop"]++
			case strings.HasPrefix(d.reason, "the matched token's prefix"):
				counts["non-owner drop"]++
			case strings.HasPrefix(d.reason, "a more specific rule"):
				counts["specificity collapse"]++
			default:
				counts["other"]++
			}
		}
	}
	t.Logf("suppressions by branch: %v", counts)
	for _, branch := range []string{"jwt-owner tie-break", "anchor self-drop", "non-owner drop", "specificity collapse"} {
		if counts[branch] < 10 {
			t.Errorf("the equivalence sets reach %q only %d times", branch, counts[branch])
		}
	}
}
