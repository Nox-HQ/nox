package fix

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestPlanPatchAndApply(t *testing.T) {
	lines := []string{"spec:", "  securityContext:", "    privileged: true"}
	f := &findings.Finding{RuleID: "IAC-007", Location: findings.Location{StartLine: 3}}

	p, ok := PlanPatch(f, lines)
	if !ok || p.Before != "privileged: true" || p.After != "privileged: false" {
		t.Fatalf("patch = %+v, %v", p, ok)
	}
	if p.Review == "" {
		t.Error("turning privileged off can stop a container starting; the patch must say a person should look")
	}
	if !p.Apply(lines) || lines[2] != "    privileged: false" {
		t.Fatalf("apply left %q", lines[2])
	}
	// Applying again is a no-op: the plan is recomputed from the live line.
	if p.Apply(lines) {
		t.Error("a patch applied twice")
	}
	if _, ok := PlanPatch(f, lines); ok {
		t.Error("proposed a change to a line that no longer holds the insecure value")
	}
}

func TestPlanPatchRefusesWhatItCannotSee(t *testing.T) {
	lines := []string{"a: b"}
	cases := map[string]findings.Finding{
		"no fixer for the rule": {RuleID: "SEC-001", Location: findings.Location{StartLine: 1}},
		"line out of range":     {RuleID: "IAC-007", Location: findings.Location{StartLine: 9}},
		"line zero":             {RuleID: "IAC-007", Location: findings.Location{StartLine: 0}},
	}
	for name, f := range cases {
		if _, ok := PlanPatch(&f, lines); ok {
			t.Errorf("%s: proposed a patch", name)
		}
	}
}

// Every deterministic fix says whether a person should look, and only the one
// that cannot change a deployed system says no.
func TestOnlyContinueOnErrorNeedsNoReview(t *testing.T) {
	for id, cf := range ContentFixes {
		if (cf.Review == "") != (id == "IAC-018") {
			t.Errorf("%s: Review = %q", id, cf.Review)
		}
	}
}
