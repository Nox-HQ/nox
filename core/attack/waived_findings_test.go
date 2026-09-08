package attack

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func waivedInjection(status findings.Status) findings.Finding {
	return findings.Finding{
		RuleID:      "AI-PI-001",
		Fingerprint: "fp-" + string(status),
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		Status:      status,
		Message:     "Prompt injection: untrusted source flows into LLM call",
		Location:    findings.Location{FilePath: "app.py", StartLine: 6},
	}
}

// A finding somebody waived does not ground an attack.
//
// `nox attack run --authorize` fires real payloads at a live target, and it was
// doing so for findings an operator had explicitly accepted — a nox:ignore, a
// baseline entry, a VEX statement. report.ActiveFindings already named `attack`
// as a consumer that needs this rule; nothing applied it.
func TestWaivedFindingsGroundNoAttack(t *testing.T) {
	for _, status := range []findings.Status{
		findings.StatusSuppressed,
		findings.StatusBaselined,
	} {
		t.Run(string(status), func(t *testing.T) {
			plan, err := BuildPlan(PlanInput{
				Root:     ".",
				Findings: []findings.Finding{waivedInjection(status)},
				Now:      "2026-09-08T00:00:00Z",
			})
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			if len(plan.Hypotheses) != 0 {
				t.Errorf("a %s finding produced %d hypotheses; an operator who accepted it "+
					"would have had payloads fired at their target for it",
					status, len(plan.Hypotheses))
			}
		})
	}
}

// Waived is not the same as silent. SkipNote exists so a plan is a complete
// account — "a finding either grounds a hypothesis or appears here" — which is
// why the filter is in BuildPlan and not in the loader. Filtering upstream
// would have dropped waived findings out of Skipped as well, trading one silent
// behaviour for another.
func TestWaivedFindingsAreRecordedAsSkipped(t *testing.T) {
	plan, err := BuildPlan(PlanInput{
		Root:     ".",
		Findings: []findings.Finding{waivedInjection(findings.StatusSuppressed)},
		Now:      "2026-09-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Skipped) != 1 {
		t.Fatalf("got %d skip notes, want 1", len(plan.Skipped))
	}
	if !strings.Contains(plan.Skipped[0].Reason, "suppressed") {
		t.Errorf("the skip reason does not say the finding was waived: %q", plan.Skipped[0].Reason)
	}
	if plan.Skipped[0].RuleID != "AI-PI-001" {
		t.Errorf("skip note names rule %q", plan.Skipped[0].RuleID)
	}
}

// An active finding still grounds one, so the filter above is not simply
// switching hypothesis generation off.
func TestActiveFindingsStillGroundAttacks(t *testing.T) {
	plan, err := BuildPlan(PlanInput{
		Root:     ".",
		Findings: []findings.Finding{waivedInjection(findings.StatusNew)},
		Now:      "2026-09-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Error("an active injection finding grounded no hypothesis; the waiver filter is " +
			"suppressing everything")
	}
}

// A plan with nothing to attempt serialises as [] rather than null. A consumer
// that can iterate an empty list cannot iterate a null, and no hypotheses is a
// normal result — most scans raise none.
func TestEmptyPlanSerialisesAsEmptyLists(t *testing.T) {
	plan, err := BuildPlan(PlanInput{Root: ".", Now: "2026-09-08T00:00:00Z"})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	raw, err := plan.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	for _, key := range []string{`"hypotheses": null`, `"skipped": null`} {
		if strings.Contains(string(raw), key) {
			t.Errorf("plan contains %s", key)
		}
	}
}
