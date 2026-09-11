package attack

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
)

// Milestone 8.1's exit is that a scan produces a STRUCTURED active-testing
// question: subject, entry point, flow, attacker input, trigger condition,
// assumptions, oracle, missing evidence.
//
// It was met on the path that starts from a finding and not on the path that
// starts from the AI inventory. Measured on 2026-09-11: of six hypotheses
// `nox scan --emit-hypotheses` emitted for examples/ai-app, four carried
// subject, trigger condition, oracle, assumptions and unknowns, and the two
// tool-matrix ones carried none of them. On nox's own repository the ratio is
// worse, because the tool-matrix path is the ONLY one that produces a
// hypothesis there: 0 of 2.
//
// A hypothesis that answers none of those questions is a scenario name with a
// rationale attached. The reader cannot disagree with it — which is what
// stating assumptions is for — and `nox attack run` receives no statement of
// what would settle it.

// planFromToolMatrix builds a plan whose hypotheses come only from the
// inventory, with no finding to ground them.
func planFromToolMatrix(t *testing.T) *Plan {
	t.Helper()
	inv := ai.NewInventory()
	inv.ToolMatrix = []ai.ToolPermissionSet{
		{
			Agent: "support-agent",
			Path:  "agents/support.py",
			Tools: []string{"read_file", "http_post", "delete_account"},
			Capabilities: map[string][]string{
				"read_file":      {"file_read"},
				"http_post":      {"http_request"},
				"delete_account": {"admin"},
			},
		},
	}
	plan, err := BuildPlan(PlanInput{Inventory: inv, Now: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Fatal("fixture: expected tool-matrix hypotheses")
	}
	return plan
}

// TestEveryHypothesisStatesWhatWouldSettleIt. The oracle is chosen when the
// hypothesis is built rather than at fire time, so a reader of the plan knows
// what success would look like before anything executes. A hypothesis without
// one defers that choice to the runner and tells the reader nothing.
func TestEveryHypothesisStatesWhatWouldSettleIt(t *testing.T) {
	for _, h := range planFromToolMatrix(t).Hypotheses {
		if h.ExpectedOracle == "" {
			t.Errorf("%s names no expected oracle, so the plan does not say what "+
				"success would look like", h.ID)
		}
	}
}

// TestEveryHypothesisStatesItsTriggerCondition. A suspicion, not a constraint —
// nox records no path constraints — but silence is not the same as "there is no
// condition", and a reader cannot tell the two apart.
func TestEveryHypothesisStatesItsTriggerCondition(t *testing.T) {
	for _, h := range planFromToolMatrix(t).Hypotheses {
		if h.TriggerCondition == "" {
			t.Errorf("%s states no trigger condition", h.ID)
		}
		if h.TriggerCondition != "" && !strings.HasPrefix(h.TriggerCondition, "suspected:") {
			t.Errorf("%s states its trigger condition as though it were derived: %q",
				h.ID, h.TriggerCondition)
		}
	}
}

// TestEveryHypothesisStatesWhatItTookForGranted. Naming the assumptions is what
// lets a reader disagree with the hypothesis rather than only with its result —
// and an inventory-derived hypothesis rests on MORE of them than a
// finding-derived one, because it is grounded in a declared tool rather than in
// observed code.
func TestEveryHypothesisStatesWhatItTookForGranted(t *testing.T) {
	for _, h := range planFromToolMatrix(t).Hypotheses {
		if len(h.Assumptions) == 0 {
			t.Fatalf("%s assumes nothing, which would mean nox established "+
				"everything it needed. It established a tool declaration in a manifest", h.ID)
		}
		joined := strings.ToLower(strings.Join(h.Assumptions, " | "))
		// The entry point is empty on every tool-matrix hypothesis, and the
		// finding-derived path already words this exact gap as an assumption.
		if h.EntryPoint == "" && !strings.Contains(joined, "entry point") {
			t.Errorf("%s has no entry point and does not say so; `nox attack run` "+
				"will probe the base URL and every request will miss: %v", h.ID, h.Assumptions)
		}
		// The grounding is a declaration, not an observation of untrusted input
		// reaching the tool. That is the assumption most likely to be wrong.
		if !strings.Contains(joined, "declar") && !strings.Contains(joined, "manifest") {
			t.Errorf("%s does not say its grounding is a declared tool rather than "+
				"an observed call: %v", h.ID, h.Assumptions)
		}
	}
}

// TestTheFindingDerivedPathKeepsAnswering guards the half that already worked,
// so a change made for the tool-matrix path cannot quietly cost it.
func TestTheFindingDerivedPathKeepsAnswering(t *testing.T) {
	plan, err := BuildPlan(PlanInput{
		Root:     "/repo",
		Findings: []findings.Finding{injectionFinding("fp-complete")},
		Now:      "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Fatal("fixture: expected injection hypotheses")
	}
	for _, h := range plan.Hypotheses {
		if h.ExpectedOracle == "" || h.TriggerCondition == "" || len(h.Assumptions) == 0 {
			t.Errorf("%s lost a field the finding-derived path already answered: "+
				"oracle=%q trigger=%q assumptions=%d",
				h.ID, h.ExpectedOracle, h.TriggerCondition, len(h.Assumptions))
		}
	}
}
