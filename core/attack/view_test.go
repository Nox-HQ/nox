package attack

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

func TestAggregateSkipsGroupsAndOrders(t *testing.T) {
	notes := []SkipNote{
		{RuleID: "IAC-001", Reason: "no scenario"},
		{RuleID: "SEC-001", Reason: "no scenario"},
		{RuleID: "IAC-001", Reason: "no scenario"},
		{RuleID: "IAC-001", Reason: "no scenario"},
		{RuleID: "SEC-001", Reason: "no scenario"},
		{RuleID: "AAA-001", Reason: "no scenario"},
	}
	got := AggregateSkips(notes)
	if len(got) != 3 {
		t.Fatalf("got %d groups, want 3", len(got))
	}
	// Most-skipped first: IAC-001 (3), SEC-001 (2), then AAA-001 (1).
	if got[0].RuleID != "IAC-001" || got[0].Count != 3 {
		t.Errorf("first = %+v, want IAC-001 x3", got[0])
	}
	if got[1].RuleID != "SEC-001" || got[1].Count != 2 {
		t.Errorf("second = %+v, want SEC-001 x2", got[1])
	}
	if got[2].RuleID != "AAA-001" || got[2].Count != 1 {
		t.Errorf("third = %+v, want AAA-001 x1", got[2])
	}
}

// Ties on count break by rule id, so the projection is stable run to run — a
// consumer diffing two runs must not see spurious reordering.
func TestAggregateSkipsTiesBreakByRuleID(t *testing.T) {
	got := AggregateSkips([]SkipNote{
		{RuleID: "ZZZ-001"}, {RuleID: "AAA-001"}, {RuleID: "MMM-001"},
	})
	want := []string{"AAA-001", "MMM-001", "ZZZ-001"}
	for i, w := range want {
		if got[i].RuleID != w {
			t.Errorf("group[%d] = %s, want %s", i, got[i].RuleID, w)
		}
	}
}

func TestAggregateSkipsEmpty(t *testing.T) {
	if got := AggregateSkips(nil); got != nil {
		t.Errorf("AggregateSkips(nil) = %v, want nil", got)
	}
}

func TestPathLabelsFallsBackToID(t *testing.T) {
	steps := []PathStep{
		{ID: "a", Label: "entry"},
		{ID: "b"}, // no label -> falls back to id
	}
	got := PathLabels(steps)
	if len(got) != 2 || got[0] != "entry" || got[1] != "b" {
		t.Fatalf("PathLabels = %v, want [entry b]", got)
	}
	if PathLabels(nil) != nil {
		t.Error("PathLabels(nil) should be nil")
	}
}

func TestRenderPathArrowForm(t *testing.T) {
	steps := []PathStep{{ID: "a", Label: "in"}, {ID: "b", Label: "model"}, {ID: "c"}}
	if got := RenderPath(steps); got != "in -> model -> c" {
		t.Errorf("RenderPath = %q, want %q", got, "in -> model -> c")
	}
	if got := RenderPath(nil); got != "" {
		t.Errorf("RenderPath(nil) = %q, want empty", got)
	}
}

// A plan executes nothing, so every hypothesis view must be PLAUSIBLE — sourced
// from the evidence ladder, not a literal, so the CLI and MCP cannot disagree
// on the word.
func TestNewPlanViewHypothesesArePlausible(t *testing.T) {
	p := &Plan{
		Root:      "/repo",
		Scenarios: []Scenario{{ID: "PI-DIRECT"}},
		Hypotheses: []Hypothesis{
			{ID: "h1", ScenarioID: "PI-DIRECT", Objective: "obey", Rationale: "because",
				Path: []PathStep{{ID: "in", Label: "entry"}, {ID: "llm", Label: "model"}}},
		},
		Skipped: []SkipNote{{RuleID: "IAC-001"}, {RuleID: "IAC-001"}},
	}
	v := NewPlanView(p)
	if v.Root != "/repo" || v.ScenarioCount != 1 {
		t.Errorf("view header wrong: %+v", v)
	}
	if len(v.Hypotheses) != 1 {
		t.Fatalf("got %d hypotheses, want 1", len(v.Hypotheses))
	}
	h := v.Hypotheses[0]
	if h.Exploitability != string(evidence.Plausible) {
		t.Errorf("Exploitability = %q, want %q", h.Exploitability, evidence.Plausible)
	}
	if h.PathArrow != "entry -> model" {
		t.Errorf("PathArrow = %q", h.PathArrow)
	}
	if len(h.Path) != 2 {
		t.Errorf("Path labels = %v", h.Path)
	}
	if v.SkippedTotal != 2 || len(v.Skipped) != 1 || v.Skipped[0].Count != 2 {
		t.Errorf("skip aggregation wrong: total=%d groups=%+v", v.SkippedTotal, v.Skipped)
	}
}

func TestNewPlanViewNilIsZeroNotPanic(t *testing.T) {
	v := NewPlanView(nil)
	if len(v.Hypotheses) != 0 || v.Root != "" {
		t.Errorf("nil plan should project a zero view, got %+v", v)
	}
}

// The standing plan disclaimers are shared constants, so a change to how nox
// describes a plan changes every surface at once. Pin the invariants that
// matter: the note must not claim execution, and the execute hint must show the
// authorization gate.
func TestPlanNotesDoNotOverstate(t *testing.T) {
	if !strings.Contains(PlanOnlyNote, "Nothing was executed") || !strings.Contains(PlanOnlyNote, "PLAUSIBLE") {
		t.Errorf("PlanOnlyNote drifted: %q", PlanOnlyNote)
	}
	if !strings.Contains(PlanExecuteHint, "--authorize") {
		t.Errorf("PlanExecuteHint must show the --authorize gate: %q", PlanExecuteHint)
	}
}
