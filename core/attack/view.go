package attack

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
)

// This file is the single source of truth for how an attack plan is presented,
// shared by every consumer — the CLI, the MCP server, and anything added later.
//
// Before it existed, the CLI and the MCP handler each re-derived the same
// facts: how to group skipped findings, how to render an attack path, and the
// standing truth that a plan's hypotheses are PLAUSIBLE and nothing was
// executed. Two copies of a rule is one copy that will drift, and for a
// security tool the rule that must never drift is what a verdict MEANS. Keeping
// the projection in the domain is what makes "the CLI and MCP say the same
// thing" a structural guarantee rather than a review promise.

// PlanOnlyNote is the standing disclaimer for a plan: it is offline, and every
// hypothesis is a credible path that has NOT been demonstrated. Both the CLI and
// the MCP tool surface this verbatim so neither can quietly imply more.
const PlanOnlyNote = "Plan only. Nothing was executed and no traffic was sent. " +
	"Every hypothesis is PLAUSIBLE — a credible attack path that has NOT been demonstrated."

// PlanExecuteHint is the CLI invocation that actually attempts a plan. It is
// guidance for a human operator, never something a consumer runs on their behalf.
const PlanExecuteHint = "nox attack run --target <url> --route <path> --fields <list> --profile sandbox --authorize"

// SkipSummary is one rule's worth of findings that no scenario covers, grouped.
type SkipSummary struct {
	// RuleID is the finding's rule.
	RuleID string `json:"rule_id"`
	// Count is how many findings of this rule were skipped.
	Count int `json:"count"`
	// Reason is why no scenario applied.
	Reason string `json:"reason"`
}

// AggregateSkips groups skip notes by rule id, most-skipped first and then by
// rule id so the result is stable run to run.
//
// A scan of any real repository skips hundreds of IaC and secret findings; one
// row per finding would bury the handful of hypotheses that matter. The per-rule
// count is the signal worth keeping — it says how much of the scan dynamic
// validation does not reach. Truncation for display is left to each consumer;
// this returns the full, ordered set so nothing is silently dropped from the
// data itself.
func AggregateSkips(skipped []SkipNote) []SkipSummary {
	if len(skipped) == 0 {
		return nil
	}
	counts := map[string]int{}
	reasons := map[string]string{}
	for i := range skipped {
		counts[skipped[i].RuleID]++
		reasons[skipped[i].RuleID] = skipped[i].Reason
	}
	out := make([]SkipSummary, 0, len(counts))
	for id, n := range counts {
		out = append(out, SkipSummary{RuleID: id, Count: n, Reason: reasons[id]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// PathLabels returns each path step's display label, falling back to the step
// ID when a step carries no label so a rendered path never shows a gap.
func PathLabels(steps []PathStep) []string {
	if len(steps) == 0 {
		return nil
	}
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		label := s.Label
		if label == "" {
			label = s.ID
		}
		out = append(out, label)
	}
	return out
}

// RenderPath joins a path into the arrow form used throughout nox's output, so
// a hypothesis and a confirmed trace read the same way wherever they appear.
func RenderPath(steps []PathStep) string {
	return strings.Join(PathLabels(steps), " -> ")
}

// HypothesisView is a presentation-neutral projection of one hypothesis: the
// same fields every consumer needs, with the path pre-rendered both ways and the
// exploitability stated once. A plan executes nothing, so this is always
// PLAUSIBLE — sourced from the evidence ladder rather than a literal, so the two
// cannot disagree.
type HypothesisView struct {
	ID                  string   `json:"id"`
	ScenarioID          string   `json:"scenario_id"`
	Objective           string   `json:"objective"`
	Rationale           string   `json:"rationale"`
	EntryPoint          string   `json:"entry_point,omitempty"`
	Path                []string `json:"path,omitempty"`
	PathArrow           string   `json:"path_arrow,omitempty"`
	FindingFingerprints []string `json:"finding_fingerprints,omitempty"`
	Exploitability      string   `json:"exploitability"`
}

// PlanView is the neutral projection of a plan for any consumer. It carries the
// counts, the projected hypotheses, and the aggregated skip summary — the data
// both the CLI summary and the MCP tool output are built from.
type PlanView struct {
	Root          string           `json:"root"`
	Assets        int              `json:"assets"`
	Boundaries    int              `json:"trust_boundaries"`
	ScenarioCount int              `json:"scenario_count"`
	Hypotheses    []HypothesisView `json:"hypotheses"`
	Skipped       []SkipSummary    `json:"skipped,omitempty"`
	SkippedTotal  int              `json:"skipped_total"`
}

// NewPlanView projects a Plan into the shared view. A nil plan yields a zero
// view rather than a panic, so a consumer that failed to build a plan can still
// render an empty result.
func NewPlanView(p *Plan) PlanView {
	if p == nil {
		return PlanView{}
	}
	v := PlanView{
		Root:          p.Root,
		Assets:        len(p.Assets),
		Boundaries:    len(p.Boundaries),
		ScenarioCount: len(p.Scenarios),
		Hypotheses:    make([]HypothesisView, 0, len(p.Hypotheses)),
		Skipped:       AggregateSkips(p.Skipped),
		SkippedTotal:  len(p.Skipped),
	}
	for i := range p.Hypotheses {
		h := p.Hypotheses[i]
		v.Hypotheses = append(v.Hypotheses, HypothesisView{
			ID:                  h.ID,
			ScenarioID:          h.ScenarioID,
			Objective:           h.Objective,
			Rationale:           h.Rationale,
			EntryPoint:          h.EntryPoint,
			Path:                PathLabels(h.Path),
			PathArrow:           RenderPath(h.Path),
			FindingFingerprints: h.FindingFingerprints,
			Exploitability:      string(evidence.Plausible),
		})
	}
	return v
}
