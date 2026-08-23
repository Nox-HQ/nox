package server

import (
	"context"
	"sort"
	"time"

	"github.com/nox-hq/nox/core/attack"
	mcp "go.klarlabs.de/mcp"
)

// Only the OFFLINE half of `nox attack` is reachable over MCP.
//
// `attack plan` reads a scan and reasons about it. It opens no socket, touches
// no target, and can be run against anything without consequence, so an agent
// calling it is no more dangerous than an agent calling `summary`.
//
// `attack run`, `replay`, and `regress` are deliberately absent, and should
// stay absent:
//
//  1. They fire attack payloads at a network target. The --authorize flag
//     exists so a HUMAN affirms they own and have isolated that target.
//     Accepting an authorization boolean from a model-initiated tool call
//     launders that affirmation through the very thing it is meant to
//     constrain — a confirmation the operator never actually gave.
//
//  2. nox scans untrusted code. A repository under analysis is attacker-
//     controlled text, and an agent reading it can be induced to call tools
//     with attacker-chosen arguments. An MCP-exposed `attack_run` would turn
//     nox into a request-forgery primitive aimed at any host named in a README
//     — the confused-deputy attack that TOOL-UNAUTH exists to detect. Shipping
//     it would make nox an instance of the vulnerability class it tests for.
//
//  3. It matches the precedent already set: `nox confirm`, the other ACTIVE
//     capability, is not an MCP tool either, and `fix_plan` is exposed as a
//     plan whose description tells operators to apply it from the CLI.
//
// The division is plan and read over MCP; act from the CLI, where the operator
// is the one typing.

// attackPlanInput selects the artifacts an attack plan is built from.
type attackPlanInput struct {
	// Path is the workspace root recorded on the plan. Defaults to the last
	// scanned path.
	Path string `json:"path,omitempty"`
}

// attackHypothesisOutput is one exploit hypothesis, flattened for an agent.
type attackHypothesisOutput struct {
	ID string `json:"id"`
	// ScenarioID names the attack scenario, e.g. PI-DIRECT.
	ScenarioID string `json:"scenario_id"`
	// Objective is the security invariant the attack would violate.
	Objective string `json:"objective"`
	// Rationale is why nox believes this attack is worth attempting. It is the
	// field that makes a plan reviewable rather than a list of assertions.
	Rationale string `json:"rationale"`
	// EntryPoint is where attacker-controlled data enters.
	EntryPoint string `json:"entry_point,omitempty"`
	// Path is the attack path, node by node.
	Path []string `json:"path,omitempty"`
	// FindingFingerprints links the hypothesis back to the static findings that
	// grounded it, so an agent can cross-reference with list_findings.
	FindingFingerprints []string `json:"finding_fingerprints,omitempty"`
	// Exploitability is always PLAUSIBLE here: a plan constructs attack paths
	// and executes nothing, so nothing has been demonstrated.
	Exploitability string `json:"exploitability"`
}

// attackSkipOutput reports a rule no V1 scenario covers, aggregated by rule.
type attackSkipOutput struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
	Reason string `json:"reason"`
}

// attackPlanOutput is the response of the attack_plan tool.
type attackPlanOutput struct {
	// Note states plainly that nothing was executed.
	Note string `json:"note"`
	// Root is the workspace the plan was built for.
	Root string `json:"root"`
	// Hypotheses are the exploit hypotheses, sorted deterministically.
	Hypotheses []attackHypothesisOutput `json:"hypotheses"`
	// Assets and Boundaries count what the plan modelled.
	Assets     int `json:"assets"`
	Boundaries int `json:"trust_boundaries"`
	// NotEligible lists rules no scenario maps, so the coverage gap is visible
	// rather than implied by absence.
	NotEligible []attackSkipOutput `json:"not_eligible,omitempty"`
	// HowToExecute is the CLI invocation an operator runs to actually attempt
	// these hypotheses. It is guidance for a human, not something the agent can
	// or should run on their behalf.
	HowToExecute string `json:"how_to_execute"`
}

// registerAttackTools adds the offline attack tooling to the MCP server.
func (s *Server) registerAttackTools(srv *mcp.Server) {
	srv.Tool("attack_plan").
		Description("Build exploit hypotheses from the last scan: which attacks are worth attempting against this codebase, why, and along what path. OFFLINE and read-only — it reasons over scan artifacts and never contacts a target, so nothing is executed and no traffic is sent. Every hypothesis is PLAUSIBLE, never CONFIRMED: confirming one requires actually exercising a running target, which operators do from the CLI via `nox attack run --authorize`. That command is intentionally not available over MCP, because firing attack payloads needs a human who has affirmed they own and isolated the target.").
		ReadOnly().
		OutputSchema(attackPlanOutput{}).
		Handler(s.handleAttackPlan)
}

// handleAttackPlan builds an attack plan from the cached scan.
func (s *Server) handleAttackPlan(_ context.Context, input attackPlanInput) (mcp.StructuredResult, error) {
	pc := s.getCache(input.Path)
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}

	root := input.Path
	if root == "" {
		root = pc.basePath
	}

	plan, err := attack.BuildPlan(attack.PlanInput{
		Root:      root,
		Findings:  pc.result.Findings.ActiveFindings(),
		Inventory: pc.result.AIInventory,
		Now:       time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return toolError("building attack plan: " + err.Error()), nil
	}

	out := attackPlanOutput{
		Note: "Plan only. Nothing was executed and no traffic was sent. " +
			"Every hypothesis is PLAUSIBLE — a credible attack path that has NOT been demonstrated.",
		Root:         plan.Root,
		Assets:       len(plan.Assets),
		Boundaries:   len(plan.Boundaries),
		Hypotheses:   []attackHypothesisOutput{},
		HowToExecute: "nox attack run --target <url> --route <path> --fields <list> --profile sandbox --authorize",
	}

	for i := range plan.Hypotheses {
		h := plan.Hypotheses[i]
		steps := make([]string, 0, len(h.Path))
		for _, st := range h.Path {
			label := st.Label
			if label == "" {
				label = st.ID
			}
			steps = append(steps, label)
		}
		out.Hypotheses = append(out.Hypotheses, attackHypothesisOutput{
			ID:                  h.ID,
			ScenarioID:          h.ScenarioID,
			Objective:           h.Objective,
			Rationale:           h.Rationale,
			EntryPoint:          h.EntryPoint,
			Path:                steps,
			FindingFingerprints: h.FindingFingerprints,
			Exploitability:      "PLAUSIBLE",
		})
	}

	out.NotEligible = aggregateSkips(plan.Skipped)
	return structured(out)
}

// aggregateSkips groups skip notes by rule id. A scan of a real repository
// skips hundreds of findings; one row per finding would bury the hypotheses
// that matter, while the per-rule count still shows how much of the scan
// dynamic validation does not reach.
func aggregateSkips(skipped []attack.SkipNote) []attackSkipOutput {
	if len(skipped) == 0 {
		return nil
	}
	counts := map[string]int{}
	reasons := map[string]string{}
	for _, sk := range skipped {
		counts[sk.RuleID]++
		reasons[sk.RuleID] = sk.Reason
	}
	out := make([]attackSkipOutput, 0, len(counts))
	for id, n := range counts {
		out = append(out, attackSkipOutput{RuleID: id, Count: n, Reason: reasons[id]})
	}
	sortSkips(out)
	return out
}

// sortSkips orders skip rows most-skipped first, then by rule id, so repeated
// calls return the same document.
func sortSkips(rows []attackSkipOutput) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].RuleID < rows[j].RuleID
	})
}
