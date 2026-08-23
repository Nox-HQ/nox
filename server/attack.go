package server

import (
	"context"
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

// attackPlanOutput is the response of the attack_plan tool. It embeds the shared
// attack.PlanView so the MCP tool and the CLI project a plan through identical
// logic — the hypotheses, their PLAUSIBLE status, the path rendering, and the
// skip aggregation all come from the domain, not from a second copy here.
type attackPlanOutput struct {
	// Note states plainly that nothing was executed.
	Note string `json:"note"`
	// PlanView is the shared, presentation-neutral projection of the plan.
	attack.PlanView
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
		Note:         attack.PlanOnlyNote,
		PlanView:     attack.NewPlanView(plan),
		HowToExecute: attack.PlanExecuteHint,
	}
	return structured(out)
}
