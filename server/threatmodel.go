package server

import (
	"context"

	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/threatmodel"
	mcp "go.klarlabs.de/mcp"
)

// threatModelOutput is what an agent receives when a user asks for a threat
// model or system documentation.
type threatModelOutput struct {
	// Summary is the plain-language reading of the model, ready to relay.
	Summary string `json:"summary"`
	// Model is the full model: elements, flows, trust boundaries, the STRIDE
	// table, questions for the team and limits, each claim citing the scan
	// output behind it.
	Model threatmodel.Model `json:"model"`
	// Note tells the agent what it may and may not say about this.
	Note string `json:"note"`
}

const threatModelNote = "Relay the summary and the questions for the team. State that this is evidence only: a scan " +
	"cannot show that a threat does not exist or has been dealt with, a cell marked not evidenced means nox has " +
	"nothing either way, and the limits list what the model cannot see. Do not add threats the model does not cite."

// threatModelInput is the threat_model tool's input.
type threatModelInput struct {
	// Previous is the model.json of an earlier run (what `nox model` writes).
	// When given, the model also says which elements, flows, trust boundaries
	// and STRIDE cells changed since it. It must sit under an allowed path.
	Previous string `json:"previous,omitempty"`
}

func (s *Server) registerThreatModelTools(srv *mcp.Server) {
	srv.Tool("threat_model").
		Description("Threat model assembled from the last scan: the elements nox can evidence (routes and their authentication middleware, AI agents and their tools, MCP servers, data stores, external services, the deployment surface), the data flows and trust boundaries between them, a STRIDE table with the evidence per element and category, questions for the team derived from the gaps, and what nox cannot see. Use when the user asks for a threat model, an architecture overview or system documentation. Deterministic and read-only; never states that a threat is absent or handled. Needs a prior scan. Pass previous (a model.json from an earlier run) to also get what changed since it.").
		ReadOnly().
		ClosedWorld().
		OutputSchema(threatModelOutput{}).
		Handler(s.handleThreatModel)
}

func (s *Server) handleThreatModel(_ context.Context, input threatModelInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}
	in, err := pc.result.ThreatModelInput(s.version)
	if err != nil {
		return toolError("building threat model input: " + err.Error()), nil
	}
	if c, err := git.HeadCommit(pc.basePath); err == nil {
		in.Commit = c
	}
	if input.Previous != "" {
		if err := s.isPathAllowed(input.Previous); err != nil {
			return toolError(err.Error()), nil
		}
	}
	m, err := threatmodel.BuildAgainst(in, input.Previous)
	if err != nil {
		return toolError("previous model: " + err.Error()), nil
	}
	return structured(threatModelOutput{Summary: m.Terminal(), Model: m, Note: threatModelNote})
}
