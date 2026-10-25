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

func (s *Server) registerThreatModelTools(srv *mcp.Server) {
	srv.Tool("threat_model").
		Description("Threat model assembled from the last scan: the elements nox can evidence (routes and their authentication middleware, AI agents and their tools, MCP servers, data stores, external services, the deployment surface), the data flows and trust boundaries between them, a STRIDE table with the evidence per element and category, questions for the team derived from the gaps, and what nox cannot see. Use when the user asks for a threat model, an architecture overview or system documentation. Deterministic and read-only; never states that a threat is absent or handled. Needs a prior scan.").
		ReadOnly().
		OutputSchema(threatModelOutput{}).
		Handler(s.handleThreatModel)
}

func (s *Server) handleThreatModel(_ context.Context, _ emptyInput) (mcp.StructuredResult, error) {
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
	m := threatmodel.Build(in)
	return structured(threatModelOutput{Summary: m.Terminal(), Model: m, Note: threatModelNote})
}
