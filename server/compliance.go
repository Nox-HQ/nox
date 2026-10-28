package server

import (
	"context"

	"github.com/nox-hq/nox/core/compliance/iso27001"
	"github.com/nox-hq/nox/core/git"
	mcp "go.klarlabs.de/mcp"
)

// complianceISO27001Output is what an agent receives when a user says "I'm
// preparing for ISO 27001".
type complianceISO27001Output struct {
	// Summary is the plain-language reading of the assessment, ready to relay.
	Summary string `json:"summary"`
	// Assessment is the full per-control evidence, gaps and limits, plus the
	// organizational checklist, each claim citing the scan output behind it.
	Assessment iso27001.Assessment `json:"assessment"`
	// Note tells the agent what it may and may not say about this.
	Note string `json:"note"`
}

const complianceISO27001Note = "Relay the summary and name the gaps. State that this is technical evidence only: a scan " +
	"cannot show that a control is met or implemented, nor that an audit would succeed, and the " +
	"organizational_evidence_required list is work still to be done by people."

func (s *Server) registerComplianceTools(srv *mcp.Server) {
	srv.Tool("compliance_iso27001").
		Description("Technical evidence from the last scan, mapped to ISO/IEC 27001:2022 Annex A controls: per control what the scan shows, what it cannot show, and the organizational evidence (policies, risk assessment, access reviews, incident records, supplier agreements) the user still needs. Use when the user asks what Nox can help with for ISO 27001. Deterministic and read-only; never states that a control is met. Needs a prior scan.").
		ReadOnly().
		ClosedWorld().
		OutputSchema(complianceISO27001Output{}).
		Handler(s.handleComplianceISO27001)
}

func (s *Server) handleComplianceISO27001(_ context.Context, _ emptyInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}
	in, err := pc.result.ISO27001Input(s.version)
	if err != nil {
		return toolError("building assessment input: " + err.Error()), nil
	}
	if c, err := git.HeadCommit(pc.basePath); err == nil {
		in.Commit = c
	}
	a := iso27001.Assess(in)
	return structured(complianceISO27001Output{
		Summary: a.Terminal(), Assessment: a, Note: complianceISO27001Note,
	})
}
