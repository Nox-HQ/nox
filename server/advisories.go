package server

import (
	"context"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/advisory"
	"github.com/nox-hq/nox/core/report"
	mcp "go.klarlabs.de/mcp"
)

// advisoriesInput is the advisories tool's input.
type advisoriesInput struct {
	// Previous is the findings.json of the last scheduled run. Without it
	// nothing can be called new and nothing is acted on. It must sit under an
	// allowed path.
	Previous string `json:"previous,omitempty"`
	// Policy overrides the .nox.yaml advisories policy: report, prepare or
	// remediate. It only changes what the decision says is permitted; this
	// server never opens a pull request or merges anything.
	Policy string `json:"policy,omitempty"`
}

// advisoriesOutput is what an agent receives: the same decision `nox advisories
// --format json` prints, plus the text a person would be shown.
type advisoriesOutput struct {
	// Summary is the headline, ready to relay.
	Summary string `json:"summary"`
	// Decision is the full decision, one entry per advisory.
	Decision advisory.Result `json:"decision"`
	// Text is the decision rendered as `nox advisories` renders it.
	Text string `json:"text"`
	// Note tells the agent what it may and may not say about this.
	Note string `json:"note"`
}

const advisoriesNote = "Relay the summary. This is a decision, not an action: nothing was merged, opened or changed, and " +
	"auto_merge only says whether the repository's policy would permit a merge. An advisory whose relevance is " +
	"undetermined is treated as possibly affecting the code; do not describe it as not affected. If the summary says the " +
	"scan is incomplete or there is no previous run, say that, and do not call the result clean."

func (s *Server) registerAdvisoryTools(srv *mcp.Server) {
	srv.Tool("advisories").
		Description("Decide what to do about the dependency advisories in the last scan, exactly as `nox advisories` does: which are new compared with a previous run, how relevant each is to this application, and what the configured policy (report, prepare, remediate) permits. Read-only: it never opens a pull request or merges. With no previous run nothing is called new; an incomplete scan acts on nothing and says so. Needs a prior scan; pass previous (a findings.json from the last run) to learn what is new.").
		ReadOnly().
		ClosedWorld().
		OutputSchema(advisoriesOutput{}).
		Handler(s.handleAdvisories)
}

func (s *Server) handleAdvisories(_ context.Context, input advisoriesInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}
	if input.Previous != "" {
		if err := s.isPathAllowed(input.Previous); err != nil {
			return toolError(err.Error()), nil
		}
	}

	cfg, err := nox.LoadScanConfig(pc.basePath)
	if err != nil {
		return toolError("loading .nox.yaml: " + err.Error()), nil
	}
	settings := cfg.Advisories
	if input.Policy != "" {
		settings.Policy = input.Policy
	}
	pol, err := settings.Resolve()
	if err != nil {
		return toolError(err.Error()), nil
	}

	in := advisory.Input{
		// Waived findings included, as the CLI reads them from findings.json.
		Findings:   pc.result.Findings.Findings(),
		Policy:     pol,
		Incomplete: advisory.IncompleteReason(report.DegradationsFrom(pc.result.Degradations)),
	}
	var warning string
	in.Previous, in.HavePrevious, warning = report.LoadPreviousFindings(input.Previous)
	res := advisory.Evaluate(in)

	note := advisoriesNote
	if warning != "" {
		note = "Warning: " + warning + ". " + note
	}
	return structured(advisoriesOutput{
		Summary: advisory.Headline(res), Decision: res, Text: advisory.Text(res), Note: note,
	})
}
