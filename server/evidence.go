package server

import (
	"context"
	"sort"

	"github.com/nox-hq/nox-core/evidence"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/explain"
	mcp "go.klarlabs.de/mcp"
)

// capabilityOutput reports what this installation can establish and what this
// scan actually established.
//
// This is the tool that closes a gap an agent could not otherwise see. The MCP
// surface already carries degradations, which say that a check BROKE. Nothing
// said that a question was never ASKED, and those are different: an agent
// reading a clean finding list has no way to learn that reachability was never
// evaluated, and "no findings" then reads as "nothing is wrong". Track D exists
// for exactly that distinction, and until now it stopped at the CLI.
type capabilityOutput struct {
	Capabilities []capabilityRow `json:"capabilities"`
	// Note is addressed to the agent reading this, because the failure mode
	// here is a confident summary written from an incomplete scan.
	Note string `json:"note"`
}

type capabilityRow struct {
	Capability string `json:"capability"`
	// Provided says whether anything on this installation can establish it at
	// all — a fact about the binary, not about this scan.
	Provided bool `json:"provided"`
	// ProvidedBy names the implementations, so "install a plugin" is
	// actionable rather than a guess.
	ProvidedBy []string `json:"provided_by,omitempty"`
	// Answered and Inconclusive are what happened in THIS scan. Provided with
	// zero answered means the capability exists and nothing used it here.
	Answered     int `json:"answered"`
	Inconclusive int `json:"inconclusive"`
	// Meaning states, in words, what the row implies for a reader.
	Meaning string `json:"meaning"`
}

func (s *Server) handleAnalysisCapabilities(_ context.Context, _ emptyInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}

	out := capabilityOutput{Note: "A capability that is provided but answered nothing was " +
		"available and never used here. That is not a clean result; it means the question " +
		"was not asked about this code."}

	for _, c := range capability.All() {
		answered, inconclusive := pc.result.Coverage.Answered(c)
		provided := pc.result.Capabilities.Provided(c)
		row := capabilityRow{
			Capability: string(c), Provided: provided,
			ProvidedBy: pc.result.Capabilities.ProvidedBy(c),
			Answered:   answered, Inconclusive: inconclusive,
		}
		switch {
		case !provided:
			row.Meaning = "Nothing on this installation can establish it. Findings that " +
				"depend on it are unevaluated, not cleared."
		case answered > 0:
			row.Meaning = "Established for some findings in this scan."
		case inconclusive > 0:
			row.Meaning = "The analysis ran and could not determine anything."
		default:
			row.Meaning = "Available, but nothing in this scan put the question."
		}
		out.Capabilities = append(out.Capabilities, row)
	}
	sort.Slice(out.Capabilities, func(i, j int) bool {
		return out.Capabilities[i].Capability < out.Capabilities[j].Capability
	})
	return structured(out)
}

// whyInput selects the finding to explain.
type whyInput struct {
	// Fingerprint is a full fingerprint or an unambiguous prefix, or a rule ID.
	// Resolved by findings.Addresses, the same selector the CLI uses.
	Fingerprint string `json:"fingerprint" jsonschema:"Fingerprint (full or prefix) or rule ID of the finding to explain"`
}

type whyOutput struct {
	Explanations []explain.Explanation `json:"explanations"`
	// Note tells the agent what this is and, more usefully, what it is not.
	Note string `json:"note"`
}

// handleWhy answers the eight questions for a finding.
//
// Deterministic: it reads only what the scan established, so an agent gets the
// same answer twice and can quote it. The two questions worth the round trip
// are "what was not evaluated" and "does it affect this application" — the ones
// a scanner normally leaves out, and the ones an agent most needs before
// writing a confident summary.
func (s *Server) handleWhy(_ context.Context, input whyInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}
	if pc.result.Reasoning == nil {
		return toolError("this scan recorded no reasoning, so there is nothing to explain " +
			"from; the evidence a finding rests on is collected during the scan and cannot " +
			"be reconstructed afterwards"), nil
	}

	cat := catalog.Catalog()
	out := whyOutput{Note: "Answers derive from what the scan established, not from a " +
		"language model. An empty 'supports' or a populated 'not_evaluated' is information, " +
		"not an omission."}

	for _, f := range pc.result.Findings.ActiveFindings() {
		if input.Fingerprint != "" && !f.Addresses(input.Fingerprint) {
			continue
		}
		subject := nox.SubjectForFinding(f)
		var ledger evidence.Ledger
		if pc.result.Reasoning != nil {
			ledger = pc.result.Reasoning.About(subject)
		}
		out.Explanations = append(out.Explanations, explain.Explain(explain.Inputs{
			Finding: f, Ledger: ledger, Subject: subject,
			Coverage: pc.result.Coverage, Registry: pc.result.Capabilities, Rule: cat[f.RuleID],
		}))
	}
	if len(out.Explanations) == 0 {
		return toolError("no active finding matches that selector"), nil
	}
	return structured(out)
}
