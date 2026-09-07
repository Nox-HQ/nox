package core

import (
	"github.com/nox-hq/nox/core/report"
	"github.com/nox-hq/nox/core/report/sarif"
)

// JSONReporter returns a findings.json reporter carrying everything this scan
// must state about itself.
//
// It exists because the alternative had already failed. Every field below is
// one a surface previously set by hand after calling report.NewJSONReporter,
// and each new one multiplied the ways a surface could quietly omit it: the MCP
// server shipped three reporter sites that never set Degradations, so an agent
// — the consumer with no stderr to fall back on — asked for the findings report
// and got one that said nothing about the checks that had not run. Adding
// capability coverage as a fifth field to remember would have re-run that
// experiment with a worse payload, because an omitted capability matrix does
// not read as missing information. It reads as a scan that asked everything.
//
// So the knowledge lives here, once, next to the ScanResult it is derived from.
// The caller still sets what the caller alone knows — Offline, Prioritize —
// because those are invocation choices rather than properties of the result.
func (r *ScanResult) JSONReporter(version string) *report.JSONReporter {
	rep := report.NewJSONReporter(version)
	if r == nil {
		return rep
	}
	rep.SASTLanguages = r.SASTProfile
	rep.Degradations = report.DegradationsFrom(r.Degradations)
	rep.Enrichments = r.Enrichments
	rep.Capabilities = report.CapabilitiesFrom(r.Capabilities, r.Coverage)
	return rep
}

// SARIFReporter returns a results.sarif reporter carrying this scan's
// capability matrix, derived once by core/report so the two artifacts state the
// same thing.
//
// It deliberately does NOT set Rules. A full rule catalog is 1,500+ descriptors,
// and the MCP surface serves SARIF under a response budget that a catalog that
// size would blow past — so whether to embed the catalog is the caller's
// size-and-audience decision, the same class as Prioritize. Capability coverage
// is not: it is a property of the result, it is small, and a surface that omits
// it publishes a scan that looks like it asked every question.
func (r *ScanResult) SARIFReporter(version string) *sarif.Reporter {
	rep := sarif.NewReporter(version, nil)
	if r == nil {
		return rep
	}
	rep.Capabilities = report.CapabilitiesFrom(r.Capabilities, r.Coverage)
	return rep
}
