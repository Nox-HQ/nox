package core

import (
	"github.com/nox-hq/nox/core/findings"
)

// raiseRouteReachableParameterFlows raises a query built from a function's
// parameter from low to medium confidence when the call graph found that
// function on a path from an HTTP route handler.
//
// The taint engine reports such a query at low confidence because nothing in
// the file shows a caller passing request data (taintflow, SourceParameter).
// The call-graph stage answers part of what the file could not: a route
// handler reaches the function, so a request does arrive there, carrying
// whatever the route accepts. It does not show that the parameter carries
// request data rather than a value the handler made up, which is why the
// finding rises to medium and not to the confidence of a traced source. A
// function reached only from a test or a main is not raised: neither is where
// a request arrives. One no path was found to keeps low, since no path found
// is not no path, but neither is it a reason to believe more.
//
// The route stays visible as the basis: original_confidence and
// confidence_basis in the metadata, and a sentence naming the route in the
// message. The fingerprint was fixed when the finding was added and does not
// move, so a baseline or waiver written against it still applies.
//
// It runs after recordCallGraphCoverage, which writes entry_kind and
// entry_reason.
func raiseRouteReachableParameterFlows(fs *findings.FindingSet) {
	if fs == nil {
		return
	}
	for i, f := range fs.Findings() {
		m := f.Metadata
		if m == nil || m["source_kind"] != "parameter" || m["entry_kind"] != "route" ||
			f.Confidence != findings.ConfidenceLow || m["confidence_basis"] != "" {
			continue
		}
		fs.SetConfidence(i, findings.ConfidenceMedium)
		fs.SetMetadata(i, "original_confidence", string(findings.ConfidenceLow))
		fs.SetMetadata(i, "confidence_basis", "route_reachable")
		sentence := " A call path reaches this function from the handler of an HTTP route"
		if r := m["entry_reason"]; r != "" {
			sentence += " (" + r + ")"
		}
		fs.SetMessage(i, f.Message+sentence+".")
	}
}
