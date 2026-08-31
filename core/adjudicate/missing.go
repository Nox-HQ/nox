package adjudicate

import (
	"sort"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
)

// Gap is a question whose answer would change this verdict, and what it would
// cost to answer it.
//
// This is the adjudicator's second job. Its first is to say what the evidence
// supports; this one says what evidence is ABSENT, which is the more actionable
// half for anyone deciding where to spend effort. A verdict of PLAUSIBLE with
// the package confirmed, the symbol confirmed and the attacker path supported
// is not a dead end — it is a question with one unknown, and naming that
// unknown turns a report into a next step.
type Gap struct {
	// Capability is the analysis that would answer it.
	Capability capability.AnalysisCapability `json:"capability"`
	// Question is what would be established, in words.
	Question string `json:"question"`
	// Cost is the relative expense of answering it, cheapest first. It orders
	// the gaps rather than pricing them: nox cannot know what a call-graph
	// build costs on somebody else's monorepo, but it does know that reading a
	// file is cheaper than executing an attack.
	Cost int `json:"cost"`
	// Available is whether anything on this installation could answer it. A gap
	// nothing can fill is still worth naming — it tells a reader the silence is
	// a limit rather than an oversight — but it is not a next step.
	Available bool `json:"available"`
}

// costs orders the capabilities by what answering them takes, cheapest first.
//
// The ordering is the useful part and it is not arbitrary: reading a file is
// cheaper than resolving symbols, which is cheaper than building a call graph,
// which is far cheaper than executing anything against a live target. A
// multi-stage architecture spends the cheap evidence first and only escalates
// on what survives, and this is the order it escalates in.
var costs = []struct {
	capability.AnalysisCapability
	question string
	cost     int
}{
	// Each question stands alone, because each is shown on its own. An earlier
	// version phrased them as a sequence — "is it reachable from one?" — which
	// read as a fragment once a reader saw only the recommended one.
	{capability.LexicalContext, "is this in real code, or in a comment or string?", 1},
	{capability.ConstantEvaluation, "is this value a literal, or is it built from input?", 2},
	{capability.SymbolResolution, "does the build actually reference the affected symbol?", 3},
	{capability.Taint, "does untrusted input reach this location?", 4},
	{capability.CallGraph, "is there any call path that reaches this code?", 5},
	{capability.EntryPoint, "what are this application's entry points?", 6},
	{capability.Reachability, "is this code reachable from an entry point?", 7},
	{capability.AttackerReachability, "is it reachable from an entry point an attacker controls?", 8},
	{capability.DynamicVerification, "does this actually happen when the code is exercised?", 9},
}

// MissingEvidence returns the questions that are open for a subject, cheapest
// first, given what the scan established.
//
// A capability that already concluded is not a gap. One that ran and could not
// tell IS — the question is open, and re-asking it may need a different
// approach rather than the same one again, which is why the answer is the
// capability and not an instruction.
//
// The cheapest available gap is the one worth taking first, and that is the
// whole point: not every hypothesis travels to the bottom of the ladder, and
// the ones that do should get there by having survived the cheap questions.
func MissingEvidence(cov *capability.Coverage, reg *capability.Registry, s evidence.Subject) []Gap {
	var out []Gap
	for _, c := range costs {
		switch cov.State(s, c.AnalysisCapability) {
		case capability.Positive, capability.Negative:
			// Answered. Not a gap, whichever way it went.
			continue
		}
		out = append(out, Gap{
			Capability: c.AnalysisCapability,
			Question:   c.question,
			Cost:       c.cost,
			Available:  reg.Provided(c.AnalysisCapability),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Cost < out[j].Cost })
	return out
}

// CheapestAvailable returns the least expensive open question something on this
// installation could actually answer, and whether there is one.
//
// Availability is part of the answer rather than a filter applied to it. A gap
// nothing can fill is real and belongs in MissingEvidence — it is why a verdict
// stops where it does — but recommending it as a next step would send a reader
// to do something they cannot.
func CheapestAvailable(gaps []Gap) (Gap, bool) {
	for _, g := range gaps {
		if g.Available {
			return g, true
		}
	}
	return Gap{}, false
}
