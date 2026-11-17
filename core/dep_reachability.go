package core

import (
	"strings"

	"github.com/nox-hq/nox/core/applicability"
	"github.com/nox-hq/nox/core/callgraph"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/findings"
)

// raiseDependencyReachability climbs a non-Go dependency finding from "the
// project imports the package" to "code that runs calls into it", with the
// call path as the witness.
//
// The deps analyzer answers that rung for Go from its own graph. For every
// other ecosystem it stopped at symbol_used, because nothing could see calls:
// the source call graph is built from the flow analyzers' walk, which runs
// beside the deps analyzer, so the climb happens here, after both.
//
// What is claimed is exactly what the graph shows: a function in this project,
// reached from where execution begins, calls into a module of the affected
// package — the rung Go reaches, call_reachable. Not attacker_reachable, even
// when the path starts at an HTTP route handler: a call into the package is
// not a call into the advisory's vulnerable function. The route is recorded
// beside the verdict (entry_kind, entry_reason) for a reader to weigh.
//
// Only climbs. A finding the deps analyzer refuted, or established further by
// a stronger witness, is left alone, and a graph that found no path changes
// nothing: no path found is not no path.
//
// The fingerprint does not move. It was computed when the finding was made,
// from the analyzer's own wording, so a baseline, waiver or VEX statement
// written against this finding before this climb still applies after it.
func raiseDependencyReachability(fs *findings.FindingSet, g *callgraph.Graph) {
	if fs == nil || g == nil {
		return
	}
	for i, f := range fs.Findings() {
		m := f.Metadata
		if f.RuleID != "VULN-001" || m == nil || strings.EqualFold(m["ecosystem"], "go") {
			continue
		}
		if m["applicability"] == string(applicability.NotImpacting) {
			continue
		}
		reached := applicability.Rung(m["applicability_reached"])
		weakWitness := m["affected_symbol_evidence"] == "source_reference"
		if !applicability.CallReachable.Above(reached) && !weakWitness {
			// Already at call_reachable or above, on a call path.
			continue
		}
		path, kind, ok := dependencyCallPath(g, m["ecosystem"], m["package"])
		if !ok {
			continue
		}
		// The sentence being replaced, rebuilt from the verdict the analyzer
		// recorded, before that record is overwritten.
		old := applicability.Verdict{
			Reached:   reached,
			Outcome:   applicability.Outcome(m["applicability"]),
			StoppedAt: applicability.Rung(m["applicability_stopped_at"]),
			Because:   capability.State(m["applicability_because"]),
		}.Describe()
		v := applicability.Established(applicability.CallReachable, path)
		fs.SetMetadata(i, "applicability", string(v.Outcome))
		fs.SetMetadata(i, "applicability_reached", string(v.Reached))
		delete(f.Metadata, "applicability_stopped_at")
		delete(f.Metadata, "applicability_because")
		fs.SetMetadata(i, "call_path", strings.Join(path, " -> "))
		fs.SetMetadata(i, "call_path_basis", "package")
		fs.SetMetadata(i, "entry_kind", kind.String())
		sentence := v.Describe()
		if fn, found := g.Func(path[0]); found && kind == callgraph.EntryRoute {
			fs.SetMetadata(i, "entry_reason", fn.EntryReason)
			sentence += " The path starts at the handler of an HTTP route: " + fn.EntryReason + "."
		}
		fs.SetMessage(i, replaceApplicabilitySentence(f.Message, old, sentence))
	}
}

// dependencyCallPath returns the best path from an entry point to a function
// that calls into the package: one from a route handler first, then the
// shortest from any concrete entry. Test entries do not count; they show the
// suite runs the code, not the program.
func dependencyCallPath(g *callgraph.Graph, ecosystem, name string) ([]string, callgraph.EntryKind, bool) {
	var best []string
	bestKind := callgraph.NotAnEntry
	for _, caller := range g.CallersOfDependency(ecosystem, name) {
		p, kind := g.PathToFunc(caller)
		if kind < callgraph.EntryConcrete || len(p) == 0 {
			continue
		}
		if kind > bestKind || (kind == bestKind && len(p) < len(best)) {
			best, bestKind = p, kind
		}
	}
	return best, bestKind, best != nil
}

// replaceApplicabilitySentence swaps the applicability sentence the deps
// analyzer appended last for the new one. The sentence may itself contain
// " — ", so it is found by its text, not by the separator: the verdict's own
// sentence, or the npm source-reference sentence, which starts with a fixed
// phrase. A message holding neither keeps its text and gains the new sentence.
func replaceApplicabilitySentence(msg, old, sentence string) string {
	if old != "" && strings.HasSuffix(msg, " — "+old) {
		return strings.TrimSuffix(msg, old) + sentence
	}
	if i := strings.LastIndex(msg, " — project source references "); i >= 0 {
		return msg[:i] + " — " + sentence
	}
	return msg + " — " + sentence
}
