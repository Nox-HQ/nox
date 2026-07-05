package engine

import "github.com/nox-hq/nox/core/taint"

// This file adds SAME-FILE interprocedural taint analysis on top of the
// intraprocedural StructuralEngine, via FUNCTION SUMMARIES. It is the multiplier
// that catches injection bugs split across helper functions defined in the same
// file — the common "thin handler delegates to a helper that does the dangerous
// thing" shape.
//
// HOW IT WORKS
//
//  1. Summarize each locally-defined function (funcSummary) by asking, for every
//     parameter i: does parameter i reach a catalog SINK unsanitized inside the
//     body (sinksArg), does it flow UNSANITIZED to the function's return
//     (returnsTaintedIf), and for which classes is it SANITIZED before either
//     (sanitizesClass). Summaries are computed by seeding each parameter as a
//     synthetic source and running the same forward propagation the
//     intraprocedural engine uses — so summary semantics never diverge from
//     intraprocedural semantics.
//
//  2. Iterate summaries to a FIXPOINT over the file's call graph (bounded): a
//     helper that returns its argument tainted lets a summary of a caller that
//     wraps then sinks compose across two hops. Iteration is bounded by the
//     function count (a monotone lattice: taint only ever spreads), so it always
//     terminates — recursion and mutual recursion included.
//
//  3. Re-run propagation over each unit, this time RESOLVING calls to local
//     functions against their summaries: a call helper(taintedVar) whose summary
//     says sinksArg(0, cmdi) emits a cross-function Flow (naming helper in Via);
//     x = wrap(taintedVar) whose summary says returnsTaintedIf(0) marks x
//     tainted and analysis continues.
//
// HONEST LIMITS (documented, and exactly where the cross-file taint-analysis
// plugin takes over):
//   - SAME-FILE ONLY. A callee defined in another file is an unknown callee: we
//     never invent a sink or propagate taint through it (fail safe — no false
//     positive). Cross-FILE flow remains the taint-analysis plugin's job.
//   - No alias or field/element sensitivity, no control-flow-graph/branch
//     merging (inherited from the intraprocedural engine).
//   - BEST-EFFORT callee resolution: a helper called by its bare local name is
//     resolved; a helper reached through an attribute, a variable holding a
//     function, or a decorator-rewrapped name is treated as unknown.
//   - BOUNDED FIXPOINT: iteration is capped at the function count; a pathological
//     graph simply stops early with the summaries computed so far (fail safe).
//   - Argument→parameter binding is POSITIONAL only (keyword and *args calls do
//     not bind a specific parameter and are conservatively ignored for
//     summary application, never fabricated).

// argSink records that a parameter reaches a specific catalog sink unsanitized.
// It carries the full Sink so the emitted cross-function Flow keeps the sink's
// RuleID/CWE/VulnClass, and the intermediate function chain that leads to it.
type argSink struct {
	sink taint.Sink
	// via is the chain of local functions between the summarized function and the
	// sink, nearest-caller first. Empty when the sink is directly in the body.
	via []string
}

// funcSummary is the interprocedural summary of one locally-defined function.
// All maps are keyed by positional parameter index. Absence means "no observed
// effect for that parameter" (fail safe: we never assume an effect we did not
// derive).
type funcSummary struct {
	name string
	// sinksArg[i] lists the sinks parameter i reaches unsanitized.
	sinksArg map[int][]argSink
	// returnsTaintedIf[i] is true when parameter i flows unsanitized to a return.
	returnsTaintedIf map[int]bool
	// sanitizesClass[i] is the set of vuln classes parameter i is sanitized for
	// before reaching any sink or return. Used to suppress a caller flow whose
	// sink class the helper already neutralized.
	sanitizesClass map[int]map[taint.VulnClass]bool
	// returnVia[i] is the local-function chain a tainted return value of
	// parameter i passed through (for Via provenance when the return is later
	// sunk). Nearest-caller first.
	returnVia map[int][]string
}

// newFuncSummary returns an empty summary for name.
func newFuncSummary(name string) *funcSummary {
	return &funcSummary{
		name:             name,
		sinksArg:         map[int][]argSink{},
		returnsTaintedIf: map[int]bool{},
		sanitizesClass:   map[int]map[taint.VulnClass]bool{},
		returnVia:        map[int][]string{},
	}
}

// maxFixpointIterations bounds summary refinement. The lattice is monotone
// (taint only spreads), so convergence is guaranteed within one pass per
// function-graph depth; capping at the function count (plus a small constant)
// makes even a fully-connected or recursive graph terminate deterministically.
const maxFixpointIterations = 64

// AnalyzeFile runs SAME-FILE interprocedural taint analysis over all units of a
// single file (as produced by ExtractUnits). It returns every un-sanitized
// source→sink flow, whether intraprocedural (source and sink in one function) or
// interprocedural (source in a caller, sink reached through a locally-defined
// helper). Flows are deterministic and de-duplicated.
//
// Determinism: units are processed in their extraction order (source order),
// summaries converge to a fixpoint independent of iteration count, and flows are
// sorted by the shared sortFlows ordering before return.
func (e *StructuralEngine) AnalyzeFile(units []taint.Unit) []taint.Flow {
	if len(units) == 0 {
		return nil
	}
	lang := units[0].Language

	summaries := e.computeSummaries(lang, units)

	var flows []taint.Flow
	seen := map[flowKey]struct{}{}
	for i := range units {
		unitFlows := e.analyzeUnitInterproc(lang, &units[i], summaries)
		for j := range unitFlows {
			f := &unitFlows[j]
			k := flowKey{f.SinkLine, f.SinkCall, f.SourceLine, f.SourceVar, f.Sink.RuleID}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			flows = append(flows, *f)
		}
	}
	sortFlows(flows)
	return flows
}

// flowKey de-duplicates flows that the intraprocedural and interprocedural
// passes could both surface (a source→sink pair reachable two ways is one bug).
type flowKey struct {
	sinkLine   int
	sinkCall   string
	sourceLine int
	sourceVar  string
	ruleID     string
}

// computeSummaries derives a funcSummary for each named function, iterating to a
// bounded fixpoint so summaries that depend on other summaries (a helper that
// returns tainted, then whose result is sunk) converge.
func (e *StructuralEngine) computeSummaries(lang string, units []taint.Unit) map[string]*funcSummary {
	summaries := map[string]*funcSummary{}
	for i := range units {
		if units[i].FuncName != "" {
			summaries[units[i].FuncName] = newFuncSummary(units[i].FuncName)
		}
	}

	for iter := 0; iter < maxFixpointIterations; iter++ {
		changed := false
		for i := range units {
			u := &units[i]
			if u.FuncName == "" {
				continue
			}
			next := e.summarize(lang, u, summaries)
			if !summaryEqual(summaries[u.FuncName], next) {
				summaries[u.FuncName] = next
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return summaries
}

// summarize computes the summary of one function by seeding each parameter as a
// distinct synthetic source and running the interprocedural-aware forward pass
// (so a parameter that flows through ANOTHER local helper's summary is tracked).
// It observes, per parameter, whether the tainted value reaches a sink, reaches a
// return, and which classes it was sanitized for.
func (e *StructuralEngine) summarize(lang string, u *taint.Unit, summaries map[string]*funcSummary) *funcSummary {
	sum := newFuncSummary(u.FuncName)
	for idx, param := range u.Params {
		// Seed: parameter `param` is tainted by a synthetic "parameter" source.
		seed := map[string]taintInfo{
			param: {
				src:     taint.Source{Call: u.FuncName + ":" + param, Kind: taint.SourceKind("parameter")},
				srcLine: 0,
				cleared: map[taint.VulnClass]bool{},
				via:     nil,
			},
		}
		res := e.forwardPass(lang, u, seed, summaries)

		for fi := range res.flows {
			f := &res.flows[fi]
			if f.SourceVar != param {
				continue
			}
			sum.sinksArg[idx] = append(sum.sinksArg[idx], argSink{sink: f.Sink, via: f.Via})
		}
		// Did the parameter's taint reach a return unsanitized?
		for _, rv := range res.returned {
			ti, ok := res.state[rv]
			if !ok || ti.src.Call != u.FuncName+":"+param {
				continue
			}
			sum.returnsTaintedIf[idx] = true
			sum.returnVia[idx] = append([]string(nil), ti.via...)
			// Classes the value was sanitized for on the way to the return.
			if len(ti.cleared) > 0 {
				cls := map[taint.VulnClass]bool{}
				for c, v := range ti.cleared {
					cls[c] = v
				}
				sum.sanitizesClass[idx] = cls
			}
		}
	}
	return sum
}

// summaryEqual reports whether two summaries are equivalent, so the fixpoint
// loop can detect convergence. It compares the observable effect sets, not the
// pointer identity.
func summaryEqual(a, b *funcSummary) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.returnsTaintedIf) != len(b.returnsTaintedIf) {
		return false
	}
	for k, v := range a.returnsTaintedIf {
		if b.returnsTaintedIf[k] != v {
			return false
		}
	}
	if len(a.sinksArg) != len(b.sinksArg) {
		return false
	}
	for k, av := range a.sinksArg {
		bv := b.sinksArg[k]
		if len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i].sink.RuleID != bv[i].sink.RuleID || av[i].sink.Call != bv[i].sink.Call {
				return false
			}
		}
	}
	return true
}
