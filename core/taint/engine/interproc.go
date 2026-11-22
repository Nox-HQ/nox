package engine

import (
	"slices"

	"github.com/nox-hq/nox/core/taint"
)

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
	// file, line and fn locate the sink statement itself, which may be in a
	// helper several calls down or another file; path is the calls from the
	// summarized function to it (ADR 0007: reported at the sink).
	file string
	line int
	fn   string
	path []taint.CallStep
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
	// returnsSource is set when the function returns a value tainted by a real
	// source it reads itself -- a getter such as `function input() { return
	// $_GET['q']; }` -- whatever its arguments. Nil when it does not.
	returnsSource *taintInfo
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
	flows, _ := e.AnalyzeFileWithSuppressions(units)
	return flows
}

// AnalyzeFileWithSuppressions is AnalyzeFile plus the flows it refused to
// report. See taint.Suppression.
func (e *StructuralEngine) AnalyzeFileWithSuppressions(units []taint.Unit) ([]taint.Flow, []taint.Suppression) {
	if len(units) == 0 {
		return nil, nil
	}
	lang := units[0].Language
	units = e.withPropertySanitizers(units)

	summaries := e.computeSummaries(lang, units)

	var flows []taint.Flow
	var suppressed []taint.Suppression
	seen := map[flowKey]struct{}{}
	for i := range units {
		res := e.forwardPass(lang, &units[i], nil, summaries)
		suppressed = append(suppressed, res.suppressed...)
		for j := range res.flows {
			f := &res.flows[j]
			k := flowKey{f.SinkLine, f.SinkCall, f.SourceLine, f.SourceVar, f.Sink.RuleID}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			flows = append(flows, *f)
		}
	}
	flows = append(flows, e.paramSQLFlows(lang, units, summaries, flows)...)
	sortFlows(flows)
	flows = onePerSink(flows)
	sortSuppressions(suppressed)
	return flows, suppressed
}

// onePerSink keeps, at each sink (file, line, rule), the interprocedural
// flows only where nothing else is reported, and then only the first.
//
// An interprocedural flow is reported at its sink inside the helper (ADR
// 0007), so every caller that hands a source to the same helper lands on the
// same line. They are one defect -- the fix goes in the helper -- and the
// call path of the first, in the flow order, is the evidence shown. A flow
// whose source is in the helper itself already names that sink, and a
// caller's path adds nothing a reader acts on. Intraprocedural flows are left
// as they were.
func onePerSink(flows []taint.Flow) []taint.Flow {
	type at struct {
		file, rule string
		line       int
	}
	direct := map[at]bool{}
	for i := range flows {
		if len(flows[i].Path) == 0 {
			direct[at{flows[i].FilePath, flows[i].Sink.RuleID, flows[i].SinkLine}] = true
		}
	}
	taken := map[at]int{}
	out := flows[:0:0]
	for i := range flows {
		f := &flows[i]
		if len(f.Path) == 0 {
			out = append(out, *f)
			continue
		}
		k := at{f.FilePath, f.Sink.RuleID, f.SinkLine}
		if direct[k] {
			continue
		}
		if j, ok := taken[k]; ok {
			// Another caller reaching the same sink: one finding, every path.
			if !hasPath(out[j], f.Path) {
				out[j].OtherPaths = append(out[j].OtherPaths, f.Path)
			}
			out[j].OtherPaths = append(out[j].OtherPaths, f.OtherPaths...)
			continue
		}
		taken[k] = len(out)
		out = append(out, *f)
	}
	return out
}

// hasPath reports whether f already carries path, as its own or another's.
func hasPath(f taint.Flow, path []taint.CallStep) bool {
	if slices.Equal(f.Path, path) {
		return true
	}
	for _, p := range f.OtherPaths {
		if slices.Equal(p, path) {
			return true
		}
	}
	return false
}

// SourceParameter is the source kind of a flow from a function's own
// parameter, which no source in the file establishes as untrusted.
const SourceParameter = taint.SourceKind("parameter")

// paramSQLFlows reports a SQL query built from a function's parameter by string
// formatting, inside the function, when the file shows no source for it.
//
// Taint needs a source, and in the commonest SQL injection shape the source is
// not in the file: a handler parses the request and calls a DAO method in
// another file, and the DAO concatenates its argument into the query. The
// summaries already compute, for every function, which parameters reach which
// sinks -- and that was used only when a caller in the same file passed a
// source in. This reports the SQL injection class of it, at the sink, held to
// the premise in sqltext.go: the parameter must have been combined with
// literal SQL text (Flow.SQLBuilt). A parameter passed through whole
// (`run(sql)` calling `cursor.execute(sql)`) is a wrapper's contract, not a
// query built from data, and is not reported.
//
// Not reported either: a sink a reported flow already names at the same line
// (a source in the same function), and a function a reported cross-function
// flow already goes through for the same rule (a source in a caller in this
// file), so one query is one finding.
func (e *StructuralEngine) paramSQLFlows(lang string, units []taint.Unit, summaries map[string]*funcSummary, reported []taint.Flow) []taint.Flow {
	type sinkAt struct {
		line int
		rule string
	}
	atSink := map[sinkAt]bool{}
	throughFn := map[string]bool{}
	for i := range reported {
		f := &reported[i]
		atSink[sinkAt{f.SinkLine, f.Sink.RuleID}] = true
		for _, fn := range f.Via {
			throughFn[fn+"\x00"+f.Sink.RuleID] = true
		}
	}
	var out []taint.Flow
	for i := range units {
		u := &units[i]
		if u.FuncName == "" || len(u.Params) == 0 {
			continue
		}
		for _, param := range u.Params {
			seed := map[string]taintInfo{param: {
				src:     taint.Source{Call: u.FuncName + ":" + param, Kind: SourceParameter},
				cleared: map[taint.VulnClass]bool{},
			}}
			res := e.forwardPass(lang, u, seed, summaries)
			for j := range res.flows {
				f := res.flows[j]
				k := sinkAt{f.SinkLine, f.Sink.RuleID}
				if f.Sink.VulnClass != taint.VulnSQLInjection || f.Source.Kind != SourceParameter ||
					f.Source.Call != u.FuncName+":"+param || len(f.Via) > 0 || !f.SQLBuilt ||
					atSink[k] || throughFn[u.FuncName+"\x00"+f.Sink.RuleID] {
					continue
				}
				atSink[k] = true
				out = append(out, f)
			}
		}
	}
	return out
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
	return e.computeSummariesWith(lang, units, nil)
}

// computeSummariesWith is computeSummaries with the summaries of calls bound
// to other files' functions supplied as fixed inputs (crossfile.go).
func (e *StructuralEngine) computeSummariesWith(lang string, units []taint.Unit, external map[string]*funcSummary) map[string]*funcSummary {
	summaries := make(map[string]*funcSummary, len(units)+len(external))
	for k, v := range external {
		summaries[k] = v
	}
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
	// Unseeded: is the function a GETTER of a source -- does every return in
	// it return a value a source it reads itself taints? One return of
	// request data among others returning constants or computed values
	// (`parse_variable($type, $name)` returning $_SERVER[$name] for one type
	// and literals otherwise) is not a getter, and summarizing it as one
	// tainted every call. The first source in line order names the summary.
	sum.returnsSource = e.getterSource(lang, u, summaries)
	for idx, param := range u.Params {
		// Seed: parameter `param` is tainted by a synthetic "parameter" source.
		seed := map[string]taintInfo{
			param: {
				src:     taint.Source{Call: u.FuncName + ":" + param, Kind: SourceParameter},
				srcLine: 0,
				cleared: map[taint.VulnClass]bool{},
				via:     nil,
			},
		}
		res := e.forwardPass(lang, u, seed, summaries)

		for fi := range res.flows {
			f := &res.flows[fi]
			// The flow is this parameter's when the seed is its source. Its
			// SourceVar is the variable read AT the sink, which is the
			// parameter only when it is passed in unchanged: matching on it
			// left every helper that binds its argument first -- `q = "..." %
			// name; c.execute(q)`, `full = "ls " + cmd; os.system(full)` --
			// without a summary, and the caller's source reached nothing.
			//
			// A binding through a call that does not hand its argument on
			// (`rows = repo.list(filter)`, `parts = cmd.split()`) is not
			// summarized: the forward pass keeps such a value tainted, which
			// is conservative inside one function, and handing that to every
			// caller reported a database row written as JSON as the request
			// text it was filtered by (chronos), and an argv list as a shell
			// string (certbot). Only the parameter itself, or a value built
			// from it by copying and string operations, is the parameter.
			if f.Source.Kind != SourceParameter || f.Source.Call != u.FuncName+":"+param {
				continue
			}
			if f.SourceVar != param && f.ThroughCall {
				continue
			}
			sum.sinksArg[idx] = append(sum.sinksArg[idx], argSink{sink: f.Sink, via: f.Via, file: f.FilePath, line: f.SinkLine, fn: f.FuncName, path: f.Path})
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
	if (a.returnsSource == nil) != (b.returnsSource == nil) {
		return false
	}
	if a.returnsSource != nil && a.returnsSource.src.Call != b.returnsSource.src.Call {
		return false
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
			if av[i].sink.RuleID != bv[i].sink.RuleID || av[i].sink.Call != bv[i].sink.Call ||
				av[i].file != bv[i].file || av[i].line != bv[i].line {
				return false
			}
		}
	}
	return true
}

// getterSource returns the source a function returns from every one of its
// return statements, or nil when some return carries something else or the
// function has none. A return is source-returning when it names a source
// directly (`return $_GET['q']`) or returns a variable the unseeded pass
// leaves tainted by a real source.
//
// Most functions are answered before that pass, which is the cost here (2.0 s
// of a 58 s crewAI scan profile): one with no return, and one with a return
// that names no source and reads no variable (`return None`, `return 1`), can
// only be nil whatever the pass finds. On crewAI that is 12,184 of 15,618
// functions.
func (e *StructuralEngine) getterSource(lang string, u *taint.Unit, summaries map[string]*funcSummary) *taintInfo {
	if !e.mayReturnASource(lang, u) {
		return nil
	}
	return e.passGetterSource(lang, u, summaries)
}

// passGetterSource is getterSource answered by the unseeded pass alone.
func (e *StructuralEngine) passGetterSource(lang string, u *taint.Unit, summaries map[string]*funcSummary) *taintInfo {
	res := e.forwardPass(lang, u, map[string]taintInfo{}, summaries)
	var first *taintInfo
	returns := 0
	for i := range u.Stmts {
		st := &u.Stmts[i]
		if !st.IsReturn {
			continue
		}
		returns++
		var found *taintInfo
		if src, ok := e.resolveSource(lang, st); ok {
			found = &taintInfo{src: src, srcLine: st.Line, cleared: map[taint.VulnClass]bool{}}
		} else {
			for _, rv := range sortedReads(st.Returns) {
				if ti, ok := res.state[rv]; ok && ti.src.Kind != SourceParameter {
					c := cloneTaintInfo(ti)
					found = &c
					break
				}
			}
		}
		if found == nil {
			return nil
		}
		if first == nil {
			first = found
		}
	}
	if returns == 0 {
		return nil
	}
	if first.srcFile == "" {
		first.srcFile = u.FilePath
	}
	return first
}

// mayReturnASource reports whether u has a return, and every return either
// names a source or reads a variable the pass could have tainted.
func (e *StructuralEngine) mayReturnASource(lang string, u *taint.Unit) bool {
	returns := 0
	for i := range u.Stmts {
		st := &u.Stmts[i]
		if !st.IsReturn {
			continue
		}
		returns++
		if len(st.Returns) == 0 {
			if _, ok := e.resolveSource(lang, st); !ok {
				return false
			}
		}
	}
	return returns > 0
}
