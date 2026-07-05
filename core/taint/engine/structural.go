package engine

import (
	"sort"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

// ExtractUnits parses source content into taint.Units ready for a TaintEngine.
// It is the substrate the design doc calls for: it turns files into function-
// scoped, ordered statement lists, consulting only lexctx (never the catalog).
// filePath and language are attached to every Unit so findings can be located.
func ExtractUnits(filePath string, lang lexctx.Lang, content []byte) []taint.Unit {
	drafts := extractUnits(lang, content)
	units := make([]taint.Unit, 0, len(drafts))
	for i := range drafts {
		d := drafts[i]
		if len(d.stmts) == 0 {
			continue
		}
		stmts := make([]taint.Statement, 0, len(d.stmts))
		for j := range d.stmts {
			stmts = append(stmts, toStatement(&d.stmts[j]))
		}
		units = append(units, taint.Unit{
			FilePath: filePath,
			FuncName: d.funcName,
			Language: lang.String(),
			Stmts:    stmts,
		})
	}
	return units
}

// toStatement converts an internal stmtDraft into the foundation's
// taint.Statement, copying the argument-shape evidence into taint.SinkArgInfo.
func toStatement(d *stmtDraft) taint.Statement {
	st := taint.Statement{
		Line:    d.line,
		Assigns: d.assigns,
		Calls:   append([]string(nil), d.calls...),
		Reads:   append([]string(nil), d.reads...),
		Chains:  append([]string(nil), d.chains...),
	}
	if len(d.sinkArgs) > 0 {
		st.SinkArgs = make(map[string]taint.SinkArgInfo, len(d.sinkArgs))
		for call, a := range d.sinkArgs {
			st.SinkArgs[call] = taint.SinkArgInfo{
				TaintedArgVars:  append([]string(nil), a.taintedArgVars...),
				ArgCount:        a.argCount,
				ShellTrue:       a.shellTrue,
				FirstArgTainted: a.firstArgTainted,
			}
		}
	}
	return st
}

// StructuralEngine is the real intraprocedural taint engine. It replaces the
// heuristic stub with class-precise sanitization and argument-aware sink gating,
// while staying deterministic, offline, and pure-Go.
//
// WHAT IT DOES (and only this):
//   - Forward, straight-line dataflow within one Unit (one function body or the
//     module top level). A variable is tainted when assigned from a catalog
//     SOURCE, from another tainted variable, or from an expression that reads a
//     tainted variable (string concat/format all count — any read propagates).
//   - Taint clears for a variable when it is assigned through a catalog SANITIZER
//     whose Neutralizes set covers the vuln class of the sink it would reach.
//     Clearing is tracked PER VULN CLASS: a value html.escaped (XSS-safe) is
//     still command-injection-tainted, so os.system(escaped) still fires.
//   - A tainted variable reaching a catalog SINK argument emits a Flow — unless
//     the sink's argument shape makes it safe: a parameterized cursor.execute
//     (tainted value only in the params tuple, not the SQL string) and a
//     subprocess.run/spawn without shell=True and a string command do not fire.
//
// LIMITS (honest, and exactly the taint-analysis plugin's territory):
//   - Intraprocedural only: no cross-function or cross-file flow. A source in one
//     function and a sink in another are never joined.
//   - Straight-line + simple reassignment: no control-flow graph, no branch
//     merging, no loops modeling, no alias analysis, no container-element or
//     field sensitivity. A taint that only exists on one branch is treated as
//     always present (conservative — may over-report), and a taint laundered
//     through an untracked structure (a dict, an object attribute) is lost
//     (may under-report).
//   - Best-effort call-name normalization via dotted-suffix matching against the
//     catalog: framework prefixes and simple import aliases resolve, but a value
//     renamed through an unrecognized wrapper is missed.
type StructuralEngine struct {
	cat *taint.Catalog
}

// NewStructuralEngine returns the engine backed by cat, or the embedded default
// catalog when cat is nil.
func NewStructuralEngine(cat *taint.Catalog) *StructuralEngine {
	if cat == nil {
		cat = taint.MustDefault()
	}
	return &StructuralEngine{cat: cat}
}

// Analyze implements taint.TaintEngine. See the StructuralEngine doc for the
// exact propagation and sanitization semantics and their limits.
func (e *StructuralEngine) Analyze(unit taint.Unit) []taint.Flow {
	lang := unit.Language

	// taintState maps a variable to its taint: the originating source and the set
	// of vuln classes for which it has been SANITIZED (cleared). A class in
	// cleared means the variable is safe for that class only.
	type taintInfo struct {
		src     taint.Source
		srcLine int
		cleared map[taint.VulnClass]bool
	}
	tainted := map[string]taintInfo{}
	var flows []taint.Flow

	for i := range unit.Stmts {
		st := &unit.Stmts[i]

		// inlineCleared maps a variable to the classes for which a sanitizer call
		// in THIS statement neutralizes it — the `os.system(shlex.quote(user))`
		// case, where the sanitizer wraps the tainted value at the sink itself
		// rather than in a prior assignment.
		inlineCleared := e.inlineSanitized(lang, st)

		// 1) Sink check: for each call that resolves to a sink, decide whether a
		//    tainted, class-un-sanitized value reaches it in a dangerous position.
		for _, rawCall := range st.Calls {
			sink, ok := e.resolveSink(lang, rawCall)
			if !ok {
				continue
			}
			if !e.sinkArgIsDangerous(st, rawCall, &sink) {
				continue // argument shape makes this call safe (parameterized, no shell)
			}
			// Which variables actually reach this sink call as arguments?
			argVars := e.sinkArgVars(st, rawCall)
			for _, v := range argVars {
				ti, isTainted := tainted[v]
				if !isTainted {
					continue
				}
				if ti.cleared[sink.VulnClass] {
					continue // sanitized for this exact class (prior assignment)
				}
				if inlineCleared[v][sink.VulnClass] {
					continue // sanitized inline at the sink call
				}
				flows = append(flows, taint.Flow{
					Source:     ti.src,
					SourceLine: ti.srcLine,
					SourceVar:  v,
					Sink:       sink,
					SinkLine:   st.Line,
					SinkCall:   sink.Call,
					FilePath:   unit.FilePath,
					FuncName:   unit.FuncName,
					Language:   unit.Language,
				})
				break // one flow per sink call is enough
			}
		}

		// 2) Propagation into the assignee.
		if st.Assigns == "" {
			continue
		}

		// A source assignment taints the LHS afresh (a re-source overwrites prior
		// taint/clear state). Sources may be CALLS (request.args.get) or bare
		// ATTRIBUTE chains (request.args, req.query), so both are consulted.
		if src, ok := e.resolveSource(lang, st); ok {
			tainted[st.Assigns] = taintInfo{src: src, srcLine: st.Line, cleared: map[taint.VulnClass]bool{}}
			continue
		}

		// Does the RHS read any tainted variable? If so, propagate — carrying the
		// most-recently-introduced source and the intersection-safe cleared set.
		var carried *taintInfo
		for _, v := range st.Reads {
			if ti, ok := tainted[v]; ok {
				c := ti
				carried = &c
				break
			}
		}
		if carried == nil {
			// LHS reassigned from untainted data: it becomes clean.
			delete(tainted, st.Assigns)
			continue
		}

		// Compute the classes this statement's sanitizer calls clear.
		cleared := map[taint.VulnClass]bool{}
		for k, v := range carried.cleared {
			cleared[k] = v
		}
		for _, rawCall := range st.Calls {
			for _, class := range e.sanitizerClasses(lang, rawCall) {
				cleared[class] = true
			}
		}
		tainted[st.Assigns] = taintInfo{src: carried.src, srcLine: carried.srcLine, cleared: cleared}
	}

	sortFlows(flows)
	return flows
}

// inlineSanitized returns, per variable, the vuln classes a sanitizer call in
// this statement neutralizes for it. It handles sanitizers applied at the sink
// call site (os.system(shlex.quote(user))) rather than in a prior assignment.
// A variable read by a sanitizer call is considered cleared for every class that
// sanitizer covers.
func (e *StructuralEngine) inlineSanitized(lang string, st *taint.Statement) map[string]map[taint.VulnClass]bool {
	out := map[string]map[taint.VulnClass]bool{}
	for _, rawCall := range st.Calls {
		classes := e.sanitizerClasses(lang, rawCall)
		if len(classes) == 0 {
			continue
		}
		info, ok := lookupSinkArg(st, rawCall)
		if !ok {
			continue
		}
		for _, v := range info.TaintedArgVars {
			if out[v] == nil {
				out[v] = map[taint.VulnClass]bool{}
			}
			for _, c := range classes {
				out[v][c] = true
			}
		}
	}
	return out
}

// resolveSink resolves a raw extracted call chain to a catalog Sink by trying
// its dotted suffixes longest-first. Returns the sink with its canonical Call.
func (e *StructuralEngine) resolveSink(lang, rawCall string) (taint.Sink, bool) {
	for _, key := range suffixKeys(rawCall) {
		if s, ok := e.cat.IsSink(lang, key); ok {
			return s, true
		}
	}
	return taint.Sink{}, false
}

// resolveSource returns the source introduced by st, matching both its call
// chains and its bare attribute chains against the catalog by dotted-suffix. A
// source CALL (request.args.get) and a source ATTRIBUTE (request.args) both
// taint the assignee. Calls are tried before attribute chains so the most
// specific match wins.
func (e *StructuralEngine) resolveSource(lang string, st *taint.Statement) (taint.Source, bool) {
	for _, rawCall := range st.Calls {
		for _, key := range suffixKeys(rawCall) {
			if s, ok := e.cat.Source(lang, key); ok {
				return s, true
			}
		}
	}
	for _, chain := range st.Chains {
		for _, key := range suffixKeys(chain) {
			if s, ok := e.cat.Source(lang, key); ok {
				return s, true
			}
		}
	}
	return taint.Source{}, false
}

// sanitizerClasses returns every vuln class a call neutralizes (by suffix match).
func (e *StructuralEngine) sanitizerClasses(lang, rawCall string) []taint.VulnClass {
	var out []taint.VulnClass
	for _, key := range suffixKeys(rawCall) {
		for _, class := range allVulnClasses {
			if e.cat.IsSanitizer(lang, key, class) {
				out = append(out, class)
			}
		}
		if len(out) > 0 {
			return out // first matching suffix wins, like sink/source resolution
		}
	}
	return out
}

// sinkArgVars returns the variables that reach this sink call as arguments. It
// prefers the precise per-call TaintedArgVars the extractor recorded, falling
// back to the statement's whole Reads set when none were captured.
func (e *StructuralEngine) sinkArgVars(st *taint.Statement, rawCall string) []string {
	if info, ok := lookupSinkArg(st, rawCall); ok && len(info.TaintedArgVars) > 0 {
		return info.TaintedArgVars
	}
	return st.Reads
}

// sinkArgIsDangerous applies the catalog's per-sink argument notes to decide
// whether a call site is a live sink given its argument shape. Unknown shape
// (no SinkArgInfo) is treated as dangerous — we never suppress on missing
// evidence.
func (e *StructuralEngine) sinkArgIsDangerous(st *taint.Statement, rawCall string, sink *taint.Sink) bool {
	info, ok := lookupSinkArg(st, rawCall)
	if !ok {
		return true
	}
	switch canonicalSuffix(sink.Call) {
	case "cursor.execute", "cursor.executemany", "connection.execute",
		"db.execute", "session.execute", "connection.query", "db.query",
		"pool.query", "sequelize.query":
		// Parameterized query: the tainted value is passed as the params
		// argument (2nd positional), NOT interpolated into the SQL string
		// (1st positional). Safe only when there is more than one positional
		// argument AND the taint is not in the first argument.
		if info.ArgCount >= 2 && !info.FirstArgTainted {
			return false
		}
		return true
	case "subprocess.run", "subprocess.call", "subprocess.Popen",
		"child_process.spawn":
		// An arg-vector exec (list/array first arg) without shell=True is safe.
		// We approximate "arg vector" as: shell not True and the first argument
		// is not a bare tainted string (FirstArgTainted false means the command
		// is a list literal or constant). shell=True always re-arms it.
		if info.ShellTrue {
			return true
		}
		if !info.FirstArgTainted {
			return false
		}
		return true
	default:
		return true
	}
}

// lookupSinkArg finds the SinkArgInfo for rawCall on st, matching by suffix so
// the extractor's full-chain key resolves against the canonical sink call.
func lookupSinkArg(st *taint.Statement, rawCall string) (taint.SinkArgInfo, bool) {
	if st.SinkArgs == nil {
		return taint.SinkArgInfo{}, false
	}
	if info, ok := st.SinkArgs[rawCall]; ok {
		return info, true
	}
	for _, key := range suffixKeys(rawCall) {
		if info, ok := st.SinkArgs[key]; ok {
			return info, true
		}
	}
	return taint.SinkArgInfo{}, false
}

// canonicalSuffix returns the shortest catalog-facing suffix used to key the
// argument-shape switch (the last two dotted segments, e.g. cursor.execute).
func canonicalSuffix(call string) string {
	keys := suffixKeys(call)
	// Prefer a two-segment suffix when present (obj.method); otherwise the whole.
	for _, k := range keys {
		if dots(k) == 1 {
			return k
		}
	}
	return call
}

// dots counts the '.' separators in s.
func dots(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			n++
		}
	}
	return n
}

// allVulnClasses is the fixed set of classes checked when resolving a sanitizer
// call to the classes it clears. Ordered deterministically.
var allVulnClasses = []taint.VulnClass{
	taint.VulnCommandInjection,
	taint.VulnSQLInjection,
	taint.VulnCodeInjection,
	taint.VulnXSS,
	taint.VulnSSTI,
	taint.VulnPathTraversal,
	taint.VulnSSRF,
	taint.VulnUnsafeDeserialization,
	taint.VulnPromptInjection,
}

// sortFlows orders flows deterministically by sink line, then source line, then
// sink call — matching the foundation stub's ordering so downstream consumers
// see one stable order regardless of which engine produced the flows.
func sortFlows(flows []taint.Flow) {
	sort.SliceStable(flows, func(i, j int) bool {
		a, b := flows[i], flows[j]
		if a.SinkLine != b.SinkLine {
			return a.SinkLine < b.SinkLine
		}
		if a.SourceLine != b.SourceLine {
			return a.SourceLine < b.SourceLine
		}
		return a.SinkCall < b.SinkCall
	})
}
