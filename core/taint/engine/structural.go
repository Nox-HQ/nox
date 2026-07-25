package engine

import (
	"sort"
	"strconv"
	"strings"

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
		// A named function with no statements is still kept: the interprocedural
		// pass needs its (possibly empty) summary and parameter list so a call to
		// it resolves as a known local callee rather than an unknown one. The
		// module unit (funcName "") with no statements carries nothing, so it is
		// dropped to avoid an empty analyzable scope.
		if len(d.stmts) == 0 && d.funcName == "" {
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
			Params:   append([]string(nil), d.params...),
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
		Returns: append([]string(nil), d.returns...),
	}
	if len(d.sinkArgs) > 0 {
		st.SinkArgs = make(map[string]taint.SinkArgInfo, len(d.sinkArgs))
		for call, a := range d.sinkArgs {
			st.SinkArgs[call] = taint.SinkArgInfo{
				TaintedArgVars:        append([]string(nil), a.taintedArgVars...),
				ArgCount:              a.argCount,
				ShellTrue:             a.shellTrue,
				FirstArgTainted:       a.firstArgTainted,
				PositionalVars:        copyPositional(a.positionalVars),
				PositionalArgs:        append([]string(nil), a.positionalArgs...),
				PromptRoles:           copyRoles(a.promptRoles),
				PromptHasStaticSystem: a.promptStaticSystem,
			}
		}
	}
	return st
}

// copyPositional deep-copies a per-slot positional-variable list so the
// foundation's SinkArgInfo never aliases the extractor's internal slices.
func copyPositional(src [][]string) [][]string {
	if len(src) == 0 {
		return nil
	}
	out := make([][]string, len(src))
	for i := range src {
		out[i] = append([]string(nil), src[i]...)
	}
	return out
}

// copyRoles copies the prompt-role map so the foundation's SinkArgInfo never
// aliases the extractor's internal map. nil stays nil (no role structure).
func copyRoles(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
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

// taintInfo is a variable's taint state during a forward pass: the originating
// source, the line it entered at, the set of vuln classes it has been SANITIZED
// (cleared) for, and the chain of local functions its taint has flowed through
// (via) for interprocedural provenance. A class in cleared means the variable is
// safe for that class only.
type taintInfo struct {
	src     taint.Source
	srcLine int
	cleared map[taint.VulnClass]bool
	// via is the nearest-caller-first chain of local helper functions whose
	// summaries carried this taint (empty for a directly-assigned source). It
	// feeds Flow.Via so a cross-function finding can name the path.
	via []string
}

// passResult is the output of a forward pass: the flows found, the final taint
// state (for summary observation), and the variables returned by the unit.
type passResult struct {
	flows    []taint.Flow
	state    map[string]taintInfo
	returned []string
}

// Analyze implements taint.TaintEngine: intraprocedural, straight-line dataflow
// over one Unit. It is unchanged in behavior — it runs the shared forward pass
// with NO interprocedural summary resolution, so a call to another function is
// just an ordinary call (its sink/source/sanitizer nature is judged by the
// catalog only, never by a summary). See the StructuralEngine doc for semantics
// and limits; cross-function flow is AnalyzeFile's job.
//
//nolint:gocritic // Analyze(unit taint.Unit) is the TaintEngine interface signature; the value parameter cannot be a pointer.
func (e *StructuralEngine) Analyze(unit taint.Unit) []taint.Flow {
	res := e.forwardPass(unit.Language, &unit, nil, nil)
	sortFlows(res.flows)
	return res.flows
}

// analyzeUnitInterproc runs the forward pass over one unit WITH interprocedural
// summary resolution enabled, so calls to locally-defined functions apply their
// summaries (sink-in-helper, return-taint). Flows are returned unsorted; the
// caller dedups and sorts.
func (e *StructuralEngine) analyzeUnitInterproc(lang string, unit *taint.Unit, summaries map[string]*funcSummary) []taint.Flow {
	res := e.forwardPass(lang, unit, nil, summaries)
	return res.flows
}

// forwardPass is the single, shared forward-propagation core used by BOTH the
// intraprocedural Analyze and the interprocedural AnalyzeFile/summarize. Keeping
// one implementation guarantees summary semantics never diverge from
// intraprocedural semantics.
//
// Parameters:
//   - seed: an optional initial taint state (used by summarize to mark a
//     parameter tainted). nil starts clean.
//   - summaries: when non-nil, calls to locally-defined functions apply their
//     summaries — a summarized sink emits a cross-function Flow and a summarized
//     tainted return propagates. When nil, no interprocedural resolution happens
//     (pure intraprocedural behavior). Summary application reads precomputed
//     summaries only (never re-enters a body), so recursion is handled by the
//     bounded summary fixpoint in computeSummaries, not here.
func (e *StructuralEngine) forwardPass(
	lang string,
	unit *taint.Unit,
	seed map[string]taintInfo,
	summaries map[string]*funcSummary,
) passResult {
	tainted := map[string]taintInfo{}
	for k, v := range seed {
		tainted[k] = cloneTaintInfo(v)
	}
	var flows []taint.Flow
	var returned []string

	for i := range unit.Stmts {
		st := &unit.Stmts[i]

		// inlineCleared maps a variable to the classes for which a sanitizer call
		// in THIS statement neutralizes it — the `os.system(shlex.quote(user))`
		// case, where the sanitizer wraps the tainted value at the sink itself
		// rather than in a prior assignment.
		inlineCleared := e.inlineSanitized(lang, st)

		// 1) Catalog sink check: for each call that resolves to a catalog sink,
		//    decide whether a tainted, class-un-sanitized value reaches it in a
		//    dangerous position.
		for _, rawCall := range st.Calls {
			sink, ok := e.resolveSink(lang, rawCall)
			if !ok {
				continue
			}
			info, hasInfo := lookupSinkArg(st, rawCall)

			// F1: a catalog source used DIRECTLY as an argument of this sink in the
			// same statement — sink(source()) — binds no variable, so ordinary
			// variable propagation never sees it and no prior assignment ever tainted
			// anything. Detect such inline sources per positional slot and fold each
			// into the sink's argument shape as a synthetic tainted operand, so the
			// gating and class-precise sanitizer clearing below apply uniformly (a
			// wrapped source like os.system(shlex.quote(source())) stays suppressed).
			inline := e.inlineSourceOperands(lang, info, st.Line)
			if len(inline) > 0 {
				info = withInlineOperands(info, inline)
				hasInfo = true
			}

			// Unknown shape (no SinkArgInfo at all) is dangerous — we never suppress
			// on missing evidence.
			if hasInfo && !e.sinkArgShapeDangerous(&sink, info) {
				continue // argument shape makes this call safe (parameterized, no shell)
			}

			argVars := info.TaintedArgVars
			if len(argVars) == 0 {
				argVars = st.Reads
			}
			for _, v := range argVars {
				ti, isTainted := tainted[v]
				sourceVar := v
				if !isTainted {
					if op, isInline := inline[v]; isInline {
						ti, isTainted = op.info, true
						sourceVar = "" // an inline source expression has no variable name
					}
				}
				if !isTainted {
					continue
				}
				if ti.cleared[sink.VulnClass] {
					continue // sanitized for this exact class (prior assignment / inline wrap)
				}
				if inlineCleared[v][sink.VulnClass] {
					continue // sanitized inline at the sink call
				}
				// Role-aware gating for LLM prompt sinks: reaching an LLM is necessary
				// but not sufficient. Determine the chat role the tainted value lands
				// in; suppress ONLY the recommended pattern (user role behind a static
				// system message), keep every system/developer/unknown placement. See
				// promptSinkRole / taint.SuppressPromptRole.
				sinkRole := ""
				if sink.VulnClass == taint.VulnPromptInjection {
					sinkRole = promptSinkRole(info, v)
					if taint.SuppressPromptRole(sinkRole, info.PromptHasStaticSystem) {
						continue // untrusted content confined to the user role (safe pattern)
					}
				}
				flows = append(flows, taint.Flow{
					Source:     ti.src,
					SourceLine: ti.srcLine,
					SourceVar:  sourceVar,
					Sink:       sink,
					SinkLine:   st.Line,
					SinkCall:   sink.Call,
					FilePath:   unit.FilePath,
					FuncName:   unit.FuncName,
					Language:   unit.Language,
					Via:        append([]string(nil), ti.via...),
					SinkRole:   sinkRole,
				})
				break // one flow per sink call is enough
			}
		}

		// 2) Interprocedural sink check: a call to a locally-defined helper whose
		//    summary says a tainted argument reaches a sink inside it emits a
		//    cross-function flow. Only when summary resolution is enabled.
		if summaries != nil {
			flows = append(flows, e.interprocSinkFlows(lang, unit, st, tainted, summaries)...)
		}

		// 3) Record returned variables (for summary observation). A return never
		//    assigns, so it is handled before the assignment logic.
		if len(st.Returns) > 0 {
			returned = append(returned, st.Returns...)
		}

		// 4) Propagation into the assignee.
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

		// Interprocedural return-taint: x = helper(taintedArg) where helper's
		// summary returnsTaintedIf(i) marks x tainted, carrying the source of the
		// tainted argument and the helper in the via chain. Checked before the
		// generic read-propagation so a helper that LAUNDERS taint (returns clean)
		// does not leak via a raw read of its tainted argument.
		if summaries != nil {
			if ti, ok := e.interprocReturnTaint(lang, st, tainted, summaries); ok {
				tainted[st.Assigns] = ti
				continue
			}
			// A lone local-helper call on the RHS (`x = helper(tainted)`) that did
			// NOT return taint is a taint BARRIER: the helper consumed the tainted
			// argument and returned a clean value, so x is clean — even though the
			// raw argument read would otherwise propagate taint. This is what makes
			// a launder-through-helper (return a constant) not over-report. Only a
			// LONE call qualifies; a compound RHS (`x = helper(a) + tainted`) still
			// falls through to conservative read-propagation.
			if e.rhsIsLoneLocalCall(st, summaries) {
				delete(tainted, st.Assigns)
				continue
			}
		}

		// Does the RHS read any tainted variable? If so, propagate — carrying the
		// most-recently-introduced source and its cleared set.
		var carried *taintInfo
		for _, v := range sortedReads(st.Reads) {
			if ti, ok := tainted[v]; ok {
				c := cloneTaintInfo(ti)
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
		tainted[st.Assigns] = taintInfo{src: carried.src, srcLine: carried.srcLine, cleared: cleared, via: carried.via}
	}

	return passResult{flows: flows, state: tainted, returned: returned}
}

// interprocSinkFlows returns cross-function flows for a statement's calls to
// locally-defined helpers whose summaries say a tainted argument reaches a sink
// inside the helper. It maps each positional argument to the callee parameter of
// the same index, and suppresses the flow when the helper sanitized that
// parameter for the sink's class.
func (e *StructuralEngine) interprocSinkFlows(lang string, unit *taint.Unit, st *taint.Statement, tainted map[string]taintInfo, summaries map[string]*funcSummary) []taint.Flow {
	var out []taint.Flow
	for _, rawCall := range sortedReads(st.Calls) {
		sum := resolveLocalCallee(rawCall, summaries)
		if sum == nil || len(sum.sinksArg) == 0 {
			continue
		}
		info, ok := lookupSinkArg(st, rawCall)
		if !ok {
			continue
		}
		for argIdx := range info.PositionalVars {
			sinks, has := sum.sinksArg[argIdx]
			if !has {
				continue
			}
			for _, op := range e.argOperands(lang, info, argIdx, tainted, st.Line) {
				for _, as := range sinks {
					if op.ti.cleared[as.sink.VulnClass] {
						continue // caller already sanitized for this class
					}
					if cls := sum.sanitizesClass[argIdx]; cls[as.sink.VulnClass] {
						continue // helper sanitizes this parameter for this class
					}
					via := append(append([]string(nil), op.ti.via...), sum.name)
					via = append(via, as.via...)
					out = append(out, taint.Flow{
						Source:     op.ti.src,
						SourceLine: op.ti.srcLine,
						SourceVar:  op.sourceVar,
						Sink:       as.sink,
						SinkLine:   st.Line,
						SinkCall:   as.sink.Call,
						FilePath:   unit.FilePath,
						FuncName:   unit.FuncName,
						Language:   unit.Language,
						Via:        via,
					})
					break // one flow per (arg, helper) is enough
				}
			}
		}
	}
	return out
}

// interprocReturnTaint checks whether st is `lhs = helper(args...)` for a local
// helper whose summary returnsTaintedIf(i) with a tainted argument in position i.
// It returns the taint state to assign to lhs (carrying the argument's source and
// extending the via chain) and ok=true when so. A helper that sanitized the
// parameter for all classes still returns tainted (the value is dangerous for the
// remaining classes) — the cleared set is carried through.
func (e *StructuralEngine) interprocReturnTaint(lang string, st *taint.Statement, tainted map[string]taintInfo, summaries map[string]*funcSummary) (taintInfo, bool) {
	for _, rawCall := range sortedReads(st.Calls) {
		sum := resolveLocalCallee(rawCall, summaries)
		if sum == nil || len(sum.returnsTaintedIf) == 0 {
			continue
		}
		info, ok := lookupSinkArg(st, rawCall)
		if !ok {
			continue
		}
		for argIdx := range info.PositionalVars {
			if !sum.returnsTaintedIf[argIdx] {
				continue
			}
			for _, op := range e.argOperands(lang, info, argIdx, tainted, st.Line) {
				cleared := map[taint.VulnClass]bool{}
				for c, val := range op.ti.cleared {
					cleared[c] = val
				}
				for c, val := range sum.sanitizesClass[argIdx] {
					cleared[c] = val
				}
				via := append(append([]string(nil), op.ti.via...), sum.name)
				via = append(via, sum.returnVia[argIdx]...)
				return taintInfo{src: op.ti.src, srcLine: op.ti.srcLine, cleared: cleared, via: via}, true
			}
		}
	}
	return taintInfo{}, false
}

// rhsIsLoneLocalCall reports whether st's assignment RHS is exactly a single
// call to a locally-defined helper, with no free variable read outside that
// call's arguments — the `x = helper(args)` shape where the helper is
// authoritative for x's taint. It is used to treat a non-taint-returning helper
// as a barrier. A compound RHS (multiple calls, or a bare variable read
// alongside the call) returns false so conservative read-propagation still runs.
func (e *StructuralEngine) rhsIsLoneLocalCall(st *taint.Statement, summaries map[string]*funcSummary) bool {
	if len(st.Calls) != 1 {
		return false
	}
	sum := resolveLocalCallee(st.Calls[0], summaries)
	if sum == nil {
		return false
	}
	// Every variable the statement reads must be an argument of the sole call;
	// any read outside the call means the RHS is compound and taint could enter
	// by a path the helper's summary does not cover.
	info, ok := lookupSinkArg(st, st.Calls[0])
	if !ok {
		return false
	}
	// Permitted reads: the call's argument variables plus the callee chain's own
	// identifiers (the callee name leaks into Reads as the head of the chain,
	// e.g. `wrap` in `x = wrap(cmd)`; it is not a data read).
	permitted := map[string]struct{}{}
	for _, v := range info.TaintedArgVars {
		permitted[v] = struct{}{}
	}
	for _, seg := range strings.Split(st.Calls[0], ".") {
		permitted[seg] = struct{}{}
	}
	for _, r := range st.Reads {
		if _, ok := permitted[r]; !ok {
			return false
		}
	}
	return true
}

// resolveLocalCallee resolves a raw call chain to a locally-defined function's
// summary by matching its dotted suffixes against the summary map. Best-effort:
// a bare local name (run, wrap) resolves; a chain whose suffix is a local name
// also resolves. An unknown callee returns nil — we never invent a summary,
// which keeps unknown/cross-file calls fail-safe (no false positive).
func resolveLocalCallee(rawCall string, summaries map[string]*funcSummary) *funcSummary {
	for _, key := range suffixKeys(rawCall) {
		if sum, ok := summaries[key]; ok {
			return sum
		}
	}
	return summaries[rawCall]
}

// cloneTaintInfo deep-copies a taintInfo so mutation of one variable's cleared
// set or via chain never aliases another's.
func cloneTaintInfo(ti taintInfo) taintInfo {
	cleared := make(map[taint.VulnClass]bool, len(ti.cleared))
	for k, v := range ti.cleared {
		cleared[k] = v
	}
	return taintInfo{src: ti.src, srcLine: ti.srcLine, cleared: cleared, via: append([]string(nil), ti.via...)}
}

// sortedReads returns a deterministically ordered copy of a read/call slice so
// the "first tainted read" chosen during propagation is stable across runs
// regardless of map iteration or extractor ordering quirks.
func sortedReads(reads []string) []string {
	out := append([]string(nil), reads...)
	sortStrings(out)
	return out
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
		if s, ok := e.sourceForChain(lang, rawCall); ok {
			return s, true
		}
	}
	for _, chain := range st.Chains {
		if s, ok := e.sourceForChain(lang, chain); ok {
			return s, true
		}
	}
	return taint.Source{}, false
}

// sourceForChain resolves one call/attribute chain to a catalog source, matching
// both by dotted SUFFIX (to strip a framework/import prefix — flask.request.args
// → request.args) AND by dotted PREFIX (to strip a trailing member accessor read
// off an attribute-source — req.query.id → req.query, request.values.get →
// request.values). This closes F2: the dominant Express `req.query.<param>` /
// `req.body.<field>` pattern and the Python `request.values.get` /
// `request.cookies.get` accessors all read a member off a catalog attribute-
// source, appending a segment the catalog does not (and should not) enumerate.
//
// WHY a prefix match is safe: a value derived from any member of an untrusted
// object is itself untrusted, so once a chain's prefix is a known source the
// whole chain is tainted. Precision is preserved by requiring a STRIPPED prefix
// to remain multi-segment (contain a dot): the exact key is honored at any length
// (bare sources like `input`, `_GET`, `fetch` keep working), but trailing
// accessors are only peeled back to a still-qualified source (req.query), never
// down to a single bare token that would swallow every `x.y` member read.
func (e *StructuralEngine) sourceForChain(lang, chain string) (taint.Source, bool) {
	for _, key := range suffixKeys(chain) {
		// Exact suffix (any length) — preserves prior bare-source behavior.
		if s, ok := e.cat.Source(lang, key); ok {
			return s, true
		}
		// Peel trailing accessor segments off the suffix, stopping before the key
		// would collapse to a single bare token.
		for {
			dot := strings.LastIndexByte(key, '.')
			if dot < 0 {
				break
			}
			key = key[:dot]
			if !strings.Contains(key, ".") {
				break // single bare token: too broad to match a member read against
			}
			if s, ok := e.cat.Source(lang, key); ok {
				return s, true
			}
		}
	}
	return taint.Source{}, false
}

// inlineOperand is a catalog source appearing DIRECTLY as a sink argument in one
// statement — sink(source()) (F1). It carries a synthetic variable name (so the
// ordinary tainted-variable sink logic can consume it), the positional slot it
// occupies, whether that slot is an argument VECTOR (a leading `[` first arg is
// not a tainted command string), and the source's taint state — including any
// vuln classes a sanitizer wrapping the source at the call site already cleared.
type inlineOperand struct {
	name   string
	slot   int
	vector bool
	info   taintInfo
}

// argOperand is one tainted value reaching a positional argument slot: its taint
// state and the SourceVar to report in a Flow ("" for an inline source expression
// that binds no variable).
type argOperand struct {
	ti        taintInfo
	sourceVar string
}

// argOperands returns every tainted value reaching positional slot argIdx of a
// call: the tainted VARIABLES in that slot, followed by an inline catalog SOURCE
// used directly in the slot (F1 composed with the interprocedural pass — a thin
// handler that calls a helper with req.query.id / $_GET['c'] inline). The inline
// source carries the sanitizer classes cleared by any sanitizer wrapping it at the
// call site. Order is deterministic: extractor slot order, then the inline source.
func (e *StructuralEngine) argOperands(lang string, info taint.SinkArgInfo, argIdx int, tainted map[string]taintInfo, srcLine int) []argOperand {
	var out []argOperand
	if argIdx < len(info.PositionalVars) {
		for _, v := range info.PositionalVars[argIdx] {
			if ti, ok := tainted[v]; ok {
				out = append(out, argOperand{ti: ti, sourceVar: v})
			}
		}
	}
	if argIdx < len(info.PositionalArgs) {
		if src, cleared, ok := e.scanInlineSource(lang, info.PositionalArgs[argIdx]); ok {
			out = append(out, argOperand{ti: taintInfo{src: src, srcLine: srcLine, cleared: cleared}, sourceVar: ""})
		}
	}
	return out
}

// inlineOperandName returns a synthetic, collision-free variable name for the
// inline source in positional slot i. The NUL prefix cannot appear in any real
// extracted identifier, so it never shadows a program variable.
func inlineOperandName(i int) string { return "\x00inline" + strconv.Itoa(i) }

// inlineSourceOperands finds, per positional argument slot of a sink call, a
// catalog source used directly in that slot (F1: sink(source())). It returns the
// operands keyed by their synthetic variable name, each carrying the sanitizer
// classes cleared by any sanitizer wrapping the source at the call site (so a
// wrapped source — os.system(shlex.quote(source())) — is correctly suppressed).
// srcLine is the statement's line (source and sink coincide for an inline flow).
func (e *StructuralEngine) inlineSourceOperands(lang string, info taint.SinkArgInfo, srcLine int) map[string]inlineOperand {
	if len(info.PositionalArgs) == 0 {
		return nil
	}
	var out map[string]inlineOperand
	for slot, argText := range info.PositionalArgs {
		src, cleared, ok := e.scanInlineSource(lang, argText)
		if !ok {
			continue
		}
		if out == nil {
			out = map[string]inlineOperand{}
		}
		name := inlineOperandName(slot)
		out[name] = inlineOperand{
			name:   name,
			slot:   slot,
			vector: strings.HasPrefix(strings.TrimSpace(argText), "["),
			info:   taintInfo{src: src, srcLine: srcLine, cleared: cleared},
		}
	}
	return out
}

// withInlineOperands returns a copy of info augmented with the inline source
// operands: their synthetic names are added to TaintedArgVars, and a non-vector
// source in the first positional slot sets FirstArgTainted (so a gated sink —
// subprocess/exec/printf/sh — treats the tainted first argument as dangerous just
// as it would for a tainted variable). TaintedArgVars is re-sorted so the sink
// loop's first-match choice stays deterministic regardless of map iteration.
func withInlineOperands(info taint.SinkArgInfo, inline map[string]inlineOperand) taint.SinkArgInfo {
	out := info
	out.TaintedArgVars = append([]string(nil), info.TaintedArgVars...)
	for name, op := range inline {
		out.TaintedArgVars = append(out.TaintedArgVars, name)
		if op.slot == 0 && !op.vector {
			out.FirstArgTainted = true
		}
	}
	sortStrings(out.TaintedArgVars)
	return out
}

// scanInlineSource walks an argument expression (code view, literals blanked)
// outermost-first and returns the first catalog source reachable in it, together
// with the sanitizer classes cleared on the path from the expression root down to
// that source. A sanitizer call wrapping the source contributes its classes to
// the cleared set, so os.system(shlex.quote(source())) is suppressed for command
// injection while a bare os.system(source()) fires. Precedence mirrors
// resolveSource: top-level calls (recursed), then attribute chains, then bare
// identifiers (PHP superglobals). Nesting is respected by recursing only into a
// call's own arguments, so a source is never matched outside the sanitizer that
// wraps it.
func (e *StructuralEngine) scanInlineSource(lang, code string) (taint.Source, map[taint.VulnClass]bool, bool) {
	for _, c := range topLevelCalls(code) {
		// The call itself may be a source (request.args.get(...), r.FormValue(...)).
		if s, ok := e.sourceForChain(lang, c.callee); ok {
			return s, map[taint.VulnClass]bool{}, true
		}
		// Otherwise recurse into the call's arguments; a wrapping sanitizer clears
		// the inner source's classes.
		if s, cleared, ok := e.scanInlineSource(lang, c.codeArgs); ok {
			for _, class := range e.sanitizerClasses(lang, c.callee) {
				cleared[class] = true
			}
			return s, cleared, true
		}
	}
	// Attribute-source used directly (req.query, request.args).
	for _, ch := range dottedChains(code) {
		if s, ok := e.sourceForChain(lang, ch); ok {
			return s, map[taint.VulnClass]bool{}, true
		}
	}
	// Bare-identifier source (PHP superglobal read: _GET['c']).
	for _, id := range freeIdentifiers(langPython, code) {
		if s, ok := e.sourceForChain(lang, id); ok {
			return s, map[taint.VulnClass]bool{}, true
		}
	}
	return taint.Source{}, nil, false
}

// topLevelCalls returns the calls at the OUTERMOST nesting level of code (each
// with its argument text), skipping over a call's own arguments rather than
// recursing into them. Unlike extractCalls (which flattens every nested call for
// sink/sanitizer discovery), this preserves nesting so scanInlineSource can tell
// a source WRAPPED by a sanitizer from one that is not. Literals are already
// blanked, so no in-string paren confuses the scan.
func topLevelCalls(code string) []callChain {
	var calls []callChain
	i, n := 0, len(code)
	for i < n {
		if !isIdentStart(code[i]) {
			i++
			continue
		}
		start := i
		for i < n && (isIdentPart(code[i]) || code[i] == '.') {
			i++
		}
		chain := code[start:i]
		j := i
		for j < n && (code[j] == ' ' || code[j] == '\t') {
			j++
		}
		if j >= n || code[j] != '(' {
			continue // an identifier/attribute read, not a call
		}
		codeArgs, end := balancedArgs(code, j)
		if callee := normalizeCallee(chain); callee != "" {
			calls = append(calls, callChain{callee: callee, codeArgs: codeArgs, rawArgs: codeArgs})
		}
		i = end // jump past the whole call: its args are NOT top-level
	}
	return calls
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

// sinkArgShapeDangerous applies the catalog's per-sink argument notes to decide
// whether a call site is a live sink given its (possibly inline-source-augmented)
// argument shape. The caller supplies the SinkArgInfo directly so an inline
// source used as an argument — sink(source()) — can set FirstArgTainted before
// this gate runs. A caller with no SinkArgInfo at all treats the sink as
// dangerous (never suppress on missing evidence); this function is only reached
// once such info exists.
func (e *StructuralEngine) sinkArgShapeDangerous(sink *taint.Sink, info taint.SinkArgInfo) bool {
	switch canonicalSuffix(sink.Call) {
	case "cursor.execute", "cursor.executemany", "connection.execute",
		"db.execute", "session.execute", "connection.query", "db.query",
		"pool.query", "sequelize.query",
		// Ruby ActiveRecord / raw-SQL: a placeholder query passes the tainted
		// value as a bind parameter (2nd+ positional) rather than interpolating it
		// into the SQL string (1st positional), e.g. `where("id = ?", id)`.
		"where", "find_by_sql", "exec_query", "execute",
		// Perl DBI: `$dbh->do("... ?", undef, $id)` and
		// `$dbh->prepare("... ?")` + bind pass the tainted value as a placeholder
		// bind argument (2nd+ positional), not interpolated into the SQL string
		// (1st positional). A bare `do`/`prepare` chain reduces to these suffixes.
		"dbh.do", "dbh.prepare", "dbh.selectrow_array",
		// Clojure jdbc: `(jdbc/query db ["… ?" v])` passes the tainted value in a
		// parameterized bind VECTOR (2nd positional after the db handle) rather than
		// concatenated into the SQL string; a `(str "… " v)` concat query interpolates
		// it into arg 0. The suffix key for `jdbc/query` / `next.jdbc/execute!` is the
		// whole symbol (no dots), so match those verbatim here.
		"jdbc/query", "jdbc/execute!", "next.jdbc/execute!",
		"clojure.java.jdbc/query", "clojure.java.jdbc/execute!",
		// Elixir Ecto raw SQL: `Repo.query("SELECT ... $1", [id])` passes the
		// tainted value as a bind parameter (2nd positional) instead of
		// interpolating it into the SQL string (1st positional). Safe only when
		// there is a 2nd+ positional arg AND the taint is not in the SQL string.
		"Repo.query", "Repo.query!",
		// Dart sqflite: `db.rawQuery("... ?", [id])` / `db.execute("... ?", [id])`
		// pass the tainted value as the arguments list (2nd positional) with a `?`
		// placeholder in the SQL string (1st positional) — the safe parameterized
		// form. A tainted value only in the SQL string (1st positional, no args
		// list) is the injection. Sink Calls are single-token (rawQuery/execute/…),
		// so canonicalSuffix keys on them directly. (`execute` is already a case
		// above, shared with the Ruby/DBI parameterized-query form.)
		"rawQuery", "rawInsert", "rawUpdate", "rawDelete",
		// Groovy groovy.sql.Sql: a parameterized query passes the bind values as a
		// list/varargs in the 2nd+ positional slot — `sql.rows("... = ?", [id])` /
		// `sql.executeQuery("... = ?", [id])` — rather than interpolating the tainted
		// value into the SQL string (1st positional). Matched on the method suffix.
		"rows", "executeQuery", "firstRow", "eachRow":
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
	case "printf", "vprintf":
		// C/C++ format-string sink (CWE-134): the vulnerability is a TAINTED FORMAT
		// STRING — `printf(user)` — not a tainted VALUE with a fixed format —
		// `printf("%s", user)`, which is SAFE. For printf the format is the first
		// argument, so danger requires the taint to be in arg 0. A fixed format
		// literal (arg 0 is a string literal, blanked in the code view) leaves
		// FirstArgTainted false and is correctly suppressed. (Shell uses `printf`
		// as a %q SANITIZER, not a sink, so it never resolves here for shell.)
		return info.FirstArgTainted
	case "sh", "bash":
		// Two sink families share the `sh`/`bash` key:
		//   - The shell/bash INTERPRETER `sh -c "$user"` / `bash -c "$user"`, a
		//     command-injection sink where a tainted string is run as a command
		//     line. The extractor flags `-c` via ShellTrue; a bare `bash script.sh`
		//     (running a file) carries no `-c` and is not a sink.
		//   - The Jenkins pipeline `sh("cmd ${x}")` / `bat("cmd ${x}")` STEP, whose
		//     sole (first) argument IS the command line executed by a shell — so a
		//     tainted first argument is command injection regardless of any `-c`.
		// Firing on ShellTrue OR a tainted first argument covers both without a
		// language discriminator: a quoted/validated shell file invocation leaves
		// both false and is still suppressed.
		return info.ShellTrue || info.FirstArgTainted
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
