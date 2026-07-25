package taint

import "sort"

// Statement is the minimal, substrate-agnostic view of a single analyzable unit
// of code the engine reasons over. The AST/structural substrate (built
// separately) will produce a richer form; this shape is the contract the
// foundation proves out and the stub engine consumes.
//
// WHY a flat statement rather than an AST node: the foundation must be buildable
// and testable before the AST substrate exists. A statement carries just enough
// — the assigned variable, the calls it makes, and the variables it reads — for
// a same-block heuristic to demonstrate the source→sink→sanitizer contract. When
// the substrate lands, StructuralEngine (its future home) will implement the
// same TaintEngine interface over real def-use edges, and this stub is deleted.
type Statement struct {
	Line int
	// Assigns is the variable this statement writes, or "" if none.
	Assigns string
	// Calls are the normalized call chains invoked in this statement, in source
	// order (e.g. ["os.getenv", "shlex.quote"]).
	Calls []string
	// Reads are the variable names this statement references.
	Reads []string
	// Chains are the dotted attribute/identifier chains read in this statement
	// (e.g. "request.args", "req.query"), populated by a richer substrate so the
	// engine can match source ATTRIBUTES (not just source calls). The stub
	// heuristicEngine ignores it and matches sources via Calls only.
	Chains []string
	// SinkArgs, when populated by a richer substrate, records per-sink-call
	// argument shape so an argument-aware engine can suppress safe usages
	// (a parameterized cursor.execute, a subprocess.run without shell=True). It
	// is keyed by the normalized sink call. The stub heuristicEngine ignores it;
	// only the StructuralEngine consults it. Absent (nil) means "unknown", which
	// the StructuralEngine treats conservatively (the call is dangerous).
	SinkArgs map[string]SinkArgInfo
	// Returns are the variable names this statement returns (a `return x` or
	// `return a, b`). Populated by the substrate so the interprocedural summary
	// pass can decide whether a parameter flows to a function's return value.
	// Empty for non-return statements. The intraprocedural engine ignores it.
	Returns []string
}

// SinkArgInfo is the argument-shape evidence a substrate extracts at a specific
// sink call site, letting the engine apply the catalog's per-sink argument notes
// (e.g. subprocess shell=True, parameterized cursor.execute). Every field is
// best-effort; a false/empty value means "not observed", never "proven absent".
type SinkArgInfo struct {
	// TaintedArgVars are the tainted variables read specifically as arguments to
	// THIS sink call (as opposed to elsewhere in the statement). When empty the
	// engine falls back to the statement's Reads.
	TaintedArgVars []string
	// ArgCount is the number of positional arguments passed to the call.
	ArgCount int
	// ShellTrue records that a shell=True / shell:true keyword was passed —
	// the trigger that turns subprocess.*/spawn into a real command-injection
	// sink. For os.system/os.popen (always shell) this is irrelevant.
	ShellTrue bool
	// FirstArgTainted records whether the tainted value flows into the first
	// positional argument. For cursor.execute the SQL string is arg 0; a tainted
	// value only in arg 1 (the params tuple) is the SAFE parameterized form.
	FirstArgTainted bool
	// PositionalVars lists, per positional argument slot (index 0 = first
	// positional), the variable identifiers appearing in that slot. It lets the
	// interprocedural summary pass map a caller's argument position to the
	// callee's parameter of the same index. Keyword arguments are excluded (they
	// have no fixed position). Best-effort; empty when unobserved.
	PositionalVars [][]string
	// PositionalArgs lists, per positional argument slot (index-aligned with
	// PositionalVars), the code-view text of that argument (string/comment
	// literals blanked). It lets an engine detect a SOURCE used directly as a sink
	// argument in one statement — sink(source()) — which introduces no tracked
	// variable and so is invisible to variable-based propagation. Keyword arguments
	// are excluded. Best-effort; empty when unobserved.
	PositionalArgs []string
	// PromptRoles maps a variable that appears inside a chat/LLM prompt argument to
	// the chat role of the message it lands in ("system", "developer", "user", …).
	// It is populated only for chat-message-shaped LLM calls (an OpenAI/Anthropic
	// messages=[{role,content}] list or a system= parameter) and is empty for every
	// other call. It is the evidence a role-aware consumer uses to tell a
	// trust-inverting system-role injection (untrusted content in the system role)
	// from the recommended pattern (untrusted content confined to the user role).
	// A variable absent from the map has an undetermined role — the caller MUST
	// treat that conservatively (keep the finding), never as safe.
	PromptRoles map[string]string
	// PromptHasStaticSystem is true when the same chat/LLM call carries a system (or
	// developer) message whose content is a static literal with no interpolated
	// variable — the data boundary that makes untrusted content in the user role
	// the recommended, non-injection pattern. It is false when no such message
	// exists or the system content is itself variable/tainted. A user-role flow is
	// only downgraded to safe when this is true.
	PromptHasStaticSystem bool
}

// Unit is a single intraprocedural scope (typically one function body) presented
// to the engine as an ordered statement list. Intraprocedural-first: the engine
// reasons within one Unit and does not follow calls into other units.
type Unit struct {
	FilePath string
	FuncName string
	Language string
	Stmts    []Statement
	// Params are the positional parameter names of this function, in declaration
	// order, so the interprocedural summary pass can map a caller's argument
	// position to the parameter the callee reasons over. Empty for the module
	// unit and for functions with no parameters. The intraprocedural engine
	// ignores it.
	Params []string
}

// Flow is a reported source-to-sink taint path within a Unit. It is the engine's
// output; a downstream adapter (not part of this foundation) maps a Flow to a
// findings.Finding using Sink.RuleID, Sink.CWE, and the location.
type Flow struct {
	Source     Source
	SourceLine int
	SourceVar  string
	Sink       Sink
	SinkLine   int
	SinkCall   string
	FilePath   string
	FuncName   string
	Language   string
	// Via names the intermediate, locally-defined functions a cross-function
	// (interprocedural) flow passes through, from the caller toward the sink
	// (e.g. ["wrap", "run"]). Empty for a purely intraprocedural flow. It lets a
	// finding explain the summary-composed path. Deterministically ordered.
	Via []string
	// SinkRole records, for a prompt-injection (LLM) sink, the chat role the
	// tainted value lands in: "system"/"developer" (a trust-inverting injection),
	// "user"/other recognized role, or "unknown" when the role could not be
	// determined (dynamic message construction). Empty for every non-LLM sink. It
	// makes the role-based verdict auditable on the emitted finding. A user-role
	// flow behind a static system message is suppressed by the engine and never
	// reaches a Flow, so SinkRole on an emitted prompt-injection flow is "system",
	// "developer", "unknown", or another non-user role that was kept conservatively.
	SinkRole string
}

// TaintEngine analyzes one intraprocedural Unit and returns the taint flows that
// reach an un-sanitized sink. Implementations must be deterministic: the same
// Unit must always yield the same Flows in the same order.
//
// This interface is the seam between the foundation and the structural substrate.
// Anything that can turn source code into Units (the AST substrate) can drive any
// TaintEngine, and any propagation strategy can be swapped in behind it.
//
// The name is the deliberate domain term (referenced in docs/design/sast-taint.md
// and by the future structural engine), so the revive stutter check is waived.
//
//nolint:revive // TaintEngine is the named contract, clearer than a bare Engine.
type TaintEngine interface {
	// Analyze returns the taint flows found in unit, sorted deterministically.
	Analyze(unit Unit) []Flow
}

// heuristicEngine is a deliberately simple, clearly-marked placeholder
// implementation of TaintEngine.
//
// TODO(sast-taint): replace with the AST-backed intraprocedural engine once the
// structural substrate exists. This stub does NOT do real dataflow — it does not
// model branches, aliasing, container element taint, field sensitivity, or
// argument-position sensitivity (e.g. subprocess shell=True). It exists to prove
// the catalog + interface shape end-to-end and to give the substrate a passing
// test target to preserve.
//
// Heuristic (same-scope forward propagation):
//  1. Walk statements top to bottom, maintaining a set of tainted variables.
//  2. A statement that calls a source and assigns a variable taints that variable.
//  3. A statement that reads a tainted variable and assigns another propagates
//     taint to the assignee — UNLESS one of its calls is a sanitizer for the
//     class of every sink we might reach, in which case taint is cleared.
//     (The stub clears taint whenever ANY sanitizer call appears; class-precise
//     clearing needs the substrate's sink-class knowledge on the path.)
//  4. A statement that calls a sink while reading a tainted variable emits a Flow.
type heuristicEngine struct {
	cat *Catalog
}

// NewHeuristicEngine returns the placeholder same-scope taint engine backed by
// the given catalog. Passing nil uses the embedded default catalog.
func NewHeuristicEngine(cat *Catalog) TaintEngine {
	if cat == nil {
		cat = MustDefault()
	}
	return &heuristicEngine{cat: cat}
}

// Analyze implements TaintEngine with the documented same-scope heuristic.
//
//nolint:gocritic // Analyze(unit Unit) is the TaintEngine interface signature; the value parameter cannot be a pointer.
func (e *heuristicEngine) Analyze(unit Unit) []Flow {
	// tainted maps a tainted variable to the Source and line that introduced it.
	type origin struct {
		src  Source
		line int
	}
	tainted := make(map[string]origin)
	var flows []Flow

	for i := range unit.Stmts {
		st := unit.Stmts[i]
		// A statement carrying a sanitizer call clears taint on its assignee.
		// WHY conservative (any sanitizer clears): without the substrate we do
		// not know which sink class the value will reach, so we treat any
		// recognized sanitizer as breaking the flow to avoid over-reporting.
		sanitized := false
		for _, call := range st.Calls {
			if len(e.cat.Sanitizers(unit.Language)) == 0 {
				break
			}
			if isAnySanitizer(e.cat, unit.Language, call) {
				sanitized = true
				break
			}
		}

		// Does this statement read a currently-tainted variable?
		var reachedVia *origin
		for _, v := range st.Reads {
			if o, ok := tainted[v]; ok {
				o := o
				reachedVia = &o
				break
			}
		}

		// Sink check: a sink call reached by a tainted read is a flow.
		if reachedVia != nil {
			for _, call := range st.Calls {
				if sink, ok := e.cat.IsSink(unit.Language, call); ok {
					flows = append(flows, Flow{
						Source:     reachedVia.src,
						SourceLine: reachedVia.line,
						Sink:       sink,
						SinkLine:   st.Line,
						SinkCall:   call,
						FilePath:   unit.FilePath,
						FuncName:   unit.FuncName,
						Language:   unit.Language,
					})
				}
			}
		}

		// Propagation into the assignee.
		if st.Assigns == "" {
			continue
		}
		switch {
		case sanitized:
			delete(tainted, st.Assigns)
		case sourceAssigned(e.cat, unit.Language, &st):
			src, _ := firstSource(e.cat, unit.Language, st.Calls)
			tainted[st.Assigns] = origin{src: src, line: st.Line}
		case reachedVia != nil:
			tainted[st.Assigns] = *reachedVia
		}
	}

	sortFlows(flows)
	return flows
}

// isAnySanitizer reports whether call neutralizes at least one vuln class.
func isAnySanitizer(cat *Catalog, lang, call string) bool {
	for _, s := range cat.Sanitizers(lang) {
		if s.Call == call && len(s.Neutralizes) > 0 {
			return true
		}
	}
	return false
}

// sourceAssigned reports whether st assigns from a source call.
func sourceAssigned(cat *Catalog, lang string, st *Statement) bool {
	_, ok := firstSource(cat, lang, st.Calls)
	return ok
}

// firstSource returns the first call in calls that is a known source.
func firstSource(cat *Catalog, lang string, calls []string) (Source, bool) {
	for _, call := range calls {
		if s, ok := cat.Source(lang, call); ok {
			return s, true
		}
	}
	return Source{}, false
}

// sortFlows orders flows deterministically by sink line, then source line, then
// sink call, so repeated runs over the same Unit produce identical output.
func sortFlows(flows []Flow) {
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
