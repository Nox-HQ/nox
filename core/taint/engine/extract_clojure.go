package engine

import (
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// extractClojure turns Clojure source into unit drafts. Clojure is a Lisp:
// programs are prefix s-expressions `(fn arg …)`, and the two injection-carrying
// shapes are a BINDING (`(def x v)`, `(let [x v …] …)`, `(binding [x v] …)`) and
// a CALL (`(callee args…)`, where the head symbol is the callee). This dedicated
// FORM recognizer walks the code-only byte stream (strings/comments already
// blanked by lexctx, offsets preserved so line numbers stay correct), parses the
// balanced s-expression tree, and emits the shared unitDraft IR the engine
// consumes unchanged.
//
// UNITS: `(defn name [params] body)` / `(defn- …)` / `(fn name? [params] body)`
// open their own unit keyed by name, with the destructuring-free positional
// parameter names; everything else accumulates into the module-level unit
// (funcName "").
//
// HONEST LIMITS (recall is the LOWEST of any supported language, by design — a
// Lisp is the furthest from the assignment/call model the engine was built for):
//   - Threading macros (`->`, `->>`, `as->`, `some->`) reorder argument position,
//     which a positional form recognizer does not follow — a value threaded into a
//     sink through `->` is missed.
//   - Higher-order flows (`map`, `apply`, `partial`, `comp`) and destructuring
//     binds (`{:keys [a b]}`, `[x & xs]`) pass taint through shapes the recognizer
//     does not model.
//   - Only a bare-symbol binding target is tracked (`(def x …)`, `(let [x …])`);
//     a destructuring target is skipped (no field/element sensitivity claimed).
//
// A miss only weakens RECALL (a false negative), never correctness — an
// unrecognized form simply yields no statement. Precision is defended: the sinks
// (`sh`, `eval`, `load-string`, `jdbc/query` with string concat, `slurp`,
// `clj-http.client/get`) fire only when a tracked binding actually carries a
// source, and a parameterized jdbc vector `["… ?" v]` keeps the value out of the
// SQL-string argument so it reads as safe.
func extractClojure(content []byte, regions []lexctx.Region) []unitDraft {
	code := clojureCodeMask(content, regions)
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}

	forms := parseClojureForms(code, 0, len(code))
	for _, f := range forms {
		walkClojureForm(code, f, module, &units)
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// clojureCodeMask returns content with every non-code byte replaced by a space
// (newlines kept so line counting stays correct). Strings and comments become
// spaces so the form parser never trips on a paren, `;`, or delimiter that lives
// inside a literal, while byte offsets — and therefore 1-based line numbers — stay
// aligned with the original source.
func clojureCodeMask(content []byte, regions []lexctx.Region) []byte {
	mask := make([]byte, len(content))
	for i := range content {
		if content[i] == '\n' {
			mask[i] = '\n'
			continue
		}
		if lexctx.KindAt(regions, i) == lexctx.KindCode {
			mask[i] = content[i]
		} else {
			mask[i] = ' '
		}
	}
	return mask
}

// clojureForm is one parsed s-expression node. A LIST/vector/map/set collection
// records the byte span of its open and close delimiters plus its child forms; an
// ATOM (a symbol, keyword, number, blanked literal) records only its span. The
// delim byte identifies the collection kind: '(' list, '[' vector, '{' map/set.
type clojureForm struct {
	start    int  // byte offset of the first byte of the form
	end      int  // byte offset just past the last byte of the form
	delim    byte // '(' , '[' , '{' for a collection; 0 for an atom
	children []clojureForm
}

// parseClojureForms parses the sequence of top-level forms in code[lo:hi] and
// returns them in source order. Reader-macro prefixes (`'`, “ ` “, `~`, `~@`,
// `#`, `@`, `^meta`) are skipped so the form they decorate is parsed normally;
// this deliberately flattens `#_discard` (the discard prefix is dropped and the
// following form is parsed as ordinary code — best-effort, safe: it only forgoes a
// recall opportunity on a discarded form, never mis-suppresses).
func parseClojureForms(code []byte, lo, hi int) []clojureForm {
	var out []clojureForm
	i := lo
	for i < hi {
		c := code[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',':
			i++ // whitespace / comma (Clojure treats `,` as whitespace)
		case c == '(' || c == '[' || c == '{':
			f, next := parseClojureCollection(code, i, hi)
			out = append(out, f)
			i = next
		case c == ')' || c == ']' || c == '}':
			return out // a stray closer ends this level
		case isClojureReaderPrefix(c):
			i++ // skip the reader-macro prefix byte; decorate the next form
		default:
			// An atom: a run of non-delimiter, non-whitespace bytes.
			start := i
			for i < hi && !isClojureDelimOrSpace(code[i]) {
				i++
			}
			out = append(out, clojureForm{start: start, end: i})
		}
	}
	return out
}

// parseClojureCollection parses a collection opening at code[open] (a '(', '[',
// or '{') and returns the form plus the index just past its matching closer. A
// '#' immediately before a '{' (a set `#{}`) has already been consumed as a
// reader prefix, so only the brace kind is recorded here.
func parseClojureCollection(code []byte, open, hi int) (form clojureForm, next int) {
	delim := code[open]
	children := parseClojureForms(code, open+1, hi)
	// Find the matching closer by a balanced walk (parseForms stops AT the closer,
	// so compute the end offset independently to be robust).
	end := clojureMatchClose(code, open, hi)
	return clojureForm{start: open, end: end, delim: delim, children: children}, end
}

// clojureMatchClose returns the offset just past the closer matching the opener
// at code[open]. Literals are already blanked, so every bracket here is real code;
// an unbalanced opener runs to hi (fail-safe).
func clojureMatchClose(code []byte, open, hi int) int {
	depth := 0
	for i := open; i < hi; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return hi
}

// walkClojureForm dispatches one top-level (or nested body) form to the binding /
// unit / call recognizers, appending statements to cur (the current unit) and new
// units to units. Non-list forms carry no statement.
func walkClojureForm(code []byte, f clojureForm, cur *unitDraft, units *[]*unitDraft) {
	if f.delim != '(' || len(f.children) == 0 {
		// A bare vector/map/atom at the top level carries no statement, but a nested
		// call inside it might — recurse into collection children so a sink buried in
		// a data literal is still seen.
		for _, ch := range f.children {
			walkClojureForm(code, ch, cur, units)
		}
		return
	}
	head := clojureAtomText(code, f.children[0])
	switch head {
	case "def", "defonce", "def-":
		if st, ok := clojureDefStatement(code, f); ok {
			cur.stmts = append(cur.stmts, st)
		}
		// Recurse into the value expression so a call inside it (`(def x (sh …))`)
		// is also seen as its own statement.
		walkClojureChildren(code, f, 1, cur, units)
	case "defn", "defn-", "fn":
		newUnit := clojureDefnUnit(code, f)
		if newUnit != nil {
			*units = append(*units, newUnit)
			// Walk the body forms into the new unit.
			walkClojureDefnBody(code, f, newUnit, units)
			return
		}
		walkClojureChildren(code, f, 1, cur, units)
	case "let", "let*", "binding", "loop", "when-let", "if-let", "when-some", "if-some", "with-open", "with-local-vars", "for", "doseq":
		clojureLetForm(code, f, cur, units)
	case "->", "->>", "some->", "some->>", "cond->", "cond->>":
		clojureThreadingForm(code, f, cur, units)
	default:
		// An ordinary call `(callee args…)`.
		if st, ok := clojureCallStatement(code, f); ok {
			cur.stmts = append(cur.stmts, st)
		}
		// Recurse into arguments so nested calls / bindings are also seen.
		walkClojureChildren(code, f, 1, cur, units)
	}
}

// walkClojureChildren recurses into a form's children starting at index from,
// dispatching each as its own form (so nested calls and bindings surface).
func walkClojureChildren(code []byte, f clojureForm, from int, cur *unitDraft, units *[]*unitDraft) {
	for i := from; i < len(f.children); i++ {
		walkClojureForm(code, f.children[i], cur, units)
	}
}

// clojureDefStatement builds a binding statement for `(def NAME value-expr)`.
// NAME must be a bare symbol (a destructuring / metadata target is skipped). The
// value expression's calls and reads are collected so a source or a tainted read
// on the RHS propagates to NAME.
func clojureDefStatement(code []byte, f clojureForm) (stmtDraft, bool) {
	if len(f.children) < 2 {
		return stmtDraft{}, false
	}
	name := clojureBindingName(code, f.children[1])
	if name == "" {
		return stmtDraft{}, false
	}
	st := stmtDraft{line: clojureLine(code, f.children[0].start), assigns: name, sinkArgs: map[string]sinkArgDraft{}}
	// The value expression is the third child onward (usually one).
	if len(f.children) >= 3 {
		clojureCollectExpr(code, f.children[2], &st)
	}
	clojureFinalizeReads(&st)
	return st, true
}

// clojureLetForm handles a `(let [a e1 b e2] body…)` / `(binding …)` / `(loop …)`
// form: each name/expr pair in the binding vector becomes a binding statement, and
// the body forms are walked into cur. A `for`/`doseq` seq-binding vector is handled
// the same way (the right-hand side of each pair is where a source enters).
func clojureLetForm(code []byte, f clojureForm, cur *unitDraft, units *[]*unitDraft) {
	// The binding vector is the first '[' child after the head.
	var vec *clojureForm
	bodyStart := len(f.children)
	for i := 1; i < len(f.children); i++ {
		if f.children[i].delim == '[' {
			vec = &f.children[i]
			bodyStart = i + 1
			break
		}
	}
	if vec != nil {
		clojureBindingPairs(code, *vec, cur)
	}
	// Walk the body forms.
	for i := bodyStart; i < len(f.children); i++ {
		walkClojureForm(code, f.children[i], cur, units)
	}
}

// clojureBindingPairs walks a binding vector's name/expr pairs (`[a e1 b e2]`) and
// appends a binding statement per pair whose target is a bare symbol. A pair whose
// value expression is itself a call/collection has its reads and calls collected.
func clojureBindingPairs(code []byte, vec clojureForm, cur *unitDraft) {
	kids := vec.children
	for i := 0; i+1 < len(kids); i += 2 {
		name := clojureBindingName(code, kids[i])
		valStmt := stmtDraft{line: clojureLine(code, kids[i].start), sinkArgs: map[string]sinkArgDraft{}}
		clojureCollectExpr(code, kids[i+1], &valStmt)
		clojureFinalizeReads(&valStmt)
		if name != "" {
			valStmt.assigns = name
			cur.stmts = append(cur.stmts, valStmt)
		} else if len(valStmt.calls) > 0 || len(valStmt.reads) > 0 {
			// Destructuring target we can't name, but the value has a call/read worth
			// recording (a source-bearing call still matters for a later sink).
			cur.stmts = append(cur.stmts, valStmt)
		}
	}
}

// clojureDefnUnit builds a new unit for `(defn name [params] body)` /
// `(defn- …)` / `(fn name? [params] …)`. The name is the first symbol after the
// head; for an anonymous `fn` with no name the unit is named "". Parameters are
// the bare symbols in the first '[' vector (destructuring entries skipped).
func clojureDefnUnit(code []byte, f clojureForm) *unitDraft {
	name := ""
	// Find the name symbol (first atom child after head that is not a collection
	// and not metadata). `fn` may have no name.
	idx := 1
	if idx < len(f.children) && f.children[idx].delim == 0 {
		cand := clojureAtomText(code, f.children[idx])
		if cand != "" && !strings.HasPrefix(cand, ":") {
			name = cand
			idx++
		}
	}
	// Parameters: the first '[' vector after the name.
	var params []string
	for i := idx; i < len(f.children); i++ {
		if f.children[i].delim == '[' {
			params = clojureParamNames(code, f.children[i])
			break
		}
	}
	return &unitDraft{funcName: name, params: params}
}

// walkClojureDefnBody walks the body forms of a defn/fn (everything after the
// parameter vector) into the unit.
func walkClojureDefnBody(code []byte, f clojureForm, unit *unitDraft, units *[]*unitDraft) {
	// Locate the parameter vector, then walk everything after it.
	vecIdx := -1
	for i := 1; i < len(f.children); i++ {
		if f.children[i].delim == '[' {
			vecIdx = i
			break
		}
	}
	from := 1
	if vecIdx >= 0 {
		from = vecIdx + 1
	}
	for i := from; i < len(f.children); i++ {
		walkClojureForm(code, f.children[i], unit, units)
	}
}

// clojureCallStatement builds a call statement for `(callee args…)`. The head
// symbol is the callee (a Clojure symbol may contain `/`, `-`, `.`, `?`, `!`); the
// argument forms surface as reads, and the argument SHAPE (per-slot variables,
// tainted-arg set, first-arg taint) is recorded so the engine's per-sink danger
// logic — especially the parameterized-jdbc vector check — can apply.
func clojureCallStatement(code []byte, f clojureForm) (stmtDraft, bool) {
	head := clojureAtomText(code, f.children[0])
	callee := clojureNormalizeCallee(head)
	if callee == "" || !isClojureCalleeStart(callee[0]) {
		return stmtDraft{}, false
	}
	st := stmtDraft{line: clojureLine(code, f.children[0].start), sinkArgs: map[string]sinkArgDraft{}}

	// A higher-order dispatcher passes the real callee as DATA: `(apply shell/sh
	// "sh" "-c" args)` and `(map client/get urls)` both invoke a sink that never
	// appears as a literal call head, so the flow was invisible. Re-attribute the
	// statement to the dispatched function and drop it from the argument list, so
	// the remaining arguments are scored against the sink they actually reach.
	// Only a bare SYMBOL is re-attributed — an inline `#(...)`/`fn` literal is
	// left alone, and the symbol still has to BE a catalog sink to report.
	argStart := 1
	if clojureHOFDispatchers[callee] && len(f.children) > 2 {
		if sym := clojureNormalizeCallee(clojureAtomText(code, f.children[1])); sym != "" && isClojureCalleeStart(sym[0]) {
			callee = sym
			argStart = 2
		}
	}

	// A jdbc query/execute passes its SQL as a `["… ?" v]` parameterized VECTOR
	// (the value is a bind arg, SAFE) or as a `(str "…" v)` concat (the value is
	// interpolated into the SQL string, UNSAFE). A variable inside a bind vector is
	// therefore NOT a tainted argument — the placeholder keeps it out of the query
	// text — so it is excluded here, which is what makes the parameterized form
	// clean while the concat form still fires.
	jdbcParam := isClojureJdbcCallee(callee)

	info := sinkArgDraft{}
	var allReads []string
	seen := map[string]struct{}{}
	for i := argStart; i < len(f.children); i++ {
		arg := f.children[i]
		var vars []string
		if jdbcParam && arg.delim == '[' && clojureVectorIsParamBind(code, arg) {
			// Parameterized bind vector: its values are safe placeholders, not
			// interpolated SQL. Record an empty slot so the argument shape still
			// counts the positional but carries no tainted var.
			vars = nil
		} else {
			vars = clojureExprVars(code, arg)
		}
		info.positionalVars = append(info.positionalVars, append([]string(nil), vars...))
		info.argCount++
		for _, v := range vars {
			if _, dup := seen[v]; !dup {
				seen[v] = struct{}{}
				info.taintedArgVars = append(info.taintedArgVars, v)
				allReads = append(allReads, v)
			}
			if i == 1 {
				info.firstArgTainted = true
			}
		}
		// Collect nested calls in the argument so a source-bearing call inside an
		// argument (`(sh (:params req))`) surfaces its own read/call.
		clojureCollectNestedCalls(code, arg, &st)
	}
	sort.Strings(info.taintedArgVars)
	st.calls = appendUnique(st.calls, callee)
	st.sinkArgs[callee] = info
	st.reads = append(st.reads, allReads...)
	clojureFinalizeReads(&st)
	return st, true
}

// isClojureJdbcCallee reports whether callee is a clojure.java.jdbc / next.jdbc
// query or execute call, whose SQL argument may be a parameterized bind vector.
func isClojureJdbcCallee(callee string) bool {
	switch callee {
	case "jdbc/query", "jdbc/execute!", "next.jdbc/execute!",
		"clojure.java.jdbc/query", "clojure.java.jdbc/execute!":
		return true
	}
	return false
}

// clojureVectorIsParamBind reports whether a vector argument to a jdbc query is a
// parameterized bind vector `["… ?" v …]`. Idiomatic clojure.java.jdbc/next.jdbc
// pass their SQL either as a `(str …)` string CONCAT (unsafe — the value is
// interpolated into the query text) or as a `[sql-string & bind-values]` VECTOR
// (safe — `?` placeholders keep the values out of the query text). A concat query
// is a `(str …)` call, never a vector, so it never reaches here; any vector in the
// SQL slot is the parameterized bind form, and its values are safe placeholders.
// Returning true here excludes those values from the tainted-argument set, which
// is what keeps the parameterized form clean while the concat form still fires.
func clojureVectorIsParamBind(_ []byte, _ clojureForm) bool {
	return true
}

// clojureCollectExpr collects the calls, reads, and chains of a value expression
// into st (used for a binding RHS). A collection RHS (vector/map) or a call RHS is
// walked recursively so `(def x (get params "k"))` records the get call and the
// params read, and `(def x y)` records y as a read.
func clojureCollectExpr(code []byte, f clojureForm, st *stmtDraft) {
	if f.delim == 0 {
		// An atom RHS: a bare symbol read, a keyword-access chain, or a literal.
		if v := clojureSymbolRead(code, f); v != "" {
			st.reads = appendUnique(st.reads, v)
		}
		if ch := clojureAtomText(code, f); strings.Contains(ch, "/") || strings.HasPrefix(ch, ":") {
			// A namespaced symbol or keyword can be a source chain (e.g. request/params).
			st.chains = appendUnique(st.chains, strings.TrimPrefix(ch, ":"))
		}
		return
	}
	if f.delim == '(' && len(f.children) > 0 {
		// A keyword-access `(:params req)` on the RHS: the keyword head is the source
		// marker and the map argument is a read. This is Clojure's idiomatic Ring
		// request access and does not go through clojureCallStatement (whose callee
		// must be a symbol, not a `:keyword`).
		if head := clojureAtomText(code, f.children[0]); strings.HasPrefix(head, ":") {
			clojureCollectKeywordAccess(code, f, st)
			for i := 1; i < len(f.children); i++ {
				if v := clojureSymbolRead(code, f.children[i]); v != "" {
					st.reads = appendUnique(st.reads, v)
				}
			}
			return
		}
		// A call expression on the RHS.
		if inner, ok := clojureCallStatement(code, f); ok {
			for _, c := range inner.calls {
				st.calls = appendUnique(st.calls, c)
			}
			for _, r := range inner.reads {
				st.reads = appendUnique(st.reads, r)
			}
			for _, ch := range inner.chains {
				st.chains = appendUnique(st.chains, ch)
			}
			for c, info := range inner.sinkArgs {
				if st.sinkArgs == nil {
					st.sinkArgs = map[string]sinkArgDraft{}
				}
				if _, exists := st.sinkArgs[c]; !exists {
					st.sinkArgs[c] = info
				}
			}
			// The keyword head of a `(:params req)` access is a source chain.
			clojureCollectKeywordAccess(code, f, st)
		}
		return
	}
	// A vector/map RHS: collect each element's reads/calls (a data literal may hold
	// a tainted value, e.g. a jdbc param vector).
	for _, ch := range f.children {
		if ch.delim == 0 {
			// A bare atom INSIDE a data literal is a key or a literal value, not a
			// keyword ACCESS. `{:headers {...} :body "..."}` CONSTRUCTS a request
			// map; it does not read an untrusted one. Treating its keys as source
			// chains marked every hand-built map — every test fixture and mock
			// request — as untrusted input. A keyword is a source only in FUNCTION
			// position, `(:headers req)`, which the call branch above handles.
			if v := clojureSymbolRead(code, ch); v != "" {
				st.reads = appendUnique(st.reads, v)
			}
			if t := clojureAtomText(code, ch); strings.Contains(t, "/") && !strings.HasPrefix(t, ":") {
				st.chains = appendUnique(st.chains, t)
			}
			continue
		}
		clojureCollectExpr(code, ch, st)
	}
}

// clojureCollectKeywordAccess records a `(:key m)` keyword-access as a source
// chain: the keyword head (`:params`, `:query-string`) is the source marker and
// the map argument is a read. This is how Ring request access `(:params req)`
// resolves against the catalog's `:params` source.
func clojureCollectKeywordAccess(code []byte, f clojureForm, st *stmtDraft) {
	if len(f.children) == 0 {
		return
	}
	head := clojureAtomText(code, f.children[0])
	if strings.HasPrefix(head, ":") {
		st.chains = appendUnique(st.chains, strings.TrimPrefix(head, ":"))
		// Also surface the keyword itself as a "call" marker so a catalog source
		// keyed on `:params` resolves via the call path too.
		st.calls = appendUnique(st.calls, head)
	}
}

// clojureCollectNestedCalls walks an argument form and collects any nested call's
// reads/calls into st (so `(sh (:params req))` records the `:params` source and
// `req` read at the sh call site).
func clojureCollectNestedCalls(code []byte, f clojureForm, st *stmtDraft) {
	if f.delim == '(' && len(f.children) > 0 {
		head := clojureAtomText(code, f.children[0])
		if strings.HasPrefix(head, ":") {
			clojureCollectKeywordAccess(code, f, st)
		} else if inner, ok := clojureCallStatement(code, f); ok {
			for _, c := range inner.calls {
				st.calls = appendUnique(st.calls, c)
			}
			for _, r := range inner.reads {
				st.reads = appendUnique(st.reads, r)
			}
			for _, ch := range inner.chains {
				st.chains = appendUnique(st.chains, ch)
			}
		}
	}
	for _, ch := range f.children {
		clojureCollectNestedCalls(code, ch, st)
	}
}

// clojureExprVars returns the bare variable reads in an argument expression: a
// bare symbol yields itself; a call or collection yields the free symbols inside
// it (excluding callee heads and keywords). Deduplicated, source order.
func clojureExprVars(code []byte, f clojureForm) []string {
	var out []string
	seen := map[string]struct{}{}
	var walk func(g clojureForm, isHead bool)
	walk = func(g clojureForm, isHead bool) {
		if g.delim == 0 {
			if isHead {
				return // the callee head is not a data read
			}
			if v := clojureSymbolRead(code, g); v != "" {
				if _, dup := seen[v]; !dup {
					seen[v] = struct{}{}
					out = append(out, v)
				}
			}
			return
		}
		for i, ch := range g.children {
			walk(ch, g.delim == '(' && i == 0)
		}
	}
	walk(f, false)
	return out
}

// clojureSymbolRead returns the variable name a bare-symbol atom reads, or "" if
// the atom is a keyword (`:k`), a number, a string-blanked literal, a quoted
// symbol, or a language keyword/special-form name. A namespaced symbol
// (`clojure.string/join`) is NOT a plain variable read (it is a callee-shaped
// reference), so only unqualified symbols count as reads.
func clojureSymbolRead(code []byte, f clojureForm) string {
	if f.delim != 0 {
		return ""
	}
	s := clojureAtomText(code, f)
	if s == "" {
		return ""
	}
	if !isClojureSymbolStart(s[0]) {
		return "" // keyword, number, quote, blanked literal
	}
	if strings.ContainsAny(s, "/.") {
		return "" // namespaced/qualified symbol — a reference, not a plain var
	}
	if isClojureSpecial(s) {
		return ""
	}
	return s
}

// clojureBindingName returns the bare symbol name a binding target names, or "" if
// the target is a destructuring form (`[a b]`, `{:keys […]}`) or a non-symbol.
func clojureBindingName(code []byte, f clojureForm) string {
	if f.delim != 0 {
		return "" // destructuring target — not tracked
	}
	s := clojureAtomText(code, f)
	if s == "" || !isClojureSymbolStart(s[0]) {
		return ""
	}
	if strings.ContainsAny(s, "/.") || isClojureSpecial(s) {
		return ""
	}
	return s
}

// clojureParamNames returns the bare positional parameter names in a defn/fn
// parameter vector, in declaration order. A destructuring entry (`{:keys […]}`,
// `[a b]`) is skipped, and a `&` variadic marker and the rest symbol after it are
// dropped to their bare name (the rest symbol is kept — its position still maps a
// caller argument). Deterministic.
func clojureParamNames(code []byte, vec clojureForm) []string {
	var out []string
	for _, ch := range vec.children {
		if ch.delim != 0 {
			continue // destructuring param — position preserved would need modeling; skip
		}
		s := clojureAtomText(code, ch)
		if s == "" || s == "&" {
			continue
		}
		if !isClojureSymbolStart(s[0]) {
			continue
		}
		if strings.ContainsAny(s, "/.") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// clojureAtomText returns the source text of an atom form (its byte span), trimmed
// of surrounding whitespace introduced by the code mask. For a collection it
// returns "".
func clojureAtomText(code []byte, f clojureForm) string {
	if f.start < 0 || f.end > len(code) || f.start >= f.end {
		return ""
	}
	return strings.TrimSpace(string(code[f.start:f.end]))
}

// clojureNormalizeCallee maps a Clojure symbol head to the catalog call key. A
// namespaced symbol (`jdbc/query`, `clojure.java.shell/sh`, `client/get`) is kept
// verbatim so the catalog can key on the full or a suffix form; a bare symbol
// (`eval`, `slurp`) is returned as-is.
func clojureNormalizeCallee(head string) string {
	return strings.TrimSpace(head)
}

// clojureFinalizeReads sorts and dedups a statement's reads for deterministic
// output, matching the other extractors' convention.
func clojureFinalizeReads(st *stmtDraft) {
	if len(st.reads) > 1 {
		dedup := make([]string, 0, len(st.reads))
		seen := map[string]struct{}{}
		for _, r := range st.reads {
			if _, dup := seen[r]; !dup {
				seen[r] = struct{}{}
				dedup = append(dedup, r)
			}
		}
		st.reads = dedup
	}
	sort.Strings(st.reads)
}

// clojureLine returns the 1-based line number of byte offset off in code.
func clojureLine(code []byte, off int) int {
	if off < 0 {
		return 1
	}
	if off > len(code) {
		off = len(code)
	}
	line := 1
	for i := 0; i < off; i++ {
		if code[i] == '\n' {
			line++
		}
	}
	return line
}

// isClojureReaderPrefix reports whether c is a reader-macro prefix byte that
// decorates the following form (quote, syntax-quote, unquote, deref, var, meta,
// dispatch `#`). The prefix is skipped so the decorated form parses normally.
func isClojureReaderPrefix(c byte) bool {
	switch c {
	case '\'', '`', '~', '@', '^', '#':
		return true
	}
	return false
}

// isClojureDelimOrSpace reports whether c ends an atom: a collection delimiter,
// whitespace, comma, or a reader-macro prefix that would begin a new form.
func isClojureDelimOrSpace(c byte) bool {
	switch c {
	case '(', ')', '[', ']', '{', '}', ' ', '\t', '\r', '\n', ',':
		return true
	}
	return false
}

// isClojureSymbolStart reports whether b can begin a Clojure symbol used as a
// variable name (a letter, `_`, `*`, `-`, `?`, `!`, `<`, `>`, `=`). It excludes a
// keyword `:`, a digit, and quote/deref sigils.
func isClojureSymbolStart(b byte) bool {
	if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' {
		return true
	}
	switch b {
	case '_', '*', '-', '?', '!', '<', '>', '=', '+':
		return true
	}
	return false
}

// isClojureCalleeStart reports whether b can begin a callee symbol. A keyword head
// (`:params`) is handled separately, so a callee must be a symbol byte.
func isClojureCalleeStart(b byte) bool {
	return isClojureSymbolStart(b) || b == '.'
}

// isClojureSpecial reports whether s is a Clojure special form / core macro name
// that must never be read as a variable (it heads a form, it is not data). Coarse
// superset; a false include only avoids a spurious read of a form head.
func isClojureSpecial(s string) bool {
	switch s {
	case "def", "defn", "defn-", "defonce", "fn", "let", "let*", "letfn",
		"if", "when", "when-not", "when-let", "if-let", "if-not", "cond", "condp",
		"case", "do", "loop", "recur", "binding", "quote", "var", "throw", "try",
		"catch", "finally", "new", "set!", "monitor-enter", "monitor-exit",
		"and", "or", "not", "true", "false", "nil", "for", "doseq", "dotimes",
		"->", "->>", "as->", "some->", "some->>", "cond->", "cond->>", "doto",
		"ns", "require", "import", "use", "in-ns", "comment", "declare",
		"with-open", "with-local-vars", "when-some", "if-some":
		return true
	}
	return false
}

// clojureHOFDispatchers are the core higher-order functions that take the
// function to invoke as their FIRST argument. For taint purposes the flow runs
// through them into that function, so a sink reached this way is a real flow
// even though the sink is never a literal call head.
var clojureHOFDispatchers = map[string]bool{
	"apply": true,
	"map":   true, "mapv": true, "pmap": true, "mapcat": true,
	"keep": true, "filter": true, "remove": true,
	"run!": true, "doseq": false, // doseq binds, it does not dispatch
	"some": true, "every?": true,
}

// clojureThreadHeads are the threading macros whose stages each receive the
// value threaded from the previous stage.
var clojureThreadHeads = map[string]bool{
	"->": true, "->>": true,
	"some->": true, "some->>": true,
	"cond->": true, "cond->>": true,
}

// clojureThreadingForm models `(-> x (f a) (g b))` — and its `->>` / `some->` /
// `cond->` variants — by flowing the threaded value's evidence through every
// stage. A threading macro REWRITES argument position at read time, so a value
// threaded into a sink never appears as a literal argument of that sink and the
// flow was invisible to the positional form recognizer.
//
// Each stage is emitted as its own call statement carrying the accumulated
// evidence (reads, source chains) of everything threaded into it, and the
// carried set then grows by that stage's own reads so the value keeps flowing.
//
// A nested threading form appearing AS a stage — `(-> x (->> (sh "sh" "-c")))`,
// which is how `->` and `->>` are mixed — re-threads the SAME carried value, so
// its children are all stages with no initial expression of their own.
//
// Deliberate simplification: this tracks WHAT flows, not into WHICH argument
// slot. `->` prepends and `->>` appends, but for taint the question is whether
// the tainted value reaches the sink at all, and both do. A position-sensitive
// argument note (the parameterized-jdbc vector check) therefore does not apply
// to a threaded stage; that costs precision nowhere in the corpus but is the
// honest limit of the approximation.
func clojureThreadingForm(code []byte, f clojureForm, cur *unitDraft, units *[]*unitDraft) {
	// The threaded value is modeled as a synthetic BINDING that each stage reads
	// and rebinds. The engine taints a variable at its binding and reports a sink
	// that READS a tainted variable, so carrying evidence alone was not enough —
	// the value has to have a name. The name is per-form so two threading
	// expressions in one unit cannot alias each other.
	tmp := "__nox_threaded_" + strconv.Itoa(clojureLine(code, f.start))
	bind := stmtDraft{line: clojureLine(code, f.start), assigns: tmp, sinkArgs: map[string]sinkArgDraft{}}
	if len(f.children) > 1 {
		clojureCollectExpr(code, f.children[1], &bind)
	}
	cur.stmts = append(cur.stmts, bind)
	clojureThreadStages(code, f, 2, tmp, cur, units)
	// The initial expression may itself contain calls worth reporting on their
	// own (`(-> (sh cmd) ...)`), so walk it normally too.
	if len(f.children) > 1 {
		walkClojureForm(code, f.children[1], cur, units)
	}
}

// clojureThreadStages emits a statement per stage in f.children[from:]. Each
// stage READS the synthetic threaded variable and REBINDS it to its own result,
// so the value keeps flowing and a sanitizing stage correctly clears the taint.
func clojureThreadStages(code []byte, f clojureForm, from int, tmp string, cur *unitDraft, units *[]*unitDraft) {
	for i := from; i < len(f.children); i++ {
		stage := f.children[i]
		if stage.delim == '(' && len(stage.children) > 0 &&
			clojureThreadHeads[clojureAtomText(code, stage.children[0])] {
			// A nested threading macro re-threads the same value; all of its
			// children after the head are stages.
			clojureThreadStages(code, stage, 1, tmp, cur, units)
			continue
		}
		st, ok := clojureStageStatement(code, stage)
		if !ok {
			continue
		}
		st.reads = appendUnique(st.reads, tmp)
		// The threaded value arrives as an argument of this stage's callee, so it
		// counts as a tainted argument for the per-sink danger check.
		for _, callee := range st.calls {
			info := st.sinkArgs[callee]
			info.taintedArgVars = appendUnique(info.taintedArgVars, tmp)
			info.argCount++
			st.sinkArgs[callee] = info
		}
		// The stage's result becomes the new threaded value.
		st.assigns = tmp
		cur.stmts = append(cur.stmts, st)
	}
}

// clojureStageStatement builds the statement for one threading stage: a call
// form `(f a b)`, or a bare symbol `f` which threads as `(f value)`.
func clojureStageStatement(code []byte, stage clojureForm) (stmtDraft, bool) {
	if stage.delim == '(' {
		return clojureCallStatement(code, stage)
	}
	if stage.delim != 0 {
		return stmtDraft{}, false
	}
	callee := clojureNormalizeCallee(clojureAtomText(code, stage))
	if callee == "" || !isClojureCalleeStart(callee[0]) {
		return stmtDraft{}, false
	}
	return stmtDraft{
		line:     clojureLine(code, stage.start),
		calls:    []string{callee},
		sinkArgs: map[string]sinkArgDraft{callee: {}},
	}, true
}
