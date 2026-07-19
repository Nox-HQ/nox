package engine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// extractGo turns Go source into unit drafts using the standard-library AST
// parser (go/parser + go/ast + go/token). Unlike the Python/JS line recognizers
// — which the project keeps deliberately parser-free to avoid CGo/heavy grammars
// in a non-Go language — Go gets a REAL AST for free: nox is itself Go, so the
// pure-Go stdlib parser adds no dependency, is precise, and stays deterministic.
// See docs/design/go-taint.md for the rationale and the AST-only (no go/types)
// scope.
//
// Each *ast.FuncDecl becomes one unitDraft (receiver + parameters as params, in
// order); package-level var declarations fold into a synthetic module unit. On a
// parse error the partial AST the parser recovers is still walked — a
// non-compiling snippet degrades gracefully and never panics or crashes the scan.
func extractGo(content []byte) []unitDraft {
	fset := token.NewFileSet()
	// SkipObjectResolution: we never need go/ast's identifier-object linking, and
	// skipping it is faster and more tolerant. ParseComments is off — comments are
	// not code and carry no flow. On error we still use the (partial) file.
	file, _ := parser.ParseFile(fset, "src.go", content, parser.SkipObjectResolution)
	if file == nil {
		return nil
	}

	ex := &goExtractor{fset: fset}
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			u := &unitDraft{funcName: d.Name.Name, params: ex.funcParams(d)}
			if d.Body != nil {
				ex.walkBlock(u, d.Body.List)
			}
			units = append(units, u)
		case *ast.GenDecl:
			// Package-level var declarations with call/source initializers fold into
			// the module unit so a top-level tainted assignment is still tracked.
			ex.walkGenDecl(module, d)
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// goExtractor holds the fileset so every emitted statement carries the accurate
// 1-based line number of its source position.
type goExtractor struct {
	fset      *token.FileSet
	tmpserial int
}

// line returns the 1-based source line of a position.
func (ex *goExtractor) line(pos token.Pos) int {
	return ex.fset.Position(pos).Line
}

// funcParams returns the receiver (if any) followed by the positional parameter
// names in declaration order — the ordering the interprocedural summary pass maps
// caller-argument position onto. A blank (`_`) or unnamed slot is kept as "" so
// positions do not shift.
func (ex *goExtractor) funcParams(d *ast.FuncDecl) []string {
	var params []string
	if d.Recv != nil {
		for _, f := range d.Recv.List {
			params = append(params, fieldNames(f)...)
		}
	}
	if d.Type != nil && d.Type.Params != nil {
		for _, f := range d.Type.Params.List {
			params = append(params, fieldNames(f)...)
		}
	}
	return params
}

// fieldNames returns the identifier names of a field (one field may declare
// several names, e.g. `a, b int`). An unnamed field yields a single "" slot so
// positional indexing stays aligned.
func fieldNames(f *ast.Field) []string {
	if len(f.Names) == 0 {
		return []string{""}
	}
	out := make([]string, 0, len(f.Names))
	for _, n := range f.Names {
		out = append(out, n.Name)
	}
	return out
}

// walkBlock walks a statement list in source order, emitting a stmtDraft per
// analyzable statement. It descends into the init clauses of if/for/switch (so
// `if err := dec.Decode(&v); err != nil` is analyzed) and into nested blocks,
// keeping everything in the same unit (straight-line, no CFG — the engine's
// documented limit).
func (ex *goExtractor) walkBlock(u *unitDraft, stmts []ast.Stmt) {
	for _, s := range stmts {
		ex.walkStmt(u, s)
	}
}

// walkStmt handles a single statement.
func (ex *goExtractor) walkStmt(u *unitDraft, s ast.Stmt) {
	switch st := s.(type) {
	case *ast.AssignStmt:
		ex.emitAssign(u, st)
	case *ast.ExprStmt:
		if call, ok := st.X.(*ast.CallExpr); ok {
			ex.emitCallStmt(u, call, ex.line(st.Pos()))
		}
	case *ast.ReturnStmt:
		ex.emitReturn(u, st)
	case *ast.IfStmt:
		if st.Init != nil {
			ex.walkStmt(u, st.Init)
		}
		if st.Body != nil {
			ex.walkBlock(u, st.Body.List)
		}
		if st.Else != nil {
			ex.walkStmt(u, st.Else)
		}
	case *ast.ForStmt:
		if st.Init != nil {
			ex.walkStmt(u, st.Init)
		}
		if st.Body != nil {
			ex.walkBlock(u, st.Body.List)
		}
	case *ast.RangeStmt:
		if st.Body != nil {
			ex.walkBlock(u, st.Body.List)
		}
	case *ast.SwitchStmt:
		if st.Init != nil {
			ex.walkStmt(u, st.Init)
		}
		if st.Body != nil {
			ex.walkBlock(u, st.Body.List)
		}
	case *ast.CaseClause:
		ex.walkBlock(u, st.Body)
	case *ast.BlockStmt:
		ex.walkBlock(u, st.List)
	}
}

// walkGenDecl folds package-level `var x = expr` initializers into the module
// unit as assignment statements.
func (ex *goExtractor) walkGenDecl(module *unitDraft, d *ast.GenDecl) {
	if d.Tok != token.VAR {
		return
	}
	for _, spec := range d.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || len(vs.Values) == 0 {
			continue
		}
		lhs := make([]ast.Expr, len(vs.Names))
		for i, n := range vs.Names {
			lhs[i] = n
		}
		ex.emitAssignExprs(module, lhs, vs.Values, ex.line(vs.Pos()))
	}
}

// emitAssign turns an *ast.AssignStmt (both `:=` and `=`) into a stmtDraft.
func (ex *goExtractor) emitAssign(u *unitDraft, st *ast.AssignStmt) {
	ex.emitAssignExprs(u, st.Lhs, st.Rhs, ex.line(st.Pos()))
}

// emitAssignExprs is the shared assignment builder. It first hoists any pure
// selector-chain argument used inside the RHS into a synthetic assignment (so an
// inline source like r.Body becomes a tracked variable — see hoistInlineSources),
// then emits the assignment itself: LHS primary name → assigns, RHS calls/reads/
// chains/sinkArgs collected from the (possibly rewritten) expressions.
func (ex *goExtractor) emitAssignExprs(u *unitDraft, lhs, rhs []ast.Expr, line int) {
	ex.hoistInlineSources(u, rhs, line)

	var st stmtDraft
	st.line = line
	st.sinkArgs = map[string]sinkArgDraft{}
	st.assigns = ex.primaryLHS(lhs)

	ex.collectExprs(&st, rhs)
	finalizeStmt(&st)
	if stmtIsEmpty(&st) {
		return
	}
	u.stmts = append(u.stmts, st)
}

// emitCallStmt emits a bare call statement (no assignment), hoisting inline
// sources first so `dec.Decode(r.Body)` style inline sources are tracked.
func (ex *goExtractor) emitCallStmt(u *unitDraft, call *ast.CallExpr, line int) {
	ex.hoistInlineSources(u, []ast.Expr{call}, line)

	var st stmtDraft
	st.line = line
	st.sinkArgs = map[string]sinkArgDraft{}
	ex.collectExprs(&st, []ast.Expr{call})
	finalizeStmt(&st)
	if stmtIsEmpty(&st) {
		return
	}
	u.stmts = append(u.stmts, st)
}

// emitReturn turns a `return e1, e2, ...` into a stmtDraft whose returns are the
// free variables of the returned expressions, while still collecting the calls
// and reads inside them (so `return db.Query(... + id)` is both a sink read and a
// return). A bare `return` yields nothing.
func (ex *goExtractor) emitReturn(u *unitDraft, st *ast.ReturnStmt) {
	if len(st.Results) == 0 {
		return
	}
	line := ex.line(st.Pos())
	ex.hoistInlineSources(u, st.Results, line)

	var out stmtDraft
	out.line = line
	out.sinkArgs = map[string]sinkArgDraft{}
	ex.collectExprs(&out, st.Results)
	finalizeStmt(&out)
	// The returned variables are exactly the free identifiers of the expressions.
	out.returns = append([]string(nil), out.reads...)
	if stmtIsEmpty(&out) {
		return
	}
	u.stmts = append(u.stmts, out)
}

// primaryLHS picks the single tracked assignee from an assignment's LHS. The
// engine's assigns field is one variable; for a multi-value assign
// (`out, _ := f()`, `tmp, err := f()`) we pick the first non-blank, non-error
// identifier so the meaningful value — not the error — is tracked.
//
// A container/element or field target (`m["c"] = v`, `obj.Field = v`) resolves
// to its BASE identifier (m, obj) so a tainted RHS taints the whole container — a
// sound, container-level over-approximation that makes taint laundered through a
// map value / slice element / struct field reach a later read of the container.
// This is the only element/field sensitivity nox claims: container-level, not
// key-level.
func (ex *goExtractor) primaryLHS(lhs []ast.Expr) string {
	names := make([]string, 0, len(lhs))
	for _, e := range lhs {
		if name := lhsAssignedName(e); name != "" {
			names = append(names, name)
		} else {
			names = append(names, "")
		}
	}
	for _, n := range names {
		if n != "" && n != "_" && n != "err" {
			return n
		}
	}
	for _, n := range names {
		if n != "" && n != "_" {
			return n
		}
	}
	return ""
}

// lhsAssignedName returns the variable name an assignment LHS target attributes
// taint to. A plain identifier (`x = v`) yields the identifier. A container or
// field target resolves to its base identifier so the whole container is tainted:
//   - `m["c"] = v` / `s[0] = v` (*ast.IndexExpr) → the base "m" / "s"
//   - `obj.Field = v` (*ast.SelectorExpr)        → the receiver head "obj"
//   - `(*p).Field = v` / `p.a.b = v` (nested)     → the leftmost identifier
//
// Container-level, not key-level: writing one key taints the container, so a read
// of any element of it is treated as tainted (a sound over-approximation). Returns
// "" for a shape with no identifier base (e.g. a literal or call target).
func lhsAssignedName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return lhsAssignedName(x.X)
	case *ast.SelectorExpr:
		return lhsAssignedName(x.X)
	case *ast.StarExpr:
		return lhsAssignedName(x.X)
	case *ast.ParenExpr:
		return lhsAssignedName(x.X)
	default:
		return ""
	}
}

// hoistInlineSources scans the given expressions for pure selector chains used as
// CALL ARGUMENTS (idents and dots only, e.g. r.Body — never a call, operator, or
// literal) and hoists each into a synthetic assignment `__noxsrcN = r.Body`
// emitted before the current statement, rewriting the argument in place to read
// the temp. This lets the engine — which only taints a VARIABLE on assignment
// from a source — handle an inline source used directly at a sink
// (gob.NewDecoder(r.Body).Decode(...)). It is catalog-independent and
// semantics-preserving: a pure selector has no side effects, so a non-source
// chain hoisted to a temp is simply never tainted and has no effect.
func (ex *goExtractor) hoistInlineSources(u *unitDraft, exprs []ast.Expr, line int) {
	for _, e := range exprs {
		ex.hoistWithinCalls(u, e, line)
	}
}

// hoistWithinCalls descends an expression; at every call it replaces a pure
// selector-chain argument with a synthetic temp identifier and emits the
// corresponding assignment.
func (ex *goExtractor) hoistWithinCalls(u *unitDraft, e ast.Expr, line int) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		// Descend common wrapping expressions that can contain calls.
		switch x := e.(type) {
		case *ast.SelectorExpr:
			ex.hoistWithinCalls(u, x.X, line)
		case *ast.ParenExpr:
			ex.hoistWithinCalls(u, x.X, line)
		case *ast.BinaryExpr:
			ex.hoistWithinCalls(u, x.X, line)
			ex.hoistWithinCalls(u, x.Y, line)
		case *ast.UnaryExpr:
			ex.hoistWithinCalls(u, x.X, line)
		}
		return
	}
	// Descend the callee's receiver first (method chains) and any nested calls in
	// arguments, so hoisting reaches every nesting level.
	ex.hoistWithinCalls(u, call.Fun, line)
	for i, arg := range call.Args {
		if pureSelectorChain(arg) != "" {
			chain := pureSelectorChain(arg)
			tmp := ex.newTemp()
			ex.emitSyntheticSource(u, tmp, arg, chain, line)
			call.Args[i] = &ast.Ident{NamePos: arg.Pos(), Name: tmp}
			continue
		}
		// F1: a source-ACCESSOR call used directly as an argument
		// (exec.Command(r.FormValue("c"))). A pure selector chain that reads an
		// attribute (r.Body) is hoisted above; a source that is a METHOD CALL with a
		// fixed key (r.FormValue("c"), r.Header.Get("X")) needs the call itself
		// hoisted so the engine's source resolution — which taints a VARIABLE on
		// assignment from a source — sees it. Restricted to a pure-selector callee
		// with literal-only arguments so it targets the request-accessor source
		// shape, never an arbitrary transform (a non-source accessor hoisted to a
		// temp is simply never tainted and changes nothing).
		if acc, ok := accessorSourceCall(arg); ok {
			tmp := ex.newTemp()
			ex.emitSyntheticSourceCall(u, tmp, acc, line)
			call.Args[i] = &ast.Ident{NamePos: arg.Pos(), Name: tmp}
			continue
		}
		ex.hoistWithinCalls(u, arg, line)
	}
}

// accessorSourceCall reports whether e is a source-accessor call safe to hoist
// into a synthetic source assignment: a CallExpr whose callee is a pure selector
// chain of at least two segments (r.FormValue, r.Header.Get) and whose arguments
// are all literals (a fixed key/index, never a variable). This is the exact shape
// of a request accessor source; a call taking a variable is a transform and is
// left for ordinary read-propagation.
func accessorSourceCall(e ast.Expr) (*ast.CallExpr, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !isPureSelector(sel) {
		return nil, false
	}
	if !strings.Contains(selectorChain(sel), ".") {
		return nil, false
	}
	for _, a := range call.Args {
		if _, isLit := a.(*ast.BasicLit); !isLit {
			return nil, false
		}
	}
	return call, true
}

// emitSyntheticSourceCall appends a synthetic assignment `tmp = <accessor call>`
// carrying the call so the engine's source resolution (which consults st.calls)
// taints tmp when the accessor is a catalog source.
func (ex *goExtractor) emitSyntheticSourceCall(u *unitDraft, tmp string, call *ast.CallExpr, line int) {
	st := stmtDraft{line: line, assigns: tmp, sinkArgs: map[string]sinkArgDraft{}}
	ex.collectExprs(&st, []ast.Expr{call})
	finalizeStmt(&st)
	if stmtIsEmpty(&st) {
		return
	}
	u.stmts = append(u.stmts, st)
}

// emitSyntheticSource appends a synthetic assignment `tmp = <chain>` carrying the
// selector chain so the engine's source resolution (which consults st.chains) can
// taint tmp when the chain is a catalog source.
func (ex *goExtractor) emitSyntheticSource(u *unitDraft, tmp string, arg ast.Expr, chain string, line int) {
	st := stmtDraft{
		line:     line,
		assigns:  tmp,
		sinkArgs: map[string]sinkArgDraft{},
		chains:   []string{chain},
	}
	// Record the chain's head identifier as a read so read-propagation still holds
	// if the head itself is (transitively) tainted.
	if head := chainHead(chain); head != "" {
		st.reads = []string{head}
	}
	u.stmts = append(u.stmts, st)
	_ = arg
}

// newTemp returns a fresh, deterministic synthetic variable name. The counter is
// per-file (per extractGo call), so names are stable for identical input.
func (ex *goExtractor) newTemp() string {
	name := "__noxsrc" + strconv.Itoa(ex.tmpserial)
	ex.tmpserial++
	return name
}

// collectExprs walks a set of RHS/return/argument expressions and records every
// call (with its argument-shape evidence), every free variable read, and every
// dotted selector chain into st.
func (ex *goExtractor) collectExprs(st *stmtDraft, exprs []ast.Expr) {
	for _, e := range exprs {
		ex.collectExpr(st, e)
	}
}

// collectExpr recursively records the taint-relevant shapes of one expression.
func (ex *goExtractor) collectExpr(st *stmtDraft, e ast.Expr) {
	switch x := e.(type) {
	case nil:
		return
	case *ast.CallExpr:
		callee := renderCallChain(x.Fun)
		// A raw `.Write` XSS-to-response sink (w.Write([]byte(...))) fires only on the
		// reflected-HTML shape: a tainted value combined with a string LITERAL in the
		// write argument (an HTML concatenation "<b>"+user+"</b>"). A bare write of a
		// precomputed value — w.Write(out) where out is command/file output — is NOT
		// reflected XSS (that value is already reported at its own upstream sink), so
		// the callee is not registered as a sink here. This gate keeps the injection
		// samples (tp_cmdinjection/pathtraversal/… all end in w.Write(out)) from
		// double-firing an XSS false positive while w.Write([]byte("…"+user)) still
		// fires. The fmt.Fprint*/io.WriteString string-writers and template.HTML
		// bypass need no literal gate — a tainted string reaching them IS reflected
		// content — so they always register and are gated only by taint.
		if callee != "" && (!isGoRawWriteSink(callee) || xssWriteArgIsHTML(x)) {
			st.calls = appendUnique(st.calls, callee)
			st.sinkArgs[callee] = ex.callArgInfo(x)
		}
		// Reads/chains from the callee receiver (e.g. db in db.Query, the package
		// path in template.New.Parse) and from every argument.
		ex.collectExpr(st, x.Fun)
		for _, a := range x.Args {
			ex.collectExpr(st, a)
		}
	case *ast.SelectorExpr:
		if chain := selectorChain(x); chain != "" && strings.Contains(chain, ".") {
			st.chains = appendUnique(st.chains, chain)
		}
		// The head identifier of the chain is a read (e.g. db in db.Query).
		if head := selectorHead(x); head != "" {
			st.reads = appendUnique(st.reads, head)
		}
		// Recurse into the selector's base so a call in the receiver spine
		// (exec.Command(...).Output, gob.NewDecoder(r.Body).Decode) is itself
		// collected as a call with its own argument evidence.
		ex.collectExpr(st, x.X)
	case *ast.Ident:
		if x.Name != "" && x.Name != "_" && !isGoKeyword(x.Name) {
			st.reads = appendUnique(st.reads, x.Name)
		}
	case *ast.BinaryExpr:
		ex.collectExpr(st, x.X)
		ex.collectExpr(st, x.Y)
	case *ast.ParenExpr:
		ex.collectExpr(st, x.X)
	case *ast.UnaryExpr:
		ex.collectExpr(st, x.X)
	case *ast.StarExpr:
		ex.collectExpr(st, x.X)
	case *ast.IndexExpr:
		ex.collectExpr(st, x.X)
		ex.collectExpr(st, x.Index)
	case *ast.CompositeLit:
		for _, elt := range x.Elts {
			ex.collectExpr(st, elt)
		}
	case *ast.KeyValueExpr:
		ex.collectExpr(st, x.Value)
	}
}

// callArgInfo derives the argument-shape evidence for one call: positional count,
// per-slot variable names, and whether a tainted variable lands in the first
// positional argument (the dangerous, non-parameterized position for db.Query /
// exec string commands). Go has no shell=True keyword, so shellTrue stays false;
// an arg-vector exec is modeled by the first argument being a string literal
// (firstArgTainted false) with the tainted value in a later, distinct argument.
func (ex *goExtractor) callArgInfo(call *ast.CallExpr) sinkArgDraft {
	var info sinkArgDraft
	seen := map[string]struct{}{}
	for idx, arg := range call.Args {
		info.argCount++
		firstIsLiteralOrVector := idx == 0 && (isStringLiteral(arg) || isCompositeVector(arg))
		vars := ex.exprVars(arg)
		info.positionalVars = append(info.positionalVars, append([]string(nil), vars...))
		for _, v := range vars {
			if _, dup := seen[v]; !dup {
				seen[v] = struct{}{}
				info.taintedArgVars = append(info.taintedArgVars, v)
			}
			if idx == 0 && !firstIsLiteralOrVector {
				info.firstArgTainted = true
			}
		}
	}
	sort.Strings(info.taintedArgVars)
	return info
}

// exprVars returns the free variable identifiers read in an expression argument,
// deduplicated and in first-seen order. It descends binary expressions (string
// concatenation), unary/star/paren wrappers, index and selector heads, so a
// tainted var interpolated anywhere in the argument is captured.
func (ex *goExtractor) exprVars(e ast.Expr) []string {
	var out []string
	seen := map[string]struct{}{}
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch x := e.(type) {
		case *ast.Ident:
			if x.Name == "" || x.Name == "_" || isGoKeyword(x.Name) {
				return
			}
			if _, dup := seen[x.Name]; !dup {
				seen[x.Name] = struct{}{}
				out = append(out, x.Name)
			}
		case *ast.BinaryExpr:
			walk(x.X)
			walk(x.Y)
		case *ast.ParenExpr:
			walk(x.X)
		case *ast.UnaryExpr:
			walk(x.X)
		case *ast.StarExpr:
			walk(x.X)
		case *ast.IndexExpr:
			walk(x.X)
			walk(x.Index)
		case *ast.SelectorExpr:
			// The receiver head of a selector is a read (r in r.Body); the field name
			// is not a free variable.
			if head := selectorHead(x); head != "" {
				if _, dup := seen[head]; !dup {
					seen[head] = struct{}{}
					out = append(out, head)
				}
			}
		case *ast.CallExpr:
			for _, a := range x.Args {
				walk(a)
			}
		}
	}
	walk(e)
	return out
}

// finalizeStmt sorts the reads for determinism, matching the recognizer engines'
// contract (sortedReads picks the first tainted read stably).
func finalizeStmt(st *stmtDraft) {
	sort.Strings(st.reads)
}

// stmtIsEmpty reports whether a statement carries nothing the engine can use.
func stmtIsEmpty(st *stmtDraft) bool {
	return st.assigns == "" && len(st.calls) == 0 && len(st.reads) == 0 &&
		len(st.chains) == 0 && len(st.returns) == 0
}

// renderCallChain renders a call's Fun expression into the dotted callee chain the
// catalog matches against, dropping call parentheses at every level:
// `template.New("g").Parse` → "template.New.Parse", `exec.Command` → "exec.Command",
// `db.Query` → "db.Query". Returns "" for a shape with no identifier spine.
func renderCallChain(fun ast.Expr) string {
	switch x := fun.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		base := renderCallChain(x.X)
		if base == "" {
			return x.Sel.Name
		}
		return base + "." + x.Sel.Name
	case *ast.CallExpr:
		// Method on a call result: render the inner callee, then append the method
		// via the enclosing SelectorExpr (handled by the SelectorExpr case above).
		return renderCallChain(x.Fun)
	case *ast.ParenExpr:
		return renderCallChain(x.X)
	case *ast.IndexExpr:
		return renderCallChain(x.X)
	case *ast.StarExpr:
		return renderCallChain(x.X)
	default:
		return ""
	}
}

// selectorChain renders a (non-call) selector expression into its dotted chain,
// dropping any call parentheses in the spine: `r.URL.Query().Get` selector parts
// render to "r.URL.Query.Get". Returns "" when there is no identifier spine.
func selectorChain(sel *ast.SelectorExpr) string {
	base := renderCallChain(sel.X)
	if base == "" {
		return sel.Sel.Name
	}
	return base + "." + sel.Sel.Name
}

// selectorHead returns the leftmost identifier of a selector chain (the receiver),
// e.g. "r" in r.URL.Query, or "" if the spine does not start with an identifier.
func selectorHead(sel *ast.SelectorExpr) string {
	return chainHead(selectorChain(sel))
}

// pureSelectorChain returns the dotted chain of an expression IFF it is a pure
// selector chain — identifiers and dots only, at least two segments, no call, no
// literal, no operator (e.g. "r.Body", "r.URL"). Returns "" otherwise. This is the
// exact shape that is safe to hoist into a synthetic source assignment.
func pureSelectorChain(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if !isPureSelector(sel) {
		return ""
	}
	chain := selectorChain(sel)
	if !strings.Contains(chain, ".") {
		return ""
	}
	return chain
}

// isPureSelector reports whether a selector expression is composed only of
// identifiers and nested selectors (no call, index, or other expression in its
// spine).
func isPureSelector(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return isPureSelector(x.X)
	default:
		return false
	}
}

// chainHead returns the first dot-separated segment of a dotted chain.
func chainHead(chain string) string {
	if i := strings.IndexByte(chain, '.'); i >= 0 {
		return chain[:i]
	}
	return chain
}

// isStringLiteral reports whether an expression is a string basic literal — a
// fixed command/query prefix, not a tainted value.
func isStringLiteral(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// isGoRawWriteSink reports whether a rendered callee chain is a raw byte `.Write`
// on a response writer (w.Write, rw.Write, …). Matched on the `.Write` suffix so an
// aliased writer name still resolves. This is the only XSS-write sink whose danger
// is gated on a co-located string literal (a bare w.Write(out) of precomputed bytes
// is not reflected XSS); the fmt.Fprint*/io.WriteString string-writers are not
// gated, and template.HTML is an unconditional bypass sink.
func isGoRawWriteSink(callee string) bool {
	return strings.HasSuffix(callee, ".Write")
}

// xssWriteArgIsHTML reports whether a write call carries the reflected-HTML shape:
// a string LITERAL appears somewhere in its arguments (a format string like
// "<div>%s</div>" or an HTML concatenation "<b>"+user+"</b>", including inside a
// []byte(...) conversion). A bare write of a single precomputed value — w.Write(out)
// — has no literal and is not treated as XSS. Deterministic, AST-only.
func xssWriteArgIsHTML(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if exprContainsStringLiteral(arg) {
			return true
		}
	}
	return false
}

// exprContainsStringLiteral reports whether an expression tree contains a string
// basic literal, descending concatenations, conversions ([]byte(...)), and the
// usual wrappers. It does not descend into nested unrelated calls' arguments
// beyond the conversion/format spine we care about — a string literal anywhere in
// the write argument's own spine is enough to mark it HTML-shaped.
func exprContainsStringLiteral(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.BinaryExpr:
		return exprContainsStringLiteral(x.X) || exprContainsStringLiteral(x.Y)
	case *ast.ParenExpr:
		return exprContainsStringLiteral(x.X)
	case *ast.CallExpr:
		// Descend a conversion / wrapping call ([]byte("<b>"+user+"</b>"),
		// string(...)) so a literal inside the converted expression counts.
		for _, a := range x.Args {
			if exprContainsStringLiteral(a) {
				return true
			}
		}
		return false
	}
	return false
}

// isCompositeVector reports whether an expression is a composite literal such as
// a slice `[]string{...}` — an argument VECTOR, not a command string. exec.Command
// with a first-arg vector is the safe arg-vector form.
func isCompositeVector(e ast.Expr) bool {
	_, ok := e.(*ast.CompositeLit)
	return ok
}

// appendUnique appends s to out if not already present, preserving order.
func appendUnique(out []string, s string) []string {
	for _, v := range out {
		if v == s {
			return out
		}
	}
	return append(out, s)
}

// isGoKeyword reports whether s is a Go keyword or predeclared literal that must
// never be treated as a variable read.
func isGoKeyword(s string) bool {
	switch s {
	case "break", "case", "chan", "const", "continue", "default", "defer",
		"else", "fallthrough", "for", "func", "go", "goto", "if", "import",
		"interface", "map", "package", "range", "return", "select", "struct",
		"switch", "type", "var", "nil", "true", "false", "iota":
		return true
	}
	return false
}
