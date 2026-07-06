package engine

import "strings"

// extractSwift turns Swift logical lines into unit drafts using the shared
// line/statement RECOGNIZER (never a real parser — only Go gets go/ast). Swift is
// brace-delimited like C#, so — like the C# recognizer — it recognizes `func`
// declarations so each function body becomes its own unit with its parameter
// list. That per-function scoping matches Python's precision and feeds the
// interprocedural summary pass (a caller's Nth argument binds the callee's Nth
// parameter).
//
// Scoping is by `func` header only: a statement is attributed to the most
// recently opened function; when block nesting falls back to the header's depth
// the function scope ends. Nested closures and methods fold into their enclosing
// function, which is conservative (it can only merge scopes, never split a real
// flow). Anything outside a function — property initializers, top-level
// statements in a `main.swift` — accumulates into the module unit (funcName "").
//
// HONEST LIMITS (why Swift line recognition is coarser than Python/Go):
//   - Optional chaining / `try?` / `guard let`: `guard let x = f(user) else {…}`
//     and `let y = obj?.z` bind through machinery the recognizer treats as an
//     opaque call or a plain assignment — taint usually survives (the argument
//     read propagates) but the control flow is invisible.
//   - Trailing closures: `session.dataTask(with: req) { data, _ in … }` — the
//     closure body folds into the enclosing function rather than its own scope.
//   - Parameter-as-source: a Vapor/`URLRequest` value arriving as a typed
//     function parameter is untrusted but is not a source CALL, so it is not
//     tainted from its type (the same documented gap as Rust/Java web extractors).
func extractSwift(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module
	// depth is the block-brace nesting at the CURRENT logical line. A function body
	// opens at the header's `{`; when nesting falls back to the header's depth the
	// function scope ends. funcDepth is -1 when not inside a recognized function.
	depth := 0
	funcDepth := -1

	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" {
			continue
		}

		// A `return ...` line is a statement, never a declaration header — check it
		// first so a `return Foo(x)` is not misread as a header.
		if st, ok := swiftReturnStatement(ll); ok {
			cur.stmts = append(cur.stmts, st)
			depth += braceDelta(trimmed)
			if funcDepth >= 0 && depth <= funcDepth {
				cur = module
				funcDepth = -1
			}
			continue
		}

		// A `func` header opens a new unit. Recognized BEFORE the generic statement
		// recognizer so the header identifiers (function name, parameter labels) are
		// never read as a data-flow call.
		if name, params, ok := swiftFuncHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			funcDepth = depth
			depth += braceDelta(trimmed)
			continue
		}

		if !isSwiftStructuralLine(trimmed) {
			if st, ok := recognizeStatement(langSwift, normalizeSwift(ll)); ok {
				cur.stmts = append(cur.stmts, st)
			}
		}

		depth += braceDelta(trimmed)
		if funcDepth >= 0 && depth <= funcDepth {
			cur = module
			funcDepth = -1
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// swiftFuncHeader returns the function name and its positional parameter INTERNAL
// binding names when trimmed is a `func` declaration header. A header is
// `[attributes] [modifiers] func name[<generics>](params) [-> Ret] [throws] {`.
// Leading attributes (`@discardableResult`) and modifiers (`public`, `static`,
// `override`, …) precede `func`; the name runs up to the first `(` or `<`; the
// parameter list is the first top-level `(...)` group. Returns ("", nil, false)
// for anything that is not a function header.
func swiftFuncHeader(trimmed string) (name string, params []string, ok bool) {
	rest := trimmed
	// Strip leading attributes (`@name` / `@name(...)`) and modifiers in any order
	// until `func` is reached.
	for {
		advanced := false
		if strings.HasPrefix(rest, "@") {
			// Drop one attribute token (up to the next space), including a trailing
			// `(...)` argument group if present.
			if sp := strings.IndexByte(rest, ' '); sp >= 0 {
				rest = strings.TrimSpace(rest[sp+1:])
				advanced = true
			}
		}
		for _, kw := range []string{
			"public ", "private ", "internal ", "fileprivate ", "open ",
			"static ", "class ", "final ", "override ", "mutating ", "nonmutating ",
			"convenience ", "required ", "dynamic ", "lazy ", "weak ", "unowned ",
			"discardableResult ",
		} {
			if strings.HasPrefix(rest, kw) {
				rest = strings.TrimSpace(strings.TrimPrefix(rest, kw))
				advanced = true
			}
		}
		if !advanced {
			break
		}
	}
	if !strings.HasPrefix(rest, "func ") {
		return "", nil, false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "func "))

	// The name runs up to the first '(' or '<' (generic parameter list).
	nameEnd := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] == '(' || rest[i] == '<' {
			nameEnd = i
			break
		}
	}
	name = strings.TrimSpace(rest[:nameEnd])
	if !isSimpleIdent(name) {
		return "", nil, false
	}

	paren := strings.IndexByte(rest, '(')
	if paren < 0 {
		return name, nil, true // header continued onto next line; no params yet
	}
	closeParen := matchParen(rest, paren)
	if closeParen < 0 {
		return name, nil, true
	}
	params = parseSwiftParams(rest[paren+1 : closeParen])
	return name, params, true
}

// parseSwiftParams splits a Swift parameter list into the INTERNAL positional
// binding names in declaration order. A Swift parameter is
// `[externalLabel] internalName: Type [= default]`:
//   - `_ name: T`   — no external label; internal binding `name`.
//   - `to name: T`  — external label `to`; internal binding `name`.
//   - `name: T`     — label and binding are both `name`.
//
// The binding is therefore the LAST identifier of the label/name run before the
// `:`. `inout`/`isolated` markers and a `= default` are dropped. A `variadic`
// `Type...` and complex patterns degrade safely (a missed parameter only weakens
// a summary, never fabricates a flow).
func parseSwiftParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Drop a default value.
		if eq := topLevelAssignIndex(p); eq >= 0 {
			p = strings.TrimSpace(p[:eq])
		}
		// The binding name is the label run before the first top-level ':'.
		labelRun := p
		if i := strings.IndexByte(p, ':'); i >= 0 {
			labelRun = strings.TrimSpace(p[:i])
		}
		// Strip a parameter modifier keyword that may precede the label run.
		labelRun = strings.TrimPrefix(labelRun, "inout ")
		labelRun = strings.TrimPrefix(labelRun, "isolated ")
		labelRun = strings.TrimSpace(labelRun)
		// The internal binding is the LAST whitespace-separated token of the run
		// (`_ name` -> name, `to name` -> name, `name` -> name).
		fields := strings.Fields(labelRun)
		if len(fields) == 0 {
			continue
		}
		name := fields[len(fields)-1]
		if isSimpleIdent(name) {
			out = append(out, name)
		}
	}
	return out
}

// swiftReturnStatement recognizes a `return <expr>` line and produces a stmtDraft
// whose `returns` lists the variable names in the returned expression while still
// capturing the calls and reads inside it (so `return String(contentsOfFile: p)`
// is both a sink read AND a return). A bare `return` yields a statement with
// empty returns. Reports ok=false for any non-return line.
func swiftReturnStatement(ll logicalLine) (stmtDraft, bool) {
	trimmed := strings.TrimSpace(ll.code)
	if trimmed != "return" && !strings.HasPrefix(trimmed, "return ") {
		return stmtDraft{}, false
	}
	kw := strings.Index(ll.code, "return")
	exprCode := ll.code
	exprRaw := ll.raw
	if kw >= 0 && kw+len("return") <= len(exprCode) {
		exprCode = blankRange(exprCode, kw, kw+len("return"))
		if kw+len("return") <= len(exprRaw) {
			exprRaw = blankRange(exprRaw, kw, kw+len("return"))
		}
	}
	inner := normalizeSwift(logicalLine{line: ll.line, code: exprCode, raw: exprRaw})
	st, ok := recognizeStatement(langSwift, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}

// swiftDiscriminatingLabels are the first-argument labels that make an otherwise
// generic Swift initializer/method DANGEROUS. Folding the label into the callee
// (`String(contentsOfFile:` -> `String.contentsOfFile(`) lets the catalog key on
// the precise, file/URL/HTML-reading form and NOT on the ubiquitous safe forms
// (`String(x)` conversion, `URL(fileURLWithPath:)` for a bundled resource, etc.).
// This is the Swift analogue of Rust's `::`->`.` normalization: it turns a
// label-discriminated call into a plain dotted call the shared recognizer and the
// catalog both understand, keyed identically. Precision-critical — without it a
// bare `String(taintedVar)` would false-positive as a path-traversal sink.
var swiftDiscriminatingLabels = map[string]bool{
	"contentsOfFile": true, // String(contentsOfFile:) / FileManager file read
	"contentsOf":     true, // Data(contentsOf:) / String(contentsOf:) reads a URL/file
	"string":         true, // URL(string:) — the SSRF-relevant remote-URL form
	"with":           true, // session.dataTask(with:) / NSKeyedUnarchiver(with:)
}

// normalizeSwift folds a discriminating first-argument label into the callee for
// the initializer/method forms whose danger depends on that label, so the shared
// recognizer sees a plain dotted call the catalog keys on. `String(contentsOfFile:
// p)` becomes `String.contentsOfFile(p)`, `Data(contentsOf: u)` becomes
// `Data.contentsOf(u)`, `URL(string: s)` becomes `URL.string(s)`, and
// `session.dataTask(with: r)` becomes `session.dataTask.with(r)` (whose suffix
// keys still include `dataTask`). The rewrite swaps `(` for `.` and the label's
// `:` for `(`, preserving byte length so the code/raw views stay aligned to each
// other (all recognizeStatement/argInfo need). Applied to BOTH views.
func normalizeSwift(ll logicalLine) logicalLine {
	code := normalizeSwiftText(ll.code)
	raw := ll.raw
	if len(raw) == len(ll.code) {
		raw = normalizeSwiftText(ll.raw)
	}
	return logicalLine{line: ll.line, code: code, raw: raw}
}

// normalizeSwiftText applies the label-fold rewrite to one view. It scans for an
// identifier immediately followed by `(` and then `label:`; when the label is
// discriminating it rewrites `ident(label:` to `ident.label(`. Length-preserving.
func normalizeSwiftText(s string) string {
	b := []byte(s)
	n := len(b)
	for i := 0; i < n; i++ {
		if b[i] != '(' {
			continue
		}
		// The `(` must immediately follow an identifier byte (a call, not a group).
		if i == 0 || !isIdentPart(b[i-1]) {
			continue
		}
		// Read the label identifier right after `(`.
		j := i + 1
		for j < n && (b[j] == ' ' || b[j] == '\t') {
			j++
		}
		labelStart := j
		for j < n && isIdentPart(b[j]) {
			j++
		}
		if j == labelStart || j >= n {
			continue
		}
		// A label is `ident:` — the next non-space byte must be a single ':' NOT
		// followed by another ':' (so a ternary/type is not mistaken for a label).
		k := j
		for k < n && (b[k] == ' ' || b[k] == '\t') {
			k++
		}
		if k >= n || b[k] != ':' {
			continue
		}
		if !swiftDiscriminatingLabels[string(b[labelStart:j])] {
			continue
		}
		// Rewrite: `(` -> `.` at i, and the label's `:` -> `(` at k.
		b[i] = '.'
		b[k] = '('
	}
	return string(b)
}

// stripSwiftLetKeyword removes a leading `let ` / `var ` binding keyword and any
// `: Type` annotation from a Swift assignment LHS, leaving the bare binding name.
// `let x = e`, `var x = e`, and `let x: String = e` all yield `x`. A non-binding
// LHS (a reassignment `x = e`) is returned with only the annotation stripped.
func stripSwiftLetKeyword(left string) string {
	left = strings.TrimSpace(left)
	if strings.HasPrefix(left, "let ") {
		left = strings.TrimSpace(strings.TrimPrefix(left, "let "))
	} else if strings.HasPrefix(left, "var ") {
		left = strings.TrimSpace(strings.TrimPrefix(left, "var "))
	}
	// Drop a `: Type` annotation on the binding (`x: String` -> `x`).
	if i := strings.IndexByte(left, ':'); i >= 0 {
		left = strings.TrimSpace(left[:i])
	}
	return left
}

// isSwiftStructuralLine reports whether a line is a block/scaffolding line whose
// tokens must not be read as a data-flow statement: a lone brace, a
// type/protocol/extension declaration, an import, an attribute, or a control-flow
// header. Intentionally coarse — a missed skip only adds a harmless non-sink call
// to the enclosing unit.
func isSwiftStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "})", "});", "};", ")":
		return true
	}
	if strings.HasPrefix(trimmed, "@") || strings.HasPrefix(trimmed, "#") {
		return true
	}
	for _, kw := range []string{
		"import ", "class ", "struct ", "enum ", "protocol ", "extension ",
		"if ", "if(", "guard ", "for ", "for(", "while ", "while(", "switch ",
		"switch(", "else", "do ", "do{", "catch", "defer", "case ", "default:",
		"public class", "final class", "public struct", "public enum",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}
