package engine

import "strings"

// extractDart turns Dart logical lines into unit drafts using the shared
// line/statement RECOGNIZER (never a real parser — only Go gets go/ast). Every
// method/function header `[ReturnType] name(params) [async] {` opens its own unit
// keyed by the function name, so a source read and a sink call in the same
// function are joined intraprocedurally (and the interprocedural summary pass can
// bind a caller argument to a callee parameter). Everything outside a recognized
// function — field initializers, top-level statements — folds into the module
// unit (funcName ""), which is conservative: merging scopes can only ever join a
// source and a sink into one unit (at worst a false positive), never hide a real
// same-function flow.
//
// Dart is brace-delimited like Java/Kotlin, so it reuses the shared
// logicalLines/splitSemicolons segmentation with bracesAreBlocks=true. Dart
// statements are `;`-terminated; the semicolon split makes each its own
// recognizable statement.
//
// HONEST LIMITS (why Dart line recognition is coarse, mirroring Java/Kotlin):
//   - Scope tracking is by brace depth; a header opens a unit that stays current
//     until its body's closing brace. Nested closures and callbacks fold into the
//     enclosing function.
//   - Expression-body members (`String f(x) => sink(x);`) are recognized as a
//     statement on the header line (the arrow's RHS is read), so the sink read is
//     still captured, but the member is not opened as its own named unit.
//   - Cascades (`..method()`), null-aware chains (`?.`), and `await`/`Future`
//     laundering are recognized only as far as their argument reads; a value
//     laundered through an async callback is not tracked. These gaps are recorded
//     as honest FNs in testdata/precision-suite-dart/README.md.
//   - A typed function PARAMETER arriving as untrusted input (a shelf `Request`)
//     is not a source CALL, so it is not tainted from its type — the same
//     documented gap as the other web extractors.
func extractDart(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	// depth is the running brace nesting. funDepth is the depth at which the
	// current function body lives (-1 when at module scope); when depth falls back
	// to funDepth the function has closed and scope returns to the module.
	depth := 0
	funDepth := -1

	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" {
			continue
		}

		// A `return ...` line is a statement, never a header — check it first so a
		// `return Foo(x)` is not misread as a header.
		if st, ok := dartReturnStatement(ll); ok {
			cur.stmts = append(cur.stmts, st)
			before := depth
			depth += braceDelta(trimmed)
			if funDepth >= 0 && before > funDepth && depth <= funDepth {
				cur = module
				funDepth = -1
			}
			continue
		}

		// A method/function header that opens a block body opens a new unit.
		// Recognized before the generic statement recognizer so the header
		// identifiers (function name, parameter types) are never read as a call.
		if name, params, ok := dartFuncHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			funDepth = depth
			depth += braceDelta(trimmed)
			continue
		}

		before := depth
		depth += braceDelta(trimmed)
		closesFun := funDepth >= 0 && before > funDepth && depth <= funDepth

		if isDartStructuralLine(trimmed) {
			if closesFun {
				cur = module
				funDepth = -1
			}
			continue
		}

		if st, ok := recognizeStatement(langDart, ll); ok {
			cur.stmts = append(cur.stmts, st)
		}

		if closesFun {
			cur = module
			funDepth = -1
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// dartFuncHeader returns the function/method name and its positional+named
// parameter binding names if trimmed is a header that opens a block body. A Dart
// header is `[modifiers] [ReturnType] name(params) [async|sync*|async*] {`. The
// body-open form ends in `{` and carries a top-level `(...)` parameter group; the
// name is the identifier immediately before that group (after any return type).
// An expression-body member (`... => e;`) has no `{` and is left to the statement
// recognizer. Returns ("", nil, false) for anything that is not a block-bodied
// header (a control-flow line such as `if (x) {` is rejected because its keyword
// head is not a simple identifier once the `if`/`for`/... prefix is filtered).
func dartFuncHeader(trimmed string) (name string, params []string, ok bool) {
	if !strings.HasSuffix(trimmed, "{") {
		return "", nil, false
	}
	// A control-flow / declaration header ending in `{` is not a function.
	if isDartControlHead(trimmed) {
		return "", nil, false
	}
	// Find the parameter parenthesis: the FIRST top-level `(` in the header.
	open := strings.IndexByte(trimmed, '(')
	if open < 0 {
		return "", nil, false
	}
	closeIdx := matchParen(trimmed, open)
	if closeIdx < 0 {
		return "", nil, false
	}
	// After the `)` only a trailing async marker and the opening `{` may appear.
	tail := strings.TrimSpace(trimmed[closeIdx+1:])
	tail = strings.TrimSuffix(tail, "{")
	tail = strings.TrimSpace(tail)
	switch tail {
	case "", "async", "sync*", "async*":
	default:
		// A `)` followed by anything else (`) : super(...) {` constructor
		// initializer, `) => e`) is not a plain block-bodied header here.
		if !strings.HasPrefix(tail, ":") { // constructor initializer list is still a header
			return "", nil, false
		}
	}
	// The name is the identifier immediately before `(`, after any return type and
	// a possible `ClassName.named` constructor prefix (take the last identifier).
	head := strings.TrimSpace(trimmed[:open])
	name = lastDartIdentifier(head)
	if !isSimpleIdent(name) {
		return "", nil, false
	}
	params = parseDartParams(trimmed[open+1 : closeIdx])
	return name, params, true
}

// isDartControlHead reports whether a `{`-terminated line is a control-flow or
// type-declaration header (never a function). These carry a leading keyword whose
// name would otherwise be mistaken for a function name.
func isDartControlHead(trimmed string) bool {
	for _, kw := range []string{
		"if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(",
		"else", "try", "try ", "try{", "catch ", "catch(", "finally", "do ", "do{",
		"class ", "abstract class ", "mixin ", "enum ", "extension ",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// lastDartIdentifier returns the trailing identifier of a header's pre-parameter
// text, dropping a generic `<...>` block, a return type, and a `ClassName.named`
// constructor receiver prefix. `Future<void> doWork` -> `doWork`; `Foo.named` ->
// `named`; `String? get value` -> `value`.
func lastDartIdentifier(head string) string {
	head = strings.TrimSpace(head)
	// Drop a trailing generic parameter block if the name carried one on the type.
	// Walk from the end collecting identifier bytes (letters/digits/_/$), stopping
	// at the first non-identifier byte — that trailing run is the name.
	i := len(head)
	for i > 0 && isDartNameByte(head[i-1]) {
		i--
	}
	return head[i:]
}

// isDartNameByte reports whether b can be part of an identifier NAME (letters,
// digits, underscore, `$`). Used to peel the trailing name off a header head.
func isDartNameByte(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// parseDartParams splits a Dart parameter list into the bare positional and named
// binding names in declaration order. A Dart parameter is `[modifiers] [Type]
// name [= default]`, and the list may contain `{...}` named groups and `[...]`
// optional-positional groups whose brace/bracket delimiters are stripped. The
// binding NAME is the LAST identifier of a slot before any `=` default (so `String
// name` -> `name`, `required int count = 0` -> `count`, `this.field` -> `field`).
// An unparsable slot is skipped (fail safe).
func parseDartParams(inner string) []string {
	// Strip the outer group delimiters `{ }` (named) / `[ ]` (optional positional)
	// so their inner comma-separated params are split like normal ones.
	inner = strings.Map(func(r rune) rune {
		switch r {
		case '{', '}', '[', ']':
			return ' '
		}
		return r
	}, inner)
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Drop a default value (`= expr` or `: expr` for a named-default form).
		if eq := topLevelAssignIndex(p); eq >= 0 {
			p = strings.TrimSpace(p[:eq])
		}
		// A `this.field` / `super.field` initializing-formal binds the field name.
		if dot := strings.LastIndexByte(p, '.'); dot >= 0 {
			p = strings.TrimSpace(p[dot+1:])
		}
		// The binding name is the LAST whitespace-separated token (dropping the
		// leading `Type`/`required`/`covariant`/`final` modifiers).
		fields := strings.Fields(p)
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

// stripDartDeclType reduces a Dart assignment LHS to its bare variable name by
// dropping a `var`/`final`/`const` keyword and/or a leading type. A Dart local
// declaration reads `var name = expr`, `final name = expr`, `const name = expr`,
// `String name = expr`, or `final String name = expr`. The variable name is the
// LAST top-level whitespace-separated token; everything before it is
// keywords/type (possibly with generic/array brackets, already balanced in the
// code view). A single bare token (`name`) is a plain reassignment and is
// returned unchanged. Best-effort and deterministic: an unrecognizable LHS falls
// through to isSimpleIdent, which rejects it safely.
func stripDartDeclType(left string) string {
	left = strings.TrimSpace(left)
	// Find the last top-level space (not inside <...>/[...]/(...)) — the boundary
	// between the type/keywords and the variable name.
	depth := 0
	lastSpace := -1
	for i := 0; i < len(left); i++ {
		switch left[i] {
		case '<', '[', '(':
			depth++
		case '>', ']', ')':
			if depth > 0 {
				depth--
			}
		case ' ', '\t':
			if depth == 0 {
				lastSpace = i
			}
		}
	}
	if lastSpace < 0 {
		return left // bare identifier: a plain reassignment
	}
	return strings.TrimSpace(left[lastSpace+1:])
}

// isDartStructuralLine reports whether a line is pure scaffolding whose tokens
// must not be read as a data-flow statement: a lone brace, an import/library/part
// directive, a class/mixin/enum/extension header, or a control keyword. It is
// coarse on purpose — a missed skip only adds a harmless non-sink call to a unit.
func isDartStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "};", "})", "});", "}, {", ")", ");":
		return true
	}
	if strings.HasPrefix(trimmed, "@") {
		return true // a Dart annotation line such as an override or route marker
	}
	for _, kw := range []string{
		"import ", "export ", "library ", "part ", "part of ",
		"class ", "abstract class ", "mixin ", "enum ", "extension ", "typedef ",
		"if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(",
		"else", "try", "try ", "try{", "catch ", "catch(", "finally", "do ", "do{",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// dartReturnStatement recognizes a `return <expr>` line and produces a stmtDraft
// whose `returns` lists the variable names in the returned expression, while
// still capturing the calls and reads inside it (so `return exec(x)` is both a
// sink read AND a return). A bare `return` yields a statement with empty returns.
// Reports ok=false for any line that is not a return.
func dartReturnStatement(ll logicalLine) (stmtDraft, bool) {
	trimmed := strings.TrimSpace(ll.code)
	if trimmed != "return" && trimmed != "return;" &&
		!strings.HasPrefix(trimmed, "return ") && !strings.HasPrefix(trimmed, "return(") {
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
	inner := logicalLine{line: ll.line, code: exprCode, raw: exprRaw}
	st, ok := recognizeStatement(langDart, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}
