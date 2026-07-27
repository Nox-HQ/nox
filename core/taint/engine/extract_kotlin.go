package engine

import "strings"

// extractKotlin turns Kotlin logical lines into unit drafts using the shared
// line/statement RECOGNIZER (never a real parser — only Go gets go/ast). Every
// `fun name(...)` opens its own unit keyed by the function name, so a source read
// and a sink call in the same function are joined intraprocedurally (and the
// interprocedural summary pass can bind a caller argument to a callee parameter).
// Everything outside a recognized function — property initializers, `init`
// blocks — folds into the module-level unit (funcName ""), which is conservative:
// merging scopes can only ever join a source and sink into one unit (at worst a
// false positive), never hide a real same-function flow.
//
// Kotlin is brace-delimited like Java/JS, so it reuses the shared
// logicalLines/splitSemicolons segmentation with bracesAreBlocks=true. Kotlin
// statements are usually newline-terminated (semicolons optional); the semicolon
// split is still applied so the rare `a; b` line becomes two statements, and
// newline-terminated lines are already one logical line each.
//
// HONEST LIMITS (why Kotlin line recognition is coarse, mirroring Java/Rust):
//   - Scope tracking is by brace depth; a `fun` header opens a unit that stays
//     current until its body's closing brace. Nested lambdas and object
//     expressions fold into the enclosing function.
//   - Expression-body functions (`fun f(x) = sink(x)`) are recognized as an
//     assignment on the header line, so the sink read is still captured, but the
//     function is not opened as its own named unit (the `=` form has no `{`).
//   - Fluent/scope-function chains (`user.let { ... }`, `?.let`, `run {}`) are
//     recognized only as far as their argument reads; a value laundered through a
//     lambda receiver is not tracked. These gaps are recorded as honest FNs in
//     testdata/precision-suite-kotlin/README.md.
func extractKotlin(lines []logicalLine) []unitDraft {
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

		// A `fun` header that opens a block body opens a new unit. Recognize it
		// before statements so its name is not mistaken for a call and its
		// parameters become the unit's.
		if name, params, ok := kotlinFunHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			funDepth = depth
			depth += braceDelta(trimmed)
			continue
		}

		before := depth
		depth += braceDelta(trimmed)
		// If this line closes the current function body (depth falls back to the
		// level the header opened at), return to module scope after recognizing any
		// statement content on the line.
		closesFun := funDepth >= 0 && before > funDepth && depth <= funDepth

		if isKotlinStructuralLine(trimmed) {
			if closesFun {
				cur = module
				funDepth = -1
			}
			continue
		}

		if st, ok := kotlinReturnStatement(ll); ok {
			cur.stmts = append(cur.stmts, st)
		} else if st, ok := recognizeStatement(langKotlin, ll); ok {
			cur.stmts = append(cur.stmts, st)
		}

		// A scope function's lambda parameter aliases its receiver, so bind it
		// before the lambda body's statements (which arrive on later lines).
		if b, ok := scopeFunctionBinding(ll); ok {
			if st, ok := recognizeStatement(langKotlin, b); ok {
				cur.stmts = append(cur.stmts, st)
			}
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

// kotlinFunHeader returns the function name and its positional parameter names if
// trimmed is a `fun` declaration header that opens a block body (ends in `{`).
// It is preceded by optional visibility/modifier keywords (`public`, `private`,
// `internal`, `suspend`, `inline`, `override`, `open`, `operator`, `tailrec`,
// `external`) in any order, and may carry a receiver (`fun String.ext(...)`) or
// generics (`fun <T> f(...)`). Parameters are the bare binding names before each
// `:` in declaration order. Returns ("", nil, false) for anything that is not a
// block-bodied function header (an expression-body `fun f() = e` has no `{` and
// is left for the statement recognizer to read as an assignment).
func kotlinFunHeader(trimmed string) (name string, params []string, ok bool) {
	if !strings.HasSuffix(trimmed, "{") {
		return "", nil, false
	}
	rest := trimmed
	// Strip leading modifier keywords that may precede `fun` in any order.
	for {
		advanced := false
		for _, kw := range []string{
			"public ", "private ", "protected ", "internal ", "suspend ", "inline ",
			"override ", "open ", "operator ", "tailrec ", "external ", "final ",
			"abstract ", "infix ", "annotation ",
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
	if !strings.HasPrefix(rest, "fun ") && !strings.HasPrefix(rest, "fun<") {
		return "", nil, false
	}
	rest = strings.TrimSpace(rest[len("fun"):])

	// Find the parameter parenthesis: the first top-level `(` in the header.
	open := strings.IndexByte(rest, '(')
	if open < 0 {
		return "", nil, false
	}
	closeIdx := matchParen(rest, open)
	if closeIdx < 0 {
		return "", nil, false
	}
	// The function name is the identifier immediately before `(`, after any
	// receiver-type prefix (`String.ext` -> `ext`) and generic `<T>` block.
	head := strings.TrimSpace(rest[:open])
	name = lastIdentifier(head)
	if !isSimpleIdent(name) {
		return "", nil, false
	}
	params = parseKotlinParams(rest[open+1 : closeIdx])
	return name, params, true
}

// parseKotlinParams splits a Kotlin parameter list into bare positional binding
// names in order. Each parameter is `[modifiers] name: Type [= default]`,
// possibly `vararg name: T` or `crossinline name: () -> Unit`. The binding NAME
// is the identifier just before the first top-level `:`. A default value after
// `=` and the type after `:` are ignored. An unparsable slot is skipped (fail
// safe: a missed parameter only weakens a summary, never fabricates a flow).
func parseKotlinParams(inner string) []string {
	parts := splitKotlinParamList(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Drop a leading `vararg`/`noinline`/`crossinline` modifier.
		for _, mod := range []string{"vararg ", "noinline ", "crossinline "} {
			p = strings.TrimPrefix(p, mod)
		}
		p = strings.TrimSpace(p)
		// The name is the text before the first top-level ':'.
		name := p
		if i := topLevelColon(p); i >= 0 {
			name = strings.TrimSpace(p[:i])
		} else if i := strings.IndexByte(p, '='); i >= 0 {
			// No type annotation but a default (`x = 0`) — name is before `=`.
			name = strings.TrimSpace(p[:i])
		}
		if isSimpleIdent(name) {
			out = append(out, name)
		}
	}
	return out
}

// splitKotlinParamList splits a Kotlin parameter list on top-level commas,
// balancing ()/[]/{}/<> so a comma inside `Map<String, String>` or a lambda type
// `(Int, Int) -> Unit` does not split the slot.
func splitKotlinParamList(inner string) []string {
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return nil
	}
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, inner[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, inner[start:])
	return parts
}

// NOTE: the `name: Type` boundary is located with the shared topLevelColon
// helper (defined in extract_rust.go): it returns the first `:` outside any
// bracket/angle-generic group and skips `::` path/reference separators, which is
// exactly what a Kotlin parameter (`name: Type`) or binding (`x: String`) needs.

// stripKotlinDeclType reduces a Kotlin assignment LHS to its bare variable name.
// A Kotlin local binding reads `val name = expr`, `var name = expr`, or
// `val name: Type = expr`; the declared name is the identifier after the
// `val`/`var` keyword and before any `: Type` annotation. A plain `name = expr`
// (reassignment) is returned unchanged. Best-effort and deterministic: an
// unrecognizable LHS falls through to isSimpleIdent, which rejects it safely.
func stripKotlinDeclType(left string) string {
	left = strings.TrimSpace(left)
	for _, kw := range []string{"val ", "var ", "const val ", "lateinit var "} {
		if strings.HasPrefix(left, kw) {
			left = strings.TrimSpace(strings.TrimPrefix(left, kw))
			break
		}
	}
	// Drop a `: Type` annotation on the binding (`x: String` -> `x`).
	if i := topLevelColon(left); i >= 0 {
		left = strings.TrimSpace(left[:i])
	}
	return left
}

// isKotlinStructuralLine reports whether a line is pure scaffolding whose tokens
// must not be read as a data-flow statement: a lone brace, a package/import, a
// class/object/interface/enum header, or a control keyword. It is coarse on
// purpose — a missed skip only adds a harmless non-sink call to a unit.
func isKotlinStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "};", "})", "});", "}, {":
		return true
	}
	for _, kw := range []string{
		"package ", "import ",
		"class ", "object ", "interface ", "enum ", "data class ", "sealed class ",
		"abstract class ", "open class ", "annotation class ", "companion object",
		"if ", "if(", "for ", "for(", "while ", "while(", "when ", "when(",
		"else", "try", "try ", "try{", "catch ", "catch(", "finally", "do ", "do{",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// kotlinReturnStatement recognizes a `return <expr>` line and produces a
// stmtDraft whose `returns` lists the variable names in the returned expression,
// while still capturing the calls and reads inside it (so `return exec(x)` is
// both a sink read AND a return). A `return@label` qualified return is handled by
// blanking through the label. A bare `return` yields a statement with empty
// returns. Reports ok=false for any line that is not a return.
func kotlinReturnStatement(ll logicalLine) (stmtDraft, bool) {
	trimmed := strings.TrimSpace(ll.code)
	if trimmed != "return" && !strings.HasPrefix(trimmed, "return ") &&
		!strings.HasPrefix(trimmed, "return(") && !strings.HasPrefix(trimmed, "return@") {
		return stmtDraft{}, false
	}
	// Blank the leading `return` keyword (and a `@label` if present) in both
	// views, preserving offsets so recognizeStatement's code/raw alignment holds.
	kw := strings.Index(ll.code, "return")
	end := kw + len("return")
	// Consume a `@label` immediately after `return`.
	if end < len(ll.code) && ll.code[end] == '@' {
		end++
		for end < len(ll.code) && isIdentPart(ll.code[end]) {
			end++
		}
	}
	exprCode := ll.code
	exprRaw := ll.raw
	if kw >= 0 && end <= len(exprCode) {
		exprCode = blankRange(exprCode, kw, end)
		if end <= len(exprRaw) {
			exprRaw = blankRange(exprRaw, kw, end)
		}
	}
	inner := logicalLine{line: ll.line, code: exprCode, raw: exprRaw}
	st, ok := recognizeStatement(langKotlin, inner)
	if !ok {
		// A bare `return` still needs a statement so the analyzer sees the line;
		// it carries no reads and no returns.
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}
