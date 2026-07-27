package engine

import "strings"

// extractGroovy turns Groovy logical lines into unit drafts using the shared
// line/statement RECOGNIZER (never a real parser — only Go gets go/ast). Every
// `def name(...)` / typed `Type name(...)` method header opens its own unit keyed
// by the method name, so a source read and a sink call in the same method are
// joined intraprocedurally (and the interprocedural summary pass can bind a caller
// argument to a callee parameter). Everything outside a recognized method — field
// initializers, top-level script statements (a Groovy/Gradle/Jenkins script body)
// — folds into the module-level unit (funcName ""), which is conservative: merging
// scopes can only ever join a source and sink into one unit (at worst a false
// positive), never hide a real same-method flow.
//
// Groovy is brace-delimited like Java/Kotlin, so it reuses the shared
// logicalLines/splitSemicolons segmentation with bracesAreBlocks=true. Groovy
// statements are usually newline-terminated (semicolons optional); the semicolon
// split is still applied so the rare `a; b` line becomes two statements.
//
// HONEST LIMITS (why Groovy line recognition is coarse, mirroring Java/Kotlin):
//   - Scope tracking is by brace depth; a method header opens a unit that stays
//     current until its body's closing brace. Closures and builder blocks fold
//     into the enclosing method/script.
//   - Groovy closures (`list.each { cmd -> ... }`, `{ it -> ... }`) launder taint
//     through a closure parameter (a named param or the implicit `it`) that the
//     flat recognizer does not alias to the receiver — a documented recall gap.
//   - Paren-less "command chains" (`sh "rm ${x}"`, `println x`) are recognized as
//     bare calls by the statement recognizer where the shape allows; a value
//     laundered through an untracked builder/DSL method is not tracked.
func extractGroovy(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	// depth is the running brace nesting. methodDepth is the depth at which the
	// current method body lives (-1 when at module/script scope); when depth falls
	// back to methodDepth the method has closed and scope returns to the module.
	depth := 0
	methodDepth := -1

	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" {
			continue
		}

		// A method header opens a new unit. Recognize it before statements so its
		// name is not mistaken for a call and its parameters become the unit's.
		if name, params, ok := groovyMethodHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			methodDepth = depth
			depth += braceDelta(trimmed)
			continue
		}

		before := depth
		depth += braceDelta(trimmed)
		// If this line closes the current method body (depth falls back to the level
		// the header opened at), return to module scope after recognizing any
		// statement content on the line.
		closesMethod := methodDepth >= 0 && before > methodDepth && depth <= methodDepth

		if isGroovyStructuralLine(trimmed) {
			if closesMethod {
				cur = module
				methodDepth = -1
			}
			continue
		}

		if st, ok := groovyReturnStatement(ll); ok {
			cur.stmts = append(cur.stmts, st)
		} else if st, ok := recognizeStatement(langGroovy, ll); ok {
			cur.stmts = append(cur.stmts, st)
		}

		// A scope function's lambda parameter aliases its receiver, so bind it
		// before the lambda body's statements (which arrive on later lines).
		if b, ok := scopeFunctionBinding(ll); ok {
			if st, ok := recognizeStatement(langGroovy, b); ok {
				cur.stmts = append(cur.stmts, st)
			}
		}

		if closesMethod {
			cur = module
			methodDepth = -1
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// groovyMethodHeader returns the method name and its positional parameter names if
// trimmed is a method declaration header (ends in `{`, has a parameter list, and
// is not a control-flow header, a closure, or a DSL block). A Groovy method reads
// `def name(params) {`, `Type name(params) {`, or a modifier-prefixed
// `public String name(params) {`. Parameters are the bare identifier names in
// declaration order (Groovy params may be typed `String x` or untyped `x`). The
// parameter list underpins interprocedural summaries: a caller's Nth argument
// binds the callee's Nth parameter.
func groovyMethodHeader(trimmed string) (name string, params []string, ok bool) {
	// A method header opens a block.
	if !strings.HasSuffix(trimmed, "{") {
		return "", nil, false
	}
	// Control-flow headers also end in `{` — exclude them.
	for _, kw := range []string{"if", "for", "while", "switch", "catch", "try", "else", "do", "synchronized"} {
		if trimmed == kw || strings.HasPrefix(trimmed, kw+" ") || strings.HasPrefix(trimmed, kw+"(") {
			return "", nil, false
		}
	}
	// Class/interface/enum/trait declarations are not methods.
	if strings.HasPrefix(trimmed, "class ") || strings.Contains(trimmed, " class ") ||
		strings.HasPrefix(trimmed, "interface ") || strings.Contains(trimmed, " interface ") ||
		strings.HasPrefix(trimmed, "trait ") || strings.Contains(trimmed, " trait ") ||
		strings.HasPrefix(trimmed, "enum ") || strings.Contains(trimmed, " enum ") {
		return "", nil, false
	}

	// Find the parameter list: the first top-level `(` before the opening `{`.
	open := strings.IndexByte(trimmed, '(')
	if open < 0 {
		return "", nil, false
	}
	closeIdx := matchParen(trimmed, open)
	if closeIdx < 0 {
		return "", nil, false
	}
	// The method name is the identifier immediately before `(`.
	head := strings.TrimSpace(trimmed[:open])
	name = lastIdentifier(head)
	if !isSimpleIdent(name) {
		return "", nil, false
	}
	// A bare `name(args) {` with NOTHING before the name is a call whose trailing
	// argument is a closure (a DSL block like `task('x') { ... }` or
	// `node('label') { ... }`), NOT a method declaration. Require either a `def`,
	// a return type, or a modifier before the name to treat it as a declaration —
	// this keeps Jenkins/Gradle DSL blocks from being mis-parsed as method units
	// (folding them into the script unit is the conservative choice).
	if head == name {
		return "", nil, false
	}
	params = parseGroovyParams(trimmed[open+1 : closeIdx])
	return name, params, true
}

// parseGroovyParams splits a Groovy parameter list into bare positional parameter
// names in order. A Groovy parameter is `[modifiers] [Type] name [= default]`,
// typed (`String user`) or untyped (`user`), possibly with generics
// (`Map<String,String> m`) or a default value. The declared NAME is the last
// identifier token of the slot (before any `=` default). An unparsable slot is
// skipped (fail safe: a missed parameter only weakens a summary, never fabricates
// a flow).
func parseGroovyParams(inner string) []string {
	parts := splitJavaParamList(inner) // reuse Java's <>-aware splitter (generics)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Drop a default value (`x = 0`) — the name is before the top-level `=`.
		if i := topLevelAssignIndex(p); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		nm := lastIdentifier(p)
		if isSimpleIdent(nm) {
			out = append(out, nm)
		}
	}
	return out
}

// stripGroovyDeclType reduces a Groovy assignment LHS to its bare variable name.
// A Groovy local binding reads `def name = expr`, a typed `Type name = expr`
// (`String user = ...`, `Map<String,String> m = ...`, `int[] a = ...`), or a plain
// `name = expr` reassignment. The declared name is the trailing identifier; `def`
// and any leading type/modifiers are stripped. A single bare token is returned
// unchanged. Best-effort and deterministic: an unrecognizable LHS falls through to
// isSimpleIdent, which rejects it safely.
func stripGroovyDeclType(left string) string {
	left = strings.TrimSpace(left)
	if isSimpleIdent(left) {
		return left // plain reassignment: `x = ...`
	}
	// `def name`, `String name`, `final def name`, `Map<K,V> name` — the declared
	// name is the trailing identifier of the LHS.
	nm := lastIdentifier(left)
	if nm == "" {
		return left
	}
	return nm
}

// isGroovyStructuralLine reports whether a line is pure scaffolding whose tokens
// must not be read as a data-flow statement: a lone brace, a package/import, a
// class/interface/enum/trait header, or a control keyword. It is coarse on purpose
// — a missed skip only adds a harmless non-sink call to a unit.
func isGroovyStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "};", "})", "});", "}):", "}, {":
		return true
	}
	for _, kw := range []string{
		"package ", "import ",
		"class ", "interface ", "enum ", "trait ", "@interface ",
		"public class ", "final class ", "abstract class ",
		"if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(",
		"else", "try", "try ", "try{", "try(", "catch ", "catch(", "finally", "do ", "do{",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// groovyReturnStatement recognizes a `return <expr>` line and produces a stmtDraft
// whose `returns` lists the variable names in the returned expression, while still
// capturing the calls and reads inside it (so `return exec(x)` is both a sink read
// AND a return). A bare `return` yields a statement with empty returns. Reports
// ok=false for any line that is not a return. (Groovy allows an implicit return of
// the last expression; that is not modeled — only an explicit `return`.)
func groovyReturnStatement(ll logicalLine) (stmtDraft, bool) {
	trimmed := strings.TrimSpace(ll.code)
	if trimmed != "return" && trimmed != "return;" &&
		!strings.HasPrefix(trimmed, "return ") && !strings.HasPrefix(trimmed, "return(") {
		return stmtDraft{}, false
	}
	// Blank the leading `return` keyword in both views, preserving offsets so
	// recognizeStatement's code/raw alignment holds.
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
	st, ok := recognizeStatement(langGroovy, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}
