package engine

import "strings"

// extractCSharp turns C# logical lines into unit drafts. C# is brace-delimited
// like JS, but — unlike the module-scoped JS recognizer — it recognizes METHOD
// declarations so each method body becomes its own unit with its parameter list.
// That per-method scoping matches Python's precision and feeds the
// interprocedural summary pass (a caller's Nth argument binds the callee's Nth
// parameter).
//
// Scoping is by method header only: a statement is attributed to the most
// recently opened method. When a method's closing brace is seen the cursor
// returns to the enclosing scope (the module unit). Nested local functions fold
// into their enclosing method, which is conservative (it can only merge scopes,
// never split a real flow). Anything outside a method — field initializers, the
// rare top-level statement — accumulates into the module unit (funcName "").
func extractCSharp(lines []logicalLine) []unitDraft {
	// Branch model: the Java one (java_branches.go); C#'s if/else, loops,
	// switch/case and ternaries have Java's syntax. Before it, an assignment
	// in an if arm was a strong update.
	jb := newJavaBranches(lines)
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module
	// depth is the block-brace nesting at the CURRENT logical line. A method body
	// opens at the header's `{` (on the same line in K&R style, or the next line in
	// Allman style); when nesting falls back to the header's depth the method scope
	// ends. methodDepth is -1 when not inside a recognized method.
	depth := 0
	methodDepth := -1
	leave := func() {
		if methodDepth >= 0 && depth <= methodDepth {
			cur = module
			methodDepth = -1
		}
	}

	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" {
			continue
		}
		before := depth
		depthHere := before - (len(trimmed) - len(strings.TrimLeft(trimmed, "}")))
		jb.enter(depthHere)

		// A method header opens a new unit. It must be recognized BEFORE the
		// generic statement recognizer so the header identifiers (method name,
		// parameters) are never read as a data-flow call. A header may or may not
		// carry its opening `{` on the same line (K&R vs Allman brace style); the
		// body's `{` is counted by braceDelta whichever line it lands on. A
		// `return ...;` line is never a header (`return new Foo(x)`).
		if !strings.HasPrefix(trimmed, "return") {
			if name, params, ok := csharpMethodHeader(trimmed); ok {
				u := &unitDraft{funcName: name, params: params}
				units = append(units, u)
				cur = u
				methodDepth = depth
				depth += braceDelta(trimmed)
				continue
			}
		}
		depth += braceDelta(trimmed)

		// A case label in a switch body: resolve it, then treat any statement
		// after the colon like any other.
		if sw := jb.innermostSwitch(); sw != nil && (strings.HasPrefix(trimmed, "case ") || strings.HasPrefix(trimmed, "default")) {
			if rest := jb.caseLabel(sw, ll.raw); rest != "" {
				if colon := strings.IndexByte(ll.code, ':'); colon >= 0 {
					csharpStatement(cur, jb, subLine(ll, colon+1), branchTaken)
				}
			}
			leave()
			continue
		}

		if isCSharpStructuralLine(trimmed) || isCSharpStructuralLine(strings.TrimLeft(trimmed, "} \t")) {
			// `using (var r = new StreamReader(path))` declares and opens in
			// the header; `foreach (var x in items)` binds x from items.
			if inner, loop, ok := csharpHeaderStatement(ll); ok {
				// A loop's element is bound only if the loop runs.
				arm := branchTaken
				if loop {
					arm = branchMaybe
				}
				csharpStatement(cur, jb, inner, arm)
			}
			if h, ok := parseJavaHeader(ll); ok {
				st := jb.header(h, depthHere)
				switch {
				case h.rest != "":
					// `if (c) stmt;` / `else stmt;` on one line.
					csharpStatement(cur, jb, subLine(ll, h.restAt), st)
				case !h.opens:
					// `if (c)` with the statement on the next line.
					jb.pending = &st
				}
			}
			leave()
			continue
		}

		arm := branchTaken
		if jb.pending != nil {
			arm = *jb.pending
			jb.pending = nil
		}
		csharpStatement(cur, jb, ll, arm)
		leave()
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// csharpStatement recognizes one statement under the branch model: dropped in
// an arm that cannot run, conditional in one that may not.
func csharpStatement(cur *unitDraft, jb *javaBranches, ll logicalLine, arm branchState) {
	state := combineStates(jb.state(), arm)
	if sw := jb.innermostSwitch(); sw != nil {
		sw.statement(strings.TrimSpace(ll.code))
	}
	if state == branchDead {
		return
	}
	ll = jb.rewriteJavaTernary(ll)
	st, ok := csharpReturnStatement(ll)
	if !ok {
		st, ok = recognizeStatement(langCSharp, ll)
	}
	if !ok {
		return
	}
	st.conditional = state == branchMaybe
	cur.stmts = append(cur.stmts, st)
	jb.learn(ll, st.assigns)
}

// csharpMethodHeader returns the method name and its positional parameter names
// when trimmed is a method (or constructor) declaration header. A header is
// `[modifiers] [ReturnType] Name(params)` optionally followed by `{` (K&R brace
// style) or nothing (Allman style, the `{` on the next line): it contains a
// parenthesized parameter list whose matching `)` is at the very end of the line
// (bar a trailing `{`), and its pre-paren text is a run of ≥2 identifiers
// (modifiers/return type + the method name — a lone identifier before `(` is a
// CALL, not a declaration). Control-flow headers (if/for/while/foreach/switch/
// using/lock/catch) are excluded by keyword. Returns ("", nil, false) otherwise.
func csharpMethodHeader(trimmed string) (name string, params []string, ok bool) {
	// A declaration is not terminated by `;` (that is a statement/abstract decl)
	// and its parameter list's `)` must be the last significant token, optionally
	// followed by `{`.
	if strings.HasSuffix(trimmed, ";") {
		return "", nil, false
	}
	body := strings.TrimSpace(strings.TrimSuffix(trimmed, "{"))
	if !strings.HasSuffix(body, ")") {
		return "", nil, false
	}
	paren := strings.IndexByte(body, '(')
	if paren <= 0 {
		return "", nil, false
	}
	closeParen := matchParen(body, paren)
	if closeParen != len(body)-1 {
		return "", nil, false // the param list must close at end of the header
	}
	// The head is everything before '(': `[modifiers] [ReturnType] Name`. It must
	// be a pure run of identifiers, generics, arrays, and namespace dots — no
	// operator (`=`, `+`, ...) may appear, or the line is an assignment/expression
	// whose RHS happens to be a call (`SqlCommand cmd = new SqlCommand(...)`), not a
	// declaration header.
	head := strings.TrimSpace(body[:paren])
	if !isCSharpHeaderHead(head) {
		return "", nil, false
	}
	tokens := strings.Fields(head)
	// A method declaration always has at least a return type (or modifier) plus a
	// name; a single token before '(' is an ordinary call, not a declaration.
	// (Constructors, which have only a name, still carry an access modifier in
	// practice — `public Foo(...)` — so requiring ≥2 tokens is safe and keeps a
	// bare `Foo(x)` call from being read as a header.)
	if len(tokens) < 2 {
		return "", nil, false
	}
	name = tokens[len(tokens)-1]
	switch name {
	case "if", "for", "while", "foreach", "switch", "using", "lock", "catch",
		"fixed", "do", "return", "new":
		return "", nil, false
	}
	if !isSimpleIdent(name) {
		return "", nil, false
	}
	params = parseCSharpParams(body[paren+1 : closeParen])
	return name, params, true
}

// isCSharpHeaderHead reports whether head (the text before a method header's
// parameter parenthesis) is a pure declaration head: identifiers separated by
// whitespace, possibly carrying generic (`<...>`), array (`[]`), namespace-dot
// (`.`), nullable (`?`), or tuple (`(...)`) type punctuation, but NO expression
// operator. The presence of any operator (`=`, `+`, `-`, `*`, `/`, `%`, `&`,
// `|`, `!`, arithmetic/logical) means the line is an assignment or expression
// whose RHS is a call, not a declaration — the guard that keeps
// `SqlCommand cmd = new SqlCommand(...)` from being misread as a header.
func isCSharpHeaderHead(head string) bool {
	if head == "" {
		return false
	}
	for i := 0; i < len(head); i++ {
		c := head[i]
		switch {
		case isIdentPart(c):
		case c == ' ' || c == '\t':
		case c == '.' || c == '<' || c == '>' || c == '[' || c == ']' ||
			c == ',' || c == '?' || c == '(' || c == ')':
			// Permitted type punctuation (generics, arrays, tuples, nullable).
		default:
			return false
		}
	}
	return true
}

// parseCSharpParams splits a C# parameter list into bare positional parameter
// names in declaration order. Each parameter is `[modifiers] Type name
// [= default]` — e.g. `string id`, `HttpRequest req`, `ref int x`,
// `params object[] args`, `int page = 1`. The name is the last identifier before
// any `=`; the type (with generic/array brackets) and modifiers precede it.
// Best-effort and deterministic; an unparsable slot is skipped rather than
// guessed (a missed parameter only weakens a summary, never fabricates a flow).
func parseCSharpParams(inner string) []string {
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
		// The parameter name is the last top-level whitespace-separated token.
		name := stripCSharpDeclType(p)
		if isSimpleIdent(name) {
			out = append(out, name)
		}
	}
	return out
}

// topLevelAssignIndex returns the index of a single top-level `=` (a default
// value) in a parameter, or -1. Bracket-nested `=` and `==` are ignored.
func topLevelAssignIndex(p string) int {
	depth := 0
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			if depth > 0 {
				depth--
			}
		case '=':
			if depth != 0 {
				continue
			}
			if i+1 < len(p) && p[i+1] == '=' {
				i++
				continue
			}
			if i > 0 {
				// Skip comparison AND compound-assignment operators, matching
				// the canonical splitAssignment. Without the compound set
				// (+ - * / %% & | ^), `x += y` returned the `=` inside `+=` and
				// produced a bogus LHS `x +`.
				switch p[i-1] {
				case '=', '!', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^':
					continue
				}
			}
			return i
		}
	}
	return -1
}

// isCSharpStructuralLine reports whether a line is a block/scaffolding line whose
// tokens must not be read as a data-flow statement: a lone brace, a
// namespace/class/using/attribute line, or a control-flow header. It is
// intentionally coarse — a missed skip only adds a harmless non-sink call to the
// enclosing unit.
func isCSharpStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "};", "});", ")":
		return true
	}
	// Attributes ([Route(...)]) and preprocessor directives.
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "#") {
		return true
	}
	for _, kw := range []string{
		"using ", "using(", "namespace ", "class ", "interface ", "struct ",
		"enum ", "if ", "if(", "else", "for ", "for(", "foreach ", "foreach(",
		"while ", "while(", "switch ", "switch(", "do ", "try", "catch", "finally",
		"lock ", "lock(", "public class", "internal class", "abstract class",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// csharpReturnStatement recognizes a `return <expr>;` line and produces a
// stmtDraft whose `returns` lists the variable names in the returned expression
// while still capturing the calls and reads inside it (so `return File.ReadAllText(id)`
// is both a sink read AND a return). A bare `return;` or `return <constant>;`
// yields a statement with empty returns. Reports ok=false for any non-return line.
func csharpReturnStatement(ll logicalLine) (stmtDraft, bool) {
	trimmed := strings.TrimSpace(ll.code)
	if trimmed != "return" && trimmed != "return;" &&
		!strings.HasPrefix(trimmed, "return ") {
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
	st, ok := recognizeStatement(langCSharp, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}

// csharpHeaderStatement returns the statement a `using (...)` or
// `foreach (... in ...)` header carries, as its own line: the declaration of a
// using, and for a foreach `x = items` (the element holds the collection's
// values). loop reports the foreach form. A header that carries none reports
// ok false.
func csharpHeaderStatement(ll logicalLine) (stmt logicalLine, loop, ok bool) {
	code := ll.code
	lead := len(code) - len(strings.TrimLeft(code, " \t}"))
	rest := code[lead:]
	var kw string
	switch {
	case strings.HasPrefix(rest, "using"):
		kw = "using"
	case strings.HasPrefix(rest, "foreach"):
		kw = "foreach"
	default:
		return logicalLine{}, false, false
	}
	open := strings.IndexByte(code[lead:], '(')
	if open < 0 || strings.TrimSpace(rest[len(kw):open]) != "" {
		return logicalLine{}, false, false
	}
	open += lead
	closing := matchParen(code, open)
	if closing < 0 {
		return logicalLine{}, false, false
	}
	inner := logicalLine{line: ll.line,
		code: blankRange(blankRange(code, 0, open+1), closing, len(code)),
		raw:  blankRange(blankRange(ll.raw, 0, min(open+1, len(ll.raw))), min(closing, len(ll.raw)), len(ll.raw))}
	if kw == "using" {
		if !strings.Contains(inner.code, "=") {
			return logicalLine{}, false, false
		}
		return inner, false, true
	}
	// foreach (T x in items): rewrite to `x = items` in place, keeping the
	// views aligned by blanking the declared type and the `in`.
	in := topLevelKeyword(inner.code, " in ")
	if in < 0 {
		return logicalLine{}, false, false
	}
	decl := strings.Fields(inner.code[:in])
	if len(decl) == 0 {
		return logicalLine{}, false, false
	}
	name := decl[len(decl)-1]
	if !isSimpleIdent(name) {
		return logicalLine{}, false, false
	}
	b := []byte(strings.Repeat(" ", len(inner.code)))
	copy(b[open+1:], name)
	b[in+1] = '='
	copy(b[in+4:], inner.code[in+4:closing])
	return logicalLine{line: ll.line, code: string(b), raw: string(b)}, true, true
}
