package engine

import "strings"

// extractScala turns Scala logical lines into unit drafts. Method bodies
// (`def name(params): R = { ... }`) become their own units keyed by name with
// their parameter list, so a source read and a sink call in the same method are
// joined intraprocedurally (and the interprocedural summary pass can bind a
// caller argument to a callee parameter). Everything outside a recognized method
// — object/class field initializers, top-level `val`s — folds into the
// module-level unit (funcName ""), which is conservative: merging scopes can only
// ever join a source and sink into one unit (at worst a false positive), never
// hide a real same-method flow.
//
// Scala is brace-delimited like Java/C#, so it reuses the shared
// logicalLines/splitSemicolons segmentation (braces are block delimiters;
// statements are newline- or `;`-terminated). Two Scala shapes need dedicated
// handling on top of the shared recognizer:
//
//   - a `def` HEADER: `def name[T](a: A, b: B): R = {` opens a braced method
//     scope; `def name(a: A) = expr` (no braces) is a single-expression method
//     whose RHS is recognized as the unit's one (return) statement. Parameters
//     are `name: Type`, so the NAME is the FIRST identifier of each slot (the
//     opposite of Java, where the name trails the type).
//   - the postfix `.!` process operator (`"cmd".!` / `Seq(...).!` /
//     `cmd.!!`): scala.sys.process executes the command. It has no ordinary call
//     syntax the shared recognizer sees, so scalaProcessBang synthesizes a `.!`
//     sink whose tainted arguments are the variables read on the line.
func extractScala(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	// depth is the running brace nesting. methodDepth is the depth at which the
	// current method body lives (-1 when at module scope); when depth falls back
	// to methodDepth the method has closed and scope returns to the module.
	depth := 0
	methodDepth := -1

	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" {
			continue
		}

		// A `def` header opens a new unit. Recognize it before statements so its
		// name/parameters are never read as a data-flow call.
		if name, params, brace, bodyLL, ok := scalaDefHeader(ll); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			if brace {
				// Braced body: track it by depth like Java/C#.
				methodDepth = depth
				depth += braceDelta(trimmed)
			} else {
				// Single-expression body `def f(...) = expr`: recognize the RHS as the
				// unit's one return statement, then fall back to module scope.
				if bodyLL.code != "" && strings.TrimSpace(bodyLL.code) != "" {
					if st, ok := scalaReturnFromExpr(bodyLL); ok {
						addScalaSinks(&st, bodyLL)
						cur.stmts = append(cur.stmts, st)
					}
				}
				cur = module
			}
			continue
		}

		before := depth
		depth += braceDelta(trimmed)
		closesMethod := methodDepth >= 0 && before > methodDepth && depth <= methodDepth

		if isScalaStructuralLine(trimmed) {
			if closesMethod {
				cur = module
				methodDepth = -1
			}
			continue
		}

		if st, ok := scalaReturnStatement(ll); ok {
			addScalaSinks(&st, ll)
			cur.stmts = append(cur.stmts, st)
		} else if st, ok := recognizeStatement(langScala, ll); ok {
			addScalaSinks(&st, ll)
			cur.stmts = append(cur.stmts, st)
		} else if st, ok := scalaSpecialStatement(ll); ok {
			// The shared recognizer saw no assignment/call, but the line may still
			// carry a Scala-only sink (a bare `"cmd".!` process expression).
			cur.stmts = append(cur.stmts, st)
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

// scalaDefHeader recognizes a `def` method-declaration header. It returns the
// method name, its positional parameter names, whether the body opens a brace on
// this line (brace=true) versus a single-expression body (`= expr`), and — for a
// single-expression body — a logicalLine holding just the RHS expression. Returns
// ok=false for any line that is not a `def` header.
//
// Handles `def name(a: A, b: B): R = {`, `def name[T](x: T) = expr`, and a
// paren-less `def name: R = expr`. Generic type params `[T]` on the name are
// skipped. Parameters are the FIRST identifier of each `name: Type` slot.
func scalaDefHeader(ll logicalLine) (name string, params []string, brace bool, body logicalLine, ok bool) {
	trimmed := strings.TrimSpace(ll.code)
	if !strings.HasPrefix(trimmed, "def ") {
		return "", nil, false, logicalLine{}, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "def "))
	// The method name is the leading identifier (possibly an operator name, but we
	// only model the common alphanumeric case). Read up to the first '(', '[',
	// ':', '=', or space.
	nameEnd := 0
	for nameEnd < len(rest) {
		c := rest[nameEnd]
		if c == '(' || c == '[' || c == ':' || c == '=' || c == ' ' || c == '\t' {
			break
		}
		nameEnd++
	}
	name = strings.TrimSpace(rest[:nameEnd])
	if !isSimpleIdent(name) {
		return "", nil, false, logicalLine{}, false
	}
	afterName := rest[nameEnd:]

	// Skip an optional generic type-parameter clause `[T, U]`.
	afterName = strings.TrimLeft(afterName, " \t")
	if strings.HasPrefix(afterName, "[") {
		closeIdx := matchBracket(afterName, 0, '[', ']')
		if closeIdx >= 0 {
			afterName = strings.TrimLeft(afterName[closeIdx+1:], " \t")
		}
	}

	// Parse a parameter list if present.
	if strings.HasPrefix(afterName, "(") {
		closeIdx := matchParen(afterName, 0)
		if closeIdx < 0 {
			return name, nil, headerOpensBrace(trimmed), logicalLine{}, true
		}
		params = parseScalaParams(afterName[1:closeIdx])
	}

	brace = headerOpensBrace(trimmed)
	if brace {
		return name, params, true, logicalLine{}, true
	}
	// Single-expression body: find the top-level `=` and take the RHS as the body.
	body, hasBody := scalaHeaderBody(ll)
	if !hasBody {
		// A header with no `=` and no `{` (an abstract def) carries no body.
		return name, params, false, logicalLine{}, true
	}
	return name, params, false, body, true
}

// headerOpensBrace reports whether a def header line opens a braced body — its
// last significant token is `{` (the K&R `= {` form, or an Allman `{` alone would
// be on the next line and handled as a structural `{`).
func headerOpensBrace(trimmed string) bool {
	return strings.HasSuffix(strings.TrimSpace(trimmed), "{")
}

// scalaHeaderBody returns the RHS-expression logicalLine of a single-expression
// def header (`def f(...) = expr`). It locates the top-level `=` (the one that is
// the def body assignment, not a `==`/`<=` or a default-value `=` inside the
// param parens) and slices both the code and raw views after it, preserving their
// byte alignment. Reports hasBody=false when there is no top-level `=`.
func scalaHeaderBody(ll logicalLine) (body logicalLine, hasBody bool) {
	code := ll.code
	depth := 0
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 {
				continue
			}
			if i+1 < len(code) && code[i+1] == '=' {
				i++
				continue
			}
			if i > 0 {
				switch code[i-1] {
				case '=', '!', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^', ':':
					continue
				}
			}
			// RHS begins just after this `=`.
			rhsStart := i + 1
			exprCode := code[rhsStart:]
			exprRaw := ll.raw
			if len(ll.raw) == len(code) {
				exprRaw = ll.raw[rhsStart:]
			}
			return logicalLine{line: ll.line, code: exprCode, raw: exprRaw}, true
		}
	}
	return logicalLine{}, false
}

// parseScalaParams splits a Scala parameter list into bare positional parameter
// names in declaration order. Each parameter is `[modifiers] name: Type
// [= default]` — e.g. `id: String`, `req: Request`, `implicit ec: Ctx`,
// `xs: Seq[Int]`, `n: Int = 1`. The NAME is the FIRST identifier of the slot
// (before the `:`). Implicit/other leading modifier keywords are stripped.
// Best-effort and deterministic; an unparsable slot is skipped.
func parseScalaParams(inner string) []string {
	parts := splitScalaParamList(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Strip a leading `implicit ` modifier.
		p = strings.TrimPrefix(p, "implicit ")
		p = strings.TrimSpace(p)
		// The name is the text up to the first ':' (the type annotation separator).
		if colon := strings.IndexByte(p, ':'); colon >= 0 {
			p = strings.TrimSpace(p[:colon])
		} else if eq := strings.IndexByte(p, '='); eq >= 0 {
			// No type annotation but a default value — take the name before '='.
			p = strings.TrimSpace(p[:eq])
		}
		if isSimpleIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

// splitScalaParamList splits a Scala parameter list on top-level commas,
// balancing ()/[]/{} and generic angle brackets <...> so a comma inside
// `Map[String, Int]` does not split the slot. (Scala uses `[]` for generics, so
// `[` is already balanced by the bracket cases; `<>` is included for the rare
// bounds case, harmlessly.)
func splitScalaParamList(inner string) []string {
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return nil
	}
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
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

// matchBracket returns the index of the bracket matching the one at open (which
// must be the byte openCh), or -1. Used to skip a generic `[...]` clause.
func matchBracket(s string, open int, openCh, closeCh byte) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case openCh:
			depth++
		case closeCh:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// stripScalaValKeyword removes a leading `val ` / `var ` / `lazy val ` binding
// keyword and any `: Type` annotation from a Scala assignment LHS, leaving the
// bare binding name. `val x = e`, `var x = e`, and `val x: String = e` all yield
// `x`. A non-binding LHS (a plain reassignment `x = e`) is returned with only the
// annotation stripped.
func stripScalaValKeyword(left string) string {
	left = strings.TrimSpace(left)
	left = strings.TrimPrefix(left, "lazy ")
	left = strings.TrimSpace(left)
	for _, kw := range []string{"val ", "var "} {
		if strings.HasPrefix(left, kw) {
			left = strings.TrimSpace(strings.TrimPrefix(left, kw))
			break
		}
	}
	// Drop a `: Type` annotation on the binding (`x: String` -> `x`).
	if i := strings.IndexByte(left, ':'); i >= 0 {
		left = strings.TrimSpace(left[:i])
	}
	return left
}

// isScalaStructuralLine reports whether a line is pure scaffolding whose tokens
// must not be read as a data-flow statement: a lone brace, a package/import, an
// object/class/trait header, or a control keyword. Coarse on purpose — a missed
// skip only adds a harmless non-sink call to the enclosing unit.
func isScalaStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "})", "});", ")", "()":
		return true
	}
	for _, kw := range []string{
		"package ", "import ", "object ", "class ", "trait ", "case class ",
		"case object ", "abstract class ", "sealed ",
		"if ", "if(", "for ", "for(", "for{", "while ", "while(", "else",
		"try", "try ", "try{", "catch ", "catch{", "finally", "match ", "case ",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// scalaReturnStatement recognizes an explicit `return <expr>` line and produces a
// stmtDraft whose `returns` lists the variable names in the returned expression
// while still capturing the calls and reads inside it (so `return exec(x)` is
// both a sink read AND a return). Reports ok=false for any non-return line.
func scalaReturnStatement(ll logicalLine) (stmtDraft, bool) {
	trimmed := strings.TrimSpace(ll.code)
	if trimmed != "return" && !strings.HasPrefix(trimmed, "return ") && !strings.HasPrefix(trimmed, "return(") {
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
	st, ok := recognizeStatement(langScala, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}

// scalaReturnFromExpr treats a bare RHS expression (the body of a single-
// expression `def f(...) = expr`) as an implicit return: the trailing expression
// is Scala's return value. It recognizes the expression's calls/reads and marks
// its reads as the unit's returns, so a `def wrap(c) = "sh -c " + c` return-taint
// summary composes across functions exactly like an explicit `return`.
func scalaReturnFromExpr(ll logicalLine) (stmtDraft, bool) {
	st, ok := recognizeStatement(langScala, ll)
	if !ok {
		return stmtDraft{}, false
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}

// scalaSpecialStatement builds a statement for a line the shared recognizer did
// not model at all but which still carries a Scala-only sink — a bare `"cmd".!`
// process-execution expression with no assignment. Returns ok=false otherwise.
func scalaSpecialStatement(ll logicalLine) (stmtDraft, bool) {
	st := stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}
	addScalaProcessBang(&st, ll)
	if len(st.calls) == 0 {
		return stmtDraft{}, false
	}
	return st, true
}

// addScalaSinks augments an already-recognized statement with Scala-only sink
// shapes the shared call recognizer cannot see: parenless method invocations
// (Scala allows `x.toInt`, `x.mkString`, `x.run` with no argument list) and the
// postfix `.!` / `.!!` process operator.
func addScalaSinks(st *stmtDraft, ll logicalLine) {
	promoteScalaParenlessChains(st)
	addScalaProcessBang(st, ll)
}

// promoteScalaParenlessChains surfaces parenless method calls as calls so the
// catalog's suffix matcher can resolve them. Scala idiom invokes many methods
// without an argument list — `raw.toInt` (a numeric-coercion SANITIZER),
// `path.getName` (a path SANITIZER), `x.readObject` — which the shared call
// recognizer, keyed on a `(`, never records as calls. Every dotted chain the
// recognizer captured (st.chains) that is not already a recognized call is
// promoted to a call; a promoted chain carries a sink-arg whose tainted variable
// is the chain's head receiver, so both sanitizer clearing (over st.calls) and a
// parenless sink resolve. Purely additive and deterministic.
func promoteScalaParenlessChains(st *stmtDraft) {
	existing := map[string]struct{}{}
	for _, c := range st.calls {
		existing[c] = struct{}{}
	}
	for _, chain := range st.chains {
		if _, ok := existing[chain]; ok {
			continue
		}
		if !strings.Contains(chain, ".") {
			continue
		}
		// The receiver is the head identifier of the chain (the value that carries
		// taint into the parenless method, e.g. `raw` in `raw.toInt`).
		head := chain
		if dot := strings.IndexByte(chain, '.'); dot >= 0 {
			head = chain[:dot]
		}
		st.calls = appendUnique(st.calls, chain)
		existing[chain] = struct{}{}
		if st.sinkArgs == nil {
			st.sinkArgs = map[string]sinkArgDraft{}
		}
		// Only synthesize a sink-arg when we have a bare-identifier receiver; a
		// deeper chain head is still recorded as a call (so a sanitizer/sink suffix
		// resolves) but with no positional evidence.
		if isSimpleIdent(head) {
			st.sinkArgs[chain] = sinkArgDraft{
				taintedArgVars:  []string{head},
				argCount:        1,
				firstArgTainted: true,
				positionalVars:  [][]string{{head}},
			}
		}
	}
}

// addScalaProcessBang detects the scala.sys.process postfix bang operator
// (`.!`, `.!!`) in the CODE view and, when present, records a synthetic `.!` sink
// whose tainted arguments are the variables read on the line (a `$var`
// interpolated into a `s"..."` command, or a bare command variable). This models
// command execution via the process DSL, which has no ordinary call syntax.
func addScalaProcessBang(st *stmtDraft, ll logicalLine) {
	if !strings.Contains(ll.code, ".!") {
		return
	}
	// The tainted command variables are the free identifiers read on the line
	// (interpolation `$var` fields are code in the lexctx view; a bare `cmd.!` has
	// `cmd` as a free read). Reuse the statement's already-collected reads when
	// present, else scan the line.
	vars := st.reads
	if len(vars) == 0 {
		vars = freeIdentifiers(langScala, ll.code)
	}
	if len(vars) == 0 {
		return
	}
	if st.sinkArgs == nil {
		st.sinkArgs = map[string]sinkArgDraft{}
	}
	st.calls = appendUnique(st.calls, ".!")
	st.sinkArgs[".!"] = sinkArgDraft{
		taintedArgVars:  append([]string(nil), vars...),
		argCount:        1,
		firstArgTainted: true,
		positionalVars:  [][]string{append([]string(nil), vars...)},
	}
	for _, v := range vars {
		st.reads = appendUnique(st.reads, v)
	}
	sortStrings(st.reads)
}
