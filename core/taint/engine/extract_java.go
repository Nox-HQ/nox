package engine

import "strings"

// extractJava turns Java logical lines into unit drafts. Method bodies become
// their own units keyed by the method name, so a source read and a sink call in
// the same method are joined intraprocedurally (and the interprocedural summary
// pass can bind a caller argument to a callee parameter). Everything outside a
// recognized method — field initializers, static blocks — folds into the
// module-level unit (funcName ""), which is conservative: merging scopes can
// only ever join a source and sink into one unit (at worst a false positive),
// never hide a real same-method flow.
//
// Java is brace-delimited and `;`-terminated like JS, so it reuses the shared
// logicalLines/splitSemicolons segmentation with bracesAreBlocks=true. A method
// HEADER ends in `{` rather than `;`; it is recognized before the statement
// recognizers so `String run(HttpServletRequest req) {` is read as a scope
// opener (name=run, params=[req]) rather than a call to `run`.
//
// Scope tracking is by brace depth: a recognized method header opens a unit that
// stays current until its body's closing brace returns depth to the header's
// level. Nested blocks (if/for/try) inside the body do not open new units — they
// are part of the enclosing method, which is exactly the intraprocedural scope
// we model.
func extractJava(lines []logicalLine) []unitDraft {
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

		// A method header opens a new unit. Recognize it before statements so its
		// name is not mistaken for a call and its parameters become the unit's.
		if name, params, ok := javaMethodHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			methodDepth = depth
			depth += braceDelta(trimmed)
			continue
		}

		before := depth
		depth += braceDelta(trimmed)
		// If this line closes the current method body (depth falls back to the
		// level the header opened at), return to module scope after recognizing any
		// statement content on the line.
		closesMethod := methodDepth >= 0 && before > methodDepth && depth <= methodDepth

		if isJavaStructuralLine(trimmed) {
			if closesMethod {
				cur = module
				methodDepth = -1
			}
			continue
		}

		if st, ok := javaReturnStatement(ll); ok {
			cur.stmts = append(cur.stmts, st)
		} else if st, ok := recognizeStatement(langJava, ll); ok {
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

// braceDelta returns the net change in `{`/`}` nesting for a code segment.
// Literals are already blanked to spaces, so every brace counted is real code.
func braceDelta(code string) int {
	d := 0
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '{':
			d++
		case '}':
			d--
		}
	}
	return d
}

// isJavaStructuralLine reports whether a line is pure scaffolding whose tokens
// must not be read as a data-flow statement: a lone brace, a package/import, a
// class/interface/enum/annotation header, or a control keyword. It is coarse on
// purpose — a missed skip only adds a harmless non-sink call to a unit.
func isJavaStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "};", "});", "}):":
		return true
	}
	// Package/import statements and type declarations carry no dataflow.
	for _, kw := range []string{
		"package ", "import ", "class ", "interface ", "enum ", "@interface ",
		"public class ", "final class ", "abstract class ",
		"if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(",
		"else", "try", "try ", "try(", "catch ", "catch(", "finally", "do ", "do{",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// javaMethodHeader returns the method name and its positional parameter names if
// trimmed is a method declaration header (ends in `{`, has a parameter list, and
// is not a control-flow header). Parameters are the bare identifier names in
// declaration order — the type, generics, annotations, and `final` modifier are
// stripped to the bare name. Returns ("", nil, false) for anything else. The
// parameter list underpins interprocedural summaries: a caller's Nth argument
// binds the callee's Nth parameter.
func javaMethodHeader(trimmed string) (name string, params []string, ok bool) {
	// A method header opens a block.
	if !strings.HasSuffix(trimmed, "{") {
		return "", nil, false
	}
	// Control-flow headers also end in `{` — exclude them (isJavaStructuralLine
	// catches most, but a method could share a prefix, so guard here too).
	for _, kw := range []string{"if", "for", "while", "switch", "catch", "try", "else", "do", "synchronized"} {
		if trimmed == kw || strings.HasPrefix(trimmed, kw+" ") || strings.HasPrefix(trimmed, kw+"(") {
			return "", nil, false
		}
	}
	// Class/interface/enum declarations are not methods.
	if strings.HasPrefix(trimmed, "class ") || strings.Contains(trimmed, " class ") ||
		strings.HasPrefix(trimmed, "interface ") || strings.Contains(trimmed, " interface ") ||
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
	params = parseJavaParams(trimmed[open+1 : closeIdx])
	return name, params, true
}

// lastIdentifier returns the final identifier token of s (the method name that
// precedes the parameter parenthesis), skipping trailing whitespace and any
// generic `>` from a generic return type. Returns "" if none.
func lastIdentifier(s string) string {
	s = strings.TrimSpace(s)
	end := len(s)
	for end > 0 && !isIdentPart(s[end-1]) {
		end--
	}
	start := end
	for start > 0 && isIdentPart(s[start-1]) {
		start--
	}
	if start >= end {
		return ""
	}
	return s[start:end]
}

// parseJavaParams splits a Java parameter list into bare positional parameter
// names in order. Each parameter is `[annotations] [final] Type name`, possibly
// with generics (`Map<String,String> m`), arrays (`String[] a`), or varargs
// (`String... rest`); the declared NAME is the last identifier token of the
// slot. Annotations and generic type arguments are handled by taking the last
// identifier, which is always the parameter name in a well-formed declaration.
// An unparsable slot is skipped (fail safe: a missed parameter only weakens a
// summary, never fabricates a flow).
func parseJavaParams(inner string) []string {
	parts := splitJavaParamList(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		nm := lastIdentifier(p)
		if isSimpleIdent(nm) {
			out = append(out, nm)
		}
	}
	return out
}

// splitJavaParamList splits a Java parameter list on top-level commas, balancing
// not only ()/[]/{} but also generic angle brackets <...>, so a comma inside
// `Map<String, String>` does not split the slot. It is Java-specific (angle
// brackets are not brackets in Python/JS) so it does not touch the shared
// splitTopLevelArgs used by the other languages.
func splitJavaParamList(inner string) []string {
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

// stripJavaDeclType removes a leading Java variable-declaration type and any
// modifiers from an assignment LHS, leaving the bare declared name. Handles
// `String user`, `final int n`, `var x`, `Map<String, String> m`, and
// `String[] parts` — the declared name is the last identifier of the LHS. A
// plain `x` (reassignment, no declaration) is returned unchanged. Returns the
// input unchanged when it is already a simple identifier so a non-declaration
// assignment is unaffected.
func stripJavaDeclType(left string) string {
	left = strings.TrimSpace(left)
	if isSimpleIdent(left) {
		return left // plain reassignment: `x = ...`
	}
	// A declaration has a type token (and possibly modifiers/generics) before the
	// name. The declared name is the trailing identifier.
	nm := lastIdentifier(left)
	if nm == "" {
		return left
	}
	return nm
}

// javaReturnStatement recognizes a `return <expr>;` line and produces a
// stmtDraft whose `returns` lists the variable names in the returned expression,
// while still capturing the calls and reads inside it (so `return exec(x);` is
// both a sink read AND a return). A bare `return;` yields a statement with empty
// returns. Reports ok=false for any line that is not a return.
func javaReturnStatement(ll logicalLine) (stmtDraft, bool) {
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
	st, ok := recognizeStatement(langJava, inner)
	if !ok {
		// A bare `return;` still needs a statement so the analyzer sees the line;
		// it carries no reads and no returns.
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}
