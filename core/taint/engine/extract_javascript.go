package engine

import "strings"

// extractJavaScript turns JS/TS logical lines into unit drafts with PER-FUNCTION
// scoping. JavaScript has no single lexically-clean function-header shape (function
// declarations, function expressions, arrow functions, class/object methods, and
// callback arrows all differ) and its bodies are brace-delimited rather than
// indented, so scoping is done by tracking BRACE DEPTH: a recognized function
// header opens a new unit whose body statements accumulate until the matching
// brace closes, then the enclosing scope resumes.
//
// WHY per-function scoping matters (F5): the previous cut merged ALL statements
// into one module unit. Merging is conservative for a MISSED split (it can only
// join a source and sink across functions — a possible false positive), and the
// concrete failure is a module-level tainted variable leaking into an unrelated
// same-named PARAMETER of another function (`const cmd = req.query` then
// `function f(cmd){ exec(cmd) }` wrongly fired). Real per-function units make each
// parameter local to its own body, so a parameter is only tainted when a caller
// actually passes a tainted argument (via the interprocedural summary pass) — not
// because an unrelated module variable shares its name.
//
// Nested functions and control blocks fold via brace depth: a function defined
// inside another opens its own unit; a non-function block (`if`, `for`, an object
// literal) just moves the depth without opening a unit. Exotic or line-wrapped
// headers a flat recognizer cannot parse degrade to the enclosing scope, which is
// the same conservative merge as before — never a hidden same-function flow.
func extractJavaScript(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}

	// frame tracks an open function body: its unit and the brace depth OUTSIDE the
	// body (the depth to which the running count must return for the body to close).
	type frame struct {
		unit      *unitDraft
		openDepth int
	}
	stack := []frame{{unit: module, openDepth: 0}}
	depth := 0

	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" {
			continue
		}

		params, name, isHeader := jsFunctionHeader(trimmed)

		// Recognize a data-flow statement into the CURRENT (innermost) unit. A
		// function-header line carries no statement we need (its own call, e.g.
		// app.get(...), is not a sink); structural lines carry only scaffolding.
		if !isHeader && !isJSStructuralLine(trimmed) {
			if st, ok := recognizeStatement(langJavaScript, ll); ok {
				stack[len(stack)-1].unit.stmts = append(stack[len(stack)-1].unit.stmts, st)
			}
		}

		openB := strings.Count(ll.code, "{")
		closeB := strings.Count(ll.code, "}")

		// A header opens its body at the CURRENT depth: push its unit before the
		// depth advances, so the body's statements (which arrive while depth exceeds
		// openDepth) land in the new unit.
		if isHeader {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			stack = append(stack, frame{unit: u, openDepth: depth})
		}

		depth += openB - closeB
		if depth < 0 {
			depth = 0
		}
		// Pop every function whose body has closed (depth fell back to its open
		// level). The module frame (openDepth 0, the stack base) is never popped.
		for len(stack) > 1 && depth <= stack[len(stack)-1].openDepth {
			stack = stack[:len(stack)-1]
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// jsFunctionHeader reports whether a trimmed line opens a function body and, if
// so, returns the body's positional parameter names and a best-effort function
// name (empty for an anonymous function/callback). It recognizes the forms that
// open a brace-delimited body: an arrow `(a, b) => {` / `x => {`, a function
// declaration or expression `function name(a) {`, and a class/object method
// `name(a) {`. A non-function block (`if (x) {`, `for (…) {`, an object literal
// `const o = {`) returns ok=false so it never opens a unit — only moves depth.
func jsFunctionHeader(trimmed string) (params []string, name string, ok bool) {
	if !strings.HasSuffix(trimmed, "{") {
		return nil, "", false
	}
	body := strings.TrimSpace(trimmed[:len(trimmed)-1])
	// Arrow function: the parameters are the part before the (rightmost) `=>`.
	if idx := strings.LastIndex(body, "=>"); idx >= 0 {
		return jsArrowParams(strings.TrimSpace(body[:idx])), jsBindingName(body), true
	}
	// `function [name](params)` — declaration or expression.
	if kw := jsFunctionKeyword(body); kw >= 0 {
		rest := strings.TrimSpace(body[kw+len("function"):])
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "*")) // generator
		nm := ""
		if p := strings.IndexByte(rest, '('); p > 0 {
			if cand := strings.TrimSpace(rest[:p]); isSimpleIdent(cand) {
				nm = cand
			}
		}
		if nm == "" {
			nm = jsBindingName(body)
		}
		if open := strings.IndexByte(rest, '('); open >= 0 {
			if closeP := matchParen(rest, open); closeP > open {
				return parseJSParams(rest[open+1 : closeP]), nm, true
			}
		}
		return nil, nm, true
	}
	// Class/object method shorthand `name(params) {` — but never a control block.
	if mp, nm, isMethod := jsMethodParams(body); isMethod {
		return mp, nm, true
	}
	return nil, "", false
}

// jsFunctionKeyword returns the index of the `function` keyword in body when it
// appears as a whole word, or -1. It avoids matching an identifier that merely
// contains the substring (e.g. `myfunction`).
func jsFunctionKeyword(body string) int {
	i := strings.Index(body, "function")
	if i < 0 {
		return -1
	}
	if i > 0 && isIdentPart(body[i-1]) {
		return -1
	}
	after := i + len("function")
	if after < len(body) && isIdentPart(body[after]) {
		return -1
	}
	return i
}

// jsArrowParams extracts the parameter names from the left side of an arrow. The
// left is either a parenthesized list (possibly preceded by a binding/callback
// prefix like `const f = ` or `app.get('/x', `) whose LAST parenthesized group is
// the parameter list, or a single bare identifier (`x =>`).
func jsArrowParams(left string) []string {
	left = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(left), "async"))
	if strings.HasSuffix(left, ")") {
		if open := matchOpenParenFromEnd(left); open >= 0 {
			return parseJSParams(left[open+1 : len(left)-1])
		}
		return nil
	}
	if fields := strings.Fields(left); len(fields) > 0 {
		if last := fields[len(fields)-1]; isSimpleIdent(last) {
			return []string{last}
		}
	}
	return nil
}

// jsMethodParams recognizes a method-shorthand header `name(params)` (with
// optional async/static/get/set/generator modifiers) and returns its params and
// name. It requires a single simple-identifier method name that is not a control
// keyword, so `if (x)`, `for (…)`, `while (…)`, `switch (x)`, `catch (e)` are
// rejected (isSimpleIdent already excludes keywords).
func jsMethodParams(body string) (params []string, name string, ok bool) {
	if !strings.HasSuffix(body, ")") {
		return nil, "", false
	}
	open := matchOpenParenFromEnd(body)
	if open <= 0 {
		return nil, "", false
	}
	name = strings.TrimSpace(body[:open])
	for _, mod := range []string{"async", "static", "get", "set", "public", "private", "*"} {
		name = strings.TrimSpace(strings.TrimPrefix(name, mod))
	}
	if !isSimpleIdent(name) {
		return nil, "", false
	}
	return parseJSParams(body[open+1 : len(body)-1]), name, true
}

// jsBindingName returns the variable a function/arrow is assigned to, so an
// arrow-or-function-expression helper bound to a name (`const run = (c) => {`,
// `handler = function (req) {`) still resolves for the interprocedural pass.
// Returns "" when there is no simple binding target.
func jsBindingName(body string) string {
	eq := jsTopLevelAssign(body)
	if eq < 0 {
		return ""
	}
	left := strings.TrimSpace(body[:eq])
	left = stripDeclKeyword(left)
	if isSimpleIdent(left) {
		return left
	}
	return ""
}

// jsTopLevelAssign returns the index of a single top-level `=` that is a binding
// (not part of `==`, `=>`, `<=`, `>=`, `!=`) and not inside brackets, or -1.
func jsTopLevelAssign(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 {
				continue
			}
			if i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '>') {
				i++
				continue
			}
			if i > 0 {
				switch s[i-1] {
				case '=', '!', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^':
					continue
				}
			}
			return i
		}
	}
	return -1
}

// parseJSParams splits a JS/TS parameter list into bare positional parameter
// names in order, stripping `...rest` markers, default values (`x = 1`), and TS
// type annotations (`x: string`). A destructuring pattern (`{a, b}` / `[a, b]`)
// binds no single tracked name and is skipped (fail safe: a missed parameter only
// weakens a summary, never fabricates a flow).
func parseJSParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.TrimSpace(strings.TrimPrefix(p, "..."))
		if i := strings.IndexAny(p, "=:"); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		if isSimpleIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

// matchOpenParenFromEnd returns the index of the '(' matching the ')' that ends s
// (s must end with ')'), or -1 if unbalanced. It scans right-to-left so a prefix
// before the parameter group (a binding or a callback receiver) is ignored.
func matchOpenParenFromEnd(s string) int {
	depth := 0
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// isJSStructuralLine reports whether a line is block/scaffolding whose header
// identifiers (control keywords, a lone brace) must not be read as a data-flow
// statement. Function headers are handled separately by jsFunctionHeader; this
// keeps a control block or closing brace from being mistaken for a statement.
func isJSStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "})", "});", "};":
		return true
	}
	for _, kw := range []string{"if ", "if(", "for ", "for(",
		"while ", "while(", "switch ", "switch(", "class ", "return ", "else"} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}
