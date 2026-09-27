package engine

import "strings"

// extractPython turns Python logical lines into unit drafts. Function bodies
// (`def name(...):`) become their own units keyed by name; everything else
// accumulates into the module-level unit (funcName ""). Scoping is by `def`
// only — nested defs and classes fold into the enclosing unit, which is
// conservative (it can only ever merge scopes, never split a real flow) and
// keeps the recognizer simple.
func extractPython(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module
	var blocks pyBlocks

	for _, ll := range lines {
		code := ll.code
		trimmed := strings.TrimSpace(code)
		if trimmed == "" {
			continue
		}
		indent := pyIndent(ll.raw)
		blocks.enter(indent)
		if name, params, ok := pyDefHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			blocks.open(indent, false)
			continue
		}
		conditional := blocks.conditional()
		if st, ok := pyReturnStatement(langPython, ll); ok {
			st.conditional = conditional
			cur.stmts = append(cur.stmts, st)
			continue
		}
		if st, ok := recognizeStatement(langPython, ll); ok {
			st.conditional = conditional
			cur.stmts = append(cur.stmts, st)
		}
		if strings.HasSuffix(trimmed, ":") {
			blocks.open(indent, pyConditionalHeader(trimmed))
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// pyDefHeader returns the function name and its positional parameter names if
// trimmed is a def header. `async def` is handled too. Parameters are the
// bare identifier names in declaration order; `self`/`cls` are kept (their
// position still matters for argument mapping) but *args/**kwargs, defaults, and
// type annotations are stripped to the bare name. Returns ("", nil, false) for
// anything else. The parameter list underpins interprocedural summaries — a
// caller's Nth argument binds the callee's Nth parameter.
func pyDefHeader(trimmed string) (name string, params []string, ok bool) {
	rest := trimmed
	if strings.HasPrefix(rest, "async ") {
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "async "))
	}
	if !strings.HasPrefix(rest, "def ") {
		return "", nil, false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "def "))
	paren := strings.IndexByte(rest, '(')
	if paren <= 0 {
		return "", nil, false
	}
	name = strings.TrimSpace(rest[:paren])
	closeParen := matchParen(rest, paren)
	if closeParen < 0 {
		// Malformed / continued header: name only, no params (fail safe).
		return name, nil, true
	}
	params = parsePythonParams(rest[paren+1 : closeParen])
	return name, params, true
}

// parsePythonParams splits a Python parameter list into bare positional
// parameter names in order. It strips default values (`x=1`), type annotations
// (`x: int`), and the `*`/`**` variadic markers, and drops a bare `*` / `/`
// separator. Best-effort and deterministic; an unparsable slot is skipped rather
// than guessed (fail safe: a missed parameter only weakens a summary, never
// fabricates a flow).
func parsePythonParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "*" || p == "/" {
			continue
		}
		p = strings.TrimLeft(p, "*") // *args / **kwargs → args / kwargs
		if i := strings.IndexAny(p, "=:"); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		if isSimpleIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

// matchParen returns the index of the ')' matching the '(' at open, or -1 if
// unbalanced within s. Literals in a def header are rare; this is a plain
// bracket scan over the already code-only header text.
func matchParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// pyReturnStatement recognizes a `return <expr>` line and produces a stmtDraft
// whose `returns` lists the variable names in the returned expression, while
// still capturing the calls and reads inside the expression (so a
// `return os.system(x)` is both a sink read AND a return). A bare `return` (no
// expression) or `return <constant>` yields a statement with empty returns.
// Reports ok=false for any line that is not a return.
func pyReturnStatement(lang langKind, ll logicalLine) (stmtDraft, bool) {
	trimmed := strings.TrimSpace(ll.code)
	if trimmed != "return" && !strings.HasPrefix(trimmed, "return ") {
		return stmtDraft{}, false
	}
	// Build the expression logical line by blanking the leading `return` keyword
	// in both views, preserving offsets so recognizeStatement's alignment holds.
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
	st, ok := recognizeStatement(lang, inner)
	if !ok {
		// A bare `return` still needs a statement so the analyzer sees the line;
		// it carries no reads and no returns.
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	// The returned variables are exactly the free identifiers of the expression
	// (its Reads already collects them). A return never assigns.
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}

// blankRange returns s with bytes [start,end) replaced by spaces, preserving
// length and offsets so aligned code/raw views stay aligned.
func blankRange(s string, start, end int) string {
	if start < 0 || end > len(s) || start >= end {
		return s
	}
	b := []byte(s)
	for i := start; i < end; i++ {
		b[i] = ' '
	}
	return string(b)
}

// pyBlocks tracks the Python blocks enclosing the current line, by indentation,
// so a statement can be marked conditional: inside an if/elif/else, a loop, or
// a try/except branch, it may not run (see taint.Statement.Conditional).
type pyBlocks struct{ stack []pyBlock }

type pyBlock struct {
	indent      int
	conditional bool
}

// enter closes every block the line at indent is not inside.
func (b *pyBlocks) enter(indent int) {
	for len(b.stack) > 0 && b.stack[len(b.stack)-1].indent >= indent {
		b.stack = b.stack[:len(b.stack)-1]
	}
}

// open records a block header at indent; its body is the lines indented
// further.
func (b *pyBlocks) open(indent int, conditional bool) {
	b.stack = append(b.stack, pyBlock{indent: indent, conditional: conditional})
}

// conditional reports whether any enclosing block may skip its body.
func (b *pyBlocks) conditional() bool {
	for _, blk := range b.stack {
		if blk.conditional {
			return true
		}
	}
	return false
}

// pyIndent is the width of a line's leading whitespace. Python requires a file
// to be consistent in how it indents, so comparing widths within one file is
// enough; a tab counts as one, like a space.
func pyIndent(raw string) int {
	return len(raw) - len(strings.TrimLeft(raw, " \t"))
}

// pyConditionalHeader reports whether a block header's body may not run: an
// if/elif/else, a for/while loop (including its else), a try's except/else
// branch, or a match case. `try:` itself, `finally:`, `with`, `def` and
// `class` bodies always run.
func pyConditionalHeader(trimmed string) bool {
	head := strings.TrimPrefix(trimmed, "async ")
	for _, kw := range []string{"if ", "if(", "elif ", "elif(", "else:", "for ", "while ", "while(", "except", "case "} {
		if strings.HasPrefix(head, kw) {
			return true
		}
	}
	return false
}
