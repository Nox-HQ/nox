package engine

import "strings"

// extractRuby turns Ruby logical lines into unit drafts. Method bodies
// (`def name(...)` or paren-less `def name a, b`) become their own units keyed by
// name; everything else accumulates into the module-level unit (funcName "").
// Scoping is by `def` only — nested defs, classes, and blocks fold into the
// enclosing unit, which is conservative (it can only merge scopes, never split a
// real flow) and keeps the recognizer simple, exactly as the Python extractor
// does.
//
// Ruby-specific shaping happens before recognition:
//   - `::` scope-resolution is normalized to `.` so `Net::HTTP.get` reads as the
//     dotted chain `Net.HTTP.get` and resolves against the catalog by suffix.
//   - paren-less calls (`system "cmd"`, `render inline: x`) are rewritten to a
//     parenthesized form so the shared call recognizer sees `system(...)`.
//   - `x = params[:id]` keeps `params` as a free read so the `params` source
//     resolves (the recognizer already surfaces bare identifiers).
func extractRuby(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	for _, ll := range lines {
		code := ll.code
		trimmed := strings.TrimSpace(code)
		if trimmed == "" {
			continue
		}
		if name, params, ok := rubyDefHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			continue
		}
		// `end`, `else`, block openers, etc. carry no dataflow; skip structural
		// lines so a bare `end` is never read as a call to a variable named end.
		if isRubyStructuralLine(trimmed) {
			continue
		}
		shaped := shapeRubyLine(ll)
		if st, ok := rubyReturnStatement(langRuby, shaped); ok {
			augmentRubyStatement(&st, ll, shaped)
			cur.stmts = append(cur.stmts, st)
			continue
		}
		if st, ok := recognizeStatement(langRuby, shaped); ok {
			augmentRubyStatement(&st, ll, shaped)
			cur.stmts = append(cur.stmts, st)
			continue
		}
		// The line was not a plain assignment/call the shared recognizer models,
		// but it may still carry a Ruby-only sink shape (a bare backtick command,
		// a no-arg `.html_safe`). Synthesize a statement for those.
		if st, ok := rubySpecialStatement(ll, shaped); ok {
			cur.stmts = append(cur.stmts, st)
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// rubyDefHeader returns the method name and its positional parameter names when
// trimmed is a `def` header. It handles both parenthesized (`def f(a, b)`) and
// paren-less (`def f a, b` / `def f`) forms, and a `self.`-prefixed class-method
// name (`def self.foo`). Parameters are bare identifier names in declaration
// order; defaults, splats, and keyword markers are stripped to the bare name.
func rubyDefHeader(trimmed string) (name string, params []string, ok bool) {
	if !strings.HasPrefix(trimmed, "def ") {
		return "", nil, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "def "))
	// Strip a `self.` / `Class.` receiver on the method name.
	if dot := strings.LastIndexByte(firstToken(rest), '.'); dot >= 0 {
		// Only strip when the dot is inside the name token (before any '(' or space).
		nameTok := firstToken(rest)
		if dot < len(nameTok) {
			rest = nameTok[dot+1:] + rest[len(nameTok):]
		}
	}
	if paren := strings.IndexByte(rest, '('); paren >= 0 {
		name = strings.TrimSpace(rest[:paren])
		closeParen := matchParen(rest, paren)
		if closeParen < 0 {
			return name, nil, true
		}
		return name, parseRubyParams(rest[paren+1 : closeParen]), true
	}
	// Paren-less: `def name a, b` or `def name`.
	sp := strings.IndexAny(rest, " \t")
	if sp < 0 {
		return strings.TrimSpace(rest), nil, true
	}
	name = strings.TrimSpace(rest[:sp])
	return name, parseRubyParams(rest[sp+1:]), true
}

// firstToken returns the leading run of non-space bytes of s (the method-name
// token, which may contain a `.` for `self.foo`).
func firstToken(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '(' {
			return s[:i]
		}
	}
	return s
}

// parseRubyParams splits a Ruby parameter list into bare positional parameter
// names in order. It strips default values (`x = 1`), type-less keyword markers
// (`x:`), splats (`*args`, `**opts`), and block params (`&blk`), and drops empty
// slots. Best-effort and deterministic; an unparsable slot is skipped.
func parseRubyParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.TrimLeft(p, "*&") // *args / **opts / &blk → bare name
		// A keyword param `name:` or a default `name = v` — take the leading name.
		if i := strings.IndexAny(p, "=:"); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		if isSimpleIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

// isRubyStructuralLine reports whether a trimmed logical line is a block/keyword
// scaffolding line that carries no dataflow statement and whose leading keyword
// must not be mistaken for a call. It is coarse on purpose: a missed skip only
// adds a harmless non-sink line to the current unit.
func isRubyStructuralLine(trimmed string) bool {
	switch trimmed {
	case "end", "else", "begin", "ensure", "rescue", "do", "then", "}":
		return true
	}
	for _, kw := range []string{
		"class ", "module ", "if ", "elsif ", "unless ", "while ", "until ",
		"for ", "case ", "when ", "rescue ", "else ", "begin ", "end ",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// shapeRubyLine rewrites a Ruby logical line into a form the shared call/assign
// recognizer understands: `::` becomes `.`, and a paren-less call is given
// synthetic parentheses. Both the code and raw views are transformed in lockstep
// so their byte lengths stay equal (the recognizer relies on that alignment).
func shapeRubyLine(ll logicalLine) logicalLine {
	code := replaceScopeResolution(ll.code)
	raw := replaceScopeResolution(ll.raw)
	code = subscriptToCall(code)
	raw = subscriptToCall(raw)
	code, raw = addParenlessCallParens(code, raw)
	return logicalLine{line: ll.line, code: code, raw: raw}
}

// subscriptToCall rewrites an identifier subscript `recv[...]` into a call
// `recv(...)` (keeping byte width by swapping `[`→`(` and its matching `]`→`)`),
// so the shared recognizer treats a hash-index source read like `params[:id]`
// as a call to `params` — which the catalog resolves as an HTTP source. It only
// rewrites a `[` that immediately follows an identifier byte (a real subscript),
// never a standalone array literal `[a, b]`. Width is preserved, so both the
// code and raw views can be transformed independently and stay aligned.
func subscriptToCall(s string) string {
	if !strings.ContainsRune(s, '[') {
		return s
	}
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] != '[' {
			continue
		}
		if i == 0 || !isIdentPart(b[i-1]) {
			continue // array literal or index after a `]`/`)` — leave as-is
		}
		// Find the matching ']' and swap the pair for parens in place.
		depth := 0
		for j := i; j < len(b); j++ {
			switch b[j] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					b[i] = '('
					b[j] = ')'
					j = len(b) // break inner loop
				}
			}
		}
	}
	return string(b)
}

// replaceScopeResolution rewrites Ruby's `::` scope-resolution operator to a
// single `.` so a namespaced chain (`Net::HTTP.get`) reads as one dotted chain
// (`Net.HTTP.get`) that the catalog resolves by suffix. Each `::` becomes one
// `.`, shortening the string by one byte per occurrence. That width change is
// safe because shapeRubyLine applies this SAME transform to both the code and
// raw views, so the two stay aligned to EACH OTHER (all the recognizer needs);
// their original alignment to the byte offsets of the source file is not used
// after shaping.
func replaceScopeResolution(s string) string {
	if !strings.Contains(s, "::") {
		return s
	}
	b := []byte(s)
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if i+1 < len(b) && b[i] == ':' && b[i+1] == ':' {
			out = append(out, '.')
			i++ // consume the second ':'
			continue
		}
		out = append(out, b[i])
	}
	return string(out)
}

// addParenlessCallParens detects a leading `ident args...` (or
// `recv.method args...`) paren-less call and rewrites it to `ident(args...)` so
// the shared recognizer sees a call. It only fires when the line is NOT already
// an assignment or a parenthesized call, the head is a bare method identifier /
// dotted chain, and the first argument token starts with something that can
// begin an argument (a quote, an identifier, `:`, a digit, `[`, `%`). Both views
// are transformed identically to stay aligned.
func addParenlessCallParens(code, raw string) (string, string) {
	// If there is already a top-level '(' before any '=', assume it is a normal
	// call — leave it alone.
	if hasTopLevelAssign(code) {
		return code, raw
	}
	head, headEnd := leadingCallHead(code)
	if head == "" {
		return code, raw
	}
	// The bytes after the head, skipping one run of spaces, are the arguments.
	argStart := headEnd
	for argStart < len(code) && (code[argStart] == ' ' || code[argStart] == '\t') {
		argStart++
	}
	if argStart >= len(code) {
		return code, raw // no args — a bare `foo` is a variable read, not a call
	}
	// If the next char is already '(' it is a normal call.
	if code[argStart] == '(' {
		return code, raw
	}
	if !canBeginArg(code[argStart]) {
		return code, raw
	}
	// Rewrite: insert '(' at argStart and ')' at end (trimming trailing space).
	end := len(code)
	for end > argStart && (code[end-1] == ' ' || code[end-1] == '\t') {
		end--
	}
	newCode := code[:argStart] + "(" + code[argStart:end] + ")" + code[end:]
	// Apply the identical transform to raw so both views stay aligned. raw shares
	// the same offsets as code because shapeRubyLine derived both from the same
	// aligned pair.
	if len(raw) == len(code) {
		newRaw := raw[:argStart] + "(" + raw[argStart:end] + ")" + raw[end:]
		return newCode, newRaw
	}
	return newCode, raw
}

// hasTopLevelAssign reports whether code contains a single top-level `=`
// assignment operator (not ==, <=, etc., and not inside brackets).
func hasTopLevelAssign(code string) bool {
	lhs, _ := splitAssignment(langRuby, code)
	return lhs != ""
}

// leadingCallHead returns the leading method-call head of a line (a bare
// identifier or a dotted/`?`/`!`-suffixed method chain like `User.where` or
// `x.html_safe`) and the offset just past it, or ("", 0) if the line does not
// begin with a call head. Keywords are rejected so `return x` is not read as a
// call to `return`.
func leadingCallHead(code string) (string, int) {
	i := 0
	n := len(code)
	for i < n && (code[i] == ' ' || code[i] == '\t') {
		i++
	}
	start := i
	for i < n && (isIdentPart(code[i]) || code[i] == '.') {
		i++
	}
	// Allow a trailing ? or ! on a Ruby method name (predicate/bang methods).
	if i < n && (code[i] == '?' || code[i] == '!') {
		i++
	}
	head := code[start:i]
	if head == "" || strings.HasPrefix(head, ".") {
		return "", 0
	}
	// Reject keywords used as statement heads.
	firstSeg := head
	if dot := strings.IndexByte(head, '.'); dot >= 0 {
		firstSeg = head[:dot]
	}
	if isKeyword(firstSeg) {
		return "", 0
	}
	return head, i
}

// canBeginArg reports whether b can start a paren-less call argument: a string
// quote, an identifier, a symbol `:`, a digit, an array `[`, a percent-literal
// `%`, or a leading `-`/`+` (a signed number) / `@` (ivar).
func canBeginArg(b byte) bool {
	if isIdentStart(b) {
		return true
	}
	switch b {
	case '"', '\'', '`', ':', '[', '%', '@', '-', '+', '#':
		// `#` covers a code view whose first argument byte is a string's
		// `#{...}` interpolation field (the literal text around it is blanked to
		// spaces, so the interpolated expression is what leads the argument).
		return true
	}
	return b >= '0' && b <= '9'
}

// rubyNoArgSinkMethods are Ruby sink methods commonly invoked WITHOUT
// parentheses and with no arguments — the receiver itself is the tainted value
// (`user_input.html_safe`, `content.raw`). The shared call recognizer needs a
// `(` to see a call, so these are recognized specially: the receiver becomes the
// sink's tainted argument.
var rubyNoArgSinkMethods = map[string]bool{
	"html_safe": true,
	"raw":       true,
}

// augmentRubyStatement adds Ruby-only sink shapes to an already-recognized
// statement: a backtick / %x command literal (a command-injection sink whose
// callee has no identifier form), and a no-argument `.html_safe` / `.raw` XSS
// sink. Both read the interpolated / receiver variable(s) already present in the
// statement's reads, so taint propagation is unchanged — only the sink call and
// its argument shape are added.
func augmentRubyStatement(st *stmtDraft, orig, shaped logicalLine) {
	addRubyCommandLiteral(st, orig, shaped)
	addRubyNoArgSink(st, shaped)
}

// addRubyCommandLiteral detects a backtick “ `...` “ or `%x(...)` command
// literal in the ORIGINAL raw line and, when present, records a synthetic sink
// call keyed "`" whose tainted arguments are the variables interpolated into the
// command (the `#{var}` fields, which lexctx marked as code and the shaped code
// view preserves). This models command execution via a command literal, which
// has no ordinary call syntax.
func addRubyCommandLiteral(st *stmtDraft, orig, shaped logicalLine) {
	if !strings.Contains(orig.raw, "`") && !strings.Contains(orig.raw, "%x") {
		return
	}
	// The interpolated variables live in the shaped CODE view (the literal text is
	// blanked; only `#{...}` expressions remain as code). Collect them as the
	// command's tainted arguments.
	vars := freeIdentifiers(langRuby, shaped.code)
	if len(vars) == 0 {
		return
	}
	if st.sinkArgs == nil {
		st.sinkArgs = map[string]sinkArgDraft{}
	}
	st.calls = append(st.calls, "`")
	st.sinkArgs["`"] = sinkArgDraft{
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

// addRubyNoArgSink detects a trailing no-argument sink method (`.html_safe`,
// `.raw`) on the statement's RHS and records it as a sink whose tainted argument
// is the receiver variable, e.g. `out = name.html_safe` → sink `html_safe`
// reading `name`.
func addRubyNoArgSink(st *stmtDraft, shaped logicalLine) {
	code := shaped.code
	for method := range rubyNoArgSinkMethods {
		recv, ok := trailingNoArgMethodReceiver(code, method)
		if !ok {
			continue
		}
		if st.sinkArgs == nil {
			st.sinkArgs = map[string]sinkArgDraft{}
		}
		st.calls = append(st.calls, method)
		st.sinkArgs[method] = sinkArgDraft{
			taintedArgVars:  []string{recv},
			argCount:        1,
			firstArgTainted: true,
			positionalVars:  [][]string{{recv}},
		}
		st.reads = appendUnique(st.reads, recv)
		sortStrings(st.reads)
	}
}

// trailingNoArgMethodReceiver reports whether code contains `recv.method` (with
// method NOT followed by a `(`), returning the bare receiver identifier. Only a
// simple `ident.method` receiver is recognized (a dotted receiver chain is
// reduced to its head identifier, which is the variable that carries taint).
func trailingNoArgMethodReceiver(code, method string) (string, bool) {
	needle := "." + method
	idx := strings.Index(code, needle)
	if idx < 0 {
		return "", false
	}
	// Reject a call form `recv.method(` — that is handled by the shared recognizer.
	after := idx + len(needle)
	if after < len(code) && (code[after] == '(' || isIdentPart(code[after])) {
		return "", false
	}
	// Walk backwards from the '.' to read the receiver identifier (its last
	// segment if it is a dotted chain).
	j := idx
	for j > 0 && (isIdentPart(code[j-1])) {
		j--
	}
	recv := code[j:idx]
	if recv == "" || !isSimpleIdent(recv) {
		return "", false
	}
	return recv, true
}

// rubySpecialStatement builds a statement for a line the shared recognizer did
// not model at all but which still carries a Ruby-only sink — a bare backtick
// command with no assignment (`\`rm -rf #{path}\“) or a bare `x.html_safe`
// expression statement. Returns ok=false when the line has no such shape.
func rubySpecialStatement(orig, shaped logicalLine) (stmtDraft, bool) {
	st := stmtDraft{line: orig.line, sinkArgs: map[string]sinkArgDraft{}}
	addRubyCommandLiteral(&st, orig, shaped)
	addRubyNoArgSink(&st, shaped)
	if len(st.calls) == 0 {
		return stmtDraft{}, false
	}
	return st, true
}

// rubyReturnStatement recognizes a `return <expr>` line and produces a stmtDraft
// whose returns lists the variable names in the returned expression, while still
// capturing the calls and reads inside it. It mirrors pyReturnStatement.
func rubyReturnStatement(lang langKind, ll logicalLine) (stmtDraft, bool) {
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
	inner := logicalLine{line: ll.line, code: exprCode, raw: exprRaw}
	st, ok := recognizeStatement(lang, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}
