package engine

import "strings"

// extractCPP turns C/C++ logical lines into unit drafts using the shared
// line/statement RECOGNIZER (never a real parser — only Go gets go/ast). C and
// C++ are brace-delimited and `;`-terminated like C#, so — like C# — it
// recognizes FUNCTION definitions so each body becomes its own unit with its
// parameter list, feeding the interprocedural summary pass (a caller's Nth
// argument binds the callee's Nth parameter). Everything outside a function
// (globals, the rare file-scope initializer) accumulates into the module unit.
//
// One module covers both C and C++ (.c/.h and .cc/.cpp/.cxx/.hpp/.hh) because
// they share lexing and the dangerous-API surface the catalog `cpp` block
// models. C++ scope-resolution `::` is normalized to `.` (like Rust's) so a call
// like `std::system` / `std::ifstream` matches the catalog's dotted keys.
//
// HONEST LIMITS (why C/C++ line recognition is coarse, mirrored in the corpus
// README): pointers/aliasing, references, and out-parameters are not modeled as
// distinct bindings, so taint can be lost across a `&buf` out-parameter or
// spuriously carried across an alias; macro-expanded sinks are matched only by
// their surface call name; and MEMORY-SAFETY bugs (buffer overflow, UAF, OOB)
// are a DIFFERENT analysis than source→sink taint and are deliberately out of
// scope for this engine (see the suite README).
func extractCPP(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module
	// depth is the block-brace nesting at the CURRENT logical line. A function body
	// opens at the header's `{` (K&R same-line or Allman next-line); when nesting
	// falls back to the header's depth the function scope ends. funcDepth is -1 when
	// not inside a recognized function.
	depth := 0
	funcDepth := -1

	for idx := 0; idx < len(lines); idx++ {
		ll := normalizeCPP(lines[idx])
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" {
			continue
		}

		// A `return ...;` line is a statement, never a definition header — check it
		// first so `return foo(x);` is not misread as a header named `foo`.
		if st, ok := cppReturnStatement(ll); ok {
			cur.stmts = append(cur.stmts, st)
			depth += braceDelta(trimmed)
			if funcDepth >= 0 && depth <= funcDepth {
				cur = module
				funcDepth = -1
			}
			continue
		}

		// A function-DEFINITION header opens a new unit. It must be recognized
		// BEFORE the generic statement recognizer so the header identifiers
		// (function name, parameters) are never read as a data-flow call. A header
		// is a DEFINITION (not a prototype/expression) only when a body brace `{`
		// follows: on the same logical line (K&R) or as the next non-empty logical
		// line (Allman). A bare `int helper(...);` prototype (no following `{`)
		// opens no unit — its `;` was stripped by splitSemicolons, so the following
		// brace is the reliable definition signal.
		if name, params, ok := cppFuncHeader(trimmed); ok && cppHeaderHasBody(trimmed, lines, idx) {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			funcDepth = depth
			depth += braceDelta(trimmed)
			continue
		}

		if !isCPPStructuralLine(trimmed) {
			ll = shapeCPPConstructorDecl(ll)
			if st, ok := recognizeStatement(langCPP, ll); ok {
				applyCPPBufferBuilder(&st)
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

// cppHeaderHasBody reports whether the function-header logical line at lines[idx]
// is a DEFINITION (a body brace follows) rather than a prototype/expression. It
// is a definition when the header line itself contains a `{` (K&R same-line
// brace) or when the next non-empty logical line begins with `{` (Allman
// next-line brace). A prototype `int f(...);` (whose `;` splitSemicolons already
// dropped) is followed by an unrelated statement, so no brace follows and this
// returns false.
func cppHeaderHasBody(trimmed string, lines []logicalLine, idx int) bool {
	if strings.Contains(trimmed, "{") {
		return true
	}
	for j := idx + 1; j < len(lines); j++ {
		next := strings.TrimSpace(lines[j].code)
		if next == "" {
			continue
		}
		return strings.HasPrefix(next, "{")
	}
	return false
}

// normalizeCPP rewrites C++ scope-resolution `::` to `.` in both the code and raw
// views (kept byte-aligned to each other — their common length shrinks together,
// which is all recognizeStatement/argInfo require) so `std::system` reads as the
// dotted call `std.system` the catalog keys on, and a plain C `system(...)` is
// left unchanged. Applied per logical line before recognition.
func normalizeCPP(ll logicalLine) logicalLine {
	code := strings.ReplaceAll(ll.code, "::", ".")
	raw := ll.raw
	if len(raw) == len(ll.code) {
		raw = strings.ReplaceAll(ll.raw, "::", ".")
	}
	return logicalLine{line: ll.line, code: code, raw: raw}
}

// cppFuncHeader returns the function name and its positional parameter names when
// trimmed is a function DEFINITION header: `[qualifiers] RetType Name(params)`
// optionally followed by `{` (K&R) or nothing (Allman, `{` on the next line). A
// header contains a parenthesized parameter list whose matching `)` is the last
// significant token (bar a trailing `{` or a `const`/`noexcept`/`override`
// specifier), and its pre-paren text is a run of ≥2 identifiers (return type +
// name — a lone identifier before `(` is a CALL, not a definition). A `;`
// terminator marks a prototype/expression, not a definition. Control-flow
// headers (if/for/while/switch/catch) are excluded by keyword.
func cppFuncHeader(trimmed string) (name string, params []string, ok bool) {
	// A prototype declaration ends in `;` and has no body — not a definition.
	if strings.HasSuffix(trimmed, ";") {
		return "", nil, false
	}
	body := strings.TrimSpace(strings.TrimSuffix(trimmed, "{"))
	// Trailing C++ specifiers after the parameter `)`: const, noexcept, override,
	// final, and a `-> Ret` trailing return type. Strip them so the `)` we test is
	// the parameter list's.
	body = stripCPPTrailingSpecifiers(body)
	if !strings.HasSuffix(body, ")") {
		return "", nil, false
	}
	// Find the parameter parenthesis: the LAST top-level '(' whose match is at end.
	closeParen := len(body) - 1
	paren := matchParenBackward(body, closeParen)
	if paren <= 0 {
		return "", nil, false
	}
	head := strings.TrimSpace(body[:paren])
	if !isCPPHeaderHead(head) {
		return "", nil, false
	}
	// The name is the last identifier token of the head (after any return type and
	// pointer/reference sigils). A `Class::method` was normalized to `Class.method`
	// upstream; take the final dotted segment as the function name.
	name = cppHeaderName(head)
	if name == "" || isKeyword(name) {
		return "", nil, false
	}
	switch name {
	case "if", "for", "while", "switch", "catch", "return", "sizeof", "do":
		return "", nil, false
	}
	if !isSimpleIdent(name) {
		return "", nil, false
	}
	// Require ≥2 head tokens (return type + name); a single token before '(' is a
	// call, not a definition. Sigils attach to a token, so count whitespace-split
	// fields with sigils stripped.
	if len(strings.Fields(head)) < 2 {
		return "", nil, false
	}
	params = parseCPPParams(body[paren+1 : closeParen])
	return name, params, true
}

// stripCPPTrailingSpecifiers removes trailing member/function specifiers that may
// follow a definition's parameter `)` — `const`, `noexcept`, `override`,
// `final`, `mutable`, a `-> ReturnType` trailing return, and cv/ref qualifiers —
// so the string ends at the parameter list's `)`. Best-effort and deterministic.
func stripCPPTrailingSpecifiers(body string) string {
	for {
		trimmed := strings.TrimSpace(body)
		// Drop a C++11 trailing-return-type `-> T` when it comes AFTER the parameter
		// list (no `)` in the arrow-suffix), so the string ends at the parameter `)`.
		if i := strings.LastIndex(trimmed, "->"); i >= 0 && !strings.Contains(trimmed[i:], ")") {
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		changed := false
		for _, kw := range []string{"const", "noexcept", "override", "final", "mutable", "&", "&&"} {
			if strings.HasSuffix(trimmed, kw) {
				// Ensure it is a whole trailing token, not a suffix of an identifier.
				pre := strings.TrimSpace(strings.TrimSuffix(trimmed, kw))
				if pre == "" || !isCppIdentTail(pre) || kw == "&" || kw == "&&" {
					trimmed = pre
					changed = true
				}
			}
		}
		if !changed {
			return trimmed
		}
		body = trimmed
	}
}

// isCppIdentTail reports whether s ends in an identifier byte (so a stripped
// keyword really abutted a token boundary rather than being part of a name).
func isCppIdentTail(s string) bool {
	if s == "" {
		return false
	}
	c := s[len(s)-1]
	return isIdentPart(c)
}

// isCPPHeaderHead reports whether head (the text before a function header's
// parameter parenthesis) is a pure declaration head: identifiers separated by
// whitespace, carrying pointer/reference sigils (`*`, `&`), namespace/member
// dots (normalized from `::`), template brackets (`<...>`), array brackets, and
// `const`/`unsigned`-style type words, but NO expression operator. An operator
// (`=`, `+`, `-`, `/`, `%`, `|`, `!`, `?`) means the line is an assignment or
// expression whose RHS is a call — the guard that keeps `auto x = foo(y)` from
// being read as a header.
func isCPPHeaderHead(head string) bool {
	if head == "" {
		return false
	}
	for i := 0; i < len(head); i++ {
		c := head[i]
		switch {
		case isIdentPart(c):
		case c == ' ' || c == '\t':
		case c == '*' || c == '&' || c == '.' || c == '<' || c == '>' ||
			c == '[' || c == ']' || c == ',' || c == '~' || c == ':':
			// Permitted type/pointer/template/destructor punctuation.
		default:
			return false
		}
	}
	return true
}

// cppHeaderName returns the function name from a header head — the last
// whitespace-separated token, with leading pointer/reference sigils and a
// `Class.` (normalized `Class::`) qualifier stripped, leaving the bare name.
func cppHeaderName(head string) string {
	fields := strings.Fields(head)
	if len(fields) == 0 {
		return ""
	}
	tok := fields[len(fields)-1]
	tok = strings.TrimLeft(tok, "*&~")
	// A `Class.method` qualifier: take the final dotted segment.
	if i := strings.LastIndexByte(tok, '.'); i >= 0 {
		tok = tok[i+1:]
	}
	return strings.TrimSpace(tok)
}

// parseCPPParams splits a C/C++ parameter list into bare positional parameter
// names in declaration order. Each parameter is `[qualifiers] Type name` — e.g.
// `char *a`, `int b`, `const std::string& s`, `char buf[]`. The name is the last
// identifier token, after the type words and any leading pointer/reference
// sigils. `void` alone yields no parameters. Unnamed prototype-style parameters
// (`int, char*`) are skipped (no binding name to track). Best-effort and
// deterministic; a missed parameter only weakens a summary, never fabricates a
// flow.
func parseCPPParams(inner string) []string {
	inner = strings.TrimSpace(inner)
	if inner == "" || inner == "void" {
		return nil
	}
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Drop a default value (`int page = 1`).
		if eq := topLevelAssignIndex(p); eq >= 0 {
			p = strings.TrimSpace(p[:eq])
		}
		name := cppParamName(p)
		if isSimpleIdent(name) && !isKeyword(name) {
			out = append(out, name)
		}
	}
	return out
}

// cppParamName extracts the binding name from one parameter declaration. It
// takes the last identifier run (after stripping a trailing `[]` array marker and
// any pointer/reference sigils), which is the parameter's name; the type and
// qualifiers precede it. A parameter with no name (a bare type in a prototype)
// yields "" and is skipped by the caller.
func cppParamName(p string) string {
	// Strip a trailing array marker: `char buf[]` / `int a[10]`.
	if i := strings.IndexByte(p, '['); i >= 0 {
		p = strings.TrimSpace(p[:i])
	}
	// The name is the last whitespace-or-sigil-delimited identifier. Walk from the
	// end over identifier bytes.
	end := len(p)
	for end > 0 && !isIdentPart(p[end-1]) {
		end--
	}
	start := end
	for start > 0 && isIdentPart(p[start-1]) {
		start--
	}
	if start >= end {
		return ""
	}
	// If the whole parameter is a single token, it is an unnamed type (`int`), not
	// a name — unless it is the only token AND preceded by a sigil (rare). Treat a
	// lone type keyword as unnamed.
	name := p[start:end]
	// A parameter that is JUST a type word (no separate name) has its "name" equal
	// to the entire trimmed token with no preceding type — reject when it is a
	// known type keyword so `int` / `char` alone are not taken as bindings.
	if start == 0 && isCPPTypeWord(name) {
		return ""
	}
	return name
}

// isCPPTypeWord reports whether tok is a bare built-in type keyword that, when it
// is the ONLY token of a parameter, means the parameter is unnamed (a prototype
// type) rather than a binding name.
func isCPPTypeWord(tok string) bool {
	switch tok {
	case "int", "char", "void", "bool", "float", "double", "long", "short",
		"unsigned", "signed", "size_t", "auto", "wchar_t":
		return true
	}
	return false
}

// stripCPPDeclType reduces a C/C++ assignment LHS to its bare variable name by
// dropping a leading type declaration. A C/C++ local declaration reads
// `<type> name` — e.g. `int n`, `char *user`, `const std::string& s`,
// `auto x`, `std::vector<int> xs`. The variable name is the last identifier
// token; the type (with template/namespace/pointer punctuation) precedes it. A
// single bare token (`name`) is returned unchanged — a plain reassignment.
// Best-effort and deterministic: an unrecognizable LHS falls through to
// isSimpleIdent, which rejects it safely.
func stripCPPDeclType(left string) string {
	left = strings.TrimSpace(left)
	// A single identifier with no space and no sigil is a reassignment.
	depth := 0
	lastBoundary := -1
	for i := 0; i < len(left); i++ {
		switch left[i] {
		case '<', '[', '(':
			depth++
		case '>', ']', ')':
			if depth > 0 {
				depth--
			}
		case ' ', '\t', '*', '&':
			if depth == 0 {
				lastBoundary = i
			}
		}
	}
	if lastBoundary < 0 {
		return left // bare identifier: a plain reassignment
	}
	name := strings.TrimSpace(left[lastBoundary+1:])
	// Guard: if what follows the boundary is empty (LHS ended in a sigil) fall back.
	if name == "" {
		return left
	}
	return name
}

// isCPPStructuralLine reports whether a line is a block/scaffolding line whose
// tokens must not be read as a data-flow statement: a lone brace, a
// namespace/class/struct/using/template line, a preprocessor directive, or a
// control-flow header. Intentionally coarse — a missed skip only adds a harmless
// non-sink call to the enclosing unit.
func isCPPStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "};", "});", ")", "(", "public:", "private:", "protected:":
		return true
	}
	// Preprocessor directives.
	if strings.HasPrefix(trimmed, "#") {
		return true
	}
	for _, kw := range []string{
		"namespace ", "class ", "struct ", "union ", "enum ", "template ",
		"template<", "using ", "typedef ", "if ", "if(", "else", "for ", "for(",
		"while ", "while(", "switch ", "switch(", "do ", "do{", "try", "catch",
		"public:", "private:", "protected:",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// cppReturnStatement recognizes a `return <expr>;` line and produces a stmtDraft
// whose `returns` lists the variable names in the returned expression while still
// capturing the calls and reads inside it (so `return fopen(path);` is both a
// sink read AND a return). A bare `return;` or `return <constant>;` yields a
// statement with empty returns. Reports ok=false for any non-return line.
func cppReturnStatement(ll logicalLine) (stmtDraft, bool) {
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
	st, ok := recognizeStatement(langCPP, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}

// cppBufferBuilders are C string/memory functions that WRITE their first
// argument (a destination buffer) from their later arguments. Idiomatic C builds
// a command/path/query string this way — `strcat(cmd, argv[1])`,
// `sprintf(buf, "%s", user)` — so taint from a source read in a later argument
// must propagate INTO the destination buffer for the canonical
// `system(strcat(cmd, tainted))` shape to be caught. The taint model otherwise
// tracks only `lhs = rhs` assignments, so these out-parameter writers are
// modeled explicitly here (a C/C++-local concern that needs no engine change).
var cppBufferBuilders = map[string]bool{
	"strcat":   true,
	"strncat":  true,
	"strcpy":   true,
	"strncpy":  true,
	"memcpy":   true,
	"memmove":  true,
	"sprintf":  true,
	"vsprintf": true,
	// snprintf/vsnprintf take the buffer as arg0 and the bound as arg1; the
	// tainted value is a later format argument, so the destination still receives
	// taint from those later args. The bound does not sanitize injection (only
	// overflow), so treating snprintf as a builder is sound for injection classes.
	"snprintf":  true,
	"vsnprintf": true,
	"stpcpy":    true,
}

// cppBufferSources are C input functions that WRITE untrusted bytes into a
// caller-provided buffer argument rather than returning the value. `fgets(buf,
// n, stdin)`, `read(fd, buf, n)`, `recv(sock, buf, n, 0)`, `fread(buf, ...)`
// each taint their buffer argument. The map value is the zero-based positional
// index of that destination buffer. These are the buffer-writing counterparts of
// the return-value sources (getenv), modeled here so the buffer becomes tainted.
var cppBufferSources = map[string]int{
	"fgets":    0,
	"gets":     0,
	"gets_s":   0,
	"fread":    0,
	"read":     1,
	"recv":     1,
	"recvfrom": 1,
	"getline":  0,
}

// applyCPPBufferBuilder rewrites a bare-call statement whose callee is a C buffer
// BUILDER (strcat/strcpy/sprintf/snprintf/...) or a buffer-writing SOURCE (fgets/
// read/recv/fread/...) into an assignment to the written buffer, so taint carried
// by a later argument — or introduced by the source — flows into that buffer. The
// taint model otherwise tracks only `lhs = rhs`, so these out-parameter writers
// need explicit modeling (a C/C++-local concern needing no engine change). It
// only fires when the statement is not already an assignment and the destination
// argument is a single bare variable; the statement's calls/reads are preserved
// so source resolution and taint propagation still see the original call.
func applyCPPBufferBuilder(st *stmtDraft) {
	if st.assigns != "" {
		return
	}
	for _, call := range st.calls {
		idx, isSource := cppBufferSources[call]
		if !isSource {
			if !cppBufferBuilders[call] {
				continue
			}
			idx = 0
		}
		info, ok := st.sinkArgs[call]
		if !ok || idx >= len(info.positionalVars) {
			continue
		}
		slot := info.positionalVars[idx]
		if len(slot) != 1 {
			continue // destination is not a single bare variable — do not guess
		}
		dst := slot[0]
		if !isSimpleIdent(dst) {
			continue
		}
		st.assigns = dst
		return
	}
}

// matchParenBackward returns the index of the '(' matching the ')' at closeIdx,
// or -1 if unbalanced. It scans backward tracking bracket depth so the parameter
// list of `RetType Name(a, b)` is located from its closing paren.
func matchParenBackward(s string, closeIdx int) int {
	depth := 0
	for i := closeIdx; i >= 0; i-- {
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

// shapeCPPConstructorDecl rewrites a C++ variable declaration whose initializer
// is a CONSTRUCTOR call — `std::ifstream in(path);` — into the assignment form
// `in = std::ifstream(path)` the shared recognizer already understands.
//
// Without it the recognizer reads `in(path)` as a call to a function named `in`
// (the VARIABLE), so the constructed type never appears as the callee and a sink
// keyed on the type (`ifstream`, opening an attacker-controlled path) never
// fires. The declared variable is also left unbound.
//
// It fires only on the unambiguous shape: exactly two tokens before a balanced
// argument list that ends the statement, no top-level `=`, the second token a
// plain identifier, and the FIRST token recognizably a type — namespace- or
// class-qualified (`std::ifstream`, containing `::` or `.`) or upper-case
// initial (`Foo bar(x)`). Requiring that keeps built-in-typed function
// PROTOTYPES (`int helper(int a);`), which reach this same path, from being
// rewritten into a call to `int`.
func shapeCPPConstructorDecl(ll logicalLine) logicalLine {
	code := strings.TrimSpace(ll.code)
	if code == "" || !strings.HasSuffix(code, ")") {
		return ll
	}
	if splitAssignmentIndexCPP(code) >= 0 {
		return ll
	}
	open := strings.IndexByte(code, '(')
	if open < 0 {
		return ll
	}
	if _, end := balancedArgs(code, open); end != len(code) {
		return ll
	}
	head := strings.Fields(code[:open])
	if len(head) != 2 {
		return ll
	}
	typeTok, name := head[0], head[1]
	// A DECLARED name may legitimately collide with the shared keyword set
	// (`std::ifstream in(path)` — `in` is Python's membership operator), so the
	// name is only required to be a bare identifier. The keyword guard belongs on
	// the TYPE token below, which is what keeps `return foo(bar)` out.
	if !isBareIdent(name) {
		return ll
	}
	qualified := strings.Contains(typeTok, "::") || strings.Contains(typeTok, ".")
	upper := typeTok != "" && typeTok[0] >= 'A' && typeTok[0] <= 'Z'
	if !qualified && !upper {
		return ll
	}
	if isKeyword(strings.SplitN(typeTok, "::", 2)[0]) {
		return ll
	}
	args := code[open:]
	indent := ll.code[:len(ll.code)-len(strings.TrimLeft(ll.code, " \t"))]
	rewritten := indent + name + " = " + typeTok + args
	return logicalLine{line: ll.line, code: rewritten, raw: rewritten}
}

// splitAssignmentIndexCPP returns the index of a top-level `=` assignment in
// code, or -1. Mirrors splitAssignment's operator filtering without building the
// two halves.
func splitAssignmentIndexCPP(code string) int {
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
				case '=', '!', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^':
					continue
				}
			}
			return i
		}
	}
	return -1
}

// isBareIdent reports whether s is a single identifier — like isSimpleIdent but
// WITHOUT the keyword exclusion, for positions where a declared name may shadow
// a keyword from another language in the shared set.
func isBareIdent(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentPart(s[i]) {
			return false
		}
	}
	return true
}
