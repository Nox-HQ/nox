package engine

import "strings"

// extractElixir turns Elixir logical lines into unit drafts. Function bodies
// (`def name(...) do` / `defp name(...) do`, and the paren-less `def name do`)
// become their own units keyed by name with their positional parameter list;
// everything else accumulates into the module-level unit (funcName ""). Scoping
// is by `def`/`defp` only — nested defs, `if/case/cond` blocks, and anonymous
// `fn -> end` closures fold into the enclosing unit, which is conservative (it
// can only merge scopes, never split a real flow) and keeps the recognizer
// simple, exactly as the Ruby extractor does.
//
// Elixir-specific shaping happens before recognition:
//   - a leading `:` on an Erlang-module chain (`:os.cmd`, `:erlang.binary_to_term`)
//     is stripped so the chain reads as `os.cmd` / `erlang.binary_to_term` and
//     resolves against the catalog by suffix.
//   - the pipe operator `x |> f(args)` is rewritten to `f(x, args)`, applied to
//     fixpoint so a MULTI-stage chain (`a |> f() |> g()`) nests all the way down
//     to `g(f(a))` — this is how a tainted value flowing through a pipe into a
//     sink is caught, however many hops downstream the sink sits.
//   - paren-less calls (`IO.puts x`, `System.halt 1`) are rewritten to a
//     parenthesized form so the shared call recognizer sees `IO.puts(...)`.
//
// HONEST LIMITS (recall is lower than the function-call-shaped languages, by
// design and documented in testdata/precision-suite-elixir/README.md):
//   - Pattern-matching binds only a SIMPLE-ident LHS (`x = expr`). A destructuring
//     match (`%{"q" => q} = conn.params`, `[h | t] = list`, `{:ok, v} = ...`) does
//     not surface `q`/`v` as a tainted binding — a documented false negative.
//   - `do...end` blocks are not depth-tracked; a def's body runs until the next
//     `def`/`defp` (or EOF), so sibling private helpers still each open a unit but
//     a stray top-level statement between two defs may fold into the earlier unit.
//     This can only MERGE scopes (at worst a false positive on a genuinely
//     unrelated pair), never hide a real same-function flow.
func extractElixir(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	for _, ll := range lines {
		code := ll.code
		trimmed := strings.TrimSpace(code)
		if trimmed == "" {
			continue
		}
		if name, params, ok := elixirDefHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			// A single-line `def f(x), do: expr` form carries its body inline; the
			// body after `, do:` is recognized as the unit's statement.
			if body, has := elixirInlineDoBody(ll); has {
				shaped := shapeElixirLine(body)
				if st, ok := recognizeStatement(langElixir, shaped); ok {
					cur.stmts = append(cur.stmts, st)
				}
			}
			continue
		}
		// `end`, `else`, block openers, etc. carry no dataflow; skip structural
		// lines so a bare `end` is never read as a call to a variable named end.
		if isElixirStructuralLine(trimmed) {
			continue
		}
		shaped := shapeElixirLine(ll)
		if st, ok := recognizeStatement(langElixir, shaped); ok {
			cur.stmts = append(cur.stmts, st)
			// A DESTRUCTURING pattern-match (`%{"q" => q} = conn.params`) binds
			// names the single-assignee model cannot express, so recognizeStatement
			// reports no assignee and the extracted variable never carries the
			// RHS's taint. Emit one additional binding statement per extracted
			// name, carrying the same RHS source evidence.
			for _, name := range elixirDestructuredNames(shaped.code) {
				cur.stmts = append(cur.stmts, stmtDraft{
					line:     st.line,
					assigns:  name,
					calls:    st.calls,
					reads:    st.reads,
					chains:   st.chains,
					sinkArgs: map[string]sinkArgDraft{},
				})
			}
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// elixirDefHeader returns the function name and its positional parameter names
// when trimmed is a `def`/`defp`/`defmacro`/`defmacrop` header. It handles both
// parenthesized (`def f(a, b) do`) and paren-less (`def f do` / `def f, do: e`)
// forms. Parameters are the bare leading identifier of each slot (a pattern in a
// parameter position — `%{} = conn`, `x \\ default` — reduces to its head name).
func elixirDefHeader(trimmed string) (name string, params []string, ok bool) {
	kw := ""
	for _, k := range []string{"defp ", "def ", "defmacrop ", "defmacro "} {
		if strings.HasPrefix(trimmed, k) {
			kw = k
			break
		}
	}
	if kw == "" {
		return "", nil, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(trimmed, kw))
	if paren := strings.IndexByte(rest, '('); paren >= 0 {
		// The name is the token before '(' — but only when '(' comes before any
		// space (a paren-less def with a later '(' in a guard is handled below).
		namePart := strings.TrimSpace(rest[:paren])
		if isSimpleIdent(elixirBareName(namePart)) {
			name = elixirBareName(namePart)
			closeParen := matchParen(rest, paren)
			if closeParen < 0 {
				return name, nil, true
			}
			return name, parseElixirParams(rest[paren+1 : closeParen]), true
		}
	}
	// Paren-less: `def name do` / `def name, do: expr` / `def name`.
	// The name is the leading identifier token.
	end := 0
	for end < len(rest) && isElixirNameByte(rest[end]) {
		end++
	}
	// Allow a trailing `?`/`!` on the function name.
	if end < len(rest) && (rest[end] == '?' || rest[end] == '!') {
		end++
	}
	name = rest[:end]
	if !isSimpleIdent(elixirBareName(name)) && name != "" {
		// A name ending in ?/! is still a valid function; accept the raw token.
		if !elixirValidFuncName(name) {
			return "", nil, false
		}
	}
	if name == "" {
		return "", nil, false
	}
	return name, nil, true
}

// elixirInlineDoBody returns the body expression of a single-line `def f(x), do:
// expr` header, and whether the header had an inline `, do:` clause. The body is
// returned as a logicalLine aligned from the original so raw/code stay in step.
func elixirInlineDoBody(ll logicalLine) (logicalLine, bool) {
	idx := strings.Index(ll.code, ", do:")
	if idx < 0 {
		idx = strings.Index(ll.code, ",do:")
		if idx < 0 {
			return logicalLine{}, false
		}
	}
	// Body starts after the `do:` marker.
	marker := ll.code[idx:]
	doAt := strings.Index(marker, "do:")
	bodyStart := idx + doAt + len("do:")
	if bodyStart >= len(ll.code) {
		return logicalLine{}, false
	}
	bodyCode := ll.code[bodyStart:]
	bodyRaw := bodyCode
	if len(ll.raw) == len(ll.code) {
		bodyRaw = ll.raw[bodyStart:]
	}
	return logicalLine{line: ll.line, code: bodyCode, raw: bodyRaw}, true
}

// elixirBareName strips a leading `:` (an atom-qualified name is not a def name,
// but this defends the header parse) and returns the token unchanged otherwise.
func elixirBareName(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), ":")
}

// elixirValidFuncName reports whether s is a valid Elixir function name (a simple
// identifier optionally ending in `?` or `!`).
func elixirValidFuncName(s string) bool {
	if s == "" {
		return false
	}
	core := s
	if c := s[len(s)-1]; c == '?' || c == '!' {
		core = s[:len(s)-1]
	}
	return isSimpleIdent(core)
}

// parseElixirParams splits an Elixir parameter list into bare positional
// parameter names in order. Each slot is reduced to its leading identifier: a
// default (`x \\ 1`), a type-guard-free pattern (`%{} = conn` → `conn`), and a
// pinned/annotated slot all yield the bare name. A destructuring slot that has no
// simple head name (`%{"q" => q}`, `[h | t]`) is skipped — a documented recall
// limit. Best-effort and deterministic.
func parseElixirParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// A `pattern = name` match binds the RIGHT side to the whole value in
		// Elixir parameter position (`%{} = conn`), so prefer the identifier AFTER a
		// top-level `=`.
		if eq := elixirTopLevelMatch(p); eq >= 0 {
			p = strings.TrimSpace(p[eq+1:])
		}
		// Drop a `\\ default` value.
		if bs := strings.Index(p, "\\\\"); bs >= 0 {
			p = strings.TrimSpace(p[:bs])
		}
		// A pinned var `^x` or an ignored `_x` still has a head name.
		p = strings.TrimLeft(p, "^")
		if isSimpleIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

// elixirTopLevelMatch returns the index of a top-level `=` match operator in p
// (not `==`, `<=`, `>=`, `!=`, `=>`), or -1. Used to find the bound name in a
// `pattern = name` parameter.
func elixirTopLevelMatch(p string) int {
	depth := 0
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 {
				continue
			}
			if i+1 < len(p) && (p[i+1] == '=' || p[i+1] == '>') {
				i++
				continue
			}
			if i > 0 {
				switch p[i-1] {
				case '=', '!', '<', '>':
					continue
				}
			}
			return i
		}
	}
	return -1
}

// isElixirStructuralLine reports whether a trimmed logical line is a block/keyword
// scaffolding line that carries no dataflow statement and whose leading keyword
// must not be mistaken for a call. Coarse on purpose: a missed skip only adds a
// harmless non-sink line to the current unit.
func isElixirStructuralLine(trimmed string) bool {
	switch trimmed {
	case "end", "else", "do", "->", "after", "rescue", "catch":
		return true
	}
	for _, kw := range []string{
		"defmodule ", "defmodule\t", "defprotocol ", "defimpl ", "defstruct ",
		"if ", "unless ", "case ", "cond ", "with ", "for ", "receive ",
		"try ", "quote ", "import ", "alias ", "require ", "use ", "@",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// shapeElixirLine rewrites an Elixir logical line into a form the shared
// call/assign recognizer understands: a leading `:` on an Erlang-module chain is
// stripped, the pipe operator is desugared into an ordinary call, and a
// paren-less call is given synthetic parentheses. Both the code and raw views are
// transformed in lockstep so their byte lengths stay equal where possible (the
// recognizer relies on that alignment for argument counting).
func shapeElixirLine(ll logicalLine) logicalLine {
	code := stripElixirErlangColon(ll.code)
	raw := stripElixirErlangColon(ll.raw)
	code = stripElixirBangCall(code)
	raw = stripElixirBangCall(raw)
	code, raw = desugarElixirPipe(code, raw)
	code, raw = addElixirParenlessCallParens(code, raw)
	return logicalLine{line: ll.line, code: code, raw: raw}
}

// stripElixirBangCall blanks a `!` or `?` that suffixes a CALL name — a `!`/`?`
// that immediately precedes a `(` (or a `(` after intervening spaces) — to a
// space, so the shared call recognizer (which stops an identifier at `!`/`?`)
// sees the bare `File.stream` / `Repo.query` chain and resolves it against the
// catalog. Elixir's bang (`File.read!`) and question (`String.valid?`) methods
// are a naming convention, not a distinct dangerous operation, so the catalog
// keys the base name and both forms resolve to it. Width is preserved (one byte
// becomes one space), so the code and raw views stay aligned. A standalone `!x`
// (boolean not) is untouched because it is not followed by `(` right after the
// operator's operand — only a `name!(` / `name?(` shape is rewritten.
func stripElixirBangCall(s string) string {
	if !strings.ContainsAny(s, "!?") {
		return s
	}
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] != '!' && b[i] != '?' {
			continue
		}
		// The byte before must be an identifier byte (the method name), so a bare
		// `!expr` (not) or a standalone `?c` char is not touched.
		if i == 0 || !isIdentPart(b[i-1]) {
			continue
		}
		// The next non-space byte must be `(` (a call).
		j := i + 1
		for j < len(b) && (b[j] == ' ' || b[j] == '\t') {
			j++
		}
		if j < len(b) && b[j] == '(' {
			b[i] = ' '
		}
	}
	return string(b)
}

// stripElixirErlangColon rewrites an Erlang-module atom chain `:mod.fun` to
// `mod.fun` (blanking the leading `:` to a space so byte offsets are preserved),
// so `:os.cmd(x)` resolves against the catalog `os.cmd` suffix. Only a `:` that
// immediately precedes an identifier AND is itself preceded by a non-identifier
// byte (an operand position) is rewritten — a `key: value` keyword or a `::` type
// operator is left alone. Width is preserved, so both views can be transformed
// independently and stay aligned.
func stripElixirErlangColon(s string) string {
	if !strings.Contains(s, ":") {
		return s
	}
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] != ':' {
			continue
		}
		// Must be followed by an identifier-start byte (an atom name) and a later
		// `.` (a module.function chain) to be an Erlang-module reference.
		if i+1 >= len(b) || !isIdentStart(b[i+1]) {
			continue
		}
		// The `:` must be in an operand position: preceded by start-of-string,
		// whitespace, or a call/operator opener — never by an identifier byte (a
		// trailing `x:` keyword) or another `:` (`::`).
		if i > 0 {
			p := b[i-1]
			if isIdentPart(p) || p == ':' {
				continue
			}
		}
		// Confirm the atom is followed by a `.` before any non-ident/space byte,
		// i.e. it is `mod.fun`, not a bare `:atom`.
		j := i + 1
		for j < len(b) && isIdentPart(b[j]) {
			j++
		}
		if j < len(b) && b[j] == '.' {
			b[i] = ' ' // blank the colon, keeping width
		}
	}
	return string(b)
}

// desugarElixirPipe rewrites a top-level pipe chain `a |> f(args) |> g()` on the
// line into the equivalent nesting `g(f(a, args))`, so the shared recognizer sees
// the piped value as the first positional argument of EVERY stage — including the
// final one, which is where the sink usually is.
//
// One rewrite consumes exactly the leftmost pipe (`a |> f() |> g()` becomes
// `f(a) |> g()`), so the transform is applied to fixpoint: each pass strictly
// removes one `|>`, which both walks the whole chain and guarantees termination.
// Rewriting only the first stage — as this did before — bound the value into the
// head of the chain and lost any sink two or more hops downstream.
//
// Both views are transformed identically so they stay aligned; if a stage cannot
// be rewritten the chain stops there (keeping what was already desugared) so the
// recognizer never sees a mismatched pair.
func desugarElixirPipe(code, raw string) (newCode, newRaw string) {
	// Guard against a pathological line; the loop already terminates on its own
	// because every pass removes one pipe.
	const maxPipeStages = 64
	for range maxPipeStages {
		pipe := elixirTopLevelPipe(code)
		if pipe < 0 {
			break
		}
		lhs := strings.TrimSpace(code[:pipe])
		rhsStart := pipe + 2 // past `|>`
		// The RHS must be a call `callee(args)` or a paren-less callee. Locate the
		// callee head and its argument list.
		rewritten, ok := rewritePipeStage(lhs, code[rhsStart:])
		if !ok {
			break
		}
		// Apply the SAME structural rewrite to the raw view by reconstructing it
		// from the raw halves, so both views carry the piped value identically.
		// Once raw is no longer aligned to code it follows the code rewrite
		// (argument counting then uses the code view, which is safe).
		nextRaw := rewritten
		if len(raw) == len(code) {
			if rr, ok := rewritePipeStage(strings.TrimSpace(raw[:pipe]), raw[rhsStart:]); ok {
				nextRaw = rr
			}
		}
		code, raw = rewritten, nextRaw
	}
	return code, raw
}

// rewritePipeStage rewrites `lhs` piped into the call expression `rhs` as
// `callee(lhs, origArgs)`. rhs is the text to the right of `|>`. A parenthesized
// call `f(a)` becomes `f(lhs, a)` (or `f(lhs)` when it had no args); a paren-less
// callee `f` becomes `f(lhs)`. Returns ok=false when rhs is not a recognizable
// call target.
func rewritePipeStage(lhs, rhs string) (string, bool) {
	rhsTrim := strings.TrimLeft(rhs, " \t")
	pad := rhs[:len(rhs)-len(rhsTrim)]
	head, headEnd := leadingCallHead(rhsTrim)
	if head == "" {
		return "", false
	}
	after := rhsTrim[headEnd:]
	afterTrim := strings.TrimLeft(after, " \t")
	if strings.HasPrefix(afterTrim, "(") {
		// Parenthesized call: insert `lhs, ` (or just `lhs`) as the first argument.
		open := strings.IndexByte(afterTrim, '(')
		closeIdx := matchParen(afterTrim, open)
		if closeIdx < 0 {
			return "", false
		}
		inner := strings.TrimSpace(afterTrim[open+1 : closeIdx])
		var newInner string
		if inner == "" {
			newInner = lhs
		} else {
			newInner = lhs + ", " + inner
		}
		rebuilt := pad + head + "(" + newInner + ")" + afterTrim[closeIdx+1:]
		return rebuilt, true
	}
	// Paren-less callee: `x |> f` → `f(x)`. Any trailing text after the head is
	// treated as additional args (rare; kept for robustness).
	trailing := strings.TrimSpace(after)
	if trailing == "" {
		return pad + head + "(" + lhs + ")", true
	}
	return pad + head + "(" + lhs + ", " + trailing + ")", true
}

// elixirTopLevelPipe returns the index of the first top-level `|>` pipe operator
// in code (not nested inside brackets), or -1. A `|>` inside a string is already
// blanked in the code view, so only real pipes are found.
func elixirTopLevelPipe(code string) int {
	depth := 0
	for i := 0; i+1 < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '|':
			if depth == 0 && code[i+1] == '>' {
				return i
			}
		}
	}
	return -1
}

// addElixirParenlessCallParens detects a leading `Mod.fun args...` (or
// `func args...`) paren-less call and rewrites it to `func(args...)` so the shared
// recognizer sees a call. It only fires when the line is NOT already an
// assignment or a parenthesized call, the head is a bare function / dotted chain,
// and the first argument token can begin an argument. Both views are transformed
// identically to stay aligned.
func addElixirParenlessCallParens(code, raw string) (newCode, newRaw string) {
	if hasTopLevelAssign(code) {
		return code, raw
	}
	head, headEnd := leadingCallHead(code)
	if head == "" {
		return code, raw
	}
	argStart := headEnd
	for argStart < len(code) && (code[argStart] == ' ' || code[argStart] == '\t') {
		argStart++
	}
	if argStart >= len(code) {
		return code, raw // a bare `x` is a variable read, not a call
	}
	if code[argStart] == '(' {
		return code, raw // already a normal call
	}
	// A leading `|>`/operator after the head is not an argument (the pipe was
	// already desugared; a residual operator means this is an expression, not a
	// paren-less call).
	if !canBeginArg(code[argStart]) {
		return code, raw
	}
	end := len(code)
	for end > argStart && (code[end-1] == ' ' || code[end-1] == '\t') {
		end--
	}
	newCode = code[:argStart] + "(" + code[argStart:end] + ")" + code[end:]
	if len(raw) == len(code) {
		newRaw = raw[:argStart] + "(" + raw[argStart:end] + ")" + raw[end:]
		return newCode, newRaw
	}
	return newCode, raw
}

// isElixirNameByte reports whether b can appear inside an Elixir function/
// variable name (letters, digits, underscore).
func isElixirNameByte(b byte) bool {
	return isIdentPart(b)
}

// elixirDestructuredNames returns the variable names bound by a destructuring
// pattern-match on the LHS of `pattern = expr` — the map, tuple and list
// patterns Elixir uses everywhere:
//
//	%{"file" => path} = conn.params      -> [path]
//	%{query: q} = conn                   -> [q]
//	{:ok, body} = fetch()                -> [body]
//	[head | tail] = list                 -> [head tail]
//
// Only a PATTERN LHS yields names; a simple `x = expr` is already handled by the
// ordinary assignment path and returns nothing here, so no binding is doubled.
//
// A name is in binding position when it is neither an atom (`:ok`, preceded by
// `:`) nor a keyword key (`query:`, followed by `:`). Module aliases (an
// upper-case first letter) and the `_` wildcard are skipped: neither is a
// taint-carrying binding. String keys are already blanked in the code view.
func elixirDestructuredNames(code string) []string {
	eq := elixirTopLevelPatternAssign(code)
	if eq < 0 {
		return nil
	}
	lhs := strings.TrimSpace(code[:eq])
	if lhs == "" || isSimpleIdent(lhs) {
		return nil
	}
	switch lhs[0] {
	case '%', '{', '[':
	default:
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for i := 0; i < len(lhs); {
		if !isIdentStart(lhs[i]) {
			i++
			continue
		}
		start := i
		for i < len(lhs) && isIdentPart(lhs[i]) {
			i++
		}
		name := lhs[start:i]
		// A keyword key (`query:`) names a field, not a binding.
		if i < len(lhs) && lhs[i] == ':' {
			continue
		}
		// An atom (`:ok`) is a literal, not a binding.
		if start > 0 && lhs[start-1] == ':' {
			continue
		}
		if name == "_" || isKeyword(name) || (name[0] >= 'A' && name[0] <= 'Z') {
			continue
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// elixirTopLevelPatternAssign returns the index of the top-level `=` match
// operator in code, or -1. It skips `==`/`<=`/`>=`/`!=` comparisons and any `=`
// nested inside brackets (a `%{a => b}` arrow is not a match, and its `>` is
// already excluded by requiring the previous byte not be `=`).
func elixirTopLevelPatternAssign(code string) int {
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
			if i+1 < len(code) && (code[i+1] == '=' || code[i+1] == '>') {
				i++
				continue
			}
			if i > 0 {
				switch code[i-1] {
				case '=', '!', '<', '>', ':', '+', '-', '*', '/':
					continue
				}
			}
			return i
		}
	}
	return -1
}
