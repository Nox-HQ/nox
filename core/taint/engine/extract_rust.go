package engine

import "strings"

// extractRust turns Rust logical lines into unit drafts using the shared
// line/statement RECOGNIZER (never a real parser — only Go gets go/ast). Every
// `fn name(...)` opens its own unit keyed by the function name; everything else
// accumulates into the enclosing unit (or the module unit for top-level
// `const`/`static` items). Scoping is by `fn` only — nested closures and `impl`
// blocks fold into the enclosing unit, which is conservative (it can only merge
// scopes, never split a real flow) and keeps the recognizer simple.
//
// HONEST LIMITS (why Rust line recognition is coarser than Python/JS, and why
// the corpus README expects Rust recall to be the lowest):
//   - Ownership & borrows: a value moved/borrowed through `&x`, `x.clone()`, or
//     a closure capture is not modeled as a distinct binding, so taint can be
//     lost across a move or spuriously carried across a borrow.
//   - `Result`/`Option` wrapping and the `?` operator: `let x = f(user)?;`
//     unwraps through machinery the recognizer treats as an opaque call — taint
//     usually survives (the argument read propagates), but the control-flow that
//     `?` implies (early return on Err) is invisible.
//   - Iterator/method chains: `user.split('/').collect()` is recognized only as
//     far as its argument reads; intermediate combinators are not tracked.
//   - Macro sinks: `sqlx::query!(...)`, `format!(...)`, `println!(...)` are
//     macros whose expansion the recognizer cannot follow. We match the macro
//     CALL by name (with or without the trailing `!`, normalized below), but a
//     value that only becomes dangerous inside the macro expansion is missed.
func extractRust(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	for _, ll := range lines {
		code := ll.code
		trimmed := strings.TrimSpace(code)
		if trimmed == "" {
			continue
		}
		if name, params, ok := rustFnHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			// Blank the header text (`fn name(params) -> Ret {`) in both views so it
			// is not itself mis-recognized as a call to `name`, then fall through:
			// when the whole body is on one line (`fn f() { g(x); }`) the trailing
			// body statement after the `{` still needs recognizing. splitSemicolons
			// keeps `;`-separated body statements as their own lines, so the common
			// case leaves nothing after the header and this yields no statement.
			ll = blankRustHeader(ll)
			if strings.TrimSpace(ll.code) == "" {
				continue
			}
		}
		if st, ok := rustReturnStatement(ll); ok {
			cur.stmts = append(cur.stmts, st)
			continue
		}
		if st, ok := recognizeStatement(langRust, normalizeRust(ll)); ok {
			cur.stmts = append(cur.stmts, st)
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// rustFnHeader returns the function name and its positional parameter names if
// trimmed begins a `fn` declaration (optionally prefixed by visibility/async/
// const/unsafe/extern qualifiers and generic parameters). Parameters are the
// bare binding names before each `:` in declaration order; a `&self`/`self`
// receiver is kept (its position still matters for argument mapping). Returns
// ("", nil, false) for anything that is not a function header.
func rustFnHeader(trimmed string) (name string, params []string, ok bool) {
	rest := trimmed
	// Strip leading item qualifiers that may precede `fn` in any order.
	for {
		advanced := false
		for _, kw := range []string{"pub(crate) ", "pub(super) ", "pub ", "async ", "const ", "unsafe ", "extern ", `extern "C" `} {
			if strings.HasPrefix(rest, kw) {
				rest = strings.TrimSpace(strings.TrimPrefix(rest, kw))
				advanced = true
			}
		}
		if !advanced {
			break
		}
	}
	if !strings.HasPrefix(rest, "fn ") {
		return "", nil, false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "fn "))

	// The name runs up to the first '(' or '<' (generic parameter list).
	nameEnd := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] == '(' || rest[i] == '<' {
			nameEnd = i
			break
		}
	}
	name = strings.TrimSpace(rest[:nameEnd])
	if name == "" {
		return "", nil, false
	}

	// Find the parameter parenthesis group, skipping any generic `<...>` block
	// between the name and the '('.
	paren := strings.IndexByte(rest, '(')
	if paren < 0 {
		// Malformed / continued header: name only, no params (fail safe).
		return name, nil, true
	}
	closeParen := matchParen(rest, paren)
	if closeParen < 0 {
		return name, nil, true
	}
	params = parseRustParams(rest[paren+1 : closeParen])
	return name, params, true
}

// blankRustHeader blanks the `fn name(...) -> Ret {` header prefix of a logical
// line up to and including the body-opening `{`, in both views (offsets
// preserved), so the header is not recognized as a call to the function name.
// When no `{` is present (a header continued onto the next physical line, or a
// trait method signature `fn f();`), the whole line is blanked. Body statements
// after the `{` survive so a one-line function body is still analyzed.
func blankRustHeader(ll logicalLine) logicalLine {
	brace := strings.IndexByte(ll.code, '{')
	end := len(ll.code)
	if brace >= 0 {
		end = brace + 1
	}
	code := blankRange(ll.code, 0, end)
	raw := ll.raw
	if end <= len(raw) {
		raw = blankRange(raw, 0, end)
	}
	return logicalLine{line: ll.line, code: code, raw: raw}
}

// parseRustParams splits a Rust parameter list into bare positional binding
// names in order. It handles `self`/`&self`/`&mut self` receivers, strips the
// `: Type` annotation from `name: Type`, and drops mutability markers. Patterns
// too complex to bind to a single name (tuple/struct destructuring) are skipped
// rather than guessed — a missed parameter only weakens a summary, never
// fabricates a flow.
func parseRustParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Receiver forms: self, &self, &mut self, mut self.
		if p == "self" || p == "&self" || p == "&mut self" || p == "mut self" {
			out = append(out, "self")
			continue
		}
		// A parameter is `name: Type`. Take the text before the first top-level ':'.
		name := p
		if i := strings.IndexByte(p, ':'); i >= 0 {
			name = strings.TrimSpace(p[:i])
		}
		name = strings.TrimPrefix(name, "mut ")
		name = strings.TrimSpace(name)
		if isSimpleIdent(name) {
			out = append(out, name)
		}
	}
	return out
}

// rustReturnStatement recognizes an explicit `return <expr>;` line and produces
// a stmtDraft whose `returns` lists the variable names in the returned
// expression, while still capturing the calls and reads inside it (so a
// `return fs::read(x);` is both a sink read AND a return). Trailing-expression
// returns (a final bare expression with no `return` keyword) are NOT modeled
// here — that gap is documented on extractRust; only explicit returns are
// tracked, which is the pragmatic, safe subset. Reports ok=false for non-returns.
func rustReturnStatement(ll logicalLine) (stmtDraft, bool) {
	trimmed := strings.TrimSpace(ll.code)
	if trimmed != "return" && !strings.HasPrefix(trimmed, "return ") &&
		trimmed != "return;" && !strings.HasPrefix(trimmed, "return;") {
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
	st, ok := recognizeStatement(langRust, normalizeRust(inner))
	if !ok {
		// A bare `return;` still needs a statement so the analyzer sees the line.
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}

// normalizeRust rewrites Rust-specific call punctuation so the shared recognizer
// (which understands only `.`-separated call chains, like Python/JS) sees
// ordinary calls. Two rewrites, applied to BOTH the code and raw views so they
// stay byte-aligned to EACH OTHER (their common length shrinks together, which
// is all recognizeStatement/argInfo require — they re-derive offsets from the
// transformed strings, never from the original):
//
//   - Path separator `::` -> `.` : `env::var` -> `env.var`, `Command::new` ->
//     `Command.new`, `sqlx::query` -> `sqlx.query`. The catalog's rust entries
//     are keyed in this normalized dotted form.
//   - Macro bang `name!(` -> `name (` : `sqlx::query!(...)` -> `sqlx.query(...)`,
//     `format!(...)` -> `format(...)`, so a macro invocation reads as a plain
//     call and matches the catalog's macro entries (keyed without the `!`). A
//     logical-not `!x` (not followed by `(`) is left alone.
func normalizeRust(ll logicalLine) logicalLine {
	code := normalizeRustText(ll.code)
	raw := ll.raw
	if len(raw) == len(ll.code) {
		raw = normalizeRustText(ll.raw)
	}
	return logicalLine{line: ll.line, code: code, raw: raw}
}

// normalizeRustText applies the `::`->`.` and `name!(`->`name (` rewrites to one
// view. Order matters: collapse `::` first, then blank a macro bang.
func normalizeRustText(s string) string {
	s = strings.ReplaceAll(s, "::", ".")
	return blankMacroBang(s)
}

// blankMacroBang replaces a `!` that immediately precedes a `(` (a macro
// invocation like `query!(`) with a space, so the identifier and its argument
// parens read as a plain call. Length and offsets are preserved.
func blankMacroBang(s string) string {
	b := []byte(s)
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '!' && b[i+1] == '(' {
			b[i] = ' '
		}
	}
	return string(b)
}
