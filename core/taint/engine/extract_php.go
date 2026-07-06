package engine

import "strings"

// extractPHP turns PHP logical lines into unit drafts. PHP has clean, lexically
// unambiguous function headers (`function name($a, $b) {`), so — like Python and
// unlike JS — it gets real per-function scoping: each `function` opens its own
// unit keyed by name, and everything at the top level accumulates into the
// module unit (funcName "").
//
// PHP-specific normalization happens per line before the shared recognizer runs
// (see normalizePHPLine): the object-operator `->` becomes `.` so a method call
// `$pdo->query(...)` renders as the dotted chain `pdo.query` the catalog keys on;
// the `$` variable sigil is deleted (uniformly across the code and raw views, so
// they stay byte-aligned) so `$cmd`/`$_GET` become the plain identifiers the
// engine's variable tracking and the catalog's superglobal source keys expect;
// and the `echo`/`print` language constructs (which take an argument without
// parentheses) are rewritten into call form `echo(x)` so they are recognized as
// sinks. Scoping folds nested/anonymous functions into the enclosing unit, which
// is conservative (it can only merge scopes, never split a real flow).
func extractPHP(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	for _, raw := range lines {
		ll := normalizePHPLine(raw)
		code := strings.TrimSpace(ll.code)
		if code == "" || isPHPStructuralLine(code) {
			continue
		}
		if name, params, ok := phpFuncHeader(code); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			// A header line may also carry a body statement after `{` on the same
			// logical line; the recognizer below still runs on the remainder is not
			// attempted here (headers are their own line in practice). Continue.
			continue
		}
		if st, ok := phpReturnStatement(ll); ok {
			promotePHPSuperglobals(&st)
			cur.stmts = append(cur.stmts, st)
			continue
		}
		if st, ok := recognizeStatement(langPHP, ll); ok {
			promotePHPSuperglobals(&st)
			cur.stmts = append(cur.stmts, st)
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// phpSuperglobals is the set of PHP superglobals that are untrusted-input
// sources. A superglobal is read via array subscript (`$_GET['x']`), so after
// normalization it appears as a bare identifier read rather than a dotted chain
// or a call — but the catalog keys sources by these names. promotePHPSuperglobals
// copies any such read into the statement's source-chain list so resolveSource
// (which consults calls and chains, not raw reads) taints the assignee.
var phpSuperglobals = map[string]bool{
	"_GET": true, "_POST": true, "_REQUEST": true, "_COOKIE": true,
	"_SERVER": true, "_FILES": true, "_ENV": true,
}

// promotePHPSuperglobals adds every superglobal read on a statement to its
// chains, so a superglobal array-index source (`$_GET['cmd']`) resolves as a
// catalog source exactly like a source CALL or attribute chain does. Idempotent
// and order-stable.
func promotePHPSuperglobals(st *stmtDraft) {
	for _, r := range st.reads {
		if !phpSuperglobals[r] {
			continue
		}
		already := false
		for _, ch := range st.chains {
			if ch == r {
				already = true
				break
			}
		}
		if !already {
			st.chains = append(st.chains, r)
		}
	}
}

// normalizePHPLine rewrites a logical line's code and raw views into the shape
// the shared recognizer understands: `->` → `.`, the `$` sigil removed, and the
// `echo`/`print` statement constructs turned into call syntax. Both views are
// transformed identically so their byte offsets stay mutually aligned (the
// recognizer slices raw by offsets found in code); the 1-based line number is
// preserved unchanged.
func normalizePHPLine(ll logicalLine) logicalLine {
	return logicalLine{
		line: ll.line,
		code: normalizePHPExpr(ll.code),
		raw:  normalizePHPExpr(ll.raw),
	}
}

// normalizePHPExpr applies the three PHP→shared-recognizer rewrites to one text
// view. The transforms are byte-for-byte identical on the code and raw views so
// applying it to both keeps them aligned.
func normalizePHPExpr(s string) string {
	s = rewriteEchoPrint(s)
	s = strings.ReplaceAll(s, "->", ".")
	s = strings.ReplaceAll(s, "$", "")
	return s
}

// rewriteEchoPrint turns a leading `echo <expr>` / `print <expr>` construct
// (which PHP accepts without parentheses) into call syntax `echo(<expr>)` so the
// recognizer models it as a sink call. It only fires when the construct is not
// already followed by a `(` argument, and leaves an `echo(...)`/`print(...)`
// that already uses parentheses untouched. `printf(...)` is a real function and
// is never a bare construct, so it is unaffected.
func rewriteEchoPrint(s string) string {
	trimmed := strings.TrimLeft(s, " \t")
	indent := s[:len(s)-len(trimmed)]
	for _, kw := range []string{"echo", "print"} {
		if !strings.HasPrefix(trimmed, kw) {
			continue
		}
		rest := trimmed[len(kw):]
		if rest == "" {
			return s
		}
		// The keyword must be a whole word: the next byte is whitespace (a bare
		// construct). `echo(` / `echof` / `printer` are excluded.
		if rest[0] != ' ' && rest[0] != '\t' {
			return s
		}
		arg := strings.TrimSpace(rest)
		if arg == "" {
			return s
		}
		return indent + kw + "(" + arg + ")"
	}
	return s
}

// isPHPStructuralLine reports whether a normalized line is block scaffolding
// whose tokens must not be read as a data-flow statement — a lone brace, a PHP
// open/close tag remnant, or a control-flow header. Coarse by design: a missed
// skip only adds a harmless non-sink identifier to the current unit.
func isPHPStructuralLine(code string) bool {
	switch code {
	case "{", "}", "});", "};", "?>", "<?php", "<?", "<?=":
		return true
	}
	for _, kw := range []string{"if ", "if(", "for ", "for(", "foreach ", "foreach(",
		"while ", "while(", "switch ", "switch(", "class ", "else", "elseif",
		"namespace ", "use ", "try", "catch", "finally", "do "} {
		if strings.HasPrefix(code, kw) {
			return true
		}
	}
	return false
}

// phpFuncHeader returns the function name and its positional parameter names if
// code is a `function name($a, $b)` header (after PHP normalization, the sigils
// are gone, so parameters are plain identifiers). It also handles a
// visibility/modifier prefix on a method (`public function foo(...)`). Returns
// ("", nil, false) for anything else. The parameter list underpins
// interprocedural summaries — a caller's Nth argument binds the callee's Nth
// parameter.
func phpFuncHeader(code string) (name string, params []string, ok bool) {
	rest := code
	// Strip method modifiers so `public function` / `static function` still match.
	for _, mod := range []string{"public ", "private ", "protected ", "static ", "final ", "abstract "} {
		for strings.HasPrefix(rest, mod) {
			rest = strings.TrimSpace(strings.TrimPrefix(rest, mod))
		}
	}
	if !strings.HasPrefix(rest, "function ") && !strings.HasPrefix(rest, "function&") {
		return "", nil, false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(rest, "function"), "&"))
	paren := strings.IndexByte(rest, '(')
	if paren <= 0 {
		return "", nil, false
	}
	name = strings.TrimSpace(rest[:paren])
	if !isSimpleIdent(name) {
		// Anonymous function `function ($x) {` has no name before `(`: fold into the
		// enclosing scope (report not-a-header) so its body statements still count.
		return "", nil, false
	}
	closeParen := matchParen(rest, paren)
	if closeParen < 0 {
		return name, nil, true // continued/malformed header: name only, fail safe
	}
	params = parsePHPParams(rest[paren+1 : closeParen])
	return name, params, true
}

// parsePHPParams splits a PHP parameter list into bare positional parameter
// names in order. After normalization the `$` sigil is gone; this strips type
// hints (`string x`), default values (`x = 1`), reference (`&`) and variadic
// (`...`) markers to the bare name. An unparsable slot is skipped (fail safe: a
// missed parameter only weakens a summary, never fabricates a flow). The names
// are re-prefixed with `$` so they match the `$`-sigil variable names the reads
// carry after normalization strips sigils uniformly — wait, reads are also
// stripped, so params must be BARE too. They are returned bare here; the caller
// keeps them bare to match stripped reads.
func parsePHPParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.TrimLeft(p, "&.") // drop & reference and ... variadic markers
		// A default value: keep the name before `=`.
		if i := strings.IndexByte(p, '='); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		// A type hint precedes the name: `string x` / `?int x` → take the last word.
		if fields := strings.Fields(p); len(fields) > 0 {
			p = fields[len(fields)-1]
		}
		if isSimpleIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

// phpReturnStatement recognizes a `return <expr>;` line and produces a stmtDraft
// whose `returns` lists the variable names in the returned expression, while
// still capturing the calls and reads inside it (so `return $pdo->query($x)` is
// both a sink read AND a return). A bare `return;` yields a statement with empty
// returns. Reports ok=false for any line that is not a return.
func phpReturnStatement(ll logicalLine) (stmtDraft, bool) {
	trimmed := strings.TrimSpace(ll.code)
	if trimmed != "return" && trimmed != "return;" && !strings.HasPrefix(trimmed, "return ") {
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
	st, ok := recognizeStatement(langPHP, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}
