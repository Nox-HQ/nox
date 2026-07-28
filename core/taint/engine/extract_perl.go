package engine

import "strings"

// extractPerl turns Perl logical lines into unit drafts. Named subroutines
// (`sub name { ... }`) become their own units keyed by name; everything else
// accumulates into the module-level unit (funcName ""). Scoping is by `sub` only
// — nested/anonymous subs fold into the enclosing unit, which is conservative (it
// can only merge scopes, never split a real flow), exactly like the PHP/Python
// extractors.
//
// Perl is the hardest mainstream language to recognize without a full
// interpreter, so this is deliberately PRAGMATIC: it covers the common
// straight-line injection idioms and accepts moderate recall. Perl-specific
// normalization happens per line before the shared recognizer runs
// (see normalizePerlLine): the method-arrow `->` becomes `.` so `$dbh->do(...)`
// renders as the dotted chain `dbh.do` the catalog keys on; the `$`/`@`/`%`
// variable sigils are deleted (uniformly across code and raw views so they stay
// byte-aligned) so `$cmd`/`$ENV`/`@ARGV` become the plain identifiers the
// engine's variable tracking and the catalog's source keys expect; `my`/`our`/
// `local` binding keywords are stripped from an assignment LHS; and a paren-less
// call construct (`system "cmd"`, `print $x`) is given synthetic parentheses so
// the shared recognizer sees a call. Backtick / qx command literals are modeled
// as command-injection sinks the same way Ruby does.
func extractPerl(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module
	// Package globals declared with `our`. Only these join across subs; a `my`
	// lexical never does.
	shared := map[string]bool{}

	for _, raw := range lines {
		ll := normalizePerlLine(raw)
		code := strings.TrimSpace(ll.code)
		for _, n := range perlOurNames(code) {
			shared[n] = true
		}
		if code == "" || isPerlStructuralLine(code) {
			continue
		}
		if name, params, ok := perlSubHeader(code); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			continue
		}
		if st, ok := perlReturnStatement(ll); ok {
			promotePerlSources(&st)
			cur.stmts = append(cur.stmts, st)
			continue
		}
		if st, ok := recognizeStatement(langPerl, ll); ok {
			augmentPerlStatement(&st, raw, ll)
			promotePerlSources(&st)
			cur.stmts = append(cur.stmts, st)
			continue
		}
		// The line was not a plain assignment/call the shared recognizer models,
		// but it may still carry a Perl-only sink shape (a bare backtick command).
		if st, ok := perlSpecialStatement(raw, ll); ok {
			cur.stmts = append(cur.stmts, st)
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return joinSharedState(out, shared)
}

// perlSources is the set of Perl source names that appear as BARE READS after
// sigil normalization rather than as call chains or dotted attributes — the
// superglobal-array reads `$ENV{X}` → `ENV`, `@ARGV`/`$ARGV[0]` → `ARGV`, and the
// filehandle read `<STDIN>` → `STDIN`. The catalog keys sources by these names,
// but resolveSource consults calls and chains (not raw reads), so
// promotePerlSources copies any such read into the statement's chains — exactly
// as promotePHPSuperglobals does for PHP superglobals.
var perlSources = map[string]bool{
	"ENV":   true,
	"ARGV":  true,
	"STDIN": true,
}

// promotePerlSources adds every Perl bare-read source on a statement to its
// chains, so an array/hash-index or filehandle source (`$ENV{cmd}`, `$ARGV[0]`,
// `<STDIN>`) resolves as a catalog source exactly like a source CALL or attribute
// chain does. Idempotent and order-stable.
func promotePerlSources(st *stmtDraft) {
	for _, r := range st.reads {
		if !perlSources[r] {
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

// normalizePerlLine rewrites a logical line's code and raw views into the shape
// the shared recognizer understands: `->` → `.`, sigils removed, and a paren-less
// call construct given synthetic parentheses. Both views are transformed
// identically so their byte offsets stay mutually aligned (the recognizer slices
// raw by offsets found in code); the 1-based line number is preserved.
func normalizePerlLine(ll logicalLine) logicalLine {
	code := normalizePerlExpr(ll.code)
	raw := normalizePerlExpr(ll.raw)
	code, raw = addParenlessCallParens(code, raw)
	return logicalLine{line: ll.line, code: code, raw: raw}
}

// normalizePerlExpr applies the sigil/arrow rewrites to one text view. `->`
// becomes a single `.` so the dotted chain reads as `recv.method`; the
// `$`/`@`/`%` sigils become a space so the following identifier stands alone.
// The `->`→`.` rewrite shortens the string by one byte per occurrence, which is
// safe because normalizePerlLine applies this SAME transform to both the code and
// raw views — they stay aligned to EACH OTHER (all the recognizer needs); their
// original alignment to the source file's byte offsets is not used after shaping.
func normalizePerlExpr(s string) string {
	b := []byte(s)
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		// `->` method/deref operator becomes a single `.` so the dotted chain reads
		// as `recv.method`.
		if b[i] == '-' && i+1 < len(b) && b[i+1] == '>' {
			out = append(out, '.')
			i++
			continue
		}
		// A `%` that is the modulo operator (surrounded by operands) must stay, but
		// a leading `%hash` sigil should be dropped. We drop a `%`/`@`/`$` only when
		// it is in SIGIL position: immediately before an identifier byte or a `{`
		// (for `${...}`) or `#` (for `$#arr`). Otherwise it is an operator and stays.
		if (b[i] == '$' || b[i] == '@' || b[i] == '%') && i+1 < len(b) && isPerlSigilNameStart(b[i+1]) {
			out = append(out, ' ')
			continue
		}
		out = append(out, b[i])
	}
	return string(out)
}

// isPerlSigilNameStart reports whether b can follow a sigil to form a variable
// name: an identifier start, a `{` (block deref `${...}`), or `#` ($#array). A
// digit is included so `$1`/`$ARGV`-adjacent forms still strip the sigil.
func isPerlSigilNameStart(b byte) bool {
	return b == '_' || b == '{' || b == '#' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// isPerlStructuralLine reports whether a normalized line is block scaffolding
// whose tokens must not be read as a data-flow statement — a lone brace, a
// pragma/use line, a package declaration, or a control-flow header. Coarse by
// design: a missed skip only adds a harmless non-sink identifier to a unit.
func isPerlStructuralLine(code string) bool {
	switch code {
	case "{", "}", "};", "});", "1;", "":
		return true
	}
	for _, kw := range []string{
		"use ", "no ", "package ", "require ", "if ", "if(", "elsif ", "elsif(",
		"unless ", "unless(", "while ", "while(", "until ", "until(", "for ",
		"for(", "foreach ", "foreach(", "else", "BEGIN", "END",
	} {
		if strings.HasPrefix(code, kw) {
			return true
		}
	}
	return false
}

// perlSubHeader returns the subroutine name and (best-effort) its parameter
// names when code is a `sub name { ... }` header. Perl subs receive arguments
// via `@_` rather than a named parameter list, so the header itself carries no
// parameters; we return an empty parameter list (the interprocedural summary
// pass still records the sub as a known local callee). A prototype/signature in
// parentheses (`sub f($a, $b)`, an experimental feature) is parsed when present.
// Returns ("", nil, false) for anything that is not a sub header.
func perlSubHeader(code string) (name string, params []string, ok bool) {
	if !strings.HasPrefix(code, "sub ") {
		return "", nil, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(code, "sub "))
	if rest == "" {
		return "", nil, false
	}
	// The name is the leading identifier token, up to a space, '(' or '{'.
	end := 0
	for end < len(rest) && (isIdentPart(rest[end]) || rest[end] == ':') {
		end++
	}
	name = strings.TrimSpace(rest[:end])
	if name == "" || !isSimpleIdent(strings.TrimRight(name, ":")) {
		// An anonymous sub (`sub { ... }`) has no name: fold into the enclosing
		// scope (report not-a-header) so its body statements still count.
		return "", nil, false
	}
	// Optional signature `($a, $b)` — sigils already stripped by normalization, so
	// the inner names are bare identifiers.
	after := strings.TrimSpace(rest[end:])
	if strings.HasPrefix(after, "(") {
		if closeIdx := matchParen(after, 0); closeIdx > 0 {
			params = parsePerlParams(after[1:closeIdx])
		}
	}
	return name, params, true
}

// parsePerlParams splits a Perl sub signature into bare positional parameter
// names. Sigils are already stripped by normalization; this drops empty slots
// and default values. Best-effort and deterministic.
func parsePerlParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if i := strings.IndexByte(p, '='); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		if isSimpleIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

// perlReturnStatement recognizes a `return <expr>;` line and produces a stmtDraft
// whose returns lists the variable names in the returned expression, while still
// capturing the calls and reads inside it. It mirrors pyReturnStatement /
// phpReturnStatement.
func perlReturnStatement(ll logicalLine) (stmtDraft, bool) {
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
	st, ok := recognizeStatement(langPerl, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}

// augmentPerlStatement adds Perl-only sink shapes to an already-recognized
// statement: a backtick “ `...` “ or `qx(...)` command literal, whose interpolated
// variables are the command-injection sink's tainted arguments. It reads the
// original (un-normalized) raw line to detect the literal and the normalized code
// view to collect the interpolated variables.
func augmentPerlStatement(st *stmtDraft, orig, shaped logicalLine) {
	addPerlCommandLiteral(st, orig, shaped)
}

// addPerlCommandLiteral detects a backtick “ `...` “ or `qx(...)` command literal
// in the ORIGINAL raw line and, when present, records a synthetic sink call keyed
// "`" whose tainted arguments are the variables interpolated into the command
// (the `$var` fields, which lexctx marked as code and the normalized code view
// preserves as bare identifiers). This models command execution via a command
// literal, which has no ordinary call syntax.
func addPerlCommandLiteral(st *stmtDraft, orig, shaped logicalLine) {
	if !strings.Contains(orig.raw, "`") && !strings.Contains(orig.raw, "qx") {
		return
	}
	vars := freeIdentifiers(langPerl, shaped.code)
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

// perlSpecialStatement builds a statement for a line the shared recognizer did
// not model at all but which still carries a Perl-only sink — a bare backtick
// command with no assignment (`\`rm -rf $path\“). Returns ok=false when the line
// has no such shape.
func perlSpecialStatement(orig, shaped logicalLine) (stmtDraft, bool) {
	st := stmtDraft{line: orig.line, sinkArgs: map[string]sinkArgDraft{}}
	addPerlCommandLiteral(&st, orig, shaped)
	if len(st.calls) == 0 {
		return stmtDraft{}, false
	}
	return st, true
}

// perlOurNames returns the package-global names declared by an `our` statement:
// `our $PAYLOAD;` -> [PAYLOAD], `our ($A, $B);` -> [A B]. The `$`/`@`/`%` sigil
// is already normalized away on the code view, so names are matched bare.
func perlOurNames(code string) []string {
	t := strings.TrimLeft(code, " \t")
	if !strings.HasPrefix(t, "our ") && !strings.HasPrefix(t, "our\t") {
		return nil
	}
	rest := t[3:]
	var out []string
	i := 0
	for i < len(rest) {
		if !isIdentStart(rest[i]) {
			i++
			continue
		}
		start := i
		for i < len(rest) && isIdentPart(rest[i]) {
			i++
		}
		name := rest[start:i]
		if !isKeyword(name) {
			out = appendUnique(out, name)
		}
	}
	return out
}
