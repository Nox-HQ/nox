package engine

import (
	"regexp"
	"strings"
)

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
	norm := make([]logicalLine, len(lines))
	for i := range lines {
		norm[i] = normalizePHPLine(lines[i])
	}
	// Branch model: the Java one (java_branches.go), which reads C-family
	// headers -- if / else if / elseif / else, loops, switch and case -- on
	// the normalized lines. Before it, a statement in an if arm was a strong
	// update, so `if (ok($x)) { $x = $x; } else { $x = ""; }` wiped the taint
	// the other arm keeps: measured on the NIST SARD PHP suite, that one shape
	// hid most of its SQL injection and XSS cases.
	jb := newJavaBranches(norm)
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module
	depth := 0

	for li, ll := range norm {
		orig := lines[li]
		code := strings.TrimSpace(ll.code)
		if code == "" {
			continue
		}
		before := depth
		depth += braceDelta(code)
		depthHere := before - (len(code) - len(strings.TrimLeft(code, "}")))
		jb.enter(depthHere)

		if name, params, ok := phpFuncHeader(code); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			// F4: a header line may carry the body on the SAME line with the brace on
			// the header — `function run($c){ system($c); }`. The multi-line form
			// (brace-on-header, body on following lines) is handled by the ordinary
			// loop, but a same-line body was previously discarded (stmts=0). Recognize
			// those inline statements into the new unit; if the body is complete on the
			// line (a matching close brace), the function ends here, so reset the
			// current scope to the module for the statements that follow.
			body, complete := phpInlineBody(ll)
			for i := range body {
				phpRecognizeInto(u, body[i])
			}
			if complete {
				cur = module
			}
			continue
		}

		// A case label in a switch body: resolve it, then treat any statement
		// after the colon like any other.
		if sw := jb.innermostSwitch(); sw != nil && (strings.HasPrefix(code, "case ") || strings.HasPrefix(code, "default")) {
			if rest := jb.caseLabel(sw, ll.raw); rest != "" {
				if colon := strings.IndexByte(ll.code, ':'); colon >= 0 {
					phpStatement(cur, jb, subLine(ll, colon+1), subLine(orig, colon+1), branchTaken)
				}
			}
			continue
		}

		if isPHPStructuralLine(code) || isPHPStructuralLine(strings.TrimLeft(code, "} \t")) {
			// `if (settype($x, "integer"))` converts $x whichever arm runs.
			if name, ok := phpSettypeNumeric(orig.raw); ok && jb.state() != branchDead {
				cur.stmts = append(cur.stmts, stmtDraft{line: ll.line, assigns: name,
					conditional: jb.state() == branchMaybe, sinkArgs: map[string]sinkArgDraft{}})
			}
			if g, ok := conditionGuard(langPHP, ll); ok {
				cur.guards = append(cur.guards, g)
			}
			if h, ok := parseJavaHeader(ll); ok {
				st := jb.header(h, depthHere)
				switch {
				case h.rest != "":
					// `if (c) stmt;` / `else stmt;` on one line.
					phpStatement(cur, jb, subLine(ll, h.restAt), subLine(orig, h.restAt), st)
				case !h.opens:
					// `if (c)` with the statement on the next line.
					jb.pending = &st
				}
			}
			continue
		}

		arm := branchTaken
		if jb.pending != nil {
			arm = *jb.pending
			jb.pending = nil
		}
		phpStatement(cur, jb, ll, orig, arm)
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// phpStatement recognizes one statement under the branch model: dropped in an
// arm that cannot run, conditional in one that may not.
//
// orig is the same line before PHP normalization, which turns the `.`
// concatenation operator into `+`: the numeric-conversion shapes below must
// tell arithmetic from concatenation, so they read the original.
func phpStatement(cur *unitDraft, jb *javaBranches, ll, orig logicalLine, arm branchState) {
	state := combineStates(jb.state(), arm)
	if sw := jb.innermostSwitch(); sw != nil {
		sw.statement(strings.TrimSpace(ll.code))
	}
	if state == branchDead {
		return
	}
	if name, ok := phpNumericAssign(orig); ok {
		// The assignee holds a number, which carries no injection.
		cur.stmts = append(cur.stmts, stmtDraft{line: ll.line, assigns: name,
			conditional: state == branchMaybe, sinkArgs: map[string]sinkArgDraft{}})
		return
	}
	ll = jb.rewriteJavaTernary(ll)
	before := len(cur.stmts)
	phpRecognizeInto(cur, ll)
	for i := before; i < len(cur.stmts); i++ {
		cur.stmts[i].conditional = state == branchMaybe
		jb.learn(ll, cur.stmts[i].assigns)
	}
}

// phpRecognizeInto recognizes one normalized PHP logical line into unit u,
// applying the return-statement special case and superglobal promotion. Empty and
// structural lines are skipped. Shared by the top-level loop and inline-body
// extraction so both paths recognize statements identically.
func phpRecognizeInto(u *unitDraft, ll logicalLine) {
	code := strings.TrimSpace(ll.code)
	if code == "" {
		return
	}
	if isPHPStructuralLine(code) {
		if g, ok := conditionGuard(langPHP, ll); ok {
			u.guards = append(u.guards, g)
		}
		return
	}
	if st, ok := phpReturnStatement(ll); ok {
		promotePHPSuperglobals(&st)
		u.stmts = append(u.stmts, st)
		return
	}
	if st, ok := recognizeStatement(langPHP, ll); ok {
		promotePHPSuperglobals(&st)
		u.stmts = append(u.stmts, st)
	}
}

// phpInlineBody extracts the statements written on the SAME line as a function
// header (`function run($c){ system($c); }`) and reports whether the body is
// complete on that line (a matching close brace present). It slices the body out
// between the header's opening brace and the trailing close brace, keeping the
// code and raw views aligned, and splits it on top-level semicolons into logical
// lines. A header with no brace on the line, or a brace-at-end with no body,
// yields no statements — the ordinary multi-line loop handles those.
func phpInlineBody(ll logicalLine) (body []logicalLine, complete bool) {
	openIdx := strings.IndexByte(ll.code, '{')
	if openIdx < 0 {
		return nil, false
	}
	closeIdx := strings.LastIndexByte(ll.code, '}')
	complete = closeIdx > openIdx
	end := len(ll.code)
	if complete {
		end = closeIdx
	}
	start := openIdx + 1
	if start >= end {
		return nil, complete
	}
	bodyCode := ll.code[start:end]
	bodyRaw := bodyCode
	if len(ll.raw) == len(ll.code) {
		bodyRaw = ll.raw[start:end]
	}
	return splitSemicolons([]logicalLine{{line: ll.line, code: bodyCode, raw: bodyRaw}}), complete
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

// normalizePHPExpr applies the PHP→shared-recognizer rewrites to one text view.
// The transforms are byte-for-byte length-preserving on the code and raw views so
// applying it to both keeps them aligned.
//
// ORDER MATTERS: the concat rewrite runs BEFORE `->`→`.`. In PHP source a bare
// `.` is ALWAYS string concatenation (object member access is `->`, static is
// `::`), so at this point every non-decimal `.` is a concat operator. Rewriting
// it to `+` FIRST — while member accesses are still `->` — keeps the two meanings
// distinct: after `->`→`.`, a `.` unambiguously marks a member chain (pdo.query)
// the recognizer treats as an attribute tail, and a concatenated tainted operand
// (`'ls '.$id`) is a `+`-separated read the recognizer captures as a variable.
func normalizePHPExpr(s string) string {
	s = rewriteEchoPrint(s)
	s = rewritePHPConcat(s)
	s = strings.ReplaceAll(s, "->", ".")
	s = phpKeywordVars(s)
	s = strings.ReplaceAll(s, "$", "")
	return s
}

// phpKeywordVars renames a variable whose name is a keyword in the shared
// recognizer's list -- `$string`, `$type`, `$match`, `$default`, `$object` --
// to `_string` and so on. The `$` sigil makes every one of them a variable in
// PHP, but once it is removed the recognizer drops the bare word as a keyword,
// and with it every read of the variable: `$string = $_POST['x'];
// unserialize($string)` reported nothing. The `$` becomes `_`, so the views
// keep their length. `$this` is left alone: it is the object, not a value a
// statement assigns.
func phpKeywordVars(s string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] != '$' {
			continue
		}
		j := i + 1
		for j < len(b) && isIdentPart(b[j]) {
			j++
		}
		if name := string(b[i+1 : j]); name != "this" && isKeyword(name) {
			b[i] = '_'
		}
		i = j - 1
	}
	return string(b)
}

// rewritePHPConcat replaces the PHP string-concatenation operator `.` with `+`
// (a neutral binary operator the shared recognizer already understands), so a
// tainted operand concatenated WITHOUT surrounding spaces — `system('ls '.$id)`
// — is captured as a variable read instead of being mistaken for a member-access
// attribute tail (`.id`) and skipped (F3). It is length-preserving (a single-byte
// substitution) so the code and raw views stay byte-aligned, and it runs before
// `->`→`.` so a genuine member access is never affected. A decimal point in a
// numeric literal (`1.5`) is left untouched (digit on both sides); a real
// concat's operands are strings/identifiers, never two digits.
func rewritePHPConcat(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] != '.' {
			continue
		}
		prevDigit := i > 0 && b[i-1] >= '0' && b[i-1] <= '9'
		nextDigit := i+1 < len(b) && b[i+1] >= '0' && b[i+1] <= '9'
		if prevDigit && nextDigit {
			continue // decimal point inside a number, not a concat operator
		}
		b[i] = '+'
	}
	return string(b)
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

// Numeric conversion in PHP.
//
// A value converted to a number carries no injection: `(int) $x`, `$x += 0`,
// `settype($x, "integer")`, `filter_var($x, FILTER_VALIDATE_INT)`. These are
// how PHP code most often makes request input safe for a query or a command,
// and nox knew only intval/floatval. Each shape below is exact: the whole
// right-hand side must be the conversion, so `(int) $a . $b` -- a number
// concatenated with a string -- is not one.
var (
	phpCastAssign  = regexp.MustCompile(`^\s*\$([A-Za-z_]\w*)\s*=\s*\(\s*(?:int|integer|float|double|bool|boolean)\s*\)\s*\$[A-Za-z_]\w*(?:\[[^\]]*\])?\s*;?\s*$`)
	phpArithUpdate = regexp.MustCompile(`^\s*\$([A-Za-z_]\w*)\s*[-+*/%]=\s*\d[0-9.]*\s*;?\s*$`)
	phpArithAssign = regexp.MustCompile(`^\s*\$([A-Za-z_]\w*)\s*=\s*(?:\$[A-Za-z_]\w*|[0-9][0-9.]*)(?:\s*[-+*/%]\s*(?:\$[A-Za-z_]\w*|[0-9][0-9.]*))+\s*;?\s*$`)
	phpFilterNum   = regexp.MustCompile(`^\s*\$([A-Za-z_]\w*)\s*=\s*filter_var\s*\([^;]*,\s*FILTER_(?:SANITIZE_NUMBER_INT|SANITIZE_NUMBER_FLOAT|VALIDATE_INT|VALIDATE_FLOAT|VALIDATE_BOOLEAN|VALIDATE_BOOL)\b[^;]*\)\s*;?\s*$`)
	phpSettype     = regexp.MustCompile(`\bsettype\s*\(\s*\$([A-Za-z_]\w*)\s*,\s*["'](?:int|integer|float|double|bool|boolean)["']\s*\)`)
)

// phpNumericAssign reports a statement that assigns a number to a variable.
// The shapes are matched on the code view before normalization (strings
// blanked, so text inside a literal never matches); settype's type name is a
// string literal, so that one is read from the raw view, and only on a line
// the code view shows is a settype call.
func phpNumericAssign(ll logicalLine) (string, bool) {
	for _, re := range []*regexp.Regexp{phpCastAssign, phpArithUpdate, phpArithAssign, phpFilterNum} {
		if m := re.FindStringSubmatch(ll.code); m != nil {
			return m[1], true
		}
	}
	if strings.HasPrefix(strings.TrimSpace(ll.code), "settype") {
		if m := phpSettype.FindStringSubmatch(ll.raw); m != nil {
			return m[1], true
		}
	}
	return "", false
}

// phpSettypeNumeric reports `settype($x, "integer")` in a control-flow
// header: the conversion happens when the condition is evaluated, before any
// arm runs.
func phpSettypeNumeric(code string) (string, bool) {
	m := phpSettype.FindStringSubmatch(code)
	if m == nil {
		return "", false
	}
	return m[1], true
}
