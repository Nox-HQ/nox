package engine

import "strings"

// extractLua turns Lua logical lines into unit drafts. Named functions
// (`function name(...)`, `local function name(...)`, and the table-method form
// `function tbl.name(...)` / `function tbl:name(...)`) become their own units
// keyed by their trailing name; everything else accumulates into the module-level
// unit (funcName ""). Scoping is by function header only — nested/anonymous
// functions fold into the enclosing unit, which is conservative (it can only
// merge scopes, never split a real flow), exactly like the Python/Perl/PHP
// extractors.
//
// Lua-specific normalization happens per line before the shared recognizer runs
// (see normalizeLuaLine): the method-call colon `obj:method(...)` is rewritten to
// the dotted chain `obj.method(...)` the catalog keys on (a `:` call passes an
// implicit `self`, but for source→sink matching the dotted method name is what
// matters). `local` binding keywords are stripped from an assignment LHS by the
// shared splitAssignment. Long-string command payloads are opaque data (lexctx
// already blanked them), so there is no Lua analogue of Perl's backtick literal.
func extractLua(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	for _, raw := range lines {
		ll := normalizeLuaLine(raw)
		code := strings.TrimSpace(ll.code)
		if code == "" || isLuaStructuralLine(code) {
			continue
		}
		if name, params, ok := luaFuncHeader(code); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			continue
		}
		if st, ok := luaReturnStatement(ll); ok {
			promoteLuaSources(&st)
			cur.stmts = append(cur.stmts, st)
			continue
		}
		if st, ok := recognizeStatement(langLua, ll); ok {
			promoteLuaSources(&st)
			cur.stmts = append(cur.stmts, st)
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// luaSources is the set of Lua source names that appear as BARE READS (a bare
// identifier or an indexed table) rather than as a call chain or a dotted
// attribute — the CLI argument table `arg` (`arg[1]`, `...`). The catalog keys
// this source by name, but resolveSource consults calls and chains (not raw
// reads), so promoteLuaSources copies any such read into the statement's chains —
// exactly as promotePerlSources does for Perl superglobals.
var luaSources = map[string]bool{
	"arg": true,
}

// promoteLuaSources adds every Lua bare-read source on a statement to its chains,
// so an indexed CLI-argument source (`arg[1]`) resolves as a catalog source
// exactly like a source CALL (`os.getenv`) or an attribute chain (`ngx.var`) does.
// It also promotes the OpenResty request-variable PREFIX `ngx.var`: the idiom is
// `ngx.var.remote_addr` / `ngx.var.arg_name`, whose full dotted chain has the
// source as a PREFIX (not a suffix), so the shared suffix-matching would miss it —
// this adds the bare `ngx.var` chain so the catalog source resolves. Idempotent
// and order-stable.
func promoteLuaSources(st *stmtDraft) {
	addChain := func(name string) {
		for _, ch := range st.chains {
			if ch == name {
				return
			}
		}
		st.chains = append(st.chains, name)
	}
	for _, r := range st.reads {
		if luaSources[r] {
			addChain(r)
		}
	}
	for _, ch := range st.chains {
		if strings.HasPrefix(ch, "ngx.var.") {
			addChain("ngx.var")
			break
		}
	}
}

// normalizeLuaLine rewrites a logical line's code and raw views into the shape the
// shared recognizer understands: the method-call colon `obj:method` becomes the
// dotted chain `obj.method`. Both views are transformed identically so their byte
// offsets stay mutually aligned (the recognizer slices raw by offsets found in
// code); the 1-based line number is preserved. The rewrite is length-preserving
// (a single byte `:` → `.`), so alignment to the original source offsets also
// holds.
func normalizeLuaLine(ll logicalLine) logicalLine {
	return logicalLine{
		line: ll.line,
		code: normalizeLuaMethodColon(ll.code),
		raw:  normalizeLuaMethodColon(ll.raw),
	}
}

// normalizeLuaMethodColon replaces a method-call colon with `.` so `obj:method`
// reads as the dotted chain `obj.method`. A colon is a METHOD colon only when it
// sits between two identifier bytes (`recv : name`) — i.e. the preceding byte is
// an identifier byte and the following byte begins an identifier. Any other colon
// (Lua has `::label::` goto labels) is left untouched. Length-preserving.
func normalizeLuaMethodColon(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] != ':' {
			continue
		}
		if i > 0 && isIdentPart(b[i-1]) && i+1 < len(b) && isIdentStart(b[i+1]) {
			b[i] = '.'
		}
	}
	return string(b)
}

// isLuaStructuralLine reports whether a normalized line is block scaffolding whose
// tokens must not be read as a data-flow statement — a lone `end`/`else`, a
// control-flow header, a `do`/`repeat` block opener, or a goto label. Coarse by
// design: a missed skip only adds a harmless non-sink identifier to a unit, and a
// wrongly-skipped line would only cost recall (never precision).
func isLuaStructuralLine(code string) bool {
	switch code {
	case "end", "else", "do", "then", "repeat", "break", "end;", "})", "end)":
		return true
	}
	for _, kw := range []string{
		"if ", "if(", "elseif ", "elseif(", "for ", "while ", "while(",
		"until ", "until(", "return end", "goto ", "::",
	} {
		if strings.HasPrefix(code, kw) {
			return true
		}
	}
	return false
}

// luaFuncHeader returns the function name and its positional parameter names when
// code is a function header: `function name(...)`, `local function name(...)`, or
// a table-method form `function tbl.name(...)` / `function tbl:name(...)` (the
// colon already normalized to `.`). The unit name is the LAST dotted segment of
// the declared name (so `function M.handler(req)` keys the unit `handler`, which
// the catalog/summary lookups reach by suffix). Returns ("", nil, false) for
// anything that is not a function header.
func luaFuncHeader(code string) (name string, params []string, ok bool) {
	rest := code
	if strings.HasPrefix(rest, "local ") {
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "local "))
	}
	if !strings.HasPrefix(rest, "function ") && rest != "function" {
		return "", nil, false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "function"))
	paren := strings.IndexByte(rest, '(')
	if paren <= 0 {
		// An anonymous function (`function()` / `function ()`) has no name: fold its
		// body into the enclosing scope (report not-a-header) so its statements still
		// count against that unit.
		return "", nil, false
	}
	rawName := strings.TrimSpace(rest[:paren])
	// Reduce a dotted/method name to its trailing segment (`M.handler` -> `handler`).
	if dot := strings.LastIndexByte(rawName, '.'); dot >= 0 {
		rawName = rawName[dot+1:]
	}
	name = strings.TrimSpace(rawName)
	if name == "" || !isSimpleIdent(name) {
		return "", nil, false
	}
	closeParen := matchParen(rest, paren)
	if closeParen < 0 {
		return name, nil, true // malformed/continued header: name only (fail safe)
	}
	params = parseLuaParams(rest[paren+1 : closeParen])
	return name, params, true
}

// parseLuaParams splits a Lua parameter list into bare positional parameter names
// in order. It drops the variadic `...` marker and any empty slot. Lua parameters
// carry no default values or type annotations, so the names are already bare.
// Best-effort and deterministic; an unparsable slot is skipped rather than guessed
// (a missed parameter only weakens a summary, never fabricates a flow).
func parseLuaParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "..." {
			continue
		}
		if isSimpleIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

// luaReturnStatement recognizes a `return <expr>` line and produces a stmtDraft
// whose returns lists the variable names in the returned expression, while still
// capturing the calls and reads inside it. It mirrors pyReturnStatement /
// perlReturnStatement. A bare `return` yields a statement with empty returns.
func luaReturnStatement(ll logicalLine) (stmtDraft, bool) {
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
	st, ok := recognizeStatement(langLua, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}
