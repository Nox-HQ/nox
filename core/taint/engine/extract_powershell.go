package engine

import "strings"

// extractPowerShell turns PowerShell logical lines into unit drafts. PowerShell
// has a `function name { ... }` / `function name ($a, $b) { ... }` header and an
// optional `param(...)` block that declares the parameters of a function or
// script; both feed per-unit scoping the same way Python's `def` and PHP's
// `function` do. Everything outside a function accumulates into the module unit
// (funcName "").
//
// PowerShell recognition is COARSER than Python/JS (no real parser — only Go gets
// go/ast). It leans on a line normalizer (shapePowerShellLine) that rewrites the
// language's non-C shapes into the parenthesized `callee(args)` form the shared
// recognizer understands:
//
//   - the `$` variable sigil is deleted (like PHP), so `$cmd`/`$env:X`/`$args`
//     become the plain identifiers the engine's variable tracking and the
//     catalog's source keys expect;
//
//   - the static-member separator `::` becomes `.` and a leading type accelerator
//     `[Namespace.Type]` is unwrapped, so `[IO.File]::ReadAllText($p)` reads as
//     the dotted chain `IO.File.ReadAllText($p)` matched by the `.ReadAllText`
//     suffix;
//
//   - a `[int]` / `[long]` cast is rewritten to a call `int(...)` / `long(...)`
//     so numeric coercion is recognized as a sanitizer;
//
//   - a cmdlet's `Verb-Noun` hyphen is normalized to an underscore (`Verb_Noun`)
//     because the shared token scanner treats `-` as an operator; the catalog is
//     keyed on the same underscore form (see the `powershell` block comment);
//
//   - a paren-less command call (`Invoke-Expression $u`, `Get-Content $p`,
//     `Invoke-WebRequest -Uri $url`) is wrapped in parentheses so the shared call
//     recognizer sees a call, with the (possibly `-Param`-prefixed) argument text
//     preserved as the call's arguments;
//
//   - the call operator `& $cmd args` is rewritten to a synthetic call
//     `InvokeOperator($cmd args)` (a command-injection sink) so an indirect
//     invocation of a tainted command is caught;
//
//   - a pipeline `a | Cmd1 args | Cmd2` is split at every top-level `|` and
//     folded left into nested positional calls `Cmd2(Cmd1(a, args))`, because
//     binding to a cmdlet's pipeline input is a real argument position.
//
// Its honest limits (documented in testdata/precision-suite-powershell/README.md):
// method-suffix sinks are matched by name rather than by proving the receiver's
// .NET type. Splatting (`@params`) was once listed here and is NOT a limit: a
// hashtable assigned from a source is tainted and carries into the splatted
// call, so `$p = @{Uri = $args[0]}; Invoke-WebRequest @p` is reported.
func extractPowerShell(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw.code)
		if trimmed == "" {
			continue
		}
		if name, params, ok := powerShellFuncHeader(trimmed); ok {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			continue
		}
		if isPowerShellStructuralLine(trimmed) {
			continue
		}
		// A `param(...)` block declares the current unit's parameters.
		if params, ok := powerShellParamBlock(trimmed); ok {
			cur.params = append(cur.params, params...)
			// The param block also introduces those names as sources when they are
			// script/function parameters bound from untrusted input; the catalog
			// models a bare `param()` parameter read as a source via promotion below.
			continue
		}

		shaped := shapePowerShellLine(raw)
		if st, ok := powerShellReturnStatement(shaped); ok {
			promotePowerShellSources(&st)
			cur.stmts = append(cur.stmts, st)
			continue
		}
		if st, ok := recognizeStatement(langPowerShell, shaped); ok {
			promotePowerShellSources(&st)
			cur.stmts = append(cur.stmts, st)
		}
	}

	// A module-scope `param(...)` block declares the SCRIPT's parameters, which are
	// bound from the (untrusted) command line — so a read of one is an untrusted
	// source, exactly like $args. Promote such reads on the module unit's
	// statements now that its full parameter set is known. Function parameters are
	// NOT promoted: a function argument may be a trusted, locally-derived value, so
	// tainting every function parameter would over-report.
	if len(module.params) > 0 {
		scriptParams := make(map[string]bool, len(module.params))
		for _, p := range module.params {
			scriptParams[p] = true
		}
		for i := range module.stmts {
			promoteScriptParamSources(&module.stmts[i], scriptParams)
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// psScriptParamSource is the sentinel chain promoted onto any statement that
// reads a script-level parameter. The catalog lists it as a source (kind argv),
// so resolveSource fires on the sentinel and taints the statement's assignee.
// A sentinel is used because script parameter NAMES are arbitrary (the catalog
// cannot enumerate them); resolveSource only needs a matching chain to mark the
// statement a source — the tainted variable is always the assignment LHS.
const psScriptParamSource = "PSScriptParameter"

// promoteScriptParamSources adds the psScriptParamSource sentinel to any
// statement that reads a script-level param name, so a top-level
// `param($Formula)` value read resolves as an untrusted source (like $args) and
// taints the assignee.
func promoteScriptParamSources(st *stmtDraft, scriptParams map[string]bool) {
	for _, r := range st.reads {
		if !scriptParams[r] {
			continue
		}
		already := false
		for _, ch := range st.chains {
			if ch == psScriptParamSource {
				already = true
				break
			}
		}
		if !already {
			st.chains = append(st.chains, psScriptParamSource)
		}
		return
	}
}

// langPowerShell is the recognizer's PowerShell dialect. Its assignment/keyword
// behavior is the shared default (a bare `ident = rhs`), which — after the `$`
// sigil is stripped in shaping — matches PowerShell's `$lhs = rhs` exactly.
// It is defined in recognize.go's langKind enum.

// powerShellSources is the set of bare-identifier reads that are untrusted-input
// sources in PowerShell after shaping strips sigils: `$args`, `$MyInvocation`,
// and the `$env:` provider (shaped to a bare `env` read). The catalog keys these
// names, but they appear as bare identifier reads rather than calls/chains, so
// promotePowerShellSources copies any such read into the statement's source-chain
// list so resolveSource taints the assignee (mirrors PHP's superglobal
// promotion).
var powerShellSources = map[string]bool{
	"args":         true,
	"MyInvocation": true,
	"env":          true,
}

// promotePowerShellSources adds every recognized bare-identifier source read on a
// statement to its chains, so a source that appears as a plain read (`$args`,
// `$env:X` → `env`) resolves as a catalog source exactly like a source CALL or
// attribute chain does. Idempotent and order-stable.
func promotePowerShellSources(st *stmtDraft) {
	for _, r := range st.reads {
		if !powerShellSources[r] {
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

// isPowerShellStructuralLine reports whether a line is block scaffolding whose
// tokens must not be read as a dataflow statement — a lone brace, a control-flow
// header, or a using/class declaration. Coarse by design: a missed skip only adds
// a harmless non-sink identifier to the current unit.
func isPowerShellStructuralLine(code string) bool {
	switch code {
	case "{", "}", "}()", "})", "param(", "(":
		return true
	}
	for _, kw := range []string{"if ", "if(", "elseif", "else", "for ", "for(",
		"foreach ", "foreach(", "while ", "while(", "switch ", "switch(",
		"class ", "try", "catch", "finally", "do ", "using ",
		"trap "} {
		if strings.HasPrefix(code, kw) {
			return true
		}
	}
	return false
}

// powerShellFuncHeader returns the function name and its positional parameter
// names if code is a `function Name { ... }` or `function Name ($a, $b) { ... }`
// header. PowerShell function names may contain hyphens (`Get-Thing`), so the
// name is read verbatim up to the first `{`, `(`, or whitespace. Parameters in an
// inline `(...)` list are parsed; a `param(...)` block on a later line is folded
// in by powerShellParamBlock. Returns ("", nil, false) for anything else.
func powerShellFuncHeader(code string) (name string, params []string, ok bool) {
	rest := strings.TrimSpace(code)
	// A `function`/`filter`/`workflow` keyword introduces a named scope.
	for _, kw := range []string{"function ", "filter ", "workflow "} {
		if !strings.HasPrefix(rest, kw) {
			continue
		}
		rest = strings.TrimSpace(strings.TrimPrefix(rest, kw))
		// Name runs to the first '{', '(', or whitespace.
		nameEnd := len(rest)
		for i := 0; i < len(rest); i++ {
			if rest[i] == '{' || rest[i] == '(' || rest[i] == ' ' || rest[i] == '\t' {
				nameEnd = i
				break
			}
		}
		name = strings.TrimSpace(rest[:nameEnd])
		if name == "" {
			return "", nil, false
		}
		// An inline parameter list `(...)` after the name.
		if paren := strings.IndexByte(rest, '('); paren >= 0 {
			if closeParen := matchParen(rest, paren); closeParen > paren {
				params = parsePowerShellParams(rest[paren+1 : closeParen])
			}
		}
		return name, params, true
	}
	return "", nil, false
}

// powerShellParamBlock returns the parameter names declared by a `param(...)`
// block line. PowerShell writes `param($A, [string]$B, [int]$C = 0)`; after the
// `$` sigil, type accelerators, and defaults are stripped, the bare names remain.
// Returns (nil, false) when the line is not a param block.
func powerShellParamBlock(code string) ([]string, bool) {
	trimmed := strings.TrimSpace(code)
	if !strings.HasPrefix(trimmed, "param(") && !strings.HasPrefix(trimmed, "param (") {
		return nil, false
	}
	paren := strings.IndexByte(trimmed, '(')
	if paren < 0 {
		return nil, false
	}
	closeParen := matchParen(trimmed, paren)
	if closeParen < 0 {
		return nil, true // continued/malformed: no names, fail safe
	}
	return parsePowerShellParams(trimmed[paren+1 : closeParen]), true
}

// parsePowerShellParams splits a PowerShell parameter list into bare positional
// parameter names in order. It strips `$` sigils, `[Type]`/`[Parameter(...)]`
// attribute and type-accelerator brackets, and `= default` values, leaving the
// bare name. An unparsable slot is skipped (fail safe: a missed parameter only
// weakens a summary, never fabricates a flow).
func parsePowerShellParams(inner string) []string {
	parts := splitTopLevelArgs(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = stripBrackets(p) // drop [type]/[attribute()] prefixes
		p = strings.ReplaceAll(p, "$", "")
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if i := strings.IndexByte(p, '='); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		// The bare name is the last whitespace-separated token.
		if fields := strings.Fields(p); len(fields) > 0 {
			p = fields[len(fields)-1]
		}
		if isSimpleIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

// stripBrackets removes every top-level `[...]` group from s (type accelerators
// and attributes like `[int]`, `[Parameter(Mandatory)]`), keeping the bytes
// between and after them. Nested brackets inside a group are consumed with it.
func stripBrackets(s string) string {
	var out strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				out.WriteByte(s[i])
			}
		}
	}
	return out.String()
}

// powerShellReturnStatement recognizes a `return <expr>` line and produces a
// stmtDraft whose `returns` lists the returned variable names while still
// capturing the calls and reads inside the expression. A bare `return` yields a
// statement with empty returns. Reports ok=false for a non-return line.
func powerShellReturnStatement(ll logicalLine) (stmtDraft, bool) {
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
	st, ok := recognizeStatement(langPowerShell, inner)
	if !ok {
		return stmtDraft{line: ll.line, sinkArgs: map[string]sinkArgDraft{}}, true
	}
	st.assigns = ""
	st.returns = append([]string(nil), st.reads...)
	return st, true
}
