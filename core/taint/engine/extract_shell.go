package engine

import "strings"

// extractShell turns shell/bash logical lines into unit drafts. Shell is
// COMMAND-ORIENTED and paren-less, which the shared assignment/call recognizer
// (built for `lhs = expr` and `callee(args)`) does not fit; this dedicated
// recognizer models the two shell statement shapes that carry the bulk of
// injection bugs:
//
//   - an assignment `NAME=value` (no whitespace around `=`, no `$` on the LHS),
//     whose RHS `$var` / `${var}` / `$(...)` / “ `...` “ reads are surfaced,
//     and whose positional-parameter / read-var / CGI-env reads resolve as
//     catalog SOURCES; and
//   - a command call `cmd arg1 arg2 …` (space-separated, paren-less) whose first
//     word is the callee and whose remaining words are positional arguments.
//
// Function bodies (`f() {` or `function f {`) open their own unit keyed by name;
// everything else accumulates into the module-level unit (funcName "").
//
// A declaration builtin that INITIALIZES (`local x="$1"`, `export u="$2"`) is an
// assignment and is recognized as one; a bare declaration (`local a b`) is not.
//
// HONEST LIMITS (by design): word-splitting, globbing, arithmetic re-entry and
// `xargs`/pipeline-fed commands are constructs a flat, per-line recognizer
// cannot follow. Arrays and `${var//a/b}` transforms were once listed here and
// are NOT limits — both propagate today (see tp_known_fns.sh); the claim was
// stale, and tp_pipeline_fed.sh now pins the one that is real.
//
// A miss only weakens recall (a false negative), never correctness — an
// unrecognized line simply yields no statement. Precision is
// defended: a properly QUOTED expansion `"$var"` passed to a NON-sink command is
// naturally clean because that command is not in the catalog, and the actual
// sinks (`eval`, `sh -c`/`bash -c`, `source`/`.`, `curl`/`wget`) are exactly the
// ones where a tainted value is dangerous.
func extractShell(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" {
			continue
		}
		// A closing `}` (function body end) returns to module scope.
		if trimmed == "}" {
			cur = module
			continue
		}
		if name, ok := shellFuncHeader(trimmed); ok {
			u := &unitDraft{funcName: name}
			units = append(units, u)
			cur = u
			continue
		}
		// A declaration builtin that introduces an ASSIGNMENT (`local x="$1"`)
		// carries real dataflow and must not be skipped with the bare
		// declarations. Blanking the keyword lets the assignment underneath be
		// recognized normally.
		if decl, ok := stripShellDeclPrefix(ll); ok {
			ll = decl
			trimmed = strings.TrimSpace(ll.code)
		}
		if isShellStructuralLine(trimmed) {
			continue
		}
		if sts, ok := shellReadStatements(ll); ok {
			cur.stmts = append(cur.stmts, sts...)
			continue
		}
		if st, ok := shellAssignment(ll); ok {
			cur.stmts = append(cur.stmts, st)
			continue
		}
		if st, ok := shellCommand(ll); ok {
			cur.stmts = append(cur.stmts, st)
			continue
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// shellReadStatements recognizes a `read [flags] var1 var2 …` builtin, which
// reads untrusted input into each named variable. Each such variable becomes a
// SOURCE-tainted assignment: the statement `assigns` the variable and carries
// the `read` source marker so resolveSource taints it. One statement is emitted
// per variable (the engine models a single assignee per statement). A bare
// `read` with no variable defaults to `$REPLY`, which the catalog also lists as
// a source. Flags (`-r`, `-p "prompt"`, `-a arr`) are skipped. Returns ok=false
// for a non-`read` line.
func shellReadStatements(ll logicalLine) ([]stmtDraft, bool) {
	code := strings.TrimSpace(ll.code)
	if code != "read" && !strings.HasPrefix(code, "read ") {
		return nil, false
	}
	fields := strings.Fields(code)[1:] // drop the `read` word
	var vars []string
	skipNext := false
	for _, f := range fields {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(f, "-") {
			// -p PROMPT / -a ARRAY / -n N / -t N take an argument; -r/-s do not.
			switch f {
			case "-p", "-a", "-n", "-t", "-u", "-d", "-i", "-N":
				skipNext = true
			}
			continue
		}
		if isSimpleIdent(f) {
			vars = append(vars, f)
		}
	}
	if len(vars) == 0 {
		// Bare `read` populates $REPLY.
		vars = []string{"REPLY"}
	}
	out := make([]stmtDraft, 0, len(vars))
	for _, v := range vars {
		out = append(out, stmtDraft{
			line:     ll.line,
			assigns:  v,
			calls:    []string{"read"},
			sinkArgs: map[string]sinkArgDraft{},
		})
	}
	return out, true
}

// shellFuncHeader recognizes `name() {` / `name () {` and `function name {` /
// `function name() {`, returning the bare function name. The trailing `{` may be
// on the same line or the next (we only need the name to open the unit).
func shellFuncHeader(trimmed string) (string, bool) {
	if strings.HasPrefix(trimmed, "function ") {
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "function "))
		// `function name` or `function name()` (optionally `{`).
		name := leadingShellName(rest)
		if name != "" {
			return name, true
		}
		return "", false
	}
	// `name()` form: an identifier immediately (or after spaces) followed by `()`.
	name := leadingShellName(trimmed)
	if name == "" {
		return "", false
	}
	rest := strings.TrimSpace(trimmed[len(nameSpan(trimmed)):])
	if strings.HasPrefix(rest, "()") {
		return name, true
	}
	return "", false
}

// nameSpan returns the leading identifier substring of s (including no trailing
// characters), used to locate where the name ends before a `()`.
func nameSpan(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	start := i
	for i < len(s) && isShellIdentByte(s[i]) {
		i++
	}
	return s[:i][start:]
}

// leadingShellName returns the leading shell identifier of s (letters, digits,
// underscore; must start with a non-digit), or "" if s does not start with one.
func leadingShellName(s string) string {
	s = strings.TrimLeft(s, " \t")
	if s == "" || !isShellIdentStart(s[0]) {
		return ""
	}
	i := 0
	for i < len(s) && isShellIdentByte(s[i]) {
		i++
	}
	return s[:i]
}

// isShellStructuralLine reports whether a trimmed logical line is shell
// block/keyword scaffolding that carries no dataflow statement (and whose
// leading keyword must not be read as a command call). Coarse on purpose: a
// missed skip only adds a harmless non-sink line.
func isShellStructuralLine(trimmed string) bool {
	switch trimmed {
	case "do", "done", "then", "fi", "else", "esac", "{", "}", "in":
		return true
	}
	for _, kw := range []string{
		"if ", "elif ", "else ", "for ", "while ", "until ", "case ", "then ",
		"do ", "return ", "local ", "declare ", "export ", "readonly ", "typeset ",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	// A `[` / `[[` test or a `(( ))` arithmetic line carries no command sink.
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "((") {
		return true
	}
	return false
}

// shellDeclKeywords are the declaration builtins that may prefix an assignment.
// Each declares a variable and may also initialize it in the same word.
var shellDeclKeywords = map[string]bool{
	"local":    true,
	"declare":  true,
	"export":   true,
	"readonly": true,
	"typeset":  true,
}

// stripShellDeclPrefix blanks a leading declaration builtin, and any option
// flags it carries, to SPACES when what follows is a real `NAME=value`
// assignment — so `local arg="$1"` is recognized as the assignment it is and the
// declared variable can carry taint.
//
// Blanking rather than slicing keeps every byte offset intact, so the code and
// raw views stay mutually aligned (the recognizer slices raw by offsets found in
// code) and the assignment recognizer, which already skips leading whitespace,
// needs no change.
//
// A BARE declaration (`local a b c`, `declare -A map`, `local count`) declares
// without initializing: it carries no dataflow, so ok=false leaves it to be
// skipped as scaffolding. Reading one as a command would invent a call to
// `local`/`declare`.
func stripShellDeclPrefix(ll logicalLine) (logicalLine, bool) {
	code := ll.code
	i := 0
	for i < len(code) && (code[i] == ' ' || code[i] == '\t') {
		i++
	}
	kwStart := i
	for i < len(code) && isShellIdentByte(code[i]) {
		i++
	}
	if !shellDeclKeywords[code[kwStart:i]] {
		return ll, false
	}
	// The keyword must be a standalone word (`localx=1` is an ordinary
	// assignment to a variable that merely starts with the keyword's letters).
	if i >= len(code) || (code[i] != ' ' && code[i] != '\t') {
		return ll, false
	}
	// Skip any option flags between the keyword and the name (`local -r`,
	// `declare -i`, `declare -A`).
	end := i
	for {
		j := end
		for j < len(code) && (code[j] == ' ' || code[j] == '\t') {
			j++
		}
		if j >= len(code) || code[j] != '-' {
			break
		}
		for j < len(code) && code[j] != ' ' && code[j] != '\t' {
			j++
		}
		end = j
	}
	// Only a real assignment underneath earns the rewrite.
	if _, _, ok := splitShellAssignment(code[end:]); !ok {
		return ll, false
	}
	out := logicalLine{line: ll.line, code: blankRange(code, kwStart, end), raw: ll.raw}
	if len(ll.raw) == len(code) {
		out.raw = blankRange(ll.raw, kwStart, end)
	}
	return out, true
}

// shellAssignment recognizes a `NAME=value` assignment (no whitespace around the
// `=`, LHS a bare shell identifier). It surfaces the RHS reads (variable
// expansions and source markers) so a `x=$1` taints x from the `$1` source and a
// `cmd="run ${input}"` propagates taint from input. Returns ok=false for a line
// that is not an assignment.
func shellAssignment(ll logicalLine) (stmtDraft, bool) {
	code := ll.code
	name, valStart, ok := splitShellAssignment(code)
	if !ok {
		return stmtDraft{}, false
	}
	st := stmtDraft{line: ll.line, assigns: name, sinkArgs: map[string]sinkArgDraft{}}

	rhsCode := code[valStart:]
	rhsRaw := rhsCode
	if len(ll.raw) == len(code) {
		rhsRaw = ll.raw[valStart:]
	}
	addShellExpansionReads(&st, rhsCode)
	addShellSourceMarkers(&st, rhsCode, rhsRaw)
	sortStrings(st.reads)
	return st, true
}

// splitShellAssignment returns (name, valueStartIndex, ok) for a `NAME=value`
// code line. The `=` must be immediately preceded by a bare identifier and NOT
// be `==`, `+=`, or preceded by whitespace (a `cmd = x` is a command, not an
// assignment, in shell). Only the FIRST word may be an assignment.
func splitShellAssignment(code string) (name string, valueStart int, ok bool) {
	i := 0
	for i < len(code) && (code[i] == ' ' || code[i] == '\t') {
		i++
	}
	start := i
	if i >= len(code) || !isShellIdentStart(code[i]) {
		return "", 0, false
	}
	for i < len(code) && isShellIdentByte(code[i]) {
		i++
	}
	name = code[start:i]
	// A `local`/`export` prefix was already skipped as structural; here the name
	// must be immediately followed by `=` (no space) and not `==`/`+=`.
	if i >= len(code) || code[i] != '=' {
		return "", 0, false
	}
	if i+1 < len(code) && code[i+1] == '=' {
		return "", 0, false // `==` comparison
	}
	if i > start && code[i-1] == '+' {
		return "", 0, false // `+=` append (handled as read+write; skip for simplicity)
	}
	return name, i + 1, true
}

// shellCommand recognizes a paren-less command call `cmd arg1 arg2 …`. The first
// word is the callee; the remaining words are positional arguments. It records
// the argument-shape evidence (which variables are tainted arguments, the
// positional slots, whether the first argument carries a tainted value) that the
// engine's per-sink danger logic consumes. Returns ok=false for a line with no
// command word.
func shellCommand(ll logicalLine) (stmtDraft, bool) {
	code := ll.code
	raw := ll.raw
	aligned := len(code) == len(raw)

	// The callee is the first bareword. Skip a leading env-assignment prefix
	// (`FOO=bar cmd …`) so the real command is the callee.
	i := skipShellLeadingAssignments(code)
	for i < len(code) && (code[i] == ' ' || code[i] == '\t') {
		i++
	}
	calleeStart := i
	var callee string
	if i < len(code) && code[i] == '.' && (i+1 >= len(code) || code[i+1] == ' ' || code[i+1] == '\t') {
		// The `.` builtin (POSIX alias for `source`): a lone `.` command word
		// followed by whitespace. Recognize it as the callee `.` so a tainted
		// `. "$path"` resolves the path-traversal sink.
		callee = "."
		i++
	} else {
		for i < len(code) && isShellCommandByte(code[i]) {
			i++
		}
		token := code[calleeStart:i]
		// A command word may be path-qualified (`/usr/bin/curl`, `./tool.sh`), so
		// a leading `/` or `.` is a valid start; shellCalleeName then reduces the
		// token to the bare final segment the catalog is keyed on. A lone `.`
		// (the source builtin) was already handled above.
		if token == "" || (!isShellIdentStart(token[0]) && token[0] != '/' && token[0] != '.') {
			return stmtDraft{}, false
		}
		callee = shellCalleeName(token)
		if callee == "" || !isShellIdentStart(callee[0]) {
			return stmtDraft{}, false
		}
	}
	// Normalize a leading `command`/`builtin`/`exec` wrapper to its target so
	// `command eval x` still resolves eval.
	// (Kept simple: only the bare callee is used.)

	// `exec` with a REDIRECTION and no command word (`exec 200>"$f"`, `exec >log`)
	// rebinds the shell's own file descriptors — it executes nothing, so a tainted
	// path there is not command injection. Only `exec CMD ...` is the sink.
	if callee == "exec" && shellStartsWithRedirection(code[i:]) {
		return stmtDraft{}, false
	}

	st := stmtDraft{line: ll.line, assigns: "", sinkArgs: map[string]sinkArgDraft{}}

	// Collect the positional arguments (space-separated words) with quoting info.
	rawArgsSeg := ""
	if aligned && i <= len(raw) {
		rawArgsSeg = raw[i:]
	}
	args := splitShellArgs(code[i:], rawArgsSeg)

	// A `-c` flag (present in the raw args) marks `sh -c` / `bash -c` — the shape
	// where a tainted string is executed as a command line. We reuse the
	// shellTrue flag to carry this so the danger check can require it for sh/bash
	// (a bare `bash script.sh` without `-c` is not a command-injection sink).
	hasDashC := shellHasDashCFlag(rawArgsSeg)

	// Build per-slot variable lists and the tainted-arg set. A variable that
	// appears only inside a SINGLE-quoted word is inert (no expansion) and is not
	// a tainted argument; an unquoted or double-quoted expansion is a live read.
	info := sinkArgDraft{}
	var allReads []string
	seen := map[string]struct{}{}
	// For `sh`/`bash`-style callees, the tainted string may be the argument to
	// `-c`; we still surface it as a read + tainted arg below via the generic
	// expansion collection.
	// On a fetch command, the argument after an output-file flag names a LOCAL
	// FILE, not a remote URL — `curl --output "$path" "$url"` fetches $url and
	// writes $path. Treating a tainted $path as the SSRF-controlling value
	// reported the wrong thing entirely, so those slots carry no tainted arg.
	fetch := shellFetchCommands[callee]
	skipNext := false
	for idx, a := range args {
		vars := shellArgVars(a)
		if skipNext {
			skipNext = false
			info.positionalVars = append(info.positionalVars, nil)
			allReads = append(allReads, vars...)
			continue
		}
		if fetch && shellFileArgFlags[strings.TrimSpace(a.raw)] {
			skipNext = true
		}
		info.positionalVars = append(info.positionalVars, append([]string(nil), vars...))
		if len(vars) > 0 {
			info.argCount++
		}
		for _, v := range vars {
			if _, dup := seen[v]; !dup {
				seen[v] = struct{}{}
				info.taintedArgVars = append(info.taintedArgVars, v)
				allReads = append(allReads, v)
			}
			if idx == 0 {
				info.firstArgTainted = true
			}
		}
	}
	// A command with no argument words but a trailing raw arg count (e.g. a bare
	// `read`) still counts its literal args for arity.
	if info.argCount == 0 {
		info.argCount = len(args)
	}
	sortStrings(info.taintedArgVars)
	info.shellTrue = hasDashC

	st.calls = append(st.calls, callee)
	st.sinkArgs[callee] = info
	st.reads = append(st.reads, allReads...)
	sortStrings(st.reads)

	if callee == "" {
		return stmtDraft{}, false
	}
	return st, true
}

// shellFetchCommands are the URL-fetching commands whose SSRF sink is controlled
// by the URL argument specifically, so their local-file flags must be excluded.
var shellFetchCommands = map[string]bool{"curl": true, "wget": true}

// shellFileArgFlags are the fetch-command flags whose FOLLOWING argument names a
// local file (an output path, a log, a cookie jar) rather than a remote URL.
// Only consulted for shellFetchCommands, so `-c` here is curl's cookie-jar and
// never `sh -c`.
var shellFileArgFlags = map[string]bool{
	"-o": true, "--output": true,
	"-O": true, "--output-document": true,
	"-D": true, "--dump-header": true,
	"-c": true, "--cookie-jar": true,
	"--output-file": true, "-a": true, "--append-output": true,
	"--trace": true, "--trace-ascii": true,
	"-K": true, "--config": true,
}

// shellStartsWithRedirection reports whether the text after a command word
// begins with an I/O redirection (`>`, `>>`, `<`, `2>`, `200>&-`) rather than an
// argument. Used to tell `exec 200>"$f"` (FD rebinding) from `exec cmd` (which
// replaces the shell with a command).
func shellStartsWithRedirection(rest string) bool {
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	// An optional leading file-descriptor number.
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	return i < len(rest) && (rest[i] == '>' || rest[i] == '<')
}

// shellHasDashCFlag reports whether a `-c` flag word appears in the raw args of
// a command, marking the `sh -c` / `bash -c` execute-a-string shape.
func shellHasDashCFlag(rawArgs string) bool {
	for _, f := range strings.Fields(rawArgs) {
		if f == "-c" {
			return true
		}
	}
	return false
}

// shellArg is a single command argument word paired with whether it was
// single-quoted (fully literal — its `$` expansions are inert).
type shellArg struct {
	code        string // code-view text of the word (literals blanked, expansions kept)
	raw         string // raw-view text of the word, needed to read literal FLAG words
	singleQuote bool   // true when the word is wholly single-quoted (no expansion)
}

// splitShellArgs splits a command's argument text into words. The CODE view has
// double-quoted / literal text blanked to spaces (only expansions remain), so a
// double-quoted word collapses to its expansions; the RAW view carries the
// quotes so a single-quoted word can be detected (its expansions are inert).
// Words are separated by unquoted whitespace in the raw view.
func splitShellArgs(code, raw string) []shellArg {
	aligned := len(code) == len(raw)
	if !aligned {
		// Fall back to a plain whitespace split of the code view.
		var out []shellArg
		for _, f := range strings.Fields(code) {
			out = append(out, shellArg{code: f, raw: f})
		}
		return out
	}
	var out []shellArg
	i := 0
	n := len(raw)
	for i < n {
		// Skip separating whitespace.
		for i < n && (raw[i] == ' ' || raw[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		wordStart := i
		singleQuoted := false
		for i < n {
			c := raw[i]
			if c == ' ' || c == '\t' {
				break
			}
			if c == '\'' {
				singleQuoted = true
				i++
				for i < n && raw[i] != '\'' {
					i++
				}
				if i < n {
					i++ // closing quote
				}
				continue
			}
			if c == '"' {
				i++
				for i < n && raw[i] != '"' {
					// A backslash escapes the next byte — but only when there IS a
					// next byte. Without the bound check a word ending in a lone
					// backslash advanced i past the end of the string.
					if raw[i] == '\\' && i+1 < n {
						i++
					}
					i++
				}
				if i < n {
					i++
				}
				continue
			}
			i++
		}
		// Defensive clamp: every scanner branch above is bounded by n, but the
		// slices below must never be able to run off the end of either view.
		wordEnd := min(i, n)
		codeWord := ""
		if wordEnd <= len(code) {
			codeWord = code[wordStart:wordEnd]
		}
		out = append(out, shellArg{
			code:        codeWord,
			raw:         raw[wordStart:wordEnd],
			singleQuote: singleQuoted && !strings.ContainsAny(codeWord, "$"),
		})
	}
	return out
}

// shellArgVars returns the live variable reads in a command argument word. A
// wholly single-quoted word yields none (its `$` is inert). Otherwise the word's
// `$var` / `${var}` / `$(...)`-nested expansions surface as reads; positional /
// special parameters (`$1`, `$@`) are NOT variable reads here (they are sources
// captured at assignment), so only NAMED variables are returned.
func shellArgVars(a shellArg) []string {
	if a.singleQuote {
		return nil
	}
	return shellNamedExpansions(a.code)
}

// addShellExpansionReads adds every NAMED variable expansion in an assignment's
// RHS code to the statement's reads (so `cmd="run ${input}"` propagates taint
// from input). Positional/special sources are added separately as markers.
func addShellExpansionReads(st *stmtDraft, rhsCode string) {
	for _, v := range shellNamedExpansions(rhsCode) {
		st.reads = appendUnique(st.reads, v)
	}
}

// addShellSourceMarkers inspects an assignment RHS for taint SOURCES and records
// a matching marker in st.calls so resolveSource finds it:
//   - positional / special parameters `$1`..`$9`, `$@`, `$*`, `$#` → marker "$1"…
//   - a `$(...)` / backtick command substitution of a known input command
//     (`cat -`) → the inner command's callee is surfaced as a read/call already.
//
// The marker strings match the shell catalog's `call` values verbatim.
func addShellSourceMarkers(st *stmtDraft, rhsCode, _ string) {
	for _, m := range shellPositionalMarkers(rhsCode) {
		st.calls = appendUnique(st.calls, m)
		if st.sinkArgs == nil {
			st.sinkArgs = map[string]sinkArgDraft{}
		}
	}
	// A `$REPLY` / `$QUERY_STRING` env-style source is a NAMED expansion; it is
	// already in reads. Surface it as a chain so resolveSource matches the catalog
	// source by name (the catalog lists `REPLY`, `QUERY_STRING`, etc.).
	for _, v := range shellNamedExpansions(rhsCode) {
		st.chains = appendUnique(st.chains, v)
	}
	// A command substitution `$(cmd …)` names cmd; surface it as a call so a
	// source command (`cat`) resolves. The inner callee is the first word after
	// `$(`.
	for _, callee := range shellCommandSubCallees(rhsCode) {
		st.calls = appendUnique(st.calls, callee)
	}
}

// shellPositionalMarkers returns the positional/special-parameter source markers
// present in code, as the exact strings the catalog keys on (`$1`, `$@`, `$*`,
// `$#`, `$2`, …). Deduplicated, in first-seen order.
func shellPositionalMarkers(code string) []string {
	var out []string
	seen := map[string]struct{}{}
	i := 0
	n := len(code)
	for i < n {
		if code[i] != '$' {
			i++
			continue
		}
		if i+1 >= n {
			break
		}
		c := code[i+1]
		var marker string
		switch {
		case c >= '0' && c <= '9':
			marker = "$" + string(c)
		case c == '@' || c == '*' || c == '#':
			marker = "$" + string(c)
		}
		if marker != "" {
			if _, dup := seen[marker]; !dup {
				seen[marker] = struct{}{}
				out = append(out, marker)
			}
		}
		i += 2
	}
	return out
}

// shellNamedExpansions returns the NAMED variable expansions in code: `$name`
// and `${name}` (the leading name of a `${name:-default}` too). Positional /
// special parameters are excluded (they are handled as markers). Deduplicated,
// in first-seen order.
func shellNamedExpansions(code string) []string {
	var out []string
	seen := map[string]struct{}{}
	i := 0
	n := len(code)
	for i < n {
		if code[i] != '$' {
			i++
			continue
		}
		j := i + 1
		if j < n && code[j] == '{' {
			j++
			// Skip a leading `#` (length) or `!` (indirection) sigil.
			for j < n && (code[j] == '#' || code[j] == '!') {
				j++
			}
			start := j
			for j < n && isShellIdentByte(code[j]) {
				j++
			}
			name := code[start:j]
			if name != "" && isShellIdentStart(name[0]) {
				addUniqueName(&out, seen, name)
			}
			i = j
			continue
		}
		if j < n && isShellIdentStart(code[j]) {
			start := j
			for j < n && isShellIdentByte(code[j]) {
				j++
			}
			addUniqueName(&out, seen, code[start:j])
			i = j
			continue
		}
		i++
	}
	return out
}

// shellCommandSubCallees returns the callee of each `$(cmd …)` command
// substitution in code (the first word after `$(`), used so a source command
// like `cat` inside `$(cat -)` resolves as a source. Backtick substitutions are
// also scanned. Deduplicated.
func shellCommandSubCallees(code string) []string {
	var out []string
	seen := map[string]struct{}{}
	i := 0
	n := len(code)
	for i < n {
		var inner int
		switch {
		case code[i] == '$' && i+1 < n && code[i+1] == '(':
			inner = i + 2
		case code[i] == '`':
			inner = i + 1
		default:
			i++
			continue
		}
		for inner < n && (code[inner] == ' ' || code[inner] == '\t') {
			inner++
		}
		start := inner
		for inner < n && isShellCommandByte(code[inner]) {
			inner++
		}
		if inner > start {
			token := code[start:inner]
			if isShellIdentStart(token[0]) {
				if callee := shellCalleeName(token); callee != "" {
					addUniqueName(&out, seen, callee)
				}
			}
		}
		i = inner
	}
	return out
}

// addUniqueName appends name to out if not already present.
func addUniqueName(out *[]string, seen map[string]struct{}, name string) {
	if name == "" {
		return
	}
	if _, dup := seen[name]; dup {
		return
	}
	seen[name] = struct{}{}
	*out = append(*out, name)
}

// skipShellLeadingAssignments returns the index in code past any leading
// `FOO=bar` environment-assignment prefixes on a command line, so the real
// command word is the callee. A single leading assignment with NO following
// command is handled by shellAssignment before this is reached.
func skipShellLeadingAssignments(code string) int {
	i := 0
	for {
		for i < len(code) && (code[i] == ' ' || code[i] == '\t') {
			i++
		}
		start := i
		if i >= len(code) || !isShellIdentStart(code[i]) {
			return start
		}
		j := i
		for j < len(code) && isShellIdentByte(code[j]) {
			j++
		}
		if j < len(code) && code[j] == '=' && (j+1 >= len(code) || code[j+1] != '=') {
			// It is an env-assignment prefix; skip the whole `NAME=word` token.
			k := j + 1
			for k < len(code) && code[k] != ' ' && code[k] != '\t' {
				k++
			}
			i = k
			continue
		}
		return start
	}
}

// isShellIdentStart reports whether b can begin a shell identifier / var name.
func isShellIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isShellIdentByte reports whether b can appear inside a shell identifier.
func isShellIdentByte(b byte) bool {
	return isShellIdentStart(b) || (b >= '0' && b <= '9')
}

// isShellCommandByte reports whether b can appear inside a command name token.
// Command names may include `/`, `.`, and `-` (paths and hyphenated commands);
// shellCalleeName normalizes the scanned token to its bare final segment. A
// leading `.` (the source/dot builtin) is handled specially by the caller.
//
// Accepting `-` is what keeps a hyphenated command NAME whole. Stopping at the
// hyphen truncated `exec-add-path` — an ordinary user-defined function — to
// `exec`, which is an exact-match command-injection sink, so any tainted
// argument to it was reported as CWE-78.
func isShellCommandByte(b byte) bool {
	return isShellIdentByte(b) || b == '-' || b == '.' || b == '/'
}

// shellCalleeName normalizes a scanned command token to the name the catalog is
// keyed on: its final path segment, so `/usr/bin/curl` and `./curl` both resolve
// as `curl`. A token that is all separators yields "".
func shellCalleeName(token string) string {
	if idx := strings.LastIndexByte(token, '/'); idx >= 0 {
		return token[idx+1:]
	}
	return token
}
