package engine

import "strings"

// shapePowerShellLine rewrites a logical line's code and raw views into the shape
// the shared recognizer understands. The transforms are applied IDENTICALLY to
// both views so their byte offsets stay mutually aligned (the recognizer slices
// raw by offsets found in code); the 1-based line number is preserved.
//
// Order matters: casts are rewritten before the sigil is stripped (a cast reads
// `[int]$x`), the `& ` call operator before paren-less wrapping, and the cmdlet
// hyphen normalization before the call recognizer scans identifiers.
func shapePowerShellLine(ll logicalLine) logicalLine {
	code := shapePowerShellExpr(ll.code)
	raw := shapePowerShellExpr(ll.raw)
	// The pipeline rewrite runs last and needs BOTH views at once: a `|` is only
	// an operator when it is not inside a string, and string bodies are blanked
	// in the code view alone. Deciding from raw would read a regex alternation
	// (`'^start|stop$'`) as a pipeline.
	code, raw = desugarPowerShellPipeline(code, raw)
	return logicalLine{line: ll.line, code: code, raw: raw}
}

// desugarPowerShellPipeline rewrites a pipeline `a | Cmd1 args | Cmd2` into the
// nested positional form `Cmd2(Cmd1(a, args))`. Binding to a cmdlet's PIPELINE
// input is a real argument position — `$x | Invoke-Expression` executes `$x`
// exactly as `Invoke-Expression $x` does — so the value has to land in the
// callee's argument list for the shared recognizer to see the flow.
//
// Stages are split at every top-level `|` and folded left, rather than peeled
// one at a time: PowerShell cmdlets are paren-LESS, so a leftmost-peel would
// swallow the remaining `| Cmd2` text into Cmd1's argument list.
//
// Pipe positions come from the CODE view (string bodies blanked) and the same
// structural rewrite is applied to raw while the two stay aligned; once
// alignment is lost raw follows code, matching how the Elixir pipe desugars.
func desugarPowerShellPipeline(code, raw string) (newCode, newRaw string) {
	pipes := powerShellTopLevelPipes(code)
	if len(pipes) == 0 {
		return code, raw
	}
	// An assignment left of the first pipe keeps its LHS: `$out = $x | Cmd`.
	prefixEnd := 0
	if eq := topLevelAssignIndex(code); eq >= 0 && eq < pipes[0] {
		prefixEnd = eq + 1
	}
	rewritten, ok := foldPowerShellPipeline(code, prefixEnd, pipes)
	if !ok {
		return code, raw
	}
	if len(raw) == len(code) {
		if rr, ok := foldPowerShellPipeline(raw, prefixEnd, pipes); ok {
			return rewritten, rr
		}
	}
	return rewritten, rewritten
}

// foldPowerShellPipeline folds the pipeline in s (whose top-level pipes sit at
// the byte offsets in pipes, all at or past prefixEnd) into nested calls,
// preserving everything before prefixEnd verbatim. Returns ok=false when a stage
// past the first has no recognizable command head, leaving the line unshaped
// rather than half-rewritten.
func foldPowerShellPipeline(s string, prefixEnd int, pipes []int) (string, bool) {
	prefix := s[:prefixEnd]
	acc := strings.TrimSpace(s[prefixEnd:pipes[0]])
	if acc == "" {
		return "", false
	}
	for i, p := range pipes {
		end := len(s)
		if i+1 < len(pipes) {
			end = pipes[i+1]
		}
		stage := strings.TrimSpace(s[p+1 : end])
		bound, ok := bindPowerShellStage(acc, stage)
		if !ok {
			return "", false
		}
		acc = bound
	}
	return prefix + acc, true
}

// bindPowerShellStage binds acc as the leading argument of one pipeline stage:
// `Cmd -Flag v` with acc becomes `Cmd(acc, -Flag v)`, and a bare `Cmd` becomes
// `Cmd(acc)`. Returns ok=false when the stage does not start with a command head
// (a scriptblock or a variable stage, which carries no callee to attribute the
// flow to).
func bindPowerShellStage(acc, stage string) (string, bool) {
	i := 0
	for i < len(stage) && (isIdentPart(stage[i]) || stage[i] == '.') {
		i++
	}
	head := stage[:i]
	if head == "" || strings.HasPrefix(head, ".") || isKeyword(head) {
		return "", false
	}
	rest := strings.TrimSpace(stage[i:])
	if rest == "" {
		return head + "(" + acc + ")", true
	}
	// An already-parenthesized stage `Cmd(a)` takes acc as its first argument.
	if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
		inner := strings.TrimSpace(rest[1 : len(rest)-1])
		if inner == "" {
			return head + "(" + acc + ")", true
		}
		return head + "(" + acc + ", " + inner + ")", true
	}
	return head + "(" + acc + ", " + rest + ")", true
}

// powerShellTopLevelPipes returns the byte offsets of every pipeline `|` in code
// that is not nested inside brackets or braces. A `||` (the PowerShell 7
// pipeline-CHAIN operator, which passes no value) is skipped: it is control
// flow, not dataflow. A `|` inside a string is already blanked in the code view.
func powerShellTopLevelPipes(code string) []int {
	var out []int
	depth := 0
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '|':
			if i+1 < len(code) && code[i+1] == '|' {
				i++ // `||` chain operator: passes no value
				continue
			}
			if i > 0 && code[i-1] == '|' {
				continue
			}
			if depth == 0 {
				out = append(out, i)
			}
		}
	}
	return out
}

// shapePowerShellExpr applies the PowerShell → shared-recognizer rewrites to one
// text view. Every transform is byte-for-byte identical on the code and raw
// views, so applying it to both keeps them aligned to each other.
func shapePowerShellExpr(s string) string {
	s = rewritePowerShellCasts(s)      // [int]$x -> int($x)
	s = rewriteStaticMember(s)         // [IO.File]::ReadAllText -> IO.File.ReadAllText
	s = strings.ReplaceAll(s, "$", "") // drop the variable sigil (like PHP)
	s = rewriteEnvProvider(s)          // env:NAME -> env NAME (bare `env` source read)
	s = rewriteCmdletHyphens(s)        // Invoke-Expression -> Invoke_Expression
	s = rewriteAmpInvoke(s)            // & cmd args -> InvokeOperator(cmd args)
	s = addPowerShellCallParens(s)     // Get-Content p -> Get_Content(p)
	return s
}

// psCastTypes are the numeric cast accelerators that act as sanitizers: coercing
// a value to one of them strips every injection metacharacter.
var psCastTypes = []string{"int", "long", "int32", "int64", "uint", "double", "decimal", "bool"}

// rewritePowerShellCasts rewrites a leading numeric cast `[int]TERM` into a call
// `int(TERM)` so the coercion is recognized as a sanitizer. TERM is the next
// balanced term after the cast: a `$var`, a parenthesized group `(...)`, or a
// bare word. Non-numeric casts (`[string]`, `[IO.File]`) are left for
// rewriteStaticMember / stripping. Width is not preserved, but the same transform
// runs on both views so they stay mutually aligned.
func rewritePowerShellCasts(s string) string {
	for _, t := range psCastTypes {
		marker := "[" + t + "]"
		for {
			idx := strings.Index(s, marker)
			if idx < 0 {
				break
			}
			after := idx + len(marker)
			termEnd := powerShellTermEnd(s, after)
			if termEnd <= after {
				// Nothing to cast (e.g. a lone `[int]` type reference); neutralize the
				// brackets so the loop terminates and no false call is produced.
				s = s[:idx] + t + " " + s[after:]
				continue
			}
			term := s[after:termEnd]
			s = s[:idx] + t + "(" + term + ")" + s[termEnd:]
		}
	}
	return s
}

// powerShellTermEnd returns the offset just past the term beginning at i: a
// `$var` / bare identifier (with an optional `$`), or a parenthesized group.
// Returns i when there is no term (e.g. a following operator or end of string).
func powerShellTermEnd(s string, i int) int {
	n := len(s)
	for i < n && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= n {
		return i
	}
	if s[i] == '(' {
		depth := 0
		for j := i; j < n; j++ {
			switch s[j] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
		}
		return n
	}
	j := i
	if s[j] == '$' {
		j++
	}
	if j >= n || !isIdentStart(s[j]) {
		return i
	}
	for j < n && (isIdentPart(s[j]) || s[j] == '.' || s[j] == ':') {
		j++
	}
	return j
}

// rewriteStaticMember rewrites the `::` static-member operator to `.` and unwraps
// a preceding type-accelerator bracket, so `[IO.File]::ReadAllText($p)` reads as
// the dotted chain `IO.File.ReadAllText($p)` matched by the `.ReadAllText`
// suffix. A `::` not preceded by `]` (rare) just becomes `.`.
func rewriteStaticMember(s string) string {
	if !strings.Contains(s, "::") {
		return s
	}
	// Drop the accelerator brackets `[Type]::` so the type name joins the chain.
	// Replace "]::" with "." and the matching "[" before it with nothing.
	b := []byte(s)
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if i+1 < len(b) && b[i] == ':' && b[i+1] == ':' {
			out = append(out, '.')
			i++
			continue
		}
		if b[i] == '[' || b[i] == ']' {
			// Only strip a bracket that participates in a static-member access; a
			// bracket far from a `::` is left alone by keeping it unless it is the
			// accelerator wrapper. Simplest safe rule: drop `[`/`]` only when a `::`
			// exists on the line (already guaranteed) AND the bracket wraps a
			// Type.Path token (letters/dots). Fall back to keeping it otherwise.
			if bracketWrapsTypeName(b, i) {
				continue
			}
		}
		out = append(out, b[i])
	}
	return string(out)
}

// bracketWrapsTypeName reports whether the bracket at index i is part of a type
// accelerator `[Namespace.Type]` (its contents are letters, digits, and dots).
// Used to decide whether to drop the bracket when unwrapping a `::` static call.
func bracketWrapsTypeName(b []byte, i int) bool {
	if b[i] == '[' {
		for j := i + 1; j < len(b); j++ {
			if b[j] == ']' {
				return j > i+1
			}
			if !isIdentPart(b[j]) && b[j] != '.' {
				return false
			}
		}
		return false
	}
	// b[i] == ']': scan backwards to the matching '['.
	for j := i - 1; j >= 0; j-- {
		if b[j] == '[' {
			return i > j+1
		}
		if !isIdentPart(b[j]) && b[j] != '.' {
			return false
		}
	}
	return false
}

// rewriteEnvProvider rewrites the `env:NAME` provider access (after the `$` sigil
// was stripped) into a bare `env NAME` so `env` surfaces as a free-identifier
// source read. `$env:PATH` → (sigil stripped) `env:PATH` → `env PATH`.
func rewriteEnvProvider(s string) string {
	if !strings.Contains(s, "env:") {
		return s
	}
	return strings.ReplaceAll(s, "env:", "env ")
}

// rewriteCmdletHyphens normalizes a `Verb-Noun` cmdlet/command name's hyphen to
// an underscore so the shared token scanner (which treats `-` as an operator)
// reads it as one identifier. It only rewrites a hyphen that sits BETWEEN two
// identifier bytes AND is not preceded by whitespace-then-hyphen (a `-Param`
// flag) — i.e. a hyphen inside a Verb-Noun token, never the `-` of an operator
// (`-eq`, `-match`) or a named parameter (`-Uri`). The catalog is keyed on the
// resulting underscore form.
func rewriteCmdletHyphens(s string) string {
	b := []byte(s)
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '-' && i > 0 && i+1 < len(b) &&
			isIdentPart(b[i-1]) && isIdentStart(b[i+1]) {
			// A `-` between two identifier bytes is a cmdlet hyphen ONLY when the
			// left side is a word that is itself preceded by a boundary (start,
			// space, or a call/pipe operator), not an operand of a binary `-`. Since
			// a named parameter `-Uri` is `<space>-Uri` (space before `-`), and an
			// operator `$a-eq` is rare (PowerShell requires spaces around -eq), the
			// "between two identifier bytes with no surrounding space" test cleanly
			// isolates Verb-Noun.
			out = append(out, '_')
			continue
		}
		out = append(out, b[i])
	}
	return string(out)
}

// rewriteAmpInvoke rewrites the call operator `& cmd args` (invoke a command
// whose name is in a variable/string) into a synthetic call
// `InvokeOperator(cmd args)`, a command-injection sink. It fires only when `&`
// leads the statement (optionally after an assignment `=`), so a bitwise/`-band`
// context is not misread. Both `& $cmd` and `. $script` (dot-source) map here.
func rewriteAmpInvoke(s string) string {
	trimmed := strings.TrimLeft(s, " \t")
	indent := s[:len(s)-len(trimmed)]
	// Allow an assignment prefix `x = & cmd`.
	prefix := ""
	body := trimmed
	if eq := topLevelAssignIndex(trimmed); eq >= 0 {
		prefix = trimmed[:eq+1]
		body = strings.TrimLeft(trimmed[eq+1:], " \t")
	}
	if !strings.HasPrefix(body, "& ") && !strings.HasPrefix(body, "&\t") {
		return s
	}
	args := strings.TrimSpace(body[1:])
	if args == "" {
		return s
	}
	return indent + prefix + " InvokeOperator(" + args + ")"
}

// addPowerShellCallParens detects a leading paren-less command call
// (`Get_Content p`, `Invoke_Expression u`, `Invoke_WebRequest -Uri url`) and
// rewrites it to `Get_Content(p)` so the shared call recognizer sees a call. It
// only fires when the line is NOT already an assignment or a parenthesized call
// and the head is a bare command identifier. The whole remaining argument text
// (including any `-Param` flags, which begin with `-` and are ignored by the
// identifier scanner) becomes the call's arguments.
func addPowerShellCallParens(code string) string {
	if hasTopLevelAssign(code) {
		// An assignment RHS may itself be a paren-less call: `$x = Get-Content $p`.
		// Shape only the RHS.
		eq := topLevelAssignIndex(code)
		if eq < 0 {
			return code
		}
		lhs := code[:eq+1]
		rhs := code[eq+1:]
		return lhs + addPowerShellCallParens(rhs)
	}
	// Leading whitespace then a command head.
	i := 0
	n := len(code)
	for i < n && (code[i] == ' ' || code[i] == '\t') {
		i++
	}
	indent := code[:i]
	start := i
	for i < n && (isIdentPart(code[i]) || code[i] == '.') {
		i++
	}
	head := code[start:i]
	if head == "" || strings.HasPrefix(head, ".") || isKeyword(head) {
		return code
	}
	// Skip a run of spaces to the first argument.
	argStart := i
	for argStart < n && (code[argStart] == ' ' || code[argStart] == '\t') {
		argStart++
	}
	if argStart >= n {
		return code // bare `Foo` — a variable read / no-arg command, not a call
	}
	if code[argStart] == '(' {
		return code // already a call
	}
	if code[argStart] == '|' || code[argStart] == '=' {
		return code // pipeline / assignment, not a paren-less call
	}
	if !canBeginPSArg(code[argStart]) {
		return code
	}
	end := n
	for end > argStart && (code[end-1] == ' ' || code[end-1] == '\t') {
		end--
	}
	return indent + head + "(" + code[argStart:end] + ")" + code[end:]
}

// canBeginPSArg reports whether b can start a PowerShell paren-less call
// argument: a variable (after sigil strip, a letter/underscore), a string quote,
// a `-Param` flag, a digit, a `$` (unlikely post-strip), a `[` array, or an `@`
// splat/here-string remnant.
func canBeginPSArg(b byte) bool {
	if isIdentStart(b) {
		return true
	}
	switch b {
	case '"', '\'', '-', '[', '@', '.', '$':
		return true
	}
	return b >= '0' && b <= '9'
}
