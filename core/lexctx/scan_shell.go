package lexctx

// scanShell walks POSIX-shell / Bash source and classifies each byte as code,
// string, or comment. Shell's grammar is word-oriented and famously context
// sensitive; a full parser is out of scope (pure-Go, no CGo, no dependency), so
// this is a deliberately PRAGMATIC, deterministic classifier that recognizes the
// constructs carrying the overwhelming majority of secret/pattern and taint
// false positives:
//
//   - `#` line comments (to end of line) — but ONLY when `#` sits in a
//     comment-start position (start of a word: at line start or after
//     whitespace / `;` / `|` / `&` / `(`). A `#` inside `${#var}` (string
//     length), `$#` (positional count), a word like `id#42`, or a string is NOT
//     a comment.
//   - single-quoted strings `'...'` — fully literal, no interpolation, and even a
//     backslash is literal (only the closing `'` ends them).
//   - double-quoted strings `"..."` — literal text is string, but `$var`,
//     `${...}`, `$(...)`, and backtick command substitutions inside are CODE (a
//     tainted value spliced via "id=$user" lives in a real expression). Backslash
//     escapes the next byte.
//   - ANSI-C strings `$'...'` — backslash escapes (\n, \t, \') are honored; the
//     whole body is string (no interpolation).
//   - backtick “ `...` “ and `$(...)` command substitution in CODE context —
//     their inner text is code (it is a command line, not a literal). The taint
//     layer treats the substitution as a command-execution carrier.
//   - heredocs `<<EOF`, `<<'EOF'`, `<<"EOF"`, and the dash form `<<-EOF` (which
//     permits a tab-indented terminator). The body from the next line up to the
//     terminator line is string; a `<<'EOF'`/`<<"EOF"` (quoted delimiter) body is
//     equally string. The `<<<word` here-string is NOT a heredoc (handled as
//     ordinary code).
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0,len(content)).
// Every heuristic degrades safely: a misread only costs FP-suppression, never
// correctness, because an over-broad code region merely disables suppression.
func scanShell(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	// prevByte is the immediately preceding source byte (0 at start of file). A
	// `#` begins a comment only when it opens a word — at line start or right
	// after whitespace or a command separator — which is exactly what prevByte
	// captures. prevByte is updated for EVERY consumed byte, whitespace included.
	var prevByte byte

	for i < n {
		c := content[i]

		switch {
		case c == '\n':
			b.emit(i, i+1, KindCode)
			i++
			prevByte = '\n'
			continue

		case c == '#' && isShellCommentStart(prevByte):
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
			prevByte = '#'
			// The trailing '\n' (if any) is handled on the next iteration.
			continue

		case c == '\'':
			end := scanShellSingleQuote(content, i)
			b.emit(i, end, KindString)
			i = end
			prevByte = '\''
			continue

		case c == '"':
			i = scanShellDoubleQuote(content, i, &b)
			prevByte = '"'
			continue

		case c == '$' && i+1 < n && content[i+1] == '\'':
			end := scanShellAnsiCString(content, i)
			b.emit(i, end, KindString)
			i = end
			prevByte = '\''
			continue

		case c == '$' && i+1 < n && content[i+1] == '(':
			// $(...) command substitution in code context: the whole thing stays
			// code (the inner text is a command line). Emit as code and skip past
			// the balanced parens so a `#`/quote inside cannot be misread.
			end := scanShellCommandSub(content, i+1)
			b.emit(i, end, KindCode)
			i = end
			prevByte = ')'
			continue

		case c == '`':
			// Backtick command substitution in code context: inner text is a
			// command line, so it is CODE (like $(...)). This is why an interpolated
			// tainted variable inside a backtick command is visible to the taint
			// layer as a live read rather than an inert string.
			end := scanShellBacktick(content, i)
			b.emit(i, end, KindCode)
			i = end
			prevByte = '`'
			continue

		case c == '<' && i+1 < n && content[i+1] == '<' &&
			isShellHeredocStart(content, i):
			i = scanShellHeredoc(content, i, &b)
			prevByte = '\n' // the heredoc scanner consumes through a newline
			continue

		default:
			b.emit(i, i+1, KindCode)
			prevByte = c
			i++
			continue
		}
	}
	return b.finish(n)
}

// isShellCommentStart reports whether a `#` following prev (the immediately
// preceding source byte, 0 at start of file) begins a comment. In shell a `#`
// only starts a comment at the beginning of a word: at the start of a line (prev
// is 0 or a newline), or right after whitespace or a command separator (`;`,
// `|`, `&`, `(`). After an identifier byte, a digit, `$`, `{`, `}`, or any other
// word character it is literal (part of `$#`, `${#x}`, `id#42`, a URL fragment).
func isShellCommentStart(prev byte) bool {
	switch prev {
	case 0, '\n', ' ', '\t', '\r', ';', '|', '&', '(':
		return true
	}
	return false
}

// scanShellSingleQuote returns the offset just past a single-quoted string
// opening at start. In shell single quotes are fully literal — not even a
// backslash escapes — so the string ends at the next `'`. An unterminated
// literal runs to EOF.
func scanShellSingleQuote(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		if content[i] == '\'' {
			return i + 1
		}
		i++
	}
	return n
}

// scanShellAnsiCString returns the offset just past a `$'...'` ANSI-C string
// opening at start (content[start]=='$', content[start+1]=='\”). Backslash
// escapes the next byte (so `\'` does not close the string). Unterminated runs
// to EOF.
func scanShellAnsiCString(content []byte, start int) int {
	n := len(content)
	i := start + 2 // past `$'`
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '\'':
			return i + 1
		}
		i++
	}
	return n
}

// scanShellDoubleQuote classifies a double-quoted string opening at start,
// emitting literal parts as string and each interpolation (`$var`, `${...}`,
// `$(...)`, backtick) as code. Backslash escapes the next byte. It emits into b
// directly because interpolation splits the region. Returns the offset just past
// the closing quote (or EOF).
func scanShellDoubleQuote(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	bodyStart := start + 1
	b.emit(start, bodyStart, KindString) // opening quote is string
	i := bodyStart
	runStart := bodyStart
	for i < n {
		c := content[i]
		if c == '\\' {
			i += 2
			continue
		}
		if c == '"' {
			b.emit(runStart, i+1, KindString)
			return i + 1
		}
		if c == '`' {
			// Backtick command sub inside the string: flush string run, emit as code.
			b.emit(runStart, i, KindString)
			end := scanShellBacktick(content, i)
			b.emit(i, end, KindCode)
			i = end
			runStart = i
			continue
		}
		if c == '$' && i+1 < n {
			// $(...) command sub, ${...} parameter expansion, or $var — all code.
			fieldEnd, ok := scanShellDollarField(content, i)
			if ok {
				b.emit(runStart, i, KindString)
				b.emit(i, fieldEnd, KindCode)
				i = fieldEnd
				runStart = i
				continue
			}
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanShellDollarField returns the offset just past a `$`-expansion beginning at
// content[open]=='$', and whether the `$` in fact begins an expansion (a `$`
// followed by a non-expansion byte such as a space or `"` is a literal dollar).
// It handles `$(...)` command substitution and `$((...))` arithmetic, `${...}`
// parameter expansion (brace-balanced), and `$name` / `$1` / `$@` / `$#` simple
// expansions.
func scanShellDollarField(content []byte, open int) (int, bool) {
	n := len(content)
	if open+1 >= n {
		return open, false
	}
	next := content[open+1]
	switch {
	case next == '(':
		// $(( arithmetic )) or $( command ). scanShellCommandSub balances parens
		// and naturally consumes the doubled parens of arithmetic too.
		return scanShellCommandSub(content, open+1), true
	case next == '{':
		return scanShellBraceExpansion(content, open+2), true
	case isShellSpecialParam(next):
		return open + 2, true
	case isShellNameStart(next):
		i := open + 2
		for i < n && isShellNameByte(content[i]) {
			i++
		}
		return i, true
	default:
		return open, false
	}
}

// scanShellBraceExpansion returns the offset just past a `${...}` parameter
// expansion whose first inner byte is at bodyStart. Braces balance so a nested
// `${...}` (e.g. default-value `${x:-${y}}`) does not close early.
func scanShellBraceExpansion(content []byte, bodyStart int) int {
	n := len(content)
	depth := 1
	i := bodyStart
	for i < n {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		case '\'':
			i = scanShellSingleQuote(content, i)
			continue
		}
		i++
	}
	return n
}

// scanShellCommandSub returns the offset just past a `$(...)` command
// substitution whose opening `(` is at open. Parens balance; nested quotes and
// `$(...)` are skipped so a `)` inside a string does not close it early.
func scanShellCommandSub(content []byte, open int) int {
	n := len(content)
	depth := 0
	i := open
	for i < n {
		switch content[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		case '\'':
			i = scanShellSingleQuote(content, i)
			continue
		case '"':
			i = skipShellNestedDouble(content, i)
			continue
		}
		i++
	}
	return n
}

// scanShellBacktick returns the offset just past a backtick command
// substitution opening at start. Backslash escapes the next byte; the closing
// backtick ends it.
func scanShellBacktick(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '`':
			return i + 1
		}
		i++
	}
	return n
}

// skipShellNestedDouble returns the offset just past a nested double-quoted
// string opening at start, honoring backslash escapes. Used only to keep
// paren-balancing honest inside a command substitution; the inner region is not
// separately classified (it stays inside the outer code field, which is
// harmless — the whole substitution is already code).
func skipShellNestedDouble(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '"':
			return i + 1
		}
		i++
	}
	return n
}

// isShellHeredocStart reports whether `<<` at i begins a heredoc rather than a
// here-string (`<<<`) or a `<< ` used elsewhere. A heredoc delimiter follows
// `<<`, an optional `-`, optional whitespace, and then a bare word or a
// quoted/backslash-escaped word. `<<<` (here-string) is rejected.
func isShellHeredocStart(content []byte, i int) bool {
	n := len(content)
	j := i + 2 // past `<<`
	if j < n && content[j] == '<' {
		return false // `<<<` here-string, not a heredoc
	}
	if j < n && content[j] == '-' {
		j++
	}
	for j < n && (content[j] == ' ' || content[j] == '\t') {
		j++
	}
	if j >= n {
		return false
	}
	c := content[j]
	return c == '\'' || c == '"' || c == '\\' || isShellNameStart(c)
}

// scanShellHeredoc classifies a heredoc opening at start. The opener line (from
// start through the newline, including any trailing code such as a `> file`
// redirect) is emitted as CODE; the body — the lines from the next line up to
// (but not including) the terminator line — is emitted as string; the terminator
// line is code. A dash heredoc (`<<-`) permits a tab-indented terminator. A
// quoted delimiter (`<<'EOF'`) suppresses interpolation but does not change
// lexical classification (the body is string either way).
func scanShellHeredoc(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	j := start + 2 // past `<<`
	dash := false
	if j < n && content[j] == '-' {
		dash = true
		j++
	}
	for j < n && (content[j] == ' ' || content[j] == '\t') {
		j++
	}
	// Read the delimiter word (possibly quoted or backslash-escaped).
	term := readShellHeredocDelim(content, j)

	// Emit the opener line (start..end-of-line inclusive of its newline) as code.
	lineEnd := start
	for lineEnd < n && content[lineEnd] != '\n' {
		lineEnd++
	}
	if lineEnd < n {
		lineEnd++ // include the newline ending the opener line
	}
	b.emit(start, lineEnd, KindCode)

	if len(term) == 0 {
		return lineEnd // malformed opener: nothing more to consume as body
	}

	bodyStart := lineEnd
	i := lineEnd
	for i < n {
		ls := i
		le := i
		for le < n && content[le] != '\n' {
			le++
		}
		if isShellHeredocTerminator(content[ls:le], term, dash) {
			if ls > bodyStart {
				b.emit(bodyStart, ls, KindString)
			}
			termEnd := le
			if termEnd < n {
				termEnd++ // include the terminator's newline
			}
			b.emit(ls, termEnd, KindCode)
			return termEnd
		}
		i = le
		if i < n {
			i++
		}
	}
	// Unterminated heredoc: the rest of the file is body (string).
	if n > bodyStart {
		b.emit(bodyStart, n, KindString)
	}
	return n
}

// readShellHeredocDelim reads the heredoc delimiter word starting at j. A quoted
// (`'EOF'` / `"EOF"`) or backslash-escaped (`\EOF`) delimiter yields the bare
// word without quotes/backslash; an unquoted delimiter is the leading run of
// name bytes. Returns nil for a malformed (empty) delimiter.
func readShellHeredocDelim(content []byte, j int) []byte {
	n := len(content)
	if j >= n {
		return nil
	}
	switch content[j] {
	case '\'', '"':
		q := content[j]
		j++
		startTok := j
		for j < n && content[j] != q {
			j++
		}
		return content[startTok:j]
	case '\\':
		j++ // skip the backslash; the word follows
	}
	startTok := j
	for j < n && isShellNameByte(content[j]) {
		j++
	}
	if j == startTok {
		return nil
	}
	return content[startTok:j]
}

// isShellHeredocTerminator reports whether line is the heredoc terminator for
// term. For a dash heredoc (`<<-`) leading TABS are ignored; otherwise the
// terminator must be at column 0. Trailing carriage returns are tolerated.
func isShellHeredocTerminator(line, term []byte, dash bool) bool {
	s := line
	if dash {
		k := 0
		for k < len(s) && s[k] == '\t' {
			k++
		}
		s = s[k:]
	}
	// Tolerate a trailing carriage return.
	for len(s) > 0 && s[len(s)-1] == '\r' {
		s = s[:len(s)-1]
	}
	if len(s) != len(term) {
		return false
	}
	for i := range term {
		if s[i] != term[i] {
			return false
		}
	}
	return true
}

// isShellNameStart reports whether c can begin a shell variable name.
func isShellNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isShellNameByte reports whether c can appear inside a shell variable name.
func isShellNameByte(c byte) bool {
	return isShellNameStart(c) || (c >= '0' && c <= '9')
}

// isShellSpecialParam reports whether c is a special positional/parameter that
// forms a one-character expansion after `$`: `$1`..`$9`, `$@`, `$*`, `$#`, `$?`,
// `$$`, `$!`, `$-`, `$0`. This is why a `$#` is not read as a comment `#`.
func isShellSpecialParam(c byte) bool {
	switch c {
	case '@', '*', '#', '?', '$', '!', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return true
	}
	return false
}
