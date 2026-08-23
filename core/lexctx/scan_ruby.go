package lexctx

// scanRuby walks Ruby source and classifies each byte as code, string, or
// comment. Ruby's grammar is famously context-sensitive; a full parser is out of
// scope (pure-Go, no CGo, no dependency), so this is a deliberately PRAGMATIC,
// deterministic classifier. It recognizes the constructs that carry the
// overwhelming majority of secret/pattern and taint false positives:
//
//   - `#` line comments (to end of line) — but NOT a `#` inside a string or the
//     `#{` of an interpolation, which the string scanner consumes first.
//   - `=begin` / `=end` block comments. Ruby requires BOTH markers to start at
//     column 0; the classifier enforces that so an indented `=begin` (a syntax
//     error in real Ruby) never swallows the rest of the file as comment.
//   - single-quoted strings `'...'` — no interpolation, only `\\` and `\'` are
//     escapes.
//   - double-quoted strings `"..."` — backslash escapes AND `#{ ... }`
//     interpolation, whose replacement fields are emitted as CODE (a tainted
//     value spliced via "id=#{params[:id]}" lives in a real expression).
//   - backtick command strings “ `...` “ — lexed as a string (they interpolate
//     like double quotes); note the taint layer treats the backtick call itself
//     as a command-execution sink carrier.
//   - `%w[...]` / `%i[...]` word/symbol arrays and `%q(...)` / `%Q(...)` /
//     `%(...)` general string literals, with matched-bracket delimiters.
//   - heredocs `<<~ID`, `<<-ID`, `<<ID` (and quoted `<<~"ID"` / `<<~'ID'`): the
//     body runs from the next line to a line whose trimmed content equals the
//     terminator. The body is emitted as string.
//   - `/.../ ` regex literals, disambiguated from `/` division by the preceding
//     non-space token (a regex only begins where an operand may not — after `=`,
//     `(`, `,`, `and`, a newline, etc.).
//   - `:symbol` symbols are ordinary code (never a string); a leading `:` is
//     skipped so `:"..."`-style quoted symbols still lex their quote.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
// Every heuristic degrades safely: a misread only costs FP-suppression, never
// correctness, because an over-broad code region merely disables suppression.
func scanRuby(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	// prevSignificant is the last non-space, non-comment code byte emitted — it
	// drives the regex-vs-division and %-literal-vs-modulo heuristics. 0 means
	// "start of file / after a newline" (a position where a literal may begin).
	var prevSignificant byte
	// atColumnZero is true when the cursor sits at the very first byte of a line
	// (no leading whitespace consumed). Ruby's `=begin`/`=end` block-comment
	// markers must start at column 0 exactly, so an indented `=begin` (a real Ruby
	// syntax error) must NOT open a block comment and swallow the file.
	atColumnZero := true

	for i < n {
		c := content[i]

		// =begin / =end block comment: only when '=' is at column 0 (start of the
		// physical line, no leading whitespace) and followed by "begin".
		if atColumnZero && c == '=' && hasWordAt(content, i+1, "begin") {
			end := scanRubyBlockComment(content, i)
			b.emit(i, end, KindComment)
			i = end
			atColumnZero = true // block comment consumes through a trailing newline
			prevSignificant = 0
			continue
		}

		// Any byte we are about to consume means we are no longer at column zero
		// for the current line (a leading space already moves us off column 0, so
		// an indented `=begin` cannot open a block comment). The '\n' case below
		// resets it to true for the next line.
		atColumnZero = false

		switch {
		case c == '#':
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
			// A comment does not change the "operand position" for the next line.
		case c == '\n':
			b.emit(i, i+1, KindCode)
			i++
			atColumnZero = true
			prevSignificant = 0
			continue
		case c == '\'':
			end := scanRubySingleQuote(content, i)
			b.emit(i, end, KindString)
			i = end
			prevSignificant = '"'
		case c == '"':
			i = scanRubyDoubleQuote(content, i, &b)
			prevSignificant = '"'
		case c == '`':
			i = scanRubyBacktick(content, i, &b)
			prevSignificant = '"'
		case c == '%' && isPercentLiteralStart(content, i, prevSignificant):
			i = scanRubyPercentLiteral(content, i, &b)
			prevSignificant = '"'
		case c == '/' && isRegexStart(prevSignificant):
			end := scanRubyRegex(content, i)
			b.emit(i, end, KindString)
			i = end
			prevSignificant = '"'
		case c == '<' && i+1 < n && content[i+1] == '<' && isHeredocStart(content, i, prevSignificant):
			i = scanRubyHeredoc(content, i, &b)
			// The heredoc scanner emits its opener as code and the body as string;
			// after it, we are on a fresh line.
			atColumnZero = true
			prevSignificant = 0
			continue
		default:
			b.emit(i, i+1, KindCode)
			if c != ' ' && c != '\t' && c != '\r' {
				prevSignificant = c
			}
			i++
			continue
		}
	}
	return b.finish(n)
}

// hasWordAt reports whether content[i:] begins with word (used to spot
// `=begin`/`=end` after the leading '=').
func hasWordAt(content []byte, i int, word string) bool {
	if i+len(word) > len(content) {
		return false
	}
	for j := 0; j < len(word); j++ {
		if content[i+j] != word[j] {
			return false
		}
	}
	return true
}

// scanRubyBlockComment returns the offset just past a `=begin ... =end` block
// whose `=begin` starts at start (column 0). The block ends at the newline
// following a line that starts with `=end` at column 0; an unterminated block
// runs to EOF.
func scanRubyBlockComment(content []byte, start int) int {
	n := len(content)
	// Advance to the end of the =begin line.
	i := start
	for i < n && content[i] != '\n' {
		i++
	}
	// Now scan line by line for a `=end` at column 0.
	for i < n {
		// i is at a '\n'; the next line starts at i+1.
		lineStart := i + 1
		if lineStart >= n {
			return n
		}
		if hasWordAt(content, lineStart, "=end") {
			// Consume through the end of the =end line (include its newline).
			j := lineStart
			for j < n && content[j] != '\n' {
				j++
			}
			if j < n {
				j++ // include the trailing newline
			}
			return j
		}
		// Skip to the next newline.
		j := lineStart
		for j < n && content[j] != '\n' {
			j++
		}
		i = j
	}
	return n
}

// scanRubySingleQuote returns the offset just past a single-quoted string
// opening at start. Only `\\` and `\'` are escapes; every other byte (including
// newlines) is literal. An unterminated literal runs to EOF.
func scanRubySingleQuote(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2 // \' or \\ — the next byte is literal
			continue
		case '\'':
			return i + 1
		}
		i++
	}
	return n
}

// scanRubyDoubleQuote classifies a double-quoted string opening at start,
// emitting the literal parts as string and each `#{ ... }` interpolation field
// as code. Backslash escapes are honored. It returns the offset just past the
// closing quote (or EOF). It emits into b directly (like the Python f-string
// scanner) because interpolation splits the region.
func scanRubyDoubleQuote(content []byte, start int, b *regionBuilder) int {
	return scanRubyInterpolated(content, start, '"', b)
}

// scanRubyBacktick classifies a backtick command string opening at start. It
// interpolates like a double-quoted string, so it reuses the interpolation
// scanner; the body is string-kind and `#{}` fields are code.
func scanRubyBacktick(content []byte, start int, b *regionBuilder) int {
	return scanRubyInterpolated(content, start, '`', b)
}

// scanRubyInterpolated is the shared body scanner for the two interpolating
// delimiters (`"` and backtick). close is the closing delimiter byte. Literal
// runs are emitted as string; `#{ ... }` fields (balanced, nesting-aware) are
// emitted as code. Backslash escapes suppress interpolation of the next byte.
func scanRubyInterpolated(content []byte, start int, closeByte byte, b *regionBuilder) int {
	n := len(content)
	// Emit the opening delimiter as string.
	bodyStart := start + 1
	b.emit(start, bodyStart, KindString)
	i := bodyStart
	runStart := bodyStart
	for i < n {
		c := content[i]
		if c == '\\' {
			i += 2
			continue
		}
		if c == '#' && i+1 < n && content[i+1] == '{' {
			// Flush the string run, then emit the interpolation field as code.
			b.emit(runStart, i, KindString)
			fieldEnd := scanRubyInterpField(content, i+1)
			b.emit(i, fieldEnd, KindCode)
			i = fieldEnd
			runStart = i
			continue
		}
		if c == closeByte {
			b.emit(runStart, i+1, KindString)
			return i + 1
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanRubyInterpField returns the offset just past a `#{ ... }` interpolation
// field whose `{` is at open. It balances nested braces and skips nested string
// literals so a `}` inside a nested string does not close the field early.
func scanRubyInterpField(content []byte, open int) int {
	n := len(content)
	depth := 0
	i := open
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
			i = scanRubySingleQuote(content, i)
			continue
		case '"':
			i = skipRubyNestedDouble(content, i)
			continue
		}
		i++
	}
	return n
}

// skipRubyNestedDouble returns the offset just past a nested double-quoted string
// inside an interpolation field, honoring backslash escapes. Nested
// interpolations inside it are not separately classified (they stay inside the
// outer code field, which is harmless — the whole field is already code).
func skipRubyNestedDouble(content []byte, start int) int {
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

// isRegexStart reports whether a `/` following prev begins a regex literal
// rather than a division operator. Heuristic: a regex may only begin where an
// operand is expected — at the start of a line (prev == 0), or after an operator
// / opening bracket / comma. After an identifier byte, a digit, or a closing
// bracket, `/` is division.
func isRegexStart(prev byte) bool {
	switch {
	case prev == 0: // start of file or line — operand position
		return true
	case isRubyIdentByte(prev):
		return false // after a variable/number: division
	}
	switch prev {
	case ')', ']', '}':
		return false // after a closing bracket: division
	case '=', '(', ',', '|', '&', '!', '<', '>', '+', '-', '*', '%', '~', '?', ':', ';', '{', '[':
		return true // operator / opener position: regex
	}
	return false
}

// scanRubyRegex returns the offset just past a `/.../ ` regex literal opening at
// start, honoring backslash escapes and skipping character classes `[...]`
// (where a `/` is literal). A newline terminates an unterminated regex
// defensively so a stray slash cannot swallow following code.
func scanRubyRegex(content []byte, start int) int {
	n := len(content)
	i := start + 1
	inClass := false
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				// Consume trailing flags (imxounse...).
				j := i + 1
				for j < n && isRubyIdentByte(content[j]) {
					j++
				}
				return j
			}
		case '\n':
			return i
		}
		i++
	}
	return n
}

// isPercentLiteralStart reports whether a `%` at i begins a `%w/%i/%q/%Q/%(...)`
// percent-literal rather than the modulo operator. A percent-literal appears in
// an operand position (like a regex) and is followed by an optional type letter
// then a delimiter byte. Modulo appears after an operand (identifier / number /
// closing bracket).
func isPercentLiteralStart(content []byte, i int, prev byte) bool {
	// After an operand, `%` is modulo.
	if isRubyIdentByte(prev) {
		return false
	}
	switch prev {
	case ')', ']', '}':
		return false
	}
	n := len(content)
	j := i + 1
	if j >= n {
		return false
	}
	// Optional type letter (w, W, i, I, q, Q, r, s, x). Then a delimiter.
	if isPercentTypeLetter(content[j]) {
		j++
	}
	if j >= n {
		return false
	}
	return isPercentDelim(content[j])
}

// isPercentTypeLetter reports whether c is a %-literal type letter.
func isPercentTypeLetter(c byte) bool {
	switch c {
	case 'w', 'W', 'i', 'I', 'q', 'Q', 'r', 's', 'x':
		return true
	}
	return false
}

// isPercentDelim reports whether c can open a %-literal. Ruby allows any
// non-alphanumeric delimiter; we accept the common bracket pairs and a set of
// punctuation delimiters (the paired brackets have a distinct closer).
func isPercentDelim(c byte) bool {
	switch c {
	case '(', '[', '{', '<', '|', '/', '!', '#', '~', '*', '-', '+', '.', ',':
		return true
	}
	return false
}

// scanRubyPercentLiteral returns the offset just past a percent-literal opening
// at start. It emits the literal (delimiters and body) as string via b, EXCEPT
// that in an INTERPOLATING variant (`%Q`, `%x`, `%r`, `%W`, `%I`, and the bare
// `%(...)`) each `#{ ... }` field is emitted as code — a tainted value spliced
// into `%x(ls #{path})` lives in a real expression, exactly like a double-quoted
// string. The non-interpolating variants (`%q`, `%w`, `%i`, `%s`) keep the whole
// body as string. Paired-bracket delimiters nest; a backslash escapes the
// delimiter. An unterminated literal runs to EOF.
func scanRubyPercentLiteral(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	j := start + 1
	interp := true // bare `%(...)` interpolates
	if j < n && isPercentTypeLetter(content[j]) {
		interp = isInterpolatingPercentType(content[j])
		j++
	}
	if j >= n {
		b.emit(start, n, KindString)
		return n
	}
	open := content[j]
	closeByte := percentCloser(open)
	nested := open != closeByte
	depth := 1
	i := j + 1
	runStart := start // string run begins at the '%' (delimiters are string)
	for i < n {
		c := content[i]
		if c == '\\' {
			i += 2
			continue
		}
		if interp && c == '#' && i+1 < n && content[i+1] == '{' {
			b.emit(runStart, i, KindString)
			fieldEnd := scanRubyInterpField(content, i+1)
			b.emit(i, fieldEnd, KindCode)
			i = fieldEnd
			runStart = i
			continue
		}
		if nested && c == open {
			depth++
		} else if c == closeByte {
			depth--
			if depth == 0 {
				b.emit(runStart, i+1, KindString)
				return i + 1
			}
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// isInterpolatingPercentType reports whether a percent-literal type letter marks
// an interpolating literal (uppercase W/I/Q, plus x and r) versus a
// non-interpolating one (lowercase q/w/i/s).
func isInterpolatingPercentType(c byte) bool {
	switch c {
	case 'Q', 'W', 'I', 'x', 'r':
		return true
	}
	return false
}

// percentCloser returns the closing delimiter for a percent-literal opener. For
// paired brackets it is the matching close; otherwise the opener is its own
// closer.
func percentCloser(open byte) byte {
	switch open {
	case '(':
		return ')'
	case '[':
		return ']'
	case '{':
		return '}'
	case '<':
		return '>'
	}
	return open
}

// isHeredocStart reports whether `<<` at i begins a heredoc rather than a
// left-shift operator. A heredoc identifier begins after `<<`, `<<~`, or `<<-`,
// optionally quoted, and must start with a letter/underscore or a quote — and it
// only appears in an operand position (after `=`, `(`, `,`, a newline, etc.),
// never after an identifier/number/close-bracket (where `<<` is left-shift).
func isHeredocStart(content []byte, i int, prev byte) bool {
	// After an operand, `<<` is the shift operator (e.g. `list << item`).
	if isRubyIdentByte(prev) {
		return false
	}
	switch prev {
	case ')', ']', '}':
		return false
	}
	n := len(content)
	j := i + 2 // past `<<`
	if j < n && (content[j] == '~' || content[j] == '-') {
		j++
	}
	if j >= n {
		return false
	}
	// Quoted identifier (<<~"ID" / <<~'ID') or a bare identifier.
	if content[j] == '"' || content[j] == '\'' || content[j] == '`' {
		return j+1 < n && isRubyIdentStart(content[j+1])
	}
	return isRubyIdentStart(content[j])
}

// scanRubyHeredoc classifies a heredoc opening at start. The `<<ID` (and any
// same-line code after it up to the newline) is emitted as CODE; the heredoc
// BODY — the lines from the next line up to (and including) the terminator line
// — is emitted as string. This ordering keeps offsets contiguous: same-line
// trailing code (e.g. `x = <<~SQL.strip`) is preserved as code, then the body
// follows. Squiggly/dash heredocs allow the terminator to be indented.
func scanRubyHeredoc(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	j := start + 2 // past `<<`
	indented := false
	if j < n && (content[j] == '~' || content[j] == '-') {
		indented = true
		j++
	}
	// Read the terminator identifier (possibly quoted).
	var term []byte
	if j < n && (content[j] == '"' || content[j] == '\'' || content[j] == '`') {
		q := content[j]
		j++
		tStart := j
		for j < n && content[j] != q {
			j++
		}
		term = content[tStart:j]
		if j < n {
			j++ // past the closing quote
		}
	} else {
		tStart := j
		for j < n && isRubyIdentByte(content[j]) {
			j++
		}
		term = content[tStart:j]
	}
	// Emit the opener line (from start to end of this physical line) as code so
	// same-line trailing code stays code. The body begins on the next line.
	lineEnd := j
	for lineEnd < n && content[lineEnd] != '\n' {
		lineEnd++
	}
	if lineEnd < n {
		lineEnd++ // include the newline that ends the opener line
	}
	b.emit(start, lineEnd, KindCode)

	// Scan body lines until a line whose (optionally trimmed) content equals the
	// terminator.
	bodyStart := lineEnd
	i := lineEnd
	for i < n {
		ls := i
		le := i
		for le < n && content[le] != '\n' {
			le++
		}
		lineBytes := content[ls:le]
		if isHeredocTerminator(lineBytes, term, indented) {
			// Emit body (excluding this terminator line) as string, then the
			// terminator line as code.
			if ls > bodyStart {
				b.emit(bodyStart, ls, KindString)
			}
			termEnd := le
			if termEnd < n {
				termEnd++ // include the newline
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

// isHeredocTerminator reports whether line is the heredoc terminator for term.
// For squiggly/dash heredocs (indented true) leading whitespace is ignored; for
// a plain heredoc the terminator must be at column 0. Trailing whitespace /
// carriage returns are tolerated.
func isHeredocTerminator(line, term []byte, indented bool) bool {
	s := line
	if indented {
		s = trimLeadingSpace(s)
	}
	s = trimTrailingSpace(s)
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

// trimLeadingSpace drops leading spaces/tabs from a byte slice (view, no copy).
func trimLeadingSpace(s []byte) []byte {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return s[i:]
}

// trimTrailingSpace drops trailing spaces/tabs/CR from a byte slice.
func trimTrailingSpace(s []byte) []byte {
	j := len(s)
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r') {
		j--
	}
	return s[:j]
}

// isRubyIdentStart reports whether b can begin a Ruby identifier.
func isRubyIdentStart(b byte) bool { return asciiIdentStart(b) }

// isRubyIdentByte reports whether b can appear inside a Ruby identifier.
func isRubyIdentByte(b byte) bool {
	return isRubyIdentStart(b) || (b >= '0' && b <= '9')
}
