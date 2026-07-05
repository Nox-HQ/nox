package lexctx

// scanPython walks Python source and classifies each byte as code, string, or
// comment. It recognizes:
//
//   - `#` line comments (to end of line) — but NOT a `#` inside a string, which
//     is handled because the string scanner consumes the whole literal first
//   - single- and double-quoted string literals with backslash escapes
//   - triple-quoted ”'...”' / """...""" strings (which span lines and are the
//     workhorse for embedding blobs and docstrings)
//   - string prefixes r/b/f/u and their case/combination variants (rb, Rb, fr,
//     …). The prefix letters are ordinary code bytes; scanning of the literal
//     begins at the quote.
//
// f-string interpolation: the `{ ... }` replacement fields of an f-string are
// CODE — a secret spliced in via `f"key={SECRET}"` lives in a real expression.
// The scanner therefore emits the interpolated bytes as code (respecting `{{`
// / `}}` escapes and nested braces). Raw strings (r"...") disable backslash
// escaping, which matters: in a raw string `\"` does NOT escape the quote.
func scanPython(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	for i < n {
		c := content[i]
		switch {
		case c == '#':
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '\'' || c == '"':
			// A bare quote with no preceding prefix.
			i = scanPyStringLiteral(content, i, i, pyStringFlags{}, &b)
		case isPyStringPrefixStart(content, i):
			// Consume the prefix letters, then the opening quote.
			prefixStart := i
			flags, quotePos := readPyPrefix(content, i)
			i = scanPyStringLiteral(content, prefixStart, quotePos, flags, &b)
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// pyStringFlags captures the semantics a string prefix confers.
type pyStringFlags struct {
	raw     bool // r/R: backslash does not escape
	fstring bool // f/F: has { } interpolation fields that are code
}

// isPyStringPrefixStart reports whether content[i] begins a prefixed string
// literal (e.g. r", b', f"""). It requires that the prefix be preceded by a
// non-identifier byte so we do not misread the tail of an identifier like
// `myvar` or a hex literal as a `r`/`b` prefix.
func isPyStringPrefixStart(content []byte, i int) bool {
	if !isPyPrefixLetter(content[i]) {
		return false
	}
	if i > 0 && isIdentByte(content[i-1]) {
		return false // part of a longer identifier, not a string prefix
	}
	_, quotePos := readPyPrefix(content, i)
	return quotePos > i && quotePos < len(content) &&
		(content[quotePos] == '\'' || content[quotePos] == '"')
}

// readPyPrefix consumes up to two prefix letters starting at i and returns the
// resulting flags and the index of the opening quote (or the first non-prefix
// byte if there is no quote, in which case the caller's guard rejects it).
func readPyPrefix(content []byte, i int) (flags pyStringFlags, quotePos int) {
	j := i
	n := len(content)
	// Python string prefixes are at most two letters (e.g. rb, fr, br).
	for count := 0; count < 2 && j < n && isPyPrefixLetter(content[j]); count++ {
		switch content[j] {
		case 'r', 'R':
			flags.raw = true
		case 'f', 'F':
			flags.fstring = true
		}
		j++
	}
	return flags, j
}

// isPyPrefixLetter reports whether c is one of the recognized string-prefix
// letters (case-insensitive): r, b, f, u.
func isPyPrefixLetter(c byte) bool {
	switch c {
	case 'r', 'R', 'b', 'B', 'f', 'F', 'u', 'U':
		return true
	}
	return false
}

// isIdentByte reports whether c can appear inside an identifier.
func isIdentByte(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// scanPyStringLiteral classifies the string literal whose prefix (if any) began
// at prefixStart and whose opening quote is at quotePos. It emits the prefix and
// quotes and body as string, EXCEPT f-string `{ ... }` fields which are emitted
// as code. It returns the offset just past the literal.
func scanPyStringLiteral(content []byte, prefixStart, quotePos int, flags pyStringFlags, b *regionBuilder) int {
	n := len(content)
	q := content[quotePos]
	triple := quotePos+2 < n && content[quotePos+1] == q && content[quotePos+2] == q
	bodyStart := quotePos + 1
	if triple {
		bodyStart = quotePos + 3
	}
	// Emit prefix + opening quote(s) as string.
	b.emit(prefixStart, bodyStart, KindString)

	i := bodyStart
	stringRunStart := bodyStart
	for i < n {
		c := content[i]
		if c == '\\' && !flags.raw {
			i += 2 // escaped byte stays inside the string
			continue
		}
		// f-string interpolation field: `{` (not `{{`) opens a code expression.
		if flags.fstring && c == '{' {
			if i+1 < n && content[i+1] == '{' {
				i += 2 // `{{` is a literal brace
				continue
			}
			// Flush the string run so far, then emit the field bytes as code.
			b.emit(stringRunStart, i, KindString)
			fieldEnd := scanPyFStringField(content, i)
			b.emit(i, fieldEnd, KindCode)
			i = fieldEnd
			stringRunStart = i
			continue
		}
		if triple {
			if c == q && i+2 <= n-1 && content[i+1] == q && content[i+2] == q {
				b.emit(stringRunStart, i+3, KindString)
				return i + 3
			}
		} else {
			if c == q {
				b.emit(stringRunStart, i+1, KindString)
				return i + 1
			}
			if c == '\n' {
				// A non-triple string does not cross a newline; stop before it
				// so runaway quotes cannot swallow real code.
				b.emit(stringRunStart, i, KindString)
				return i
			}
		}
		i++
	}
	b.emit(stringRunStart, n, KindString)
	return n
}

// scanPyFStringField returns the offset just past an f-string replacement field
// that opens at content[open] == '{'. It balances nested braces and skips over
// nested string literals inside the expression (so a `}` inside a nested string
// does not close the field early). A format spec after `:` is included in the
// field span; classifying it as code is harmless (it is not a secret carrier).
func scanPyFStringField(content []byte, open int) int {
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
		case '\'', '"':
			// Skip a nested string literal wholesale.
			i = skipPyNestedString(content, i)
			continue
		}
		i++
	}
	return n
}

// skipPyNestedString returns the offset just past a simple (non-triple) nested
// string opening at content[start], used only to keep brace-balancing honest
// inside f-string fields.
func skipPyNestedString(content []byte, start int) int {
	n := len(content)
	q := content[start]
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case q:
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}
