package lexctx

// scanGo walks Go source and classifies each byte as code, string, or comment.
// It recognizes the four lexical constructs that carry secret/prompt false
// positives in Go — a `//` in a URL string, a base64 blob in a raw string, a
// provider prefix in a comment — and treats everything else as code:
//
//   - `//` line comments (to end of line) and `/* ... */` block comments. Go
//     block comments do NOT nest, so the FIRST `*/` closes the comment even if
//     an inner `/*` appeared (scanBlockComment, shared with the JS scanner,
//     encodes exactly this).
//   - interpreted string literals `"..."` with backslash escapes (`\"`, `\\`).
//     A newline terminates an unclosed interpreted string (Go spec) so a stray
//     quote cannot swallow the following code.
//   - raw string literals “ `...` “ — no escapes are processed (a backslash is
//     literal and does NOT escape the closing backtick) and they CAN span many
//     lines, which matters because a base64/data-URI blob is often a raw string.
//   - rune literals `'...'` with backslash escapes, closed at the matching `'`
//     or defensively at a newline.
//
// It shares scanBlockComment with the JS scanner. Like the other scanners it
// emits strictly increasing, contiguous spans into a regionBuilder so the
// returned regions are gap-free and cover [0, len(content)).
func scanGo(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	for i < n {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '/':
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '"':
			end := scanGoInterpreted(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '`':
			end := scanGoRawString(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '\'':
			end := scanGoRune(content, i)
			b.emit(i, end, KindString)
			i = end
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// scanGoInterpreted returns the offset just past an interpreted string literal
// `"..."` opening at content[start]. Backslash escapes are honored (`\"`, `\\`);
// a newline ends the scan because an interpreted string may not span a line in
// Go, so a runaway quote cannot swallow real code.
func scanGoInterpreted(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '"':
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}

// scanGoRawString returns the offset just past a raw string literal “ `...` “
// opening at content[start]. Raw strings process NO escapes — a backslash is an
// ordinary byte and does not escape the closing backtick — and they may span
// multiple lines. An unterminated raw string runs to EOF.
func scanGoRawString(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		if content[i] == '`' {
			return i + 1
		}
		i++
	}
	return n
}

// scanGoRune returns the offset just past a rune literal `'...'` opening at
// content[start]. Backslash escapes are honored (an escaped quote and an escaped
// newline both stay inside the literal), the literal is closed at the matching
// quote, and a real newline ends the scan defensively so a stray apostrophe
// cannot swallow code.
func scanGoRune(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '\'':
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}
