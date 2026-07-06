package lexctx

// scanJava walks Java source and classifies each byte as code, string, or
// comment. It recognizes the lexical constructs that carry secret/prompt false
// positives in Java — a `//` inside a URL string, a base64 blob in a text
// block, a provider prefix in a javadoc comment — and treats everything else as
// code:
//
//   - `//` line comments (to end of line) and `/* ... */` block comments.
//     Javadoc `/** ... */` is lexically just a block comment that happens to
//     start with an extra `*`, so it is handled by the same path. Java block
//     comments do NOT nest, so the FIRST `*/` closes the comment even if an
//     inner `/*` appeared (scanBlockComment, shared with the Go/JS scanners,
//     encodes exactly this).
//   - ordinary string literals `"..."` with backslash escapes (`\"`, `\\`). A
//     newline terminates an unclosed string (Java strings may not span a line)
//     so a stray quote cannot swallow the following code.
//   - text blocks `"""` ... `"""` (Java 15+). These span multiple lines and are
//     the workhorse for embedding SQL, JSON, and base64 blobs, so the whole
//     construct — opening delimiter, multi-line body, and closing delimiter — is
//     classified as one KindString region. Backslash escapes are honored inside
//     so an escaped `"""` fragment does not close the block early.
//   - char literals `'x'` with backslash escapes, closed at the matching `'` or
//     defensively at a newline.
//
// It shares scanBlockComment with the Go/JS scanners. Like the other scanners it
// emits strictly increasing, contiguous spans into a regionBuilder so the
// returned regions are gap-free and cover [0, len(content)).
func scanJava(content []byte) []Region {
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
			// Covers both `/* ... */` and javadoc `/** ... */`: the extra `*` is
			// part of the comment body, and non-nesting close semantics are the
			// same. scanBlockComment scans from just past the opening `/*`.
			end := scanBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"':
			// Text block `"""` ... `"""` — checked before the ordinary string case
			// so a triple quote is never mis-scanned as an empty `""` literal.
			end := scanJavaTextBlock(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '"':
			end := scanJavaString(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '\'':
			end := scanJavaChar(content, i)
			b.emit(i, end, KindString)
			i = end
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// scanJavaString returns the offset just past an ordinary string literal
// `"..."` opening at content[start]. Backslash escapes are honored (`\"`, `\\`);
// a newline ends the scan because a Java string literal may not span a line, so
// a runaway quote cannot swallow real code.
func scanJavaString(content []byte, start int) int {
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

// scanJavaTextBlock returns the offset just past a text block `"""` ... `"""`
// opening at content[start] (which must index the first of the three opening
// quotes). Text blocks span multiple lines, so no newline terminates the scan;
// backslash escapes are honored so an escaped quote sequence cannot close the
// block early. The block ends at the first unescaped run of three quotes after
// the opening delimiter; an unterminated block runs to EOF.
func scanJavaTextBlock(content []byte, start int) int {
	n := len(content)
	// Skip the opening `"""`.
	i := start + 3
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '"':
			if i+2 < n && content[i+1] == '"' && content[i+2] == '"' {
				return i + 3
			}
			// A lone or double quote inside the body is ordinary text.
			i++
			continue
		}
		i++
	}
	return n
}

// scanJavaChar returns the offset just past a char literal `'x'` opening at
// content[start]. Backslash escapes are honored (an escaped quote stays inside
// the literal), the literal is closed at the matching quote, and a real newline
// ends the scan defensively so a stray apostrophe cannot swallow code.
func scanJavaChar(content []byte, start int) int {
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
