package lexctx

// scanKotlin walks Kotlin source and classifies each byte as code, string, or
// comment. It recognizes the lexical constructs that carry secret/blob false
// positives in Kotlin and treats everything else as code. Kotlin's grammar has
// three gotchas a Go/Java-style scanner gets wrong, and this scanner handles
// each explicitly:
//
//   - Comments: `//` line comments (incl. the KDoc form `/** ... */`, which lexes
//     as an ordinary block comment) run to end of line, and `/* ... */` block
//     comments that NEST. Unlike Go/Java, an inner `/*` opens a nested comment
//     whose matching `*/` does NOT close the outer one; scanKotlinBlockComment
//     tracks depth so commented-out code containing `/*`…`*/` is fully consumed.
//
//   - Strings: ordinary `"..."` with backslash escapes (`\"`, `\\`) and `$var` /
//     `${expr}` string TEMPLATES. The template markers do not end the string —
//     the whole literal (interpolation holes included) is one string region,
//     which is the safe degrade: an expression inside `${...}` is treated as
//     string, never revealing a spurious code match. An ordinary string is closed
//     at the matching unescaped `"` or defensively at a newline (a Kotlin ordinary
//     string may not span a line), so a runaway quote cannot swallow real code.
//
//   - Raw strings `"""..."""`: opened and closed by a run of three `"`, may span
//     many lines, and process NO escapes — a backslash and a `//` are literal and
//     a single interior `"` (or a pair) does not close the literal. This is the
//     usual carrier of a base64/data-URI blob or a multi-line SQL string.
//
//   - Char literals `'x'` with backslash escapes, closed at the matching `'` or
//     defensively at a newline.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
func scanKotlin(content []byte) []Region {
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
			end := scanKotlinBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"':
			end := scanKotlinRawString(content, i+3)
			b.emit(i, end, KindString)
			i = end
		case c == '"':
			end := scanKotlinInterpreted(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '\'':
			end := scanKotlinChar(content, i)
			b.emit(i, end, KindString)
			i = end
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// scanKotlinBlockComment returns the offset just past a `/* ... */` block comment
// whose body begins at bodyStart (i.e. just after the opening `/*`). Kotlin block
// comments NEST: each inner `/*` increments depth and each `*/` decrements it; the
// comment ends only when depth returns to zero. An unterminated comment runs to
// EOF.
func scanKotlinBlockComment(content []byte, bodyStart int) int {
	n := len(content)
	depth := 1
	i := bodyStart
	for i < n {
		if content[i] == '/' && i+1 < n && content[i+1] == '*' {
			depth++
			i += 2
			continue
		}
		if content[i] == '*' && i+1 < n && content[i+1] == '/' {
			depth--
			i += 2
			if depth == 0 {
				return i
			}
			continue
		}
		i++
	}
	return n
}

// scanKotlinInterpreted returns the offset just past an ordinary string literal
// `"..."` opening at content[start]. Backslash escapes are honored (`\"`, `\\`).
// `$var` / `${expr}` template markers do NOT end the string — the whole literal
// stays one string region. A newline ends the scan because an ordinary Kotlin
// string may not span a line, so a runaway quote cannot swallow real code.
func scanKotlinInterpreted(content []byte, start int) int {
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

// scanKotlinRawString returns the offset just past a triple-quoted raw string
// literal whose body begins at bodyStart (the byte after the opening `"""`). Raw
// strings process NO escapes — a backslash is an ordinary byte — and are closed
// by the first run of three `"`; a single or double interior `"` is literal. They
// may span multiple lines. An unterminated raw string runs to EOF.
func scanKotlinRawString(content []byte, bodyStart int) int {
	n := len(content)
	i := bodyStart
	for i < n {
		if content[i] == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"' {
			return i + 3
		}
		i++
	}
	return n
}

// scanKotlinChar returns the offset just past a character literal `'...'` opening
// at content[start]. Backslash escapes are honored (an escaped quote stays inside
// the literal), the literal is closed at the matching quote, and a real newline
// ends the scan defensively so a stray apostrophe cannot swallow code.
func scanKotlinChar(content []byte, start int) int {
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
