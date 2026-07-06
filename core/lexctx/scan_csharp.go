package lexctx

// scanCSharp walks C# source and classifies each byte as code, string, or
// comment. C# is lexically close to Go/Java but carries a richer string family
// that dominates its secret/blob false positives:
//
//   - `//` line comments and `///` documentation comments (both run to end of
//     line — a `///` is just a `//` for our purposes), and `/* ... */` block
//     comments. C# block comments do NOT nest, so the FIRST `*/` closes them
//     (scanBlockComment, shared with the Go/JS scanners, encodes exactly this).
//   - ordinary string literals `"..."` with backslash escapes (`\"`, `\\`),
//     closed at the matching quote or defensively at a newline.
//   - verbatim string literals `@"..."`: NO backslash escapes (a `\` is a
//     literal byte and does NOT escape the closing quote), a doubled `""` is a
//     literal quote (not a close), and they CAN span many lines — this is the
//     usual carrier of a base64/data-URI blob or a Windows path.
//   - interpolated strings `$"..."` (escapes like an ordinary string) and
//     interpolated-verbatim strings `$@"..."` / `@$"..."` (verbatim rules,
//     doubled-quote literal, multi-line). Interpolation holes `{ ... }` are
//     conservatively kept as STRING: treating a hole's expression as string
//     never surfaces a false positive (it only ever fails to reveal a match
//     hiding in code, which is the safe degrade for this classifier).
//   - raw string literals `"""..."""` (C# 11): a run of three-or-more double
//     quotes opens the literal, which is closed by a run of the SAME length,
//     may span many lines, and treats interior quotes and `//` as literal.
//   - character literals `'x'` with backslash escapes, closed at the matching
//     `'` or defensively at a newline.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
func scanCSharp(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	for i < n {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '/':
			// `//` line comment and `///` doc comment both run to end of line.
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"':
			// Raw string literal `"""..."""` (C# 11): three-or-more quotes.
			end := scanCSharpRawString(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '@' && i+1 < n && content[i+1] == '"':
			// Verbatim string `@"..."`.
			end := scanCSharpVerbatim(content, i+2)
			b.emit(i, end, KindString)
			i = end
		case c == '@' && i+2 < n && content[i+1] == '$' && content[i+2] == '"':
			// Interpolated-verbatim string `@$"..."` — verbatim quoting rules.
			end := scanCSharpVerbatim(content, i+3)
			b.emit(i, end, KindString)
			i = end
		case c == '$' && i+2 < n && content[i+1] == '@' && content[i+2] == '"':
			// Interpolated-verbatim string `$@"..."` — verbatim quoting rules.
			end := scanCSharpVerbatim(content, i+3)
			b.emit(i, end, KindString)
			i = end
		case c == '$' && i+1 < n && content[i+1] == '"':
			// Interpolated string `$"..."` — ordinary-escape quoting rules.
			end := scanCSharpQuoted(content, i+2)
			b.emit(i, end, KindString)
			i = end
		case c == '"':
			// Ordinary string literal `"..."`.
			end := scanCSharpQuoted(content, i+1)
			b.emit(i, end, KindString)
			i = end
		case c == '\'':
			end := scanCSharpChar(content, i)
			b.emit(i, end, KindString)
			i = end
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// scanCSharpQuoted returns the offset just past an ordinary or interpolated
// string literal whose body begins at bodyStart (the byte after the opening
// quote). Backslash escapes are honored (`\"`, `\\`); a newline ends the scan
// because a non-verbatim C# string may not span a line, so a runaway quote
// cannot swallow real code.
func scanCSharpQuoted(content []byte, bodyStart int) int {
	n := len(content)
	i := bodyStart
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

// scanCSharpVerbatim returns the offset just past a verbatim (or interpolated-
// verbatim) string literal whose body begins at bodyStart (the byte after the
// opening quote). Verbatim strings process NO escapes — a backslash is an
// ordinary byte — a doubled `""` is a literal quote (consumed, not a close),
// and they may span multiple lines. An unterminated verbatim string runs to EOF.
func scanCSharpVerbatim(content []byte, bodyStart int) int {
	n := len(content)
	i := bodyStart
	for i < n {
		if content[i] == '"' {
			if i+1 < n && content[i+1] == '"' {
				i += 2 // doubled quote is a literal quote, not a close
				continue
			}
			return i + 1
		}
		i++
	}
	return n
}

// scanCSharpRawString returns the offset just past a raw string literal opening
// at content[start] (which indexes the first of a run of three-or-more `"`).
// The opening run of N quotes is closed by the first run of exactly-N-or-more
// quotes; interior quotes shorter than the delimiter, `//`, and backslashes are
// all literal, and the literal may span many lines. An unterminated raw string
// runs to EOF.
func scanCSharpRawString(content []byte, start int) int {
	n := len(content)
	// Count the opening quote run length (>= 3, guaranteed by the caller).
	open := start
	for open < n && content[open] == '"' {
		open++
	}
	quoteRun := open - start
	i := open
	for i < n {
		if content[i] == '"' {
			runStart := i
			for i < n && content[i] == '"' {
				i++
			}
			if i-runStart >= quoteRun {
				return i // a closing run at least as long as the opener closes it
			}
			continue // a shorter interior run is literal
		}
		i++
	}
	return n
}

// scanCSharpChar returns the offset just past a character literal `'...'`
// opening at content[start]. Backslash escapes are honored (an escaped quote
// stays inside the literal), the literal is closed at the matching quote, and a
// real newline ends the scan defensively so a stray apostrophe cannot swallow
// code.
func scanCSharpChar(content []byte, start int) int {
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
