package lexctx

// scanScala walks Scala source and classifies each byte as code, string, or
// comment. Scala is lexically close to Java/C but carries three quirks that a
// naive Java-style scanner mis-handles and that drive its secret/blob false
// positives and taint mis-lexing:
//
//   - `//` line comments run to end of line, and `/* ... */` block comments
//     NEST (unlike Go/Java/C): an inner `/*` opens a nested comment whose
//     matching `*/` does NOT close the outer one, so scanScalaBlockComment
//     tracks depth (shared shape with the Rust scanner).
//   - ordinary string literals `"..."` with backslash escapes (`\"`, `\\`),
//     closed at the matching quote or defensively at a newline (a single-quoted
//     literal may not span a line in Scala).
//   - triple-quoted raw string literals `"""..."""`: NO escapes are processed (a
//     backslash is a literal byte), interior single/double quotes and `//` are
//     literal, and they CAN span many lines — the usual carrier of a base64/
//     data-URI blob, an embedded SQL heredoc, or a generated banner.
//   - interpolated strings: an IDENTIFIER immediately followed by `"` or `"""`
//     — `s"..."`, `f"..."`, `raw"..."`, and any custom `id"..."` — where a
//     `$ident` or `${ expr }` interpolation field is emitted as CODE (a tainted
//     value spliced via s"id=$id" lives in a real expression, exactly like the
//     Ruby `#{...}` field). The `raw"..."` interpolator still interpolates; only
//     its escape handling differs, which does not affect region kinds here.
//   - character literals `'x'` with backslash escapes, closed at the matching
//     `'`. CRUCIALLY a leading `'` followed by an identifier NOT closed by a `'`
//     is a Scala SYMBOL literal (`'foo`, like a Rust lifetime), which must be
//     lexed as CODE — not as a runaway char literal that swallows the rest of
//     the line. scanScalaCharOrSymbol encodes exactly this disambiguation.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
// Every heuristic degrades safely: a misread only costs FP-suppression, never
// correctness, because an over-broad code region merely disables suppression.
func scanScala(content []byte) []Region {
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
			end := scanScalaBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '"':
			// A `"""` triple-quote opens a raw multi-line string; a single `"`
			// opens an ordinary string. Neither is prefixed here (an interpolator
			// prefix is handled by the identifier branch below).
			if i+2 < n && content[i+1] == '"' && content[i+2] == '"' {
				end := scanScalaTripleString(content, i)
				b.emit(i, end, KindString)
				i = end
			} else {
				end := scanScalaInterpreted(content, i)
				b.emit(i, end, KindString)
				i = end
			}
		case c == '\'':
			end, isChar := scanScalaCharOrSymbol(content, i)
			if isChar {
				b.emit(i, end, KindString)
				i = end
			} else {
				// Symbol literal `'foo` — ordinary code. Emit the leading quote as
				// code and let the identifier fall through on the next iterations.
				b.emit(i, i+1, KindCode)
				i++
			}
		case isScalaIdentStart(c) && scalaInterpolatorAt(content, i):
			// An interpolator: `ident"..."` or `ident"""..."""`. The prefix
			// identifier is code; the string body classifies its literal runs as
			// string and its `$id` / `${...}` fields as code.
			identEnd := i
			for identEnd < n && isScalaIdentPart(content[identEnd]) {
				identEnd++
			}
			b.emit(i, identEnd, KindCode)
			i = scanScalaInterpolated(content, identEnd, &b)
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// scanScalaBlockComment returns the offset just past a `/* ... */` block comment
// whose body begins at bodyStart (just after the opening `/*`). Scala block
// comments NEST: each inner `/*` increments depth and each `*/` decrements it;
// the comment ends only when depth returns to zero. An unterminated comment runs
// to EOF.
func scanScalaBlockComment(content []byte, bodyStart int) int {
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

// scanScalaInterpreted returns the offset just past an ordinary string literal
// `"..."` opening at content[start]. Backslash escapes are honored (`\"`, `\\`);
// a newline ends the scan because a single-quoted Scala string may not span a
// line, so a runaway quote cannot swallow real code.
func scanScalaInterpreted(content []byte, start int) int {
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

// scanScalaTripleString returns the offset just past a triple-quoted raw string
// `"""..."""` opening at content[start] (which indexes the first of the three
// opening quotes). No escapes are processed — a backslash is literal — interior
// single and double quotes are literal, and the literal may span many lines. The
// literal is closed by the first run of three-or-more `"` (Scala closes on `"""`
// even when more quotes follow, keeping the longest trailing run inside). An
// unterminated triple string runs to EOF.
func scanScalaTripleString(content []byte, start int) int {
	n := len(content)
	i := start + 3 // past the opening `"""`
	for i < n {
		if content[i] == '"' {
			// A run of quotes: three-or-more closes. Count the run.
			runStart := i
			for i < n && content[i] == '"' {
				i++
			}
			if i-runStart >= 3 {
				return i
			}
			continue // a shorter interior run (`"` or `""`) is literal
		}
		i++
	}
	return n
}

// scalaInterpolatorAt reports whether an identifier beginning at content[start]
// is a string interpolator prefix — the identifier is immediately (no space)
// followed by a `"` (ordinary or triple). `s"..."`, `f"..."`, `raw"..."`, and a
// custom `json"..."` all qualify. A bare identifier followed by whitespace or an
// operator is NOT an interpolator (an ordinary variable read).
func scalaInterpolatorAt(content []byte, start int) bool {
	n := len(content)
	i := start
	if i >= n || !isScalaIdentStart(content[i]) {
		return false
	}
	for i < n && isScalaIdentPart(content[i]) {
		i++
	}
	return i < n && content[i] == '"'
}

// scanScalaInterpolated classifies an interpolated string whose opening quote is
// at content[quotePos] (the identifier prefix has already been emitted as code by
// the caller). It emits literal runs as string and each `$ident` / `${ ... }`
// interpolation field as code, and returns the offset just past the closing
// quote (or EOF). Both the single-quoted (`s"..."`) and triple-quoted
// (`s"""..."""`) forms are handled: a triple-quoted interpolator spans lines and
// is closed by `"""`, a single-quoted one is closed by `"` or a newline.
func scanScalaInterpolated(content []byte, quotePos int, b *regionBuilder) int {
	n := len(content)
	triple := quotePos+2 < n && content[quotePos+1] == '"' && content[quotePos+2] == '"'
	openLen := 1
	if triple {
		openLen = 3
	}
	// Emit the opening delimiter as string.
	bodyStart := quotePos + openLen
	b.emit(quotePos, bodyStart, KindString)
	i := bodyStart
	runStart := bodyStart
	for i < n {
		c := content[i]
		// Escapes only apply to the single-quoted form; a raw triple-quoted string
		// has no escapes, but treating a `\` as a normal byte there is harmless
		// because the only bytes we act on are `$` and the closing quote.
		if !triple && c == '\\' {
			i += 2
			continue
		}
		if c == '$' && i+1 < n {
			next := content[i+1]
			if next == '$' {
				// `$$` is a literal dollar sign — stays string, consume both.
				i += 2
				continue
			}
			if next == '{' {
				// Emit the `${` marker as string and only the inner expression as
				// code, so the code field is the bare expression (no `$` prefix that
				// would glue onto the identifier as `$id`).
				b.emit(runStart, i+2, KindString)
				fieldEnd := scanScalaInterpField(content, i+1)
				// fieldEnd indexes just past the closing `}`; the code span is the
				// inner expression (i+2 .. fieldEnd-1); the `}` is string.
				if fieldEnd-1 > i+2 {
					b.emit(i+2, fieldEnd-1, KindCode)
				}
				b.emit(fieldEnd-1, fieldEnd, KindString)
				i = fieldEnd
				runStart = i
				continue
			}
			if isScalaIdentStart(next) {
				// `$ident` (with optional dotted `.field` accessors): emit the `$` as
				// string and only the identifier chain as code, so the code field is
				// the bare `ident` the taint engine reads (not `$ident`).
				b.emit(runStart, i+1, KindString)
				j := i + 1
				for j < n && (isScalaIdentPart(content[j]) || content[j] == '.') {
					j++
				}
				// A trailing '.' not followed by an identifier is not part of the
				// field (e.g. end of a sentence); trim it back to the last ident byte.
				for j > i+1 && content[j-1] == '.' {
					j--
				}
				b.emit(i+1, j, KindCode)
				i = j
				runStart = i
				continue
			}
		}
		if triple {
			if c == '"' {
				runStart2 := i
				for i < n && content[i] == '"' {
					i++
				}
				if i-runStart2 >= 3 {
					b.emit(runStart, i, KindString)
					return i
				}
				continue // interior `"`/`""` run is literal
			}
		} else {
			if c == '"' {
				b.emit(runStart, i+1, KindString)
				return i + 1
			}
			if c == '\n' {
				b.emit(runStart, i, KindString)
				return i
			}
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanScalaInterpField returns the offset just past a `${ ... }` interpolation
// field whose `{` is at open. It balances nested braces and skips nested string
// literals so a `}` inside a nested string does not close the field early.
func scanScalaInterpField(content []byte, open int) int {
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
		case '"':
			// Skip a nested string literal (triple or single) so its braces/quotes
			// do not confuse field balancing.
			if i+2 < n && content[i+1] == '"' && content[i+2] == '"' {
				i = scanScalaTripleString(content, i)
			} else {
				i = scanScalaInterpreted(content, i)
			}
			continue
		}
		i++
	}
	return n
}

// scanScalaCharOrSymbol disambiguates a `'` at content[start] between a char
// literal and a Symbol literal. It returns (end, true) with end just past the
// closing `'` for a char literal, or (start, false) for a Symbol literal (the
// caller then treats the `'` as ordinary code).
//
// Rules (mirroring the Rust char-vs-lifetime disambiguation):
//   - `'\...'` (an escape immediately after the quote) is always a char literal.
//   - `'x'` — a single byte/char followed immediately by `'` — is a char literal.
//   - `'foo`, `'static` — an identifier NOT closed by a `'` — is a Symbol literal
//     (Scala's deprecated-but-still-lexed `Symbol("foo")` shorthand). We look
//     ahead over the identifier run: if the byte after it is a `'`, it was a
//     (multi-byte) char literal after all; otherwise it is a Symbol.
func scanScalaCharOrSymbol(content []byte, start int) (end int, isChar bool) {
	n := len(content)
	i := start + 1
	if i >= n {
		return start, false // trailing quote at EOF: treat as code
	}
	// Escaped char: '\n', '\'', '\\', '\uXXXX' — definitely a char literal.
	if content[i] == '\\' {
		i += 2
		for i < n {
			if content[i] == '\'' {
				return i + 1, true
			}
			if content[i] == '\n' {
				return i, true // defensive: newline ends a runaway char scan
			}
			i++
		}
		return n, true
	}
	// An identifier-start byte MIGHT be a Symbol literal.
	if isScalaIdentStart(content[i]) {
		j := i
		for j < n && isScalaIdentPart(content[j]) {
			j++
		}
		if j < n && content[j] == '\'' {
			return j + 1, true // 'x' char literal (or oddly-long, still closed)
		}
		return start, false // Symbol literal: 'foo, 'static, …
	}
	// A non-identifier char (punctuation, digit, space) followed by `'` is a char
	// literal like '9' or ' '.
	if i+1 < n && content[i+1] == '\'' {
		return i + 2, true
	}
	// Anything else: not a well-formed char; treat the `'` as code so we never
	// swallow following code into a runaway string.
	return start, false
}

// isScalaIdentStart reports whether b can begin a Scala identifier (letter or
// underscore). Non-ASCII identifiers degrade safely to "not an identifier start".
func isScalaIdentStart(b byte) bool { return asciiIdentStart(b) }

// isScalaIdentPart reports whether b can continue a Scala identifier.
func isScalaIdentPart(b byte) bool { return asciiIdentPart(b) }
