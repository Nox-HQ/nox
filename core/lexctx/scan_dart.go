package lexctx

// scanDart walks Dart source and classifies each byte as code, string, or
// comment. Dart's grammar has five gotchas a Go/C-style scanner gets wrong, and
// this scanner handles each explicitly:
//
//   - Comments: `//` line comments (and `///` doc comments, which are just line
//     comments to the lexer) run to end of line, and `/* ... */` block comments
//     that NEST (like Rust/Swift, unlike Go/C). An inner `/*` opens a nested
//     comment whose matching `*/` does NOT close the outer one, so a base64 blob
//     or commented-out code containing `/*`…`*/` is fully consumed
//     (scanDartBlockComment tracks depth).
//
//   - Ordinary strings `'...'` and `"..."`: Dart uses both quote characters
//     interchangeably. Backslash escapes (`\'`, `\"`, `\\`) are honored and
//     STRING INTERPOLATION comes in two forms — `$identifier` (a simple hole) and
//     `${expr}` (a braced expression hole). The literal parts are emitted as
//     STRING and each interpolation hole is emitted as CODE, because a tainted
//     value spliced via 'id=$userInput' or "id=${req.query}" lives in a real
//     expression the taint engine must see (this is the dominant SQL/command-
//     injection carrier in Dart, the analogue of Ruby's `#{...}` and Swift's
//     `\(...)`). The braced-hole scanner balances braces and skips nested strings
//     so a `${m['}']}` hole is not mis-terminated. Ordinary Dart strings do not
//     span lines, so a newline defensively ends the scan.
//
//   - Multiline strings (triple single-quote and triple double-quote): opened by
//     three quote characters, closed by the next matching triple, span many lines,
//     treat interior single/double quotes and `//` as literal, and honor
//     `$`/`${...}` interpolation (emitted as code) and `\` escapes.
//
//   - Raw strings `r'...'`, `r"..."`, and their triple-quoted forms: an `r` prefix
//     makes the string RAW — NO backslash escapes (a `\` is a literal byte) and
//     NO interpolation (a `$` is literal). Terminated by the matching quote/triple
//     only. This is the SVG/base64/regex FP carrier the blob heuristic feeds on.
//
// Dart has no character literal (a code unit is written as an `int`/`String`), so
// there is no `'...'`-as-char case: `'x'` is always a String.
//
// The string scanners emit into the regionBuilder directly (like the Swift/Ruby
// interpolated-string scanners) because interpolation splits a string region into
// string/code sub-runs. All spans are strictly increasing and contiguous so the
// returned regions are gap-free and cover [0, len(content)).
func scanDart(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	for i < n {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '/':
			// `//` line comment (a `///` doc comment is the same to the lexer).
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanDartBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == 'r' && dartRawStringPrefix(content, i):
			i = scanDartRawString(content, i, &b)
		case (c == '\'' || c == '"') && i+2 < n && content[i+1] == c && content[i+2] == c:
			// Triple-quoted (multiline) string: three single or double quotes.
			i = scanDartMultiline(content, i, c, false, &b)
		case c == '\'' || c == '"':
			i = scanDartInterpreted(content, i, c, false, &b)
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// scanDartBlockComment returns the offset just past a `/* ... */` block comment
// whose body begins at bodyStart (just after the opening `/*`). Dart block
// comments NEST: each inner `/*` increments depth and each `*/` decrements it;
// the comment ends only when depth returns to zero. An unterminated comment runs
// to EOF.
func scanDartBlockComment(content []byte, bodyStart int) int {
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

// dartRawStringPrefix reports whether content[start] begins a raw-string prefix:
// an `r` immediately followed by a `'` or `"` quote. It is the disambiguator that
// stops an ordinary identifier beginning with `r` (a variable `route`) from being
// scanned as a raw string. The preceding byte, if any, must not be an identifier
// part (so `myr"..."` — impossible in valid Dart but defensive — is not a raw
// string, and `foo.r'...'` is not either).
func dartRawStringPrefix(content []byte, start int) bool {
	n := len(content)
	if start >= n || content[start] != 'r' {
		return false
	}
	if start > 0 && isDartIdentPart(content[start-1]) {
		return false
	}
	q := start + 1
	return q < n && (content[q] == '\'' || content[q] == '"')
}

// isDartIdentPart reports whether b can be part of a Dart identifier (letters,
// digits, underscore, or `$`). Used to disambiguate a raw-string `r` prefix and
// to bound a simple `$identifier` interpolation hole.
func isDartIdentPart(b byte) bool { return b == '$' || asciiIdentPart(b) }

// isDartIdentStart reports whether b can begin a Dart identifier (letter or
// underscore; `$` is not a valid identifier START in a simple `$x` hole — the
// `$` is the interpolation marker itself).
func isDartIdentStart(b byte) bool { return asciiIdentStart(b) }

// scanDartRawString classifies a raw string opening at content[start] (an `r`
// prefix satisfying dartRawStringPrefix). Raw strings process NO escapes and NO
// interpolation: the whole body is string. It dispatches to the multiline raw
// form on a triple-quote opener, else the single-line raw form. Returns the
// offset just past the literal (or EOF).
func scanDartRawString(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	quote := content[start+1] // the `'` or `"` after `r`
	// A triple-quote opener makes it a raw multiline string.
	if start+3 < n && content[start+2] == quote && content[start+3] == quote {
		return scanDartMultiline(content, start, quote, true, b)
	}
	// Single-line raw string: opener run [start, start+2) (the `r` and one quote)
	// is string; the body begins after the opening quote and runs to the next
	// unescaped-but-in-raw-terms matching quote (no escapes, so a bare quote ends
	// it). A newline defensively ends the scan.
	bodyStart := start + 2
	i := bodyStart
	for i < n {
		if content[i] == quote {
			b.emit(start, i+1, KindString)
			return i + 1
		}
		if content[i] == '\n' { // single-line raw string does not span lines
			b.emit(start, i, KindString)
			return i
		}
		i++
	}
	b.emit(start, n, KindString)
	return n
}

// scanDartInterpreted classifies an ordinary interpreted string opening at
// content[start] (content[start] is the opening quote `quote`), emitting literal
// runs as string and each `$identifier` / `${expr}` interpolation hole as code.
// Backslash escapes are honored; a newline defensively ends the scan (a
// non-multiline Dart string may not span a line) so a runaway quote cannot
// swallow real code. `raw` is false here (raw strings go through
// scanDartRawString). Returns the offset just past the literal (or EOF).
func scanDartInterpreted(content []byte, start int, quote byte, _ bool, b *regionBuilder) int {
	n := len(content)
	bodyStart := start + 1
	i := bodyStart
	runStart := start // include the opening quote in the leading string run
	for i < n {
		switch content[i] {
		case '\\':
			i += 2 // ordinary escape consumes the next byte
			continue
		case '$':
			b.emit(runStart, i, KindString)
			holeEnd := scanDartInterpolation(content, i, b)
			i = holeEnd
			runStart = i
			continue
		case quote:
			b.emit(runStart, i+1, KindString)
			return i + 1
		case '\n':
			b.emit(runStart, i, KindString)
			return i
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanDartMultiline classifies a multiline (triple-quoted) string opening at
// content[start]. For the ordinary form (`raw` false) content[start] is the first
// of the opening triple; for the raw form (`raw` true) content[start] is the `r`
// and the opener is `r` + the triple. It is closed by the matching triple quote,
// spans many lines, treats interior single/double quotes and `//` as literal, and
// — for the non-raw form — emits `$`/`${...}` interpolation holes as code
// (backslash escapes honored). The raw form processes no escapes/interpolation.
// Returns the offset just past the literal (or EOF).
func scanDartMultiline(content []byte, start int, quote byte, raw bool, b *regionBuilder) int {
	n := len(content)
	// The opener is (optional `r`) + three quote bytes.
	bodyStart := start + 3
	if raw {
		bodyStart = start + 4 // `r` + three opening quote bytes
	}
	if bodyStart > n {
		bodyStart = n
	}
	i := bodyStart
	runStart := start // include the opener in the leading string run
	for i < n {
		if content[i] == quote && i+2 < n && content[i+1] == quote && content[i+2] == quote {
			end := i + 3
			b.emit(runStart, end, KindString)
			return end
		}
		if !raw {
			if content[i] == '\\' {
				i += 2 // ordinary escape consumes the next byte
				continue
			}
			if content[i] == '$' {
				b.emit(runStart, i, KindString)
				holeEnd := scanDartInterpolation(content, i, b)
				i = holeEnd
				runStart = i
				continue
			}
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanDartInterpolation emits a `$identifier` or `${expr}` interpolation hole
// opening at content[start] (content[start] is the `$`) as a CODE region and
// returns the offset just past the hole. For `${...}` it balances braces inside
// the hole and skips nested string literals so a `}` inside `${f(g())}` or an
// inner string does not close the hole early. For `$identifier` the hole is the
// `$` plus the identifier run. A lone `$` not followed by an identifier or `{`
// (rare, e.g. a literal dollar sign the author forgot to escape) is emitted as
// string so it is not silently dropped from coverage.
func scanDartInterpolation(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	if start+1 >= n {
		b.emit(start, n, KindString)
		return n
	}
	next := content[start+1]
	if next == '{' {
		// The `${` and `}` delimiters stay string; only the expression inside is
		// code, so a downstream identifier scan sees `f(g(y))`, not `${f(g(y))}`.
		holeEnd := scanDartBracedHole(content, start+1)
		b.emit(start, start+2, KindString) // `${`
		exprEnd := holeEnd
		if holeEnd <= n && holeEnd-1 >= start+2 && content[holeEnd-1] == '}' {
			exprEnd = holeEnd - 1 // strip the closing `}` from the code span
		}
		if exprEnd > start+2 {
			b.emit(start+2, exprEnd, KindCode) // expression
		}
		if exprEnd < holeEnd {
			b.emit(exprEnd, holeEnd, KindString) // closing `}`
		}
		return holeEnd
	}
	if isDartIdentStart(next) {
		// The `$` marker stays string; only the identifier is code, so a downstream
		// identifier scan reads `name`, not `$name`.
		b.emit(start, start+1, KindString)
		i := start + 1
		for i < n && isDartIdentPart(content[i]) {
			i++
		}
		b.emit(start+1, i, KindCode)
		return i
	}
	// A `$` not beginning an interpolation is a literal dollar in the string.
	b.emit(start, start+1, KindString)
	return start + 1
}

// scanDartBracedHole returns the offset just past a `{...}` interpolation hole
// whose opening `{` is at content[open]. It balances braces and skips nested
// string literals (so their quotes/braces are not miscounted). An unterminated
// hole runs to EOF.
func scanDartBracedHole(content []byte, open int) int {
	n := len(content)
	i := open
	if i >= n || content[i] != '{' {
		return i
	}
	depth := 0
	for i < n {
		switch content[i] {
		case '{':
			depth++
			i++
		case '}':
			depth--
			i++
			if depth == 0 {
				return i
			}
		case '\'', '"':
			i = skipDartNestedString(content, i)
		default:
			i++
		}
	}
	return n
}

// skipDartNestedString returns the offset just past a nested string inside an
// interpolation hole, honoring backslash escapes and ending at the matching quote,
// EOF, or a newline. Nested interpolations inside it are not separately classified
// (they stay inside the outer code hole, which is harmless — the whole hole is
// already code).
func skipDartNestedString(content []byte, start int) int {
	n := len(content)
	quote := content[start]
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case quote:
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}
