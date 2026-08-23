package lexctx

// scanGroovy walks Groovy source (also Gradle build scripts and Jenkins
// pipeline files) and classifies each byte as code, string, or comment. Like the
// other scanners it recognizes only the lexical constructs that carry
// secret/blob false positives and treats everything else as code, emitting
// strictly increasing, contiguous spans so the returned regions are gap-free and
// cover [0, len(content)).
//
// Groovy's grammar has several gotchas a Go/Java-style scanner gets wrong, and
// this scanner handles each explicitly:
//
//   - Comments: `//` line comments run to end of line, and `/* ... */` block
//     comments that do NOT nest (unlike Kotlin/Scala) — the first `*/` closes.
//     A leading `#!` shebang line (Groovy allows it on line 1) is a comment.
//
//   - GStrings `"..."`: double-quoted strings with backslash escapes and
//     `$var` / `${expr}` interpolation. The interpolation markers do NOT end the
//     string — the whole literal (holes included) is one string region, the safe
//     degrade: an expression inside `${...}` is treated as string, never
//     revealing a spurious code match. Closed at the matching unescaped `"` or
//     defensively at a newline (a single-line GString may not span a line).
//
//   - Plain strings `'...'`: single-quoted, NO interpolation, backslash escapes
//     honored. Closed at the matching `'` or defensively at a newline.
//
//   - Triple-quoted strings: a triple-double-quoted GString (processes escapes and
//     interpolation) and a triple-single-quoted plain string (no interpolation) may
//     span many lines. Both are the usual carriers of a base64/data-URI blob or a
//     multi-line SQL string. Closed by the first matching run of three quotes.
//
//   - Slashy strings `/.../`: regex-flavored literals with `$`/`${}` interpolation
//     and NO need to escape a `"` or `'`. Because a bare `/` is also the division
//     operator, a slashy string is recognized only when a `/` appears where an
//     EXPRESSION may start (start of file, or right after an operator/`(`/`,`/`=`
//     etc.), which is the best-effort disambiguation Groovy's own parser makes.
//
//   - Dollar-slashy strings `$/.../$`: opened by `$/` and closed by `/$`, spanning
//     lines, with `$var`/`${}` interpolation and only `$$`/`$/` as escapes. A
//     handy carrier for Windows paths and regexes that contain `/`.
func scanGroovy(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	// prevSignificant is the last non-space, non-newline CODE byte seen; it drives
	// the slashy-string vs division disambiguation. 0 means start-of-input (an
	// expression may start), which is the same as after an operator.
	var prevSignificant byte
	for i < n {
		c := content[i]
		switch {
		case c == '#' && i+1 < n && content[i+1] == '!' && i == 0:
			// Shebang line (only valid as the very first line).
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '/' && i+1 < n && content[i+1] == '/':
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanGroovyBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '$' && i+1 < n && content[i+1] == '/':
			i = scanGroovyDollarSlashy(content, i, &b)
		case c == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"':
			i = scanGroovyTriple(content, i, '"', true, &b)
		case c == '\'' && i+2 < n && content[i+1] == '\'' && content[i+2] == '\'':
			i = scanGroovyTriple(content, i, '\'', false, &b)
		case c == '"':
			i = scanGroovyQuoted(content, i, '"', true, &b)
		case c == '\'':
			i = scanGroovyQuoted(content, i, '\'', false, &b)
		case c == '/' && groovySlashyCanStart(prevSignificant):
			i = scanGroovySlashy(content, i, &b)
			prevSignificant = '/'
			continue
		default:
			b.emit(i, i+1, KindCode)
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				prevSignificant = c
			}
			i++
			continue
		}
		// A string or comment just consumed: its closing delimiter (a quote, `/`,
		// or `/` of `*/`) is the last significant byte, so a following `/` reads as
		// division (not a new slashy string) — matching Groovy's own lexing.
		if i > 0 {
			prevSignificant = content[i-1]
		}
	}
	return b.finish(n)
}

// scanGroovyBlockComment returns the offset just past a `/* ... */` block comment
// whose body begins at bodyStart (just after the opening `/*`). Groovy block
// comments do NOT nest — the first `*/` closes. An unterminated comment runs to
// EOF.
func scanGroovyBlockComment(content []byte, bodyStart int) int {
	n := len(content)
	i := bodyStart
	for i < n {
		if content[i] == '*' && i+1 < n && content[i+1] == '/' {
			return i + 2
		}
		i++
	}
	return n
}

// scanGroovyQuoted classifies a single-line string literal opening at
// content[start] (content[start] is the opening quote) with delimiter q, emitting
// literal runs as string. For a GString (gstring true, double-quoted) a $var /
// ${expr} interpolation field is emitted as CODE — a tainted value spliced via
// "run ${cmd}" lives in a real expression the taint engine must see, matching the
// Swift interpolation treatment. A plain single-quoted string (gstring false) has
// no interpolation. Backslash escapes are honored; a newline defensively ends the
// scan (a single-line Groovy string may not span a line) so a runaway quote cannot
// swallow real code. Returns the offset just past the literal (or EOF).
func scanGroovyQuoted(content []byte, start int, q byte, gstring bool, b *regionBuilder) int {
	n := len(content)
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
		if gstring && groovyInterpStart(content, i) {
			b.emit(runStart, i, KindString)
			i = groovyEmitInterp(content, i, b)
			runStart = i
			continue
		}
		if c == q {
			b.emit(runStart, i+1, KindString)
			return i + 1
		}
		if c == '\n' {
			b.emit(runStart, i, KindString)
			return i
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanGroovyTriple classifies a triple-quoted string literal opening at
// content[start] (content[start] is the first of the opening run of three q).
// Triple-quoted strings span many lines and are closed by the first run of three
// q. For the GString form (double-quoted, gstring true) $var/${expr} interpolation
// fields are emitted as CODE; the plain single-quoted form has none. Backslash
// escapes are honored. An unterminated literal runs to EOF. Returns the offset
// just past the literal (or EOF).
func scanGroovyTriple(content []byte, start int, q byte, gstring bool, b *regionBuilder) int {
	n := len(content)
	bodyStart := start + 3
	if bodyStart > n {
		bodyStart = n
	}
	b.emit(start, bodyStart, KindString)
	i := bodyStart
	runStart := bodyStart
	for i < n {
		if content[i] == '\\' {
			i += 2
			continue
		}
		if content[i] == q && i+2 < n && content[i+1] == q && content[i+2] == q {
			b.emit(runStart, i+3, KindString)
			return i + 3
		}
		if gstring && groovyInterpStart(content, i) {
			b.emit(runStart, i, KindString)
			i = groovyEmitInterp(content, i, b)
			runStart = i
			continue
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanGroovySlashy classifies a slashy string /.../ opening at content[start]
// (content[start] is the opening slash), emitting literal runs as string and its
// $var/${} interpolation fields as CODE. A backslash-slash is an escaped
// delimiter. Closed at the first unescaped slash; a newline defensively ends the
// scan (a slashy string is single-line) so a stray slash cannot swallow code.
// Returns the offset just past the literal (or EOF).
func scanGroovySlashy(content []byte, start int, b *regionBuilder) int {
	n := len(content)
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
		if groovyInterpStart(content, i) {
			b.emit(runStart, i, KindString)
			i = groovyEmitInterp(content, i, b)
			runStart = i
			continue
		}
		if c == '/' {
			b.emit(runStart, i+1, KindString)
			return i + 1
		}
		if c == '\n' {
			b.emit(runStart, i, KindString)
			return i
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanGroovyDollarSlashy classifies a dollar-slashy string opening at
// content[start] (content[start] is the dollar of the opening dollar-slash). These
// span many lines; the only escapes are a double-dollar (a literal dollar) and a
// dollar-slash (a literal slash), and the literal is closed by the first
// slash-dollar. ${expr} interpolation fields are emitted as CODE. An unterminated
// literal runs to EOF. Returns the offset just past the literal.
func scanGroovyDollarSlashy(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	bodyStart := start + 2
	if bodyStart > n {
		bodyStart = n
	}
	b.emit(start, bodyStart, KindString)
	i := bodyStart
	runStart := bodyStart
	for i < n {
		if content[i] == '$' && i+1 < n && (content[i+1] == '$' || content[i+1] == '/') {
			i += 2 // dollar-dollar and dollar-slash are escapes, not a close
			continue
		}
		if content[i] == '/' && i+1 < n && content[i+1] == '$' {
			b.emit(runStart, i+2, KindString)
			return i + 2
		}
		if groovyInterpStart(content, i) {
			b.emit(runStart, i, KindString)
			i = groovyEmitInterp(content, i, b)
			runStart = i
			continue
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// groovyInterpStart reports whether an interpolation field begins at content[i]:
// either a dollar-brace (a braced expression) or a dollar immediately followed by
// an identifier start (a $var / $a.b dotted path). A dollar followed by anything
// else (a space, a digit, another dollar) is a literal dollar sign.
func groovyInterpStart(content []byte, i int) bool {
	if content[i] != '$' || i+1 >= len(content) {
		return false
	}
	nxt := content[i+1]
	return nxt == '{' || isGroovyIdentStart(nxt)
}

// groovyEmitInterp emits a Groovy interpolation field opening at content[start]
// (content[start] is the dollar) and returns the offset just past it. The dollar
// (and, for a braced field, the surrounding braces) are emitted as STRING while
// only the inner EXPRESSION is emitted as CODE — so the engine reads the spliced
// expression's identifiers cleanly, without a spurious `$` token. A ${expr} field's
// body runs to its balanced closing brace (nested braces and nested strings inside
// the hole are skipped so a brace in a nested literal does not close it early). A
// bare $var / $a.b.c field's body is the dotted identifier path.
func groovyEmitInterp(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	if start+1 < n && content[start+1] == '{' {
		end := scanGroovyBraceField(content, start+2)
		// Emit `${` and the closing `}` as string; the inner expression as code.
		b.emit(start, start+2, KindString)
		if end > start+2 {
			// end includes the trailing `}`; the expression body is [start+2, end-1).
			b.emit(start+2, end-1, KindCode)
			b.emit(end-1, end, KindString)
		}
		return end
	}
	// Bare $identifier with an optional dotted tail ($a.b.c). Emit the `$` as string
	// and the identifier path as code.
	i := start + 1
	for i < n && isGroovyIdentPart(content[i]) {
		i++
	}
	for i+1 < n && content[i] == '.' && isGroovyIdentStart(content[i+1]) {
		i++ // consume '.'
		for i < n && isGroovyIdentPart(content[i]) {
			i++
		}
	}
	b.emit(start, start+1, KindString) // the `$`
	b.emit(start+1, i, KindCode)       // the identifier path
	return i
}

// scanGroovyBraceField returns the offset just past a ${ ... } interpolation body
// whose body begins at bodyStart (the byte after the opening brace). It balances
// braces and skips nested string literals so a brace inside a nested literal or a
// nested pair does not close the field early. An unterminated field runs to EOF.
func scanGroovyBraceField(content []byte, bodyStart int) int {
	n := len(content)
	depth := 1
	i := bodyStart
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
		case '"', '\'':
			i = skipGroovyNestedString(content, i)
		default:
			i++
		}
	}
	return n
}

// skipGroovyNestedString returns the offset just past a nested string literal
// inside a ${...} interpolation hole, opening at content[i] (a double or single
// quote). It handles triple- and single-quoted forms with backslash escapes so
// their quotes and braces are not miscounted by the brace balancer. An
// unterminated nested string runs to EOF.
func skipGroovyNestedString(content []byte, i int) int {
	n := len(content)
	q := content[i]
	if i+2 < n && content[i+1] == q && content[i+2] == q {
		// Triple-quoted nested string.
		j := i + 3
		for j < n {
			if content[j] == '\\' {
				j += 2
				continue
			}
			if content[j] == q && j+2 < n && content[j+1] == q && content[j+2] == q {
				return j + 3
			}
			j++
		}
		return n
	}
	j := i + 1
	for j < n {
		if content[j] == '\\' {
			j += 2
			continue
		}
		if content[j] == q {
			return j + 1
		}
		if content[j] == '\n' {
			return j
		}
		j++
	}
	return n
}

// isGroovyIdentStart / isGroovyIdentPart mirror the taint engine's identifier
// rules (letters and underscore) so a $var interpolation path is delimited the
// same way the extractor reads identifiers.
func isGroovyIdentStart(b byte) bool { return asciiIdentStart(b) }

func isGroovyIdentPart(b byte) bool { return asciiIdentPart(b) }

// groovySlashyCanStart reports whether a `/` following prev may begin a slashy
// string rather than the division operator. A slashy string can start only where
// an EXPRESSION may start: at the start of input (prev == 0) or immediately after
// an operator, an opening bracket, a comma, a colon, or a semicolon. After an
// identifier byte, a digit, a `)`/`]`, or a closing quote the `/` is division.
// This is the same best-effort heuristic Groovy's own parser applies; a wrong
// guess only costs the FP-suppression benefit for that literal, never correctness.
func groovySlashyCanStart(prev byte) bool {
	switch prev {
	case 0: // start of input
		return true
	case '(', '[', '{', ',', ';', ':', '=', '+', '-', '*', '%', '&', '|',
		'^', '!', '<', '>', '~', '?':
		return true
	}
	return false
}
