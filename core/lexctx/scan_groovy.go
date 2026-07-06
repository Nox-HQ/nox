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
//   - Triple-quoted `"""..."""` (GString) and `”'...”'` (plain): may span many
//     lines. `"""` processes escapes and interpolation; `”'` is plain. Both are
//     the usual carriers of a base64/data-URI blob or a multi-line SQL string.
//     Closed by the first matching run of three quotes.
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
			end := scanGroovyDollarSlashy(content, i+2)
			b.emit(i, end, KindString)
			i = end
		case c == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"':
			end := scanGroovyTriple(content, i+3, '"')
			b.emit(i, end, KindString)
			i = end
		case c == '\'' && i+2 < n && content[i+1] == '\'' && content[i+2] == '\'':
			end := scanGroovyTriple(content, i+3, '\'')
			b.emit(i, end, KindString)
			i = end
		case c == '"':
			end := scanGroovyQuoted(content, i, '"')
			b.emit(i, end, KindString)
			i = end
		case c == '\'':
			end := scanGroovyQuoted(content, i, '\'')
			b.emit(i, end, KindString)
			i = end
		case c == '/' && groovySlashyCanStart(prevSignificant):
			end := scanGroovySlashy(content, i+1)
			b.emit(i, end, KindString)
			i = end
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

// scanGroovyQuoted returns the offset just past a single-line string literal
// (`"..."` GString or `'...'` plain) opening at content[start] with delimiter q.
// Backslash escapes are honored; for a GString the `$var`/`${expr}` markers do
// NOT end the string (the whole literal stays one region). A newline ends the
// scan because a single-line Groovy string may not span a line, so a runaway
// quote cannot swallow real code.
func scanGroovyQuoted(content []byte, start int, q byte) int {
	n := len(content)
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

// scanGroovyTriple returns the offset just past a triple-quoted string literal
// (`"""..."""` or `”'...”'`) whose body begins at bodyStart (the byte after the
// opening run of three delimiter bytes q). Triple-quoted strings may span many
// lines and are closed by the first run of three q. Backslash escapes are honored
// (so `\"""` inside a `"""` block does not close it early). An unterminated
// literal runs to EOF.
func scanGroovyTriple(content []byte, bodyStart int, q byte) int {
	n := len(content)
	i := bodyStart
	for i < n {
		if content[i] == '\\' {
			i += 2
			continue
		}
		if content[i] == q && i+2 < n && content[i+1] == q && content[i+2] == q {
			return i + 3
		}
		i++
	}
	return n
}

// scanGroovySlashy returns the offset just past a slashy string `/.../` whose body
// begins at bodyStart (the byte after the opening `/`). Slashy strings honor `\/`
// as an escaped delimiter and carry `$var`/`${}` interpolation (markers do not end
// the string). Closed at the first unescaped `/`; a newline ends the scan
// defensively (a slashy string is single-line) so a stray `/` cannot swallow code.
func scanGroovySlashy(content []byte, bodyStart int) int {
	n := len(content)
	i := bodyStart
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '/':
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}

// scanGroovyDollarSlashy returns the offset just past a dollar-slashy string
// `$/.../$` whose body begins at bodyStart (the byte after the opening `$/`).
// These span multiple lines; the only escapes are `$$` (a literal `$`) and `$/`
// (a literal `/`), and the literal is closed by the first `/$`. An unterminated
// literal runs to EOF.
func scanGroovyDollarSlashy(content []byte, bodyStart int) int {
	n := len(content)
	i := bodyStart
	for i < n {
		if content[i] == '$' && i+1 < n && (content[i+1] == '$' || content[i+1] == '/') {
			i += 2 // `$$` and `$/` are escapes, not a close
			continue
		}
		if content[i] == '/' && i+1 < n && content[i+1] == '$' {
			return i + 2
		}
		i++
	}
	return n
}

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
