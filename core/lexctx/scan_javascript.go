package lexctx

// scanJavaScript walks JS/TS/JSX/TSX source and classifies each byte. It
// recognizes:
//
//   - `//` line comments and `/* ... */` block comments — including a `//` that
//     appears inside a string or URL, which is NOT a comment because the string
//     scanner consumes the literal first
//   - single-quoted, double-quoted, and backtick template-literal strings, all
//     with backslash escapes
//   - template-literal `${ ... }` interpolation, whose bytes are emitted as
//     CODE (a value spliced into a template lives in a real expression), with
//     correct handling of nested templates and brace balancing
//   - regex literals (`/.../`) vs the division operator, disambiguated by the
//     preceding significant token (the standard lexer heuristic), so a pattern
//     inside a regex body is classified as string rather than mis-scanned as a
//     `//` comment
//
// It does not model JSX element structure: JSX text between tags is ordinary
// code as far as "could a secret hide here" goes, and treating it as code is
// the safe default (it never wrongly suppresses).
func scanJavaScript(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	// lastSignificant is the previous non-space, non-comment byte; it decides
	// whether a `/` begins a regex literal or is a division operator.
	var lastSignificant byte
	for i < n {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '/':
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
			// comment does not change lastSignificant
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '/' && regexAllowedAfter(lastSignificant):
			end := scanJSRegex(content, i)
			b.emit(i, end, KindString)
			i = end
			lastSignificant = '/'
		case c == '\'' || c == '"':
			end := scanJSQuoted(content, i, c)
			b.emit(i, end, KindString)
			i = end
			lastSignificant = c
		case c == '`':
			end := scanJSTemplate(content, i, &b)
			i = end
			lastSignificant = '`'
		default:
			b.emit(i, i+1, KindCode)
			if !isJSSpace(c) {
				lastSignificant = c
			}
			i++
		}
	}
	return b.finish(n)
}

// isJSSpace reports whether c is insignificant whitespace for the regex/division
// disambiguation.
func isJSSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// regexAllowedAfter reports whether a `/` following the given previous
// significant byte begins a regex literal rather than a division. A regex is
// allowed at expression-start positions: after operators, `(`, `[`, `{`, `,`,
// `;`, etc., or at the very start of input (prev == 0). After an identifier
// char, `)`, `]`, or `}` a `/` is division. This is the well-known,
// deterministic heuristic; it can misjudge a few exotic cases, but a misjudged
// regex only ever fails to suppress an FP — it never surfaces one.
func regexAllowedAfter(prev byte) bool {
	if prev == 0 {
		return true
	}
	if isIdentByte(prev) {
		return false
	}
	switch prev {
	case ')', ']', '}':
		return false
	default:
		return true
	}
}

// scanBlockComment returns the offset just past a `/* ... */` block comment
// whose body begins at bodyStart. Unterminated comments run to EOF.
func scanBlockComment(content []byte, bodyStart int) int {
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

// scanJSQuoted returns the offset just past a '...'/"..." literal opening at
// content[start] with delimiter q. A newline ends the scan (JS single/double
// quotes do not span lines unless escaped) so a stray quote cannot swallow code.
func scanJSQuoted(content []byte, start int, q byte) int {
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

// scanJSRegex returns the offset just past a `/.../flags` regex literal opening
// at content[start]. It honors escapes and character classes (`[...]`) inside
// which a `/` is literal, then consumes trailing flag letters. A newline ends
// the scan defensively.
func scanJSRegex(content []byte, start int) int {
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
				i++ // consume closing slash
				for i < n && isIdentByte(content[i]) {
					i++ // consume flag letters
				}
				return i
			}
		case '\n':
			return i
		}
		i++
	}
	return n
}

// scanJSTemplate classifies a `...` template literal opening at content[start],
// emitting the literal chunks as string and each `${ ... }` interpolation as
// code. It handles nested templates (a template inside an interpolation) via
// recursion and returns the offset just past the closing backtick. It emits
// directly into b so the mixed string/code structure is preserved.
func scanJSTemplate(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	i := start + 1
	stringRunStart := start // include the opening backtick in the string run
	for i < n {
		c := content[i]
		switch {
		case c == '\\':
			i += 2
			continue
		case c == '`':
			b.emit(stringRunStart, i+1, KindString)
			return i + 1
		case c == '$' && i+1 < n && content[i+1] == '{':
			// Flush the string chunk up to `${`, then scan the interpolation
			// expression as code.
			b.emit(stringRunStart, i, KindString)
			exprEnd := scanJSInterpolation(content, i, b)
			i = exprEnd
			stringRunStart = i
			continue
		}
		i++
	}
	b.emit(stringRunStart, n, KindString)
	return n
}

// scanJSInterpolation classifies a `${ ... }` field opening at content[open].
// The `${` and `}` framing plus the expression bytes are code, except that
// nested strings and nested templates inside the expression are recursed into
// so their contents keep the correct kind. Returns the offset just past `}`.
func scanJSInterpolation(content []byte, open int, b *regionBuilder) int {
	n := len(content)
	depth := 0
	i := open
	codeRunStart := open
	for i < n {
		c := content[i]
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				b.emit(codeRunStart, i+1, KindCode)
				return i + 1
			}
		case '\'', '"':
			b.emit(codeRunStart, i, KindCode)
			end := scanJSQuoted(content, i, c)
			b.emit(i, end, KindString)
			i = end
			codeRunStart = i
			continue
		case '`':
			b.emit(codeRunStart, i, KindCode)
			end := scanJSTemplate(content, i, b)
			i = end
			codeRunStart = i
			continue
		}
		i++
	}
	b.emit(codeRunStart, n, KindCode)
	return n
}
