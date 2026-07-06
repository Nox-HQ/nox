package lexctx

// scanPowerShell walks PowerShell source and classifies each byte as code,
// string, or comment. PowerShell has no CGo-free parser in nox's toolchain, so
// this is a deliberately PRAGMATIC, deterministic classifier (the same posture
// as the Ruby/PHP scanners): it recognizes the constructs that carry the
// overwhelming majority of secret/pattern and taint false positives.
//
//   - `#` line comments (to end of line) — but NOT a `#` inside a string, which
//     the string scanner consumes first.
//   - `<# ... #>` block comments, which span lines. They do NOT nest in Windows
//     PowerShell (the first `#>` closes), matching how the Go/C-style block
//     comment scanners behave; the first close wins.
//   - single-quoted strings `'...'` — no interpolation; the only escape is a
//     doubled quote `”` (PowerShell's literal-quote escape), so `'it”s'` is one
//     string.
//   - double-quoted strings `"..."` — interpolate `$var`, `${var name}`, and
//     `$( ... )` subexpressions, whose replacement bytes are emitted as CODE (a
//     tainted value spliced via "id=$($q)" lives in a real expression). The
//     backtick "`" is PowerShell's escape character, so a "`\"" does not close
//     the string and a doubled quote `""` is a literal quote.
//   - here-strings `@"..."@` (interpolating) and `@'...'@` (literal). A
//     here-string opener (`@"` / `@'`) must be the last token on its line, and
//     the terminator (`"@` / `'@`) must appear at the START of a line (column 0,
//     leading whitespace not allowed on the closing token per the language
//     spec). The body runs across newlines to that terminator and is emitted as
//     string (data blobs and templates live here); interpolating here-strings
//     still emit `$(...)`/`${...}` fields as code.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
// Every heuristic degrades safely: a misread only costs FP-suppression, never
// correctness, because an over-broad code region merely disables suppression.
func scanPowerShell(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)

	for i < n {
		c := content[i]

		switch {
		case c == '<' && i+1 < n && content[i+1] == '#':
			// `<# ... #>` block comment (spans lines, does not nest).
			end := scanPSBlockComment(content, i)
			b.emit(i, end, KindComment)
			i = end
			continue
		case c == '#':
			// `#` line comment to end of line.
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
			continue
		case c == '@' && i+1 < n && content[i+1] == '"' && psHereStringOpens(content, i):
			// Interpolating here-string @"..."@ .
			i = scanPSHereString(content, i, true, &b)
			continue
		case c == '@' && i+1 < n && content[i+1] == '\'' && psHereStringOpens(content, i):
			// Literal here-string @'...'@ .
			i = scanPSHereString(content, i, false, &b)
			continue
		case c == '\'':
			end := scanPSSingleQuote(content, i)
			b.emit(i, end, KindString)
			i = end
			continue
		case c == '"':
			i = scanPSDoubleQuote(content, i, &b)
			continue
		case c == '`':
			// Backtick is the line-continuation / escape char in code; consume it
			// and the following byte as code so a "`#" does not open a comment.
			end := i + 2
			if end > n {
				end = n
			}
			b.emit(i, end, KindCode)
			i = end
			continue
		default:
			b.emit(i, i+1, KindCode)
			i++
			continue
		}
	}
	return b.finish(n)
}

// scanPSBlockComment returns the offset just past a `<# ... #>` block comment
// opening at start. It does NOT nest — the first `#>` closes it. An unterminated
// block runs to EOF.
func scanPSBlockComment(content []byte, start int) int {
	n := len(content)
	i := start + 2 // past `<#`
	for i < n {
		if content[i] == '#' && i+1 < n && content[i+1] == '>' {
			return i + 2
		}
		i++
	}
	return n
}

// scanPSSingleQuote returns the offset just past a single-quoted string opening
// at start. PowerShell single-quoted strings do not interpolate and have no
// backslash/backtick escaping; the only escape is a DOUBLED quote (`”`), which
// stays inside the literal. A single quote that is not doubled closes the
// string. Single-quoted strings do not span newlines, so a newline defensively
// closes an unterminated literal so a stray quote cannot swallow real code.
func scanPSSingleQuote(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\'':
			if i+1 < n && content[i+1] == '\'' {
				i += 2 // doubled quote is a literal quote inside the string
				continue
			}
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}

// scanPSDoubleQuote classifies a double-quoted string opening at start, emitting
// the literal parts as string and each interpolation as CODE: a `$( ... )`
// subexpression, a `${ ... }` braced variable, and a bare `$var` (and `$a.b`
// property access). Emitting the interpolated expression as code mirrors the
// Ruby `#{}` and Python f-string scanners — a tainted value spliced via
// "id=$id" lives in a real expression the taint engine must see. The backtick
// escapes the next byte (so "`\"" does not close the string, and "`$" is a
// literal dollar, not an interpolation), and a DOUBLED quote (`""`) is a literal
// quote. It returns the offset just past the closing quote (or a newline / EOF
// for an unterminated string).
func scanPSDoubleQuote(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	bodyStart := start + 1
	b.emit(start, bodyStart, KindString)
	i := bodyStart
	runStart := bodyStart
	for i < n {
		c := content[i]
		switch {
		case c == '`':
			i += 2 // backtick escapes the next byte (including a quote or `$`)
			continue
		case c == '$' && i+1 < n:
			// An interpolation: `$( ... )`, `${ ... }`, or a bare `$var`/`$a.b`.
			fieldEnd := scanPSInterpolation(content, i)
			if fieldEnd > i {
				b.emit(runStart, i, KindString)
				b.emit(i, fieldEnd, KindCode)
				i = fieldEnd
				runStart = i
				continue
			}
			i++
			continue
		case c == '"':
			if i+1 < n && content[i+1] == '"' {
				i += 2 // doubled quote is a literal quote inside the string
				continue
			}
			b.emit(runStart, i+1, KindString)
			return i + 1
		case c == '\n':
			b.emit(runStart, i, KindString)
			return i
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanPSInterpolation returns the offset just past a PowerShell interpolation
// beginning at content[dollar] == '$', or dollar itself when the `$` does not
// start an interpolation (e.g. a trailing `$` or `$` before a non-identifier).
// It recognizes three forms:
//
//   - `$( ... )` subexpression — balanced parentheses.
//   - `${ ... }` braced variable — to the matching `}`.
//   - `$var` / `$var.prop` — an identifier run with dotted property access.
//
// The `$env:NAME` provider form is read as `$env` (the `:NAME` provider suffix
// stays in the surrounding string, which is harmless: the `env` variable read is
// what the source model keys on).
func scanPSInterpolation(content []byte, dollar int) int {
	n := len(content)
	if dollar+1 >= n {
		return dollar
	}
	switch content[dollar+1] {
	case '(':
		return scanPSSubexpr(content, dollar+1)
	case '{':
		// `${ ... }` braced variable to the matching '}'.
		for j := dollar + 2; j < n; j++ {
			if content[j] == '}' {
				return j + 1
			}
			if content[j] == '\n' {
				return j
			}
		}
		return n
	}
	// Bare `$var` (letters/digits/underscore), with optional `.prop` chains.
	j := dollar + 1
	if !isInterpIdentByte(content[j]) {
		return dollar // `$` not followed by an identifier: not an interpolation
	}
	for j < n && isInterpIdentByte(content[j]) {
		j++
	}
	// Consume `.prop` chains (property access), but not a trailing `.` alone.
	for j+1 < n && content[j] == '.' && isInterpIdentByte(content[j+1]) {
		j++ // consume '.'
		for j < n && isInterpIdentByte(content[j]) {
			j++
		}
	}
	return j
}

// isInterpIdentByte reports whether b can appear in a bare `$var` interpolation
// name (letters, digits, underscore).
func isInterpIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// scanPSSubexpr returns the offset just past a `$( ... )` subexpression whose
// `(` is at open. It balances nested parentheses and skips nested string
// literals so a `)` inside a nested string does not close the field early.
func scanPSSubexpr(content []byte, open int) int {
	n := len(content)
	depth := 0
	i := open
	for i < n {
		switch content[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		case '\'':
			i = scanPSSingleQuote(content, i)
			continue
		case '"':
			i = skipPSNestedDouble(content, i)
			continue
		}
		i++
	}
	return n
}

// skipPSNestedDouble returns the offset just past a nested double-quoted string
// inside a subexpression, honoring the backtick escape and doubled-quote escape.
// Nested interpolations inside it are not separately classified (they stay in the
// outer code field, which is harmless — the whole field is already code).
func skipPSNestedDouble(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '`':
			i += 2
			continue
		case '"':
			if i+1 < n && content[i+1] == '"' {
				i += 2
				continue
			}
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}

// psHereStringOpens reports whether the `@"` / `@'` at i is a here-string opener
// rather than an ordinary `@` (splat/array) followed by a string. A here-string
// opener must be the LAST non-whitespace token on its physical line: the byte
// after the opening quote may only be whitespace (or a CR) up to the newline.
func psHereStringOpens(content []byte, i int) bool {
	n := len(content)
	j := i + 2 // past `@"` or `@'`
	for j < n && content[j] != '\n' {
		if content[j] != ' ' && content[j] != '\t' && content[j] != '\r' {
			return false
		}
		j++
	}
	return true
}

// scanPSHereString classifies a here-string opening at start. The opener line
// (`@"` / `@'` and its trailing newline) and the body run to a terminator line
// whose content is exactly `"@` / `'@` at column 0 (leading whitespace is NOT
// allowed on the closing token). The opener and body are emitted as string; for
// an interpolating (`@"`) here-string, `$( ... )` and `${ ... }` fields are
// still emitted as code. An unterminated here-string runs to EOF.
func scanPSHereString(content []byte, start int, interp bool, b *regionBuilder) int {
	n := len(content)
	// The terminator byte pair: `"@` for @"..."@, `'@` for @'...'@ .
	quote := content[start+1] // '"' or '\''
	// Advance past the opener line (to just after its newline).
	bodyStart := start + 2
	for bodyStart < n && content[bodyStart] != '\n' {
		bodyStart++
	}
	if bodyStart < n {
		bodyStart++ // include the newline that ends the opener line
	}

	runStart := start // the opener bytes are string too
	// Scan line by line: the terminator `"@` / `'@` is only valid at column 0.
	lineStart := bodyStart
	for lineStart < n {
		// Terminator line: `"@` / `'@` at column 0 (leading whitespace not allowed).
		if content[lineStart] == quote && lineStart+1 < n && content[lineStart+1] == '@' {
			b.emit(runStart, lineStart+2, KindString)
			return lineStart + 2
		}
		// Find the end of this physical line.
		lineEnd := lineStart
		for lineEnd < n && content[lineEnd] != '\n' {
			lineEnd++
		}
		// For an interpolating here-string, emit each interpolation ($(...), ${...},
		// bare $var) on this line as code, mirroring the double-quoted-string policy.
		if interp {
			j := lineStart
			for j < lineEnd {
				if content[j] == '`' {
					j += 2 // backtick escapes the next byte
					continue
				}
				if content[j] == '$' {
					fieldEnd := scanPSInterpolation(content, j)
					if fieldEnd > j {
						b.emit(runStart, j, KindString)
						b.emit(j, fieldEnd, KindCode)
						runStart = fieldEnd
						j = fieldEnd
						continue
					}
				}
				j++
			}
		}
		// A `$( ... )` field may span lines; never step backwards over one.
		if runStart > lineEnd {
			lineEnd = runStart
			for lineEnd < n && content[lineEnd] != '\n' {
				lineEnd++
			}
		}
		lineStart = lineEnd
		if lineStart < n {
			lineStart++ // move to the first byte of the next line
		}
	}
	// Unterminated here-string: the rest of the file is body (string).
	b.emit(runStart, n, KindString)
	return n
}
