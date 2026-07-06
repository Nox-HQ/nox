package lexctx

// scanElixir walks Elixir source and classifies each byte as code, string, or
// comment. Elixir has no macro-level grammar we can cheaply parse (pure-Go, no
// CGo, no dependency), so this is a deliberately PRAGMATIC, deterministic
// classifier that recognizes the constructs carrying the overwhelming majority
// of secret/pattern and taint false positives:
//
//   - `#` LINE comments (to end of line). Elixir has NO block comments, so a `#`
//     in code context always begins a line comment — but a `#` inside a string,
//     an interpolation `#{`, or a `?#` char code is consumed by those scanners
//     first and never seen here.
//   - double-quoted strings `"..."` — backslash escapes AND `#{ ... }`
//     interpolation, whose replacement fields are emitted as CODE (a tainted
//     value spliced via "id=#{conn.params}" lives in a real expression).
//   - single-quoted charlists `'...'` — same escape/interpolation rules as double
//     quotes (Elixir charlists interpolate); the body is string, `#{}` is code.
//   - triple-quoted heredocs `"""..."""` and `”'...”'` — the body from the line
//     after the opening delimiter to the closing delimiter line is string;
//     `#{}` interpolation inside is code (heredocs interpolate like their
//     single-line counterpart unless the sigil form suppresses it).
//   - sigils `~x(...)`, `~x{...}`, `~x[...]`, `~x<...>`, `~x/.../`, `~x|...|`,
//     `~x"..."`, `~x'...'` — a LOWERCASE sigil letter interpolates (its `#{}`
//     fields are code); an UPPERCASE sigil letter does NOT (the whole body is
//     literal string). Paired-bracket delimiters nest; a backslash escapes the
//     closing delimiter.
//   - `?c` character codes — `?a`, `?\n`, `?"`, `?#` are a single integer literal,
//     NOT a string/comment opener. The two bytes (`?` and the char, or `?\` and
//     the escaped char) are code, so a `?"` never opens a string that swallows
//     the line.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0,len(content)).
// Every heuristic degrades safely: a misread only costs FP-suppression, never
// correctness, because an over-broad code region merely disables suppression.
func scanElixir(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)

	for i < n {
		c := content[i]

		switch {
		case c == '\n':
			b.emit(i, i+1, KindCode)
			i++
			continue

		case c == '#' && i+1 < n && content[i+1] == '{':
			// A bare `#{` in CODE context is not valid Elixir (interpolation only
			// lives inside strings), but treat it defensively as code so it never
			// opens a comment.
			b.emit(i, i+2, KindCode)
			i += 2
			continue

		case c == '#':
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
			continue

		case c == '?':
			// `?c` character code: the `?` plus one char (or `?\x` escape) is a single
			// integer literal. Emit both bytes as code so a `?"` / `?#` never opens a
			// string or comment.
			end := i + 1
			if end < n && content[end] == '\\' {
				end += 2 // ?\n, ?\", ?\\ …
			} else if end < n {
				end++
			}
			if end > n {
				end = n
			}
			b.emit(i, end, KindCode)
			i = end
			continue

		case c == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"':
			i = scanElixirHeredoc(content, i, '"', &b)
			continue

		case c == '\'' && i+2 < n && content[i+1] == '\'' && content[i+2] == '\'':
			i = scanElixirHeredoc(content, i, '\'', &b)
			continue

		case c == '"':
			i = scanElixirInterpolated(content, i, '"', true, &b)
			continue

		case c == '\'':
			i = scanElixirInterpolated(content, i, '\'', true, &b)
			continue

		case c == '~' && isElixirSigilStart(content, i):
			i = scanElixirSigil(content, i, &b)
			continue

		default:
			b.emit(i, i+1, KindCode)
			i++
			continue
		}
	}
	return b.finish(n)
}

// scanElixirInterpolated classifies a single-line string or charlist opening at
// start with delimiter closeByte (`"` or `'`). Literal runs are emitted as
// string; `#{ ... }` fields (balanced, nesting-aware) are emitted as code when
// interp is true. Backslash escapes suppress the next byte. Returns the offset
// just past the closing delimiter (or EOF / newline for an unterminated literal).
func scanElixirInterpolated(content []byte, start int, closeByte byte, interp bool, b *regionBuilder) int {
	n := len(content)
	bodyStart := start + 1
	b.emit(start, bodyStart, KindString) // opening delimiter is string
	i := bodyStart
	runStart := bodyStart
	for i < n {
		c := content[i]
		if c == '\\' {
			i += 2
			continue
		}
		if interp && c == '#' && i+1 < n && content[i+1] == '{' {
			b.emit(runStart, i, KindString)
			fieldEnd := scanElixirInterpField(content, i+1)
			b.emit(i, fieldEnd, KindCode)
			i = fieldEnd
			runStart = i
			continue
		}
		if c == closeByte {
			b.emit(runStart, i+1, KindString)
			return i + 1
		}
		if c == '\n' {
			// A single-line string does not cross a newline in valid Elixir;
			// terminate defensively so a missing close quote cannot swallow code.
			b.emit(runStart, i, KindString)
			return i
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanElixirHeredoc classifies a triple-quoted heredoc opening at start with
// quote byte q (`"` for `"""`, `'` for `”'`). The opener line (the `"""` and any
// trailing code up to the newline) is emitted as code; the body — from the next
// line to the closing `"""` line — is string, with `#{}` interpolation fields
// emitted as code; the closing delimiter line is code. An unterminated heredoc
// runs to EOF as string.
func scanElixirHeredoc(content []byte, start int, q byte, b *regionBuilder) int {
	n := len(content)
	// Emit the opener line (start .. end of the physical line, inclusive of its
	// newline) as code so same-line trailing code stays code.
	lineEnd := start + 3
	for lineEnd < n && content[lineEnd] != '\n' {
		lineEnd++
	}
	if lineEnd < n {
		lineEnd++ // include the newline ending the opener line
	}
	b.emit(start, lineEnd, KindCode)

	bodyStart := lineEnd
	i := lineEnd
	for i < n {
		// At the start of a physical line: is this the closing delimiter line
		// (optional leading whitespace, then `"""`/`'''`)?
		ls := i
		j := ls
		for j < n && (content[j] == ' ' || content[j] == '\t') {
			j++
		}
		if j+3 <= n && content[j] == q && content[j+1] == q && content[j+2] == q {
			// Flush the body (excluding this closing line) as string.
			if ls > bodyStart {
				b.emit(bodyStart, ls, KindString)
			}
			// The closing line (through its newline) is code.
			le := j + 3
			for le < n && content[le] != '\n' {
				le++
			}
			if le < n {
				le++ // include the trailing newline
			}
			b.emit(ls, le, KindCode)
			return le
		}
		// Not a closing line: consume the physical line (it stays in the body).
		le := ls
		for le < n && content[le] != '\n' {
			le++
		}
		if le < n {
			le++ // include the newline in the body
		}
		i = le
	}
	// Unterminated heredoc: the rest of the file is body (string).
	if n > bodyStart {
		b.emit(bodyStart, n, KindString)
	}
	return n
}

// scanElixirInterpField returns the offset just past a `#{ ... }` interpolation
// field whose `{` is at open. It balances nested braces and skips nested string
// literals so a `}` inside a nested string does not close the field early.
func scanElixirInterpField(content []byte, open int) int {
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
			i = skipElixirNestedQuote(content, i, '"')
			continue
		case '\'':
			i = skipElixirNestedQuote(content, i, '\'')
			continue
		}
		i++
	}
	return n
}

// skipElixirNestedQuote returns the offset just past a nested single-line string
// or charlist inside an interpolation field, honoring backslash escapes. Nested
// interpolations inside it are not separately classified (they stay inside the
// outer code field, which is harmless — the whole field is already code).
func skipElixirNestedQuote(content []byte, start int, closeByte byte) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case closeByte:
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}

// isElixirSigilStart reports whether a `~` at i begins a sigil rather than a
// bitwise-not / `~~~`. A sigil is `~` followed by a sigil letter (a single ASCII
// letter) then a delimiter byte. `~~~` (bitwise not) and `~=`/`~>` (rare
// operators) do not match because the byte after `~` is not a lone letter+delim.
func isElixirSigilStart(content []byte, i int) bool {
	n := len(content)
	j := i + 1
	if j >= n {
		return false
	}
	c := content[j]
	if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
		return false
	}
	// Elixir sigil names are a single letter (custom multi-letter sigils exist in
	// modern Elixir but are rare; a single-letter name covers ~s ~r ~w ~c ~D etc.).
	// The byte after the letter must be a recognized delimiter.
	d := j + 1
	if d >= n {
		return false
	}
	return elixirSigilCloser(content[d]) != 0
}

// scanElixirSigil classifies a sigil opening at start (`~` at start). The `~x`
// prefix and its delimiters are string-kind; a LOWERCASE sigil letter
// interpolates (its `#{}` fields are code), an UPPERCASE one does not. Modifier
// letters after the closing delimiter (e.g. `~r/.../i`) are consumed as code.
// Returns the offset just past the sigil (including modifiers).
func scanElixirSigil(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	letter := content[start+1]
	interp := letter >= 'a' && letter <= 'z' // lowercase interpolates
	open := content[start+2]
	closeByte := elixirSigilCloser(open)
	nested := open != closeByte
	depth := 1
	i := start + 3
	runStart := start // the `~x` + opening delimiter are string
	for i < n {
		c := content[i]
		if c == '\\' {
			i += 2
			continue
		}
		if interp && c == '#' && i+1 < n && content[i+1] == '{' {
			b.emit(runStart, i, KindString)
			fieldEnd := scanElixirInterpField(content, i+1)
			b.emit(i, fieldEnd, KindCode)
			i = fieldEnd
			runStart = i
			continue
		}
		if nested && c == open {
			depth++
		} else if c == closeByte {
			depth--
			if depth == 0 {
				// Consume trailing modifier letters (they are part of the sigil, and
				// carry no data — classify them as string so the whole sigil is one
				// string run).
				j := i + 1
				for j < n && (content[j] >= 'a' && content[j] <= 'z' || content[j] >= 'A' && content[j] <= 'Z') {
					j++
				}
				b.emit(runStart, j, KindString)
				return j
			}
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// elixirSigilCloser returns the closing delimiter for a sigil opener, or 0 if the
// byte cannot open a sigil. Paired brackets have a distinct closer; the symmetric
// delimiters (`/ | " '`) are their own closer.
func elixirSigilCloser(open byte) byte {
	switch open {
	case '(':
		return ')'
	case '{':
		return '}'
	case '[':
		return ']'
	case '<':
		return '>'
	case '/', '|', '"', '\'':
		return open
	}
	return 0
}
