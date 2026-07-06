package lexctx

// scanSwift walks Swift source and classifies each byte as code, string, or
// comment. Swift's grammar has four gotchas a Go/C-style scanner gets wrong, and
// this scanner handles each explicitly:
//
//   - Comments: `//` line comments (to end of line) and `/* ... */` block
//     comments that NEST (like Rust, unlike Go/C). An inner `/*` opens a nested
//     comment whose matching `*/` does NOT close the outer one, so a base64 blob
//     or commented-out code containing `/*`…`*/` is fully consumed
//     (scanSwiftBlockComment tracks depth).
//
//   - Ordinary strings `"..."`: backslash escapes (`\"`, `\\`) and STRING
//     INTERPOLATION `\(expr)`. The interpolation expression may itself contain
//     parentheses and nested strings, so the scanner balances `(`…`)` inside the
//     hole (skipping nested string literals) rather than stopping at the first
//     `)` — otherwise a `\(f(x))` hole would be mis-terminated. Swift ordinary
//     strings do not span lines, so a newline defensively ends the scan.
//
//   - Multiline strings `"""..."""`: opened by three double-quotes, closed by the
//     next `"""`, span many lines, and treat interior single `"` and `//` as
//     literal. They also honor `\(...)` interpolation and `\` escapes.
//
//   - Raw strings `#"..."#`, `##"..."##`, … (N `#`s): NO backslash escapes — a
//     `\` is a literal byte — terminated only by `"` followed by the SAME number
//     of `#`s (an interior `"#` with too few hashes stays inside). Raw strings
//     interpolate with `\#(...)` (one extra `#` per opening hash); the hole is
//     kept inside the string with balanced parens. A raw string may combine with
//     the multiline form (`#"""..."""#`), which this scanner also recognizes.
//     Swift has no character literal (a `Character` is written as a String), so
//     there is no `'...'` rune/char case.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
func scanSwift(content []byte) []Region {
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
			end := scanSwiftBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '#' && swiftRawStringPrefix(content, i):
			end := scanSwiftRawString(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"':
			// Multiline string `"""..."""` (ordinary, hash count 0).
			end := scanSwiftMultiline(content, i+3, 0)
			b.emit(i, end, KindString)
			i = end
		case c == '"':
			end := scanSwiftInterpreted(content, i+1, 0)
			b.emit(i, end, KindString)
			i = end
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// scanSwiftBlockComment returns the offset just past a `/* ... */` block comment
// whose body begins at bodyStart (just after the opening `/*`). Swift block
// comments NEST: each inner `/*` increments depth and each `*/` decrements it;
// the comment ends only when depth returns to zero. An unterminated comment runs
// to EOF.
func scanSwiftBlockComment(content []byte, bodyStart int) int {
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

// swiftRawStringPrefix reports whether the byte at start begins a raw-string
// prefix `#"` or `##`…`"` — i.e. one or more `#` followed by a `"` (for the
// single-line form) or by `"""` (for the multiline raw form). It is the
// disambiguator that stops an ordinary `#` (an attribute/directive marker such
// as `#if`, `#selector`) from being scanned as a raw string.
func swiftRawStringPrefix(content []byte, start int) bool {
	n := len(content)
	if start >= n || content[start] != '#' {
		return false
	}
	i := start
	for i < n && content[i] == '#' {
		i++
	}
	return i < n && content[i] == '"'
}

// scanSwiftRawString returns the offset just past a raw string literal opening at
// content[start] (which must satisfy swiftRawStringPrefix). It counts the N `#`s,
// then dispatches to the multiline raw form when the opening quote run is `"""`,
// otherwise the single-line raw form. No backslash escapes are processed; `\#(…)`
// interpolation (one `#` per opening hash) is kept inside the string with
// balanced parens. Termination is `"` (single-line) or `"""` (multiline)
// followed by exactly N `#`s.
func scanSwiftRawString(content []byte, start int) int {
	n := len(content)
	i := start
	hashes := 0
	for i < n && content[i] == '#' {
		hashes++
		i++
	}
	// content[i] is the opening '"'. A `"""` run opens the multiline raw form.
	if i+2 < n && content[i] == '"' && content[i+1] == '"' && content[i+2] == '"' {
		return scanSwiftMultiline(content, i+3, hashes)
	}
	// Single-line raw string: body begins after the single opening quote.
	i++ // past opening quote
	for i < n {
		if content[i] == '"' {
			// A candidate close: require exactly `hashes` trailing '#'.
			if swiftHashRun(content, i+1, hashes) {
				return i + 1 + hashes
			}
			i++
			continue
		}
		if content[i] == '\\' && swiftRawInterpStart(content, i, hashes) {
			// `\#(…)` interpolation hole: skip it (balanced) so its `)` and any
			// nested `"` are not read as a close.
			i = skipSwiftInterpolation(content, i+1+hashes)
			continue
		}
		// Raw strings do not span physical lines in single-line form.
		if content[i] == '\n' {
			return i
		}
		i++
	}
	return n
}

// scanSwiftInterpreted returns the offset just past an ordinary interpreted
// string literal whose body begins at bodyStart (the byte after the opening
// `"`). Backslash escapes are honored, `\(…)` interpolation holes are skipped
// with balanced parens, and — because a non-multiline Swift string may not span
// a line — a newline defensively ends the scan so a runaway quote cannot swallow
// real code. hashes is 0 for ordinary strings (kept for signature symmetry with
// the raw/multiline forms).
func scanSwiftInterpreted(content []byte, bodyStart, hashes int) int {
	n := len(content)
	i := bodyStart
	for i < n {
		switch content[i] {
		case '\\':
			if swiftInterpStart(content, i, hashes) {
				i = skipSwiftInterpolation(content, i+1+hashes)
				continue
			}
			i += 2 // ordinary escape
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

// scanSwiftMultiline returns the offset just past a multiline string whose body
// begins at bodyStart (just after the opening `"""`). It is closed by the next
// `"""` followed by exactly `hashes` trailing `#`s (0 for the ordinary multiline
// form). Interior single/double `"`, `//`, and — for the ordinary form —
// backslash escapes and `\(…)` interpolation are all handled; the literal spans
// many lines. For the raw multiline form (hashes > 0) backslashes are literal
// except a `\###(…)`-style interpolation with the matching hash count.
func scanSwiftMultiline(content []byte, bodyStart, hashes int) int {
	n := len(content)
	i := bodyStart
	for i < n {
		if content[i] == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"' {
			if swiftHashRun(content, i+3, hashes) {
				return i + 3 + hashes
			}
		}
		if content[i] == '\\' {
			if swiftInterpStart(content, i, hashes) {
				i = skipSwiftInterpolation(content, i+1+hashes)
				continue
			}
			// A raw multiline string (hashes > 0) treats a lone `\` as literal;
			// an ordinary multiline string consumes the escaped byte.
			if hashes == 0 {
				i += 2
				continue
			}
		}
		i++
	}
	return n
}

// swiftInterpStart reports whether content[i] begins a `\` … interpolation for a
// string with the given hash count: `\(` for an ordinary string (hashes 0) or
// `\#(`, `\##(`, … with exactly `hashes` `#`s for a raw string.
func swiftInterpStart(content []byte, i, hashes int) bool {
	n := len(content)
	if i >= n || content[i] != '\\' {
		return false
	}
	j := i + 1
	for k := 0; k < hashes; k++ {
		if j >= n || content[j] != '#' {
			return false
		}
		j++
	}
	return j < n && content[j] == '('
}

// swiftRawInterpStart is swiftInterpStart specialized for the raw single-line
// scanner's readability; it reports a `\#…(` interpolation with `hashes` hashes.
func swiftRawInterpStart(content []byte, i, hashes int) bool {
	return swiftInterpStart(content, i, hashes)
}

// skipSwiftInterpolation returns the offset just past a `\(...)` interpolation
// hole whose OPENING `(` is at content[open]. It balances parentheses so a
// nested call `f(g(x))` does not end the hole early, and skips nested string
// literals inside the hole so a `)` inside an inner string is not counted.
// Everything inside the hole remains classified as STRING by the caller (the
// conservative, safe-degrade choice for the classifier). An unterminated hole
// runs to EOF.
func skipSwiftInterpolation(content []byte, open int) int {
	n := len(content)
	i := open
	if i >= n || content[i] != '(' {
		return i
	}
	depth := 0
	for i < n {
		switch content[i] {
		case '(':
			depth++
			i++
		case ')':
			depth--
			i++
			if depth == 0 {
				return i
			}
		case '"':
			// Skip a nested string literal inside the interpolation expression so
			// its parens/quotes are not miscounted. Multiline nested strings are
			// rare inside a hole; the single-line skip is sufficient and safe.
			i = scanSwiftInterpreted(content, i+1, 0)
		default:
			i++
		}
	}
	return n
}

// swiftHashRun reports whether content has exactly `hashes` `#` bytes starting at
// start (used to confirm a raw string's closing hash count matches its opener).
// A run of MORE than `hashes` still matches — only the required count must be
// present — mirroring Swift, where trailing `#`s beyond the opener's count are
// outside the literal.
func swiftHashRun(content []byte, start, hashes int) bool {
	n := len(content)
	if hashes == 0 {
		return true
	}
	count := 0
	for i := start; i < n && count < hashes && content[i] == '#'; i++ {
		count++
	}
	return count == hashes
}
