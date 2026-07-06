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
//     INTERPOLATION `\(expr)`. The literal parts are emitted as STRING and each
//     `\(...)` interpolation field is emitted as CODE — because a tainted value
//     spliced via "id=\(userInput)" lives in a real expression the taint engine
//     must see (this is the dominant SQL/command-injection carrier in Swift, the
//     analogue of Ruby's `#{...}`). The field scanner balances parentheses and
//     skips nested strings so a `\(f(x))` hole is not mis-terminated. Swift
//     ordinary strings do not span lines, so a newline defensively ends the scan.
//
//   - Multiline strings `"""..."""`: opened by three double-quotes, closed by the
//     next `"""`, span many lines, treat interior single `"` and `//` as literal,
//     and honor `\(...)` interpolation (emitted as code) and `\` escapes.
//
//   - Raw strings `#"..."#`, `##"..."##`, … (N `#`s): NO backslash escapes — a
//     `\` is a literal byte — terminated only by `"` followed by the SAME number
//     of `#`s (an interior `"#` with too few hashes stays inside). Raw strings
//     interpolate with `\#(...)` (one extra `#` per opening hash), whose field is
//     likewise emitted as code. A raw string may combine with the multiline form
//     (`#"""..."""#`), which this scanner also recognizes. Swift has no character
//     literal (a `Character` is written as a String), so there is no `'...'` case.
//
// The string scanners emit into the regionBuilder directly (like the Ruby/Python
// f-string scanners) because interpolation splits a string region into
// string/code sub-runs. All spans are strictly increasing and contiguous so the
// returned regions are gap-free and cover [0, len(content)).
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
			i = scanSwiftRawString(content, i, &b)
		case c == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"':
			// Multiline string `"""..."""` (ordinary, hash count 0).
			i = scanSwiftMultiline(content, i, 0, &b)
		case c == '"':
			i = scanSwiftInterpreted(content, i, 0, &b)
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
// prefix `#"` or `##`…`"` — i.e. one or more `#` followed by a `"` (single-line)
// or `"""` (multiline raw). It is the disambiguator that stops an ordinary `#`
// (an attribute/directive marker such as `#if`, `#selector`) from being scanned
// as a raw string.
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

// scanSwiftRawString classifies a raw string literal opening at content[start]
// (which must satisfy swiftRawStringPrefix), emitting literal runs as string and
// each `\#(…)` interpolation field (one `#` per opening hash) as code. It counts
// the N `#`s, dispatches to the multiline raw form on a `"""` opener, else the
// single-line raw form. No backslash escapes are processed (a `\` not starting a
// matching-hash interpolation is literal). Termination is `"` (single-line) or
// `"""` (multiline) followed by exactly N `#`s. Returns the offset just past the
// literal (or EOF).
func scanSwiftRawString(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	i := start
	hashes := 0
	for i < n && content[i] == '#' {
		hashes++
		i++
	}
	// content[i] is the opening '"'. A `"""` run opens the multiline raw form.
	if i+2 < n && content[i] == '"' && content[i+1] == '"' && content[i+2] == '"' {
		return scanSwiftMultiline(content, start, hashes, b)
	}
	// Single-line raw string: the opener run [start, i+1) (hashes + one quote) is
	// string; the body begins after the opening quote.
	bodyStart := i + 1
	b.emit(start, bodyStart, KindString)
	i = bodyStart
	runStart := bodyStart
	for i < n {
		if content[i] == '"' && swiftHashRun(content, i+1, hashes) {
			end := i + 1 + hashes
			b.emit(runStart, end, KindString)
			return end
		}
		if content[i] == '\\' && swiftInterpStart(content, i, hashes) {
			b.emit(runStart, i, KindString)
			fieldEnd := swiftEmitInterpolation(content, i, hashes, b)
			i = fieldEnd
			runStart = i
			continue
		}
		if content[i] == '\n' { // single-line raw string does not span lines
			b.emit(runStart, i, KindString)
			return i
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// scanSwiftInterpreted classifies an ordinary interpreted string literal opening
// at content[start] (content[start] is the opening `"`), emitting literal runs as
// string and each `\(…)` interpolation field as code. Backslash escapes are
// honored; a newline defensively ends the scan (a non-multiline Swift string may
// not span a line) so a runaway quote cannot swallow real code. hashes is 0 for
// ordinary strings. Returns the offset just past the literal (or EOF).
func scanSwiftInterpreted(content []byte, start, hashes int, b *regionBuilder) int {
	n := len(content)
	bodyStart := start + 1
	b.emit(start, bodyStart, KindString)
	i := bodyStart
	runStart := bodyStart
	for i < n {
		c := content[i]
		if c == '\\' {
			if swiftInterpStart(content, i, hashes) {
				b.emit(runStart, i, KindString)
				fieldEnd := swiftEmitInterpolation(content, i, hashes, b)
				i = fieldEnd
				runStart = i
				continue
			}
			i += 2 // ordinary escape
			continue
		}
		if c == '"' {
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

// scanSwiftMultiline classifies a multiline string opening at content[start]. For
// the ordinary form (hashes 0) content[start] is the first of the opening `"""`;
// for the raw multiline form (hashes > 0) content[start] is the first `#` and the
// opener is `#…"""`. It is closed by `"""` followed by exactly `hashes` trailing
// `#`s, spans many lines, treats interior single/double `"` and `//` as literal,
// and emits `\(…)` interpolation fields as code (backslash escapes honored for
// the ordinary form; a `\` is literal for the raw form except a matching-hash
// interpolation). Returns the offset just past the literal (or EOF).
func scanSwiftMultiline(content []byte, start, hashes int, b *regionBuilder) int {
	n := len(content)
	// The opener is `#…` (hashes) + `"""`; emit it as string and set the body.
	bodyStart := start + hashes + 3
	if bodyStart > n {
		bodyStart = n
	}
	b.emit(start, bodyStart, KindString)
	i := bodyStart
	runStart := bodyStart
	for i < n {
		if content[i] == '"' && i+2 < n && content[i+1] == '"' && content[i+2] == '"' &&
			swiftHashRun(content, i+3, hashes) {
			end := i + 3 + hashes
			b.emit(runStart, end, KindString)
			return end
		}
		if content[i] == '\\' {
			if swiftInterpStart(content, i, hashes) {
				b.emit(runStart, i, KindString)
				fieldEnd := swiftEmitInterpolation(content, i, hashes, b)
				i = fieldEnd
				runStart = i
				continue
			}
			if hashes == 0 {
				i += 2 // ordinary escape consumes the next byte
				continue
			}
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// swiftEmitInterpolation emits a `\(…)` (or `\#…(…)`) interpolation field opening
// at content[start] (content[start] is the `\`) as a single CODE region and
// returns the offset just past the closing `)`. It balances parentheses inside
// the hole and skips nested string literals so a `)` inside `\(f(g(x)))` or an
// inner string does not close the field early. An unterminated field runs to EOF.
func swiftEmitInterpolation(content []byte, start, hashes int, b *regionBuilder) int {
	// The `(` sits after `\` + `hashes` `#`s.
	open := start + 1 + hashes
	end := scanSwiftInterpField(content, open)
	b.emit(start, end, KindCode)
	return end
}

// scanSwiftInterpField returns the offset just past a `(...)` interpolation field
// whose opening `(` is at content[open]. It balances parentheses and skips nested
// string literals (so their quotes/parens are not miscounted). An unterminated
// field runs to EOF.
func scanSwiftInterpField(content []byte, open int) int {
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
			i = skipSwiftNestedString(content, i)
		default:
			i++
		}
	}
	return n
}

// skipSwiftNestedString returns the offset just past a nested double-quoted
// string inside an interpolation field, honoring backslash escapes and ending at
// EOF or a newline. Nested interpolations inside it are not separately classified
// (they stay inside the outer code field, which is harmless — the whole field is
// already code).
func skipSwiftNestedString(content []byte, start int) int {
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

// swiftHashRun reports whether content has at least `hashes` `#` bytes starting
// at start (used to confirm a raw string's closing hash count matches its
// opener). hashes == 0 always matches.
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
