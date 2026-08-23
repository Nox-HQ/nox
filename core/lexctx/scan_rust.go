package lexctx

// scanRust walks Rust source and classifies each byte as code, string, or
// comment. It recognizes the lexical constructs that carry secret/prompt false
// positives in Rust and treats everything else as code. Rust's grammar has
// three gotchas that a Go/C-style scanner gets wrong, and this scanner handles
// each explicitly:
//
//   - Comments: `//` line comments (incl. the doc forms `///` and `//!`, which
//     lex identically — run to end of line) and `/* ... */` block comments that
//     NEST. Unlike Go/C, an inner `/*` opens a nested comment whose matching
//     `*/` does NOT close the outer one; scanRustBlockComment tracks depth so a
//     base64 blob or commented-out code containing `/*`…`*/` is fully consumed.
//
//   - Strings: interpreted `"..."` (backslash escapes) plus RAW strings
//     `r"..."`, `r#"..."#`, `r##"..."##` … (N `#`s, no escapes, terminated only
//     by `"` followed by the SAME number of `#`s — an embedded `"` or `"#` with
//     too few hashes stays inside). Byte strings `b"..."` and raw byte strings
//     `br#"..."#` lex like their non-byte forms. Raw strings may span many
//     lines, which matters because a base64/data-URI blob is often a raw string.
//
//   - Char literals vs LIFETIMES: a char literal is a single char or escape in
//     single quotes (x, newline, or an escaped quote), closed at the matching
//     quote. But `'a` in `&'a str` or
//     `fn f<'a>()` is a LIFETIME — a `'` followed by an identifier that is NOT
//     then closed by a `'`. Treating a lifetime as an unterminated char literal
//     would swallow the following code (and the next string's opening quote)
//     into a bogus string region, so scanRustCharOrLifetime looks ahead and, on
//     recognizing a lifetime, emits nothing (the `'` is left as ordinary code).
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
func scanRust(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	for i < n {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '/':
			// Covers //, /// (outer doc) and //! (inner doc) uniformly.
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanRustBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == 'r' && rustRawStringPrefix(content, i):
			end := scanRustRawString(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == 'b' && i+1 < n && content[i+1] == 'r' && rustRawStringPrefix(content, i+1):
			// br"..." / br#"..."# raw byte string: same delimiter rules as a raw
			// string, just prefixed with the byte marker.
			end := scanRustRawString(content, i+1)
			b.emit(i, end, KindString)
			i = end
		case c == 'b' && i+1 < n && content[i+1] == '"':
			// b"..." byte string: escapes as in an ordinary string.
			end := scanRustInterpreted(content, i+1)
			b.emit(i, end, KindString)
			i = end
		case c == '"':
			end := scanRustInterpreted(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '\'':
			end, isChar := scanRustCharOrLifetime(content, i)
			if isChar {
				b.emit(i, end, KindString)
				i = end
			} else {
				// A lifetime: the `'` is ordinary code. Emit just the quote and
				// advance one byte so the following identifier is scanned as code.
				b.emit(i, i+1, KindCode)
				i++
			}
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// scanRustBlockComment returns the offset just past a `/* ... */` block comment
// whose body begins at bodyStart (i.e. just after the opening `/*`). Rust block
// comments NEST: each inner `/*` increments depth and each `*/` decrements it;
// the comment ends only when depth returns to zero. An unterminated comment runs
// to EOF.
func scanRustBlockComment(content []byte, bodyStart int) int {
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

// rustRawStringPrefix reports whether the byte at start begins a raw-string
// prefix `r"` or `r#`…`#"` — i.e. `r` followed by zero or more `#` and then a
// `"`. It is the disambiguator that stops an ordinary identifier beginning with
// `r` (like `run`) from being scanned as a raw string.
func rustRawStringPrefix(content []byte, start int) bool {
	n := len(content)
	if start >= n || content[start] != 'r' {
		return false
	}
	i := start + 1
	for i < n && content[i] == '#' {
		i++
	}
	return i < n && content[i] == '"'
}

// scanRustRawString returns the offset just past a raw string literal opening at
// content[start] (which must satisfy rustRawStringPrefix). It counts the N `#`s
// after `r`, then scans to the terminating `"` followed by exactly N `#`s. No
// escapes are processed and the literal may span multiple lines. An unterminated
// raw string runs to EOF.
func scanRustRawString(content []byte, start int) int {
	n := len(content)
	i := start + 1 // past 'r'
	hashes := 0
	for i < n && content[i] == '#' {
		hashes++
		i++
	}
	// content[i] is the opening '"'.
	i++ // past opening quote
	for i < n {
		if content[i] == '"' {
			// A candidate close: require exactly `hashes` trailing '#'.
			j := i + 1
			count := 0
			for j < n && count < hashes && content[j] == '#' {
				count++
				j++
			}
			if count == hashes {
				return j
			}
		}
		i++
	}
	return n
}

// scanRustInterpreted returns the offset just past an interpreted string literal
// `"..."` opening at content[start]. Backslash escapes are honored (`\"`, `\\`).
// Rust strings MAY span multiple lines, so — unlike Go/JS — a newline does not
// terminate the scan; only the matching unescaped `"` (or EOF) does.
func scanRustInterpreted(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '"':
			return i + 1
		}
		i++
	}
	return n
}

// scanRustCharOrLifetime disambiguates a `'` at content[start] between a char
// literal and a lifetime. It returns (end, true) with end just past the closing
// `'` for a char literal, or (start, false) for a lifetime (the caller then
// treats the `'` as ordinary code).
//
// Rules:
//   - `'\...'` (an escape immediately after the quote) is always a char literal.
//   - `'x'` — a single byte/char followed immediately by `'` — is a char literal.
//   - `'a`, `'abc`, `'static` — an identifier NOT closed by a `'` — is a
//     lifetime. We look ahead over the identifier run: if the byte after it is a
//     `'`, it was a (multi-byte / raw) char literal after all; otherwise it is a
//     lifetime.
func scanRustCharOrLifetime(content []byte, start int) (end int, isChar bool) {
	n := len(content)
	i := start + 1
	if i >= n {
		return start, false // a trailing quote at EOF: treat as non-char code
	}
	// Escaped char: '\n', '\'', '\\', '\u{...}' — definitely a char literal.
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
	// Not an escape. Peek: an identifier-start byte MIGHT be a lifetime.
	if isRustIdentStart(content[i]) {
		j := i
		for j < n && isRustIdentPart(content[j]) {
			j++
		}
		// If the run is a single char and immediately closed by `'`, it is a char
		// literal ('x'). If closed by `'` after a longer run it is still a char
		// literal by our lexing (rare), but a run NOT closed by `'` is a lifetime.
		if j < n && content[j] == '\'' {
			return j + 1, true // 'x' char literal (or oddly-long, still closed)
		}
		return start, false // lifetime: 'a, 'static, …
	}
	// A non-identifier char (punctuation, digit, space) followed by `'` is a
	// char literal like '9' or ' '.
	if i+1 < n && content[i+1] == '\'' {
		return i + 2, true
	}
	// Anything else: not a well-formed char; treat the `'` as code so we never
	// swallow following code into a runaway string.
	return start, false
}

// isRustIdentStart / isRustIdentPart mirror Rust's ASCII identifier rules (the
// subset that matters for lifetime detection: leading letter/underscore, then
// alnum/underscore). Non-ASCII identifiers are rare in lifetimes and degrade
// safely to "not a lifetime start".
func isRustIdentStart(b byte) bool { return asciiIdentStart(b) }

func isRustIdentPart(b byte) bool { return asciiIdentPart(b) }
