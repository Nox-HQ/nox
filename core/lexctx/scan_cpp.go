package lexctx

// scanCPP walks C and C++ source and classifies each byte as code, string, or
// comment. C and C++ share one lexer because their comment/string grammars and
// dangerous-API surface are identical for our purposes. It recognizes the
// lexical constructs that carry secret/prompt false positives — a `//` inside a
// URL string, a base64 blob in a string literal, a provider prefix in a comment
// — and treats everything else as code:
//
//   - `//` line comments (to end of line, honoring a `\`-newline splice that
//     continues the comment onto the next physical line) and `/* ... */` block
//     comments. C/C++ block comments do NOT nest, so the FIRST `*/` closes the
//     comment (scanBlockComment, shared with the Go/JS scanners, encodes this).
//   - string literals `"..."` with backslash escapes (`\"`, `\\`). An encoding
//     prefix (`L"..."`, `u8"..."`, `u"..."`, `U"..."`) is ordinary code before
//     the quote; the quote itself begins the string. A newline ends an
//     unterminated string defensively (a real C string may splice across lines
//     with a trailing `\`, which the escape handling already absorbs).
//   - RAW string literals `R"(...)"` / `R"delim(...)delim"` (C++11): no escapes
//     are processed and the body runs until the matching `)delim"`. An optional
//     encoding prefix may precede the `R` (`LR"(...)"`, `u8R"(...)"`). Raw
//     strings commonly carry regexes/base64/data-URI blobs, so getting them
//     right is the whole point of the classifier for C++.
//   - char literals `'a'` / `'\n'` with backslash escapes, closed at the
//     matching `'` or defensively at a newline. A digit separator apostrophe in
//     a numeric literal (`1'000`) is handled by only entering char-literal mode
//     when the `'` is not preceded by an identifier/digit byte.
//   - preprocessor directives (`#include <stdio.h>`, `#define X 1`). The line is
//     scanned as ordinary code EXCEPT that on an `#include`/`#import` directive
//     the angle-bracket header name `<stdio.h>` is treated as a string span so
//     its `/` and `.` never begin a comment and its `<`/`>` never look like
//     operators leaking into a stray string scan. `#`-leading lines also honor
//     `\`-newline splicing (a multi-line macro).
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
func scanCPP(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	atLineStart := true // true at the first non-blank byte of a logical line
	for i < n {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '/':
			end := scanCPPLineComment(content, i)
			b.emit(i, end, KindComment)
			i = end
			atLineStart = false
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
			atLineStart = false
		case c == '#' && atLineStart:
			// A preprocessor directive. Scan the (possibly line-spliced) directive,
			// classifying an `#include <...>` header name as a string so its bytes
			// never trip comment/operator scanning; everything else stays code.
			i = scanCPPPreprocessor(content, i, &b)
			atLineStart = false
		case c == '"':
			end := scanCPPString(content, i, 0)
			b.emit(i, end, KindString)
			i = end
			atLineStart = false
		case isRawStringOpen(content, i):
			end := scanCPPRawString(content, i)
			b.emit(i, end, KindString)
			i = end
			atLineStart = false
		case c == '\'' && cppCharLiteralHere(content, i):
			end := scanCPPChar(content, i)
			b.emit(i, end, KindString)
			i = end
			atLineStart = false
		case c == '\n':
			b.emit(i, i+1, KindCode)
			i++
			atLineStart = true
		case c == ' ' || c == '\t' || c == '\r':
			b.emit(i, i+1, KindCode)
			i++
			// Leading whitespace does not end line-start: `  #define` is a directive.
		default:
			b.emit(i, i+1, KindCode)
			i++
			atLineStart = false
		}
	}
	return b.finish(n)
}

// scanCPPLineComment returns the offset just past a `//` line comment opening at
// content[start]. The comment runs to end of line, but a `\`-newline splice
// (trailing backslash before the newline) continues it onto the next physical
// line — a C/C++ line-continuation quirk that also applies to comments.
func scanCPPLineComment(content []byte, start int) int {
	n := len(content)
	i := start + 2
	for i < n {
		if content[i] == '\\' && i+1 < n {
			// Absorb a spliced newline (optionally a CRLF) so the comment continues.
			if content[i+1] == '\n' {
				i += 2
				continue
			}
			if content[i+1] == '\r' && i+2 < n && content[i+2] == '\n' {
				i += 3
				continue
			}
			i++
			continue
		}
		if content[i] == '\n' {
			return i
		}
		i++
	}
	return n
}

// scanCPPString returns the offset just past a string literal `"..."` whose
// opening quote is at content[quote]. prefixLen is unused by the scan itself (the
// caller has already positioned quote at the `"`); backslash escapes are honored
// (`\"`, `\\`, and a `\`-newline splice), the literal closes at the matching
// unescaped quote, and a bare newline ends the scan defensively so a runaway
// quote cannot swallow following code.
func scanCPPString(content []byte, quote, prefixLen int) int {
	_ = prefixLen
	n := len(content)
	i := quote + 1
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

// isRawStringOpen reports whether a C++11 raw string literal opens at content[i].
// A raw string is `R"delim(` optionally preceded by an encoding prefix (`L`,
// `u8`, `u`, `U`). We require the `R` to be immediately followed by `"` and to
// sit at an identifier boundary (the `R`/prefix is not the tail of a longer
// identifier), so a variable named `myR` or `configuration` is never mistaken
// for a raw-string introducer.
func isRawStringOpen(content []byte, i int) bool {
	n := len(content)
	// Find the position of the `R` given an optional encoding prefix ending here.
	r := i
	// The byte at i must be part of {L, u, U, R, 8}. Locate the R that precedes `"`.
	// Accept: R"  LR"  uR"  UR"  u8R"
	// Try to match starting at i.
	if i >= n || content[i] != 'L' && content[i] != 'u' && content[i] != 'U' && content[i] != 'R' {
		return false
	}
	switch content[i] {
	case 'R':
		r = i
	case 'L', 'U':
		if i+1 < n && content[i+1] == 'R' {
			r = i + 1
		} else {
			return false
		}
	case 'u':
		switch {
		case i+1 < n && content[i+1] == 'R':
			r = i + 1
		case i+2 < n && content[i+1] == '8' && content[i+2] == 'R':
			r = i + 2
		default:
			return false
		}
	}
	if r+1 >= n || content[r] != 'R' || content[r+1] != '"' {
		return false
	}
	// Boundary: the byte before i must not be an identifier part, else this is the
	// tail of a longer identifier (e.g. `myR"..."` is not valid C++ but guard anyway).
	if i > 0 && isCppIdentByte(content[i-1]) {
		return false
	}
	return true
}

// scanCPPRawString returns the offset just past a raw string literal opening at
// content[start] (start points at the encoding prefix or the `R`). The body
// between `R"delim(` and `)delim"` is verbatim — no escapes — so a `"`, `\`, or
// `//` inside is inert. The delimiter is the (possibly empty) run of chars
// between `"` and `(`. An unterminated raw string runs to EOF.
func scanCPPRawString(content []byte, start int) int {
	n := len(content)
	// Advance to the `"` (skip prefix + R).
	i := start
	for i < n && content[i] != '"' {
		i++
	}
	if i >= n {
		return n
	}
	i++ // past the opening quote
	// Read the delimiter up to '('.
	delimStart := i
	for i < n && content[i] != '(' && content[i] != '\n' {
		i++
	}
	if i >= n || content[i] != '(' {
		return n // malformed; consume to EOF (fail safe, stays string)
	}
	delim := content[delimStart:i]
	i++ // past '('
	// Search for the terminator `)delim"`.
	closer := make([]byte, 0, len(delim)+2)
	closer = append(closer, ')')
	closer = append(closer, delim...)
	closer = append(closer, '"')
	for i < n {
		if content[i] == ')' && i+len(closer) <= n && bytesEqual(content[i:i+len(closer)], closer) {
			return i + len(closer)
		}
		i++
	}
	return n
}

// scanCPPChar returns the offset just past a char literal `'...'` opening at
// content[start]. Backslash escapes are honored (`'\”`, `'\n'`), the literal
// closes at the matching quote, and a newline ends the scan defensively.
func scanCPPChar(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '\'':
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}

// cppCharLiteralHere reports whether a `'` at content[i] opens a char literal
// rather than acting as a C++14 digit separator inside a numeric literal
// (`1'000'000`). A digit separator sits between two digits/identifier bytes, so
// we only treat the `'` as a char-literal opener when the preceding byte is not
// an identifier/digit byte.
func cppCharLiteralHere(content []byte, i int) bool {
	if i == 0 {
		return true
	}
	return !isCppIdentByte(content[i-1])
}

// scanCPPPreprocessor scans a preprocessor directive line starting at content[hash]
// (the `#`), emitting its bytes as code except for an `#include`/`#import` angle
// header name `<...>`, which is emitted as a string so its `/` and `.` never
// begin a comment. A trailing `\`-newline splices the directive onto the next
// physical line. Returns the offset just past the directive.
func scanCPPPreprocessor(content []byte, hash int, b *regionBuilder) int {
	n := len(content)
	// Determine the directive keyword to decide angle-include handling.
	isInclude := directiveIsInclude(content, hash)
	i := hash
	for i < n {
		c := content[i]
		switch {
		case c == '\\' && i+1 < n && content[i+1] == '\n':
			b.emit(i, i+2, KindCode)
			i += 2
		case c == '\\' && i+1 < n && content[i+1] == '\r' && i+2 < n && content[i+2] == '\n':
			b.emit(i, i+3, KindCode)
			i += 3
		case c == '\n':
			return i // directive ends; newline handled by caller loop
		case c == '/' && i+1 < n && content[i+1] == '/':
			// A trailing comment on a directive line.
			end := scanCPPLineComment(content, i)
			b.emit(i, end, KindComment)
			i = end
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '"':
			end := scanCPPString(content, i, 0)
			b.emit(i, end, KindString)
			i = end
		case c == '<' && isInclude:
			// The angle-bracket header name — treat as a string so its path bytes
			// (`/`, `.`) never begin a comment or leak into operator scanning.
			end := scanCPPAngleInclude(content, i)
			b.emit(i, end, KindString)
			i = end
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return n
}

// scanCPPAngleInclude returns the offset just past an angle-bracket header name
// `<stdio.h>` opening at content[start]. It closes at the matching `>` or at a
// newline defensively.
func scanCPPAngleInclude(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '>':
			return i + 1
		case '\n':
			return i
		}
		i++
	}
	return n
}

// directiveIsInclude reports whether the preprocessor directive at content[hash]
// is `#include` or `#import` (which carry an angle-bracket header name). It skips
// whitespace between `#` and the keyword (`#  include` is legal).
func directiveIsInclude(content []byte, hash int) bool {
	n := len(content)
	i := hash + 1
	for i < n && (content[i] == ' ' || content[i] == '\t') {
		i++
	}
	for _, kw := range []string{"include", "import"} {
		if i+len(kw) <= n && string(content[i:i+len(kw)]) == kw {
			return true
		}
	}
	return false
}

// isCppIdentByte reports whether b can be part of a C/C++ identifier.
func isCppIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// bytesEqual reports whether two byte slices are element-wise equal. Local to
// avoid a bytes import in this dependency-lean package.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
