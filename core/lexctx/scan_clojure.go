package lexctx

// scanClojure walks Clojure / ClojureScript / EDN source and classifies each
// byte as code, string, or comment. Clojure is a Lisp — prefix s-expressions
// `(fn arg …)`, `(def x v)`, `(let [x v] …)` — but the LEXICAL layer only needs
// to know "is this cursor inside code" so downstream analyzers can drop matches
// that are provably data or prose. It recognizes:
//
//   - `;` line comments to end of line. There are NO block comments (the
//     `(comment …)` macro is ordinary code, and `#_` discards a single following
//     form — see below). A `;` is a comment ONLY when it is not part of a `\;`
//     character literal, which is handled because a `\` begins a char literal that
//     the scanner consumes whole before it can be read as a comment.
//   - double-quoted strings `"..."` with Java-style backslash escapes (`\"`,
//     `\\`, `\n`). Clojure strings CAN span newlines (unlike Go interpreted
//     strings), which matters because a base64/data-URI blob is often a multi-line
//     string.
//   - regex literals `#"..."` — lexically a string with the same backslash-escape
//     handling (a `\"` does not close it). Emitted as string-kind so a pattern
//     inside a regex is treated as data, not code.
//   - character literals `\c`, `\newline`, `\space`, `\tab`, `\uNNNN`, and the
//     crucial delimiter forms `\;`, `\"`, `\(`, `\)` — a `\` immediately before a
//     delimiter is a CHARACTER, not a comment/string start. Character literals are
//     emitted as CODE (they are single scalar values, not data blobs).
//   - `#_` discard: best-effort. Reader-discarding the next form is hard to do
//     without a full reader, so `#_` and the form after it are left as ordinary
//     code. This is safe: it only forgoes FP-suppression on a discarded form, it
//     never mis-suppresses live code.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0,len(content)).
// Every heuristic degrades safely: a misread only costs FP-suppression, never
// correctness, because an over-broad code region merely disables suppression.
func scanClojure(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	for i < n {
		c := content[i]
		switch {
		case c == ';':
			// Line comment to end of line. (A `\;` char literal never reaches here
			// because the `\` case below consumes it first.)
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)

		case c == '\\':
			// Character literal: `\c`, `\newline`, `\;`, `\"`, `\(`, `\uNNNN`, ….
			// Emitted as code (a scalar value, not a data blob). Consuming it here
			// is what stops a `\;` being read as a comment or a `\"` as a string.
			end := scanClojureChar(content, i)
			b.emit(i, end, KindCode)
			i = end

		case c == '"':
			end := scanClojureString(content, i)
			b.emit(i, end, KindString)
			i = end

		case c == '#' && i+1 < n && content[i+1] == '"':
			// Regex literal `#"..."` — lexically a string (escapes honored).
			end := scanClojureString(content, i+1)
			b.emit(i, end, KindString)
			i = end

		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// scanClojureString returns the offset just past a double-quoted string opening
// at content[start] (which is `"`). Backslash escapes the next byte (`\"`, `\\`)
// so an escaped quote does not close the string. Clojure strings may span
// newlines, so — unlike Go interpreted strings — a newline does NOT terminate
// the scan. An unterminated string runs to EOF. This same routine scans a regex
// literal body (the caller passes the index of the `"` after `#`).
func scanClojureString(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2 // escaped byte stays inside the string
			continue
		case '"':
			return i + 1
		}
		i++
	}
	return n
}

// scanClojureChar returns the offset just past a character literal opening at
// content[start] (which is `\`). The first byte after `\` is always part of the
// literal — even a delimiter (`\;`, `\"`, `\(`, `\space`) — so it is consumed
// unconditionally. If that byte begins an alphabetic NAME (`\newline`, `\space`,
// `\tab`, `\uNNNN`, `\o377`), the trailing name bytes are consumed too. A bare
// `\` at EOF is treated as a one-byte literal. This is what keeps a `\;` from
// starting a comment and a `\"` from opening a string.
func scanClojureChar(content []byte, start int) int {
	n := len(content)
	if start+1 >= n {
		return n // lone trailing backslash
	}
	first := content[start+1]
	i := start + 2 // the char byte after `\` is always consumed
	// A named/unicode char literal (`\newline`, `\uNNNN`) continues with word
	// bytes. A delimiter char (`\;`, `\"`, `\(`) is a single byte and stops here.
	if isClojureCharNameStart(first) {
		for i < n && isClojureCharNameByte(content[i]) {
			i++
		}
	}
	return i
}

// isClojureCharNameStart reports whether b can begin a multi-byte character-name
// literal (`\newline`, `\space`, `\tab`, `\uNNNN`, `\o377`) — a letter or digit.
// A punctuation/delimiter char (`\;`, `\(`, `\"`) is single-byte and is excluded.
func isClojureCharNameStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// isClojureCharNameByte reports whether b can continue a character-name literal.
// Named literals are alphanumeric (`newline`, `space`) or hex (`uNNNN`); a
// leading digit form (`\o377`) is also alphanumeric.
func isClojureCharNameByte(b byte) bool {
	return isClojureCharNameStart(b)
}
