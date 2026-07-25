package lexctx

// scanConfig classifies `#`-comment configuration formats — YAML (including
// GitHub Actions workflows) and Dockerfiles — into code, string, and comment
// regions. These formats share one lexical grammar for our purposes: `#` line
// comments, single-quoted `'…'` scalars, and double-quoted `"…"` scalars. HCL
// and TOML line comments look the same, so the scanner degrades acceptably on
// them too (their `//` and `/*…*/` forms are simply left as code, which only
// forgoes suppression, never invents it).
//
// It is the single source of truth for the one question the IaC absence matcher
// asks: "is this `#` a live comment, or does it sit inside a quoted value?" A
// keyword mentioned only in a comment must never satisfy a "must contain X"
// requirement, and — the far more dangerous direction for a security scanner —
// a `#` inside a quoted value, a JSON string, or a URL fragment must never be
// mistaken for a comment, because cutting it would strip real content and flip a
// present property to absent (a false positive).
//
// Like the other scanners it emits strictly increasing, contiguous spans so the
// returned regions are gap-free and cover [0,len(content)). Every heuristic
// degrades safely: a misread only forgoes FP-suppression, never correctness.
func scanConfig(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	// prev is the immediately preceding source byte (0 at start of file, reset to
	// a newline at each line break). A `#` opens a comment only when prev is a
	// line/word boundary — start of line or after whitespace — which mirrors
	// YAML's rule that an inline comment must be separated from the value by a
	// space, and keeps `abc#x` / `$#` / a URL fragment out of comment territory.
	var prev byte

	for i < n {
		c := content[i]
		switch {
		case c == '\n':
			b.emit(i, i+1, KindCode)
			i++
			prev = '\n'
			continue

		case c == '\'' || c == '"':
			end := scanConfigString(content, i)
			b.emit(i, end, KindString)
			i = end
			// The real preceding byte is now the closing quote; recording the
			// quote is enough for comment-start detection (a `#` glued to a closing
			// quote is not a comment anyway).
			prev = c
			continue

		case c == '#' && isConfigCommentStart(prev):
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
			prev = '#'
			continue

		default:
			b.emit(i, i+1, KindCode)
			prev = c
			i++
			continue
		}
	}
	return b.finish(n)
}

// isConfigCommentStart reports whether a `#` following prev begins a comment. A
// `#` opens a comment only at the start of a line (prev is 0 or a newline) or
// after whitespace. After any other byte it is literal — part of `abc#x`, a URL
// fragment, or a `$#`-style token.
func isConfigCommentStart(prev byte) bool {
	switch prev {
	case 0, '\n', ' ', '\t', '\r':
		return true
	}
	return false
}

// scanConfigString returns the offset just past a quoted scalar opening at
// start. Strings do not cross a line break in this pragmatic model (a stray
// newline closes the string), matching the per-line reset the absence matcher
// has always used. In a double-quoted scalar a backslash escapes the next byte
// (so `"a\" # b"` does not close early); single-quoted scalars are literal and
// close at the next `'`. An unterminated string runs to end of line / EOF, which
// is the conservative choice: it keeps a trailing `#` classified as string
// (never a comment) so no real content is cut.
func scanConfigString(content []byte, start int) int {
	n := len(content)
	q := content[start]
	i := start + 1
	for i < n {
		c := content[i]
		switch {
		case c == '\n':
			return i
		case c == '\\' && q == '"':
			i += 2
			continue
		case c == q:
			return i + 1
		}
		i++
	}
	return n
}

// HashCommentStart returns the byte index at which a `#` line comment begins in
// a single line of a `#`-comment configuration format (YAML, Dockerfile, and
// the like), or -1 when the line has no comment. It is the reusable primitive
// the core/rules absence matcher uses in place of its former hand-rolled quote
// tracking, so that "where does the comment start" has exactly one
// implementation — this package.
//
// A `#` is reported only when it opens a comment: at line start or after
// whitespace, and outside any quoted scalar. A `#` inside a quoted value, a JSON
// string, or a URL fragment returns -1, preserving the guarantee that comment
// stripping never removes real content. The argument should be a single line
// (no trailing newline); the first comment region's start is returned.
func HashCommentStart(line []byte) int {
	for _, r := range scanConfig(line) {
		if r.Kind == KindComment {
			return r.Start
		}
	}
	return -1
}
