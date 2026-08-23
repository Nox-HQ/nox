package lexctx

// scanPHP walks PHP source and classifies each byte as code, string, or comment.
//
// PHP is a TEMPLATING language: a file is literal HTML output by default and
// executable code lives only INSIDE `<?php … ?>` (or the echo-shorthand
// `<?= … ?>`) islands. Everything outside those tags is inert template text that
// merely looks like markup — never code — so this scanner classifies it as a
// KindString region: the taint recognizer walks only code regions, so treating
// the HTML shell as non-code keeps it from misreading `<div class=...>` as an
// assignment. That non-code default is also why a SAST regex that matches inside
// the HTML template is correctly suppressed as a false positive.
//
// Inside a code island the scanner recognizes:
//
//   - `//` and `#` line comments (to end of line) and `/* … */` block comments.
//     PHP block comments do NOT nest, so the first `*/` closes them
//     (scanBlockComment, shared with the Go/JS scanners, encodes exactly this).
//   - single-quoted strings `'…'` — backslash escapes ONLY `\'` and `\\`; there
//     is no `$` interpolation, so a `$var` inside stays string.
//   - double-quoted strings `"…"` — backslash escapes the usual set; they DO
//     interpolate `$var` / `{…}`, but for lexical classification we treat the
//     whole literal as string (an interpolated `$var` inside a `"…"` is a data
//     read the taint recognizer catches elsewhere; the classifier only needs to
//     know "this is not top-level code").
//   - heredoc `<<<EOT … \nEOT` (interpolates) and nowdoc `<<<'EOT' … \nEOT` (no
//     interpolation). Both span many lines and are the workhorse for embedding
//     SQL/HTML blobs; the closing identifier must appear at the start of a line
//     (optionally indented, PHP 7.3+) followed by `;` or end of line.
//   - the closing `?>` returns the scanner to HTML (non-code) mode.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
func scanPHP(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	inCode := false
	for i < n {
		if !inCode {
			// HTML / template mode: everything is non-code until the next opening
			// tag. Emit the inert text as string so the recognizer ignores it.
			start := i
			for i < n && !isPHPOpenTag(content, i) {
				i++
			}
			b.emit(start, i, KindString)
			if i < n {
				// Consume the opening tag as code and switch to code mode.
				tagEnd := phpOpenTagEnd(content, i)
				b.emit(i, tagEnd, KindCode)
				i = tagEnd
				inCode = true
			}
			continue
		}

		c := content[i]
		switch {
		case c == '?' && i+1 < n && content[i+1] == '>':
			// Closing tag: emit as code, return to HTML mode. A newline directly
			// after `?>` is swallowed by PHP, but classifying it as code is
			// harmless — it is whitespace either way.
			b.emit(i, i+2, KindCode)
			i += 2
			inCode = false
		case c == '/' && i+1 < n && content[i+1] == '/':
			start := i
			for i < n && content[i] != '\n' && !isPHPCloseTag(content, i) {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '#':
			// PHP `#` line comment. (A `#[` attribute in PHP 8 opens with `#[`;
			// treating it as a comment to EOL is imprecise but safe — attributes
			// are not taint-carrying code — and matches the conservative degrade
			// the package documents.)
			start := i
			for i < n && content[i] != '\n' && !isPHPCloseTag(content, i) {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
		case c == '\'':
			end := scanPHPSingleQuoted(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '"':
			end := scanPHPDoubleQuoted(content, i)
			b.emit(i, end, KindString)
			i = end
		case c == '<' && isPHPHeredocStart(content, i):
			end := scanPHPHeredoc(content, i)
			b.emit(i, end, KindString)
			i = end
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// isPHPOpenTag reports whether content[i] begins a PHP open tag (`<?php`, `<?=`,
// or the bare short tag `<?`). The long `<?php` form requires the tag to be
// followed by whitespace or EOF so `<?phpsomething` (not a real tag) is not
// misread; the other forms are unambiguous.
func isPHPOpenTag(content []byte, i int) bool {
	n := len(content)
	if i >= n || content[i] != '<' || i+1 >= n || content[i+1] != '?' {
		return false
	}
	// `<?php` (case-insensitive) must be followed by whitespace or EOF.
	if hasFoldPrefix(content[i:], "<?php") {
		after := i + 5
		if after >= n || isPHPSpace(content[after]) {
			return true
		}
	}
	// `<?=` echo shorthand.
	if i+2 < n && content[i+2] == '=' {
		return true
	}
	// Bare `<?` short-open tag: anything else that is `<?` and not the start of
	// `<?xml` handled by the caller as a tag. We accept it so short-tag files scan.
	return true
}

// phpOpenTagEnd returns the offset just past the recognized open tag at content[i].
func phpOpenTagEnd(content []byte, i int) int {
	n := len(content)
	if hasFoldPrefix(content[i:], "<?php") {
		return i + 5
	}
	if i+2 < n && content[i+2] == '=' {
		return i + 3 // <?=
	}
	return i + 2 // <?
}

// isPHPCloseTag reports whether content[i] begins a `?>` close tag.
func isPHPCloseTag(content []byte, i int) bool {
	return i+1 < len(content) && content[i] == '?' && content[i+1] == '>'
}

// hasFoldPrefix reports whether s starts with prefix, ASCII-case-insensitively.
// PHP open tags are `<?php` but PHP accepts any letter case (`<?PHP`).
func hasFoldPrefix(s []byte, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if lowerASCII(s[i]) != lowerASCII(prefix[i]) {
			return false
		}
	}
	return true
}

// lowerASCII lowercases an ASCII byte.
func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// isPHPSpace reports whether b is PHP inter-token whitespace.
func isPHPSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// scanPHPSingleQuoted returns the offset just past a single-quoted string opening
// at content[start]. In a single-quoted PHP string only `\'` and `\\` are
// escapes; every other backslash is literal. There is no interpolation. The
// literal MAY span newlines in PHP, but a defensive newline stop is unsafe here
// because real single-quoted strings can contain newlines; instead we run to the
// matching quote or EOF, which mirrors PHP semantics.
func scanPHPSingleQuoted(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			// Only `\'` and `\\` consume the next byte; any other `\` is literal.
			if i+1 < n && (content[i+1] == '\'' || content[i+1] == '\\') {
				i += 2
				continue
			}
			i++
		case '\'':
			return i + 1
		default:
			i++
		}
	}
	return n
}

// scanPHPDoubleQuoted returns the offset just past a double-quoted string opening
// at content[start]. Backslash escapes the next byte. Interpolation of `$var` and
// `{…}` is left inside the string region: the classifier only needs code vs
// non-code, and the taint recognizer reads interpolated variables from the raw
// text separately. Runs to the matching quote or EOF (PHP double-quoted strings
// may span newlines).
func scanPHPDoubleQuoted(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1
		default:
			i++
		}
	}
	return n
}

// isPHPHeredocStart reports whether content[i] begins a heredoc/nowdoc opener
// `<<<` (optionally followed by `'ID'`, `"ID"`, or a bare `ID`).
func isPHPHeredocStart(content []byte, i int) bool {
	n := len(content)
	if i+3 > n || content[i] != '<' || content[i+1] != '<' || content[i+2] != '<' {
		return false
	}
	// Skip optional spaces/tabs after <<<, then require a quote or identifier start.
	j := i + 3
	for j < n && (content[j] == ' ' || content[j] == '\t') {
		j++
	}
	if j >= n {
		return false
	}
	c := content[j]
	return c == '\'' || c == '"' || isPHPIdentStart(c)
}

// scanPHPHeredoc returns the offset just past a heredoc or nowdoc opening at
// content[start] (`<<<ID`, `<<<'ID'` nowdoc, or `<<<"ID"` heredoc). The body runs
// to a line whose first non-space token is the closing identifier ID, followed by
// a non-identifier byte (`;`, `,`, `)` or end of line) — PHP 7.3+ allows the
// closing marker to be indented. Nowdoc vs heredoc differ only in interpolation,
// which does not affect lexical classification, so both are scanned identically.
func scanPHPHeredoc(content []byte, start int) int {
	n := len(content)
	j := start + 3
	for j < n && (content[j] == ' ' || content[j] == '\t') {
		j++
	}
	// Optional surrounding quote for the label.
	if j < n && (content[j] == '\'' || content[j] == '"') {
		j++
	}
	labelStart := j
	for j < n && isPHPIdentPart(content[j]) {
		j++
	}
	label := string(content[labelStart:j])
	if label == "" {
		return n // malformed opener; consume to EOF (fail safe)
	}
	// Advance to end of the opening line.
	for j < n && content[j] != '\n' {
		j++
	}
	if j < n {
		j++ // step past the newline into the body
	}
	// Scan lines until one begins (after optional indentation) with the closing
	// label followed by a non-identifier byte.
	for j < n {
		lineStart := j
		k := lineStart
		for k < n && (content[k] == ' ' || content[k] == '\t') {
			k++
		}
		if matchesHeredocClose(content, k, label) {
			end := k + len(label)
			return end
		}
		// Not the closing line: skip to the next line.
		for j < n && content[j] != '\n' {
			j++
		}
		if j < n {
			j++
		}
		if j == lineStart {
			break // no progress (defensive)
		}
	}
	return n
}

// matchesHeredocClose reports whether content[k:] begins with label and the byte
// after it is not an identifier byte (so `EOT;` closes but `EOTHER` does not).
func matchesHeredocClose(content []byte, k int, label string) bool {
	if k+len(label) > len(content) {
		return false
	}
	if string(content[k:k+len(label)]) != label {
		return false
	}
	after := k + len(label)
	return after >= len(content) || !isPHPIdentPart(content[after])
}

// isPHPIdentStart reports whether c can begin a PHP heredoc label / identifier.
func isPHPIdentStart(c byte) bool { return asciiIdentStart(c) }

// isPHPIdentPart reports whether c can continue a PHP identifier.
func isPHPIdentPart(c byte) bool { return asciiIdentPart(c) }
