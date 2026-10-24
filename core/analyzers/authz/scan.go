package authz

import "strings"

// The helpers here read JavaScript/TypeScript as TEXT over a masked copy of
// the file (core/lexctx.MaskNonCode): every comment byte and string-body byte
// is a space, offsets are unchanged. Structure — brackets, calls, names — is
// read from the mask so that text inside a string or comment can never look
// like code; a string literal's VALUE (a route path, a module specifier, a SQL
// statement) is read from the raw bytes at the same offsets.

// matchClose returns the offset of the bracket that closes the one at open, or
// -1 when the brackets do not balance before the end of code. A stack, not a
// counter: `( [ ) ]` is a mismatch, and a mismatch means the text is not what
// this reader assumed, so it gives up rather than guessing a span.
func matchClose(code string, open int) int {
	if open < 0 || open >= len(code) {
		return -1
	}
	var stack []byte
	for i := open; i < len(code); i++ {
		c := code[i]
		switch c {
		case '(', '[', '{':
			stack = append(stack, c)
		case ')', ']', '}':
			if len(stack) == 0 || stack[len(stack)-1] != opener(c) {
				return -1
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i
			}
		}
	}
	return -1
}

func opener(c byte) byte {
	switch c {
	case ')':
		return '('
	case ']':
		return '['
	}
	return '{'
}

// span is a half-open byte range [start, end) of a file.
type span struct{ start, end int }

// splitArgs splits the argument text between a call's parentheses at its
// top-level commas, returning each argument's span relative to the file.
// argsStart is the offset just after `(`, argsEnd the offset of `)`.
func splitArgs(code string, argsStart, argsEnd int) []span {
	var out []span
	depth := 0
	from := argsStart
	for i := argsStart; i < argsEnd; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, trimSpan(code, span{from, i}))
				from = i + 1
			}
		}
	}
	last := trimSpan(code, span{from, argsEnd})
	if last.end > last.start {
		out = append(out, last)
	}
	return out
}

func trimSpan(code string, s span) span {
	for s.start < s.end && isSpace(code[s.start]) {
		s.start++
	}
	for s.end > s.start && isSpace(code[s.end-1]) {
		s.end--
	}
	return s
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// stringLiteral returns the value of the string literal that s consists of,
// read from raw, and whether s is exactly one literal ('…', "…" or a template
// with no interpolation).
func stringLiteral(raw []byte, code string, s span) (string, bool) {
	if s.end-s.start < 2 {
		return "", false
	}
	q := code[s.start]
	if q != '\'' && q != '"' && q != '`' {
		return "", false
	}
	if code[s.end-1] != q {
		return "", false
	}
	val := string(raw[s.start+1 : s.end-1])
	if q == '`' && strings.Contains(val, "${") {
		return "", false
	}
	return val, true
}

// lineAt returns the 1-based line number of offset off.
func lineAt(lineStarts []int, off int) int {
	lo, hi := 0, len(lineStarts)
	for lo < hi {
		mid := (lo + hi) / 2
		if lineStarts[mid] <= off {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

func computeLineStarts(b []byte) []int {
	starts := []int{0}
	for i, c := range b {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// hasWord reports whether text contains name as a whole identifier (not as a
// member after a dot, and not as part of a longer name).
func hasWord(text, name string) bool {
	for i := 0; ; {
		j := strings.Index(text[i:], name)
		if j < 0 {
			return false
		}
		at := i + j
		end := at + len(name)
		before := at == 0 || (!isIdentByte(text[at-1]) && text[at-1] != '.')
		after := end >= len(text) || !isIdentByte(text[end])
		if before && after {
			return true
		}
		i = at + 1
	}
}
