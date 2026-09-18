package rules

import (
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Reading a "parameter is pinned to a literal" out of regex source
// ---------------------------------------------------------------------------

// opSpan is the offset range of one assignment operator inside a pattern.
type opSpan struct{ start, end int }

// assignmentOperators locates every construct in a regex source that spells
// "the thing on the left is set to the thing on the right".
//
// It is a scanner rather than a regex because the two characters that spell an
// assignment in the rules' own patterns, `:` and `=`, are also regex syntax.
// A regex looking for `[:=]` reports the `:` in every `(?:` non-capturing
// group, which is how the first draft read the trailing `(?:[\s,)\]}]|$)` of
// AI-029's pattern as the assignment and extracted nothing.
func assignmentOperators(pattern string) []opSpan {
	var out []opSpan
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++ // the escaped character is data, never syntax
		case '[':
			j := classEnd(pattern, i)
			if j < 0 {
				return out
			}
			// `[:=]`, `[=:]` and `[= ]` are assignments spelled as a class.
			// Whitespace may join them — `--chmod[= ]777` — but a class of
			// whitespace ALONE is a separator, not an assignment, so at least
			// one of the two operator characters must be present.
			if inner := pattern[i+1 : j]; strings.ContainsAny(inner, ":=") &&
				strings.Trim(inner, `:= \t`) == "" {
				out = append(out, opSpan{i, j + 1})
			}
			i = j
		case '=':
			out = append(out, opSpan{i, i + 1})
		case ':':
			if !isGroupColon(pattern, i) {
				out = append(out, opSpan{i, i + 1})
			}
		}
	}
	return out
}

// classEnd returns the index of the `]` closing the class opened at `open`,
// or -1 if it is unterminated. A `]` in the first position is a literal.
func classEnd(pattern string, open int) int {
	j := open + 1
	if j < len(pattern) && pattern[j] == '^' {
		j++
	}
	if j < len(pattern) && pattern[j] == ']' {
		j++
	}
	for j < len(pattern) {
		switch pattern[j] {
		case '\\':
			j++
		case ']':
			return j
		}
		j++
	}
	return -1
}

// isGroupColon reports whether the colon at `i` closes a group prefix —
// `(?:`, `(?i:`, `(?ims:`, `(?-i:` — rather than spelling an assignment.
func isGroupColon(pattern string, i int) bool {
	j := i - 1
	for j >= 0 && strings.IndexByte("imsU-", pattern[j]) >= 0 {
		j--
	}
	return j >= 1 && pattern[j] == '?' && pattern[j-1] == '('
}

// flaggedAssignment extracts the parameter names and the literal value a
// pattern requires in order to fire.
//
// The last operator that yields a valid reading wins: a pattern that mentions
// several is pinning its value at the one nearest that value.
func flaggedAssignment(pattern string) (params []string, value string, ok bool) {
	for _, op := range assignmentOperators(pattern) {
		p := paramsLeftOf(pattern, op.start)
		if len(p) == 0 {
			continue
		}
		v, vok := valueRightOf(pattern, op.end)
		if !vok {
			continue
		}
		params, value, ok = p, v, true
	}
	return params, value, ok
}

// noiseAtom reports whether a regex atom is the optional whitespace or quoting
// that sits between a parameter and its value and carries no meaning here.
func noiseAtom(atom string) bool {
	switch atom {
	case `\s`, `\t`, `\n`, `\r`, " ", "\t":
		return true
	}
	if strings.HasPrefix(atom, "[") && strings.HasSuffix(atom, "]") {
		inner := strings.NewReplacer(`\s`, "", `\t`, "", `\n`, "", `\r`, "").
			Replace(atom[1 : len(atom)-1])
		return strings.Trim(inner, " \t\"'") == ""
	}
	return false
}

// trailingAtomLen returns the length of the last regex atom in s, or 0.
func trailingAtomLen(s string) int {
	if s == "" {
		return 0
	}
	if s[len(s)-1] == ']' {
		for i := len(s) - 2; i >= 0; i-- {
			if s[i] == '[' && (i == 0 || s[i-1] != '\\') {
				return len(s) - i
			}
		}
		return 0
	}
	if n := len(s); n >= 2 && s[n-2] == '\\' {
		return 2
	}
	return 1
}

// stripTrailingNoise removes quantified whitespace and optional-quote atoms
// from the end of s — `\s*`, `["']?`, `[ \t]*` — leaving the parameter.
func stripTrailingNoise(s string) string {
	for {
		trimmed := strings.TrimRight(s, " \t")
		if q := len(trimmed); q > 0 {
			if c := trimmed[q-1]; c == '*' || c == '?' || c == '+' {
				body := trimmed[:q-1]
				if n := trailingAtomLen(body); n > 0 && noiseAtom(body[len(body)-n:]) {
					s = body[:len(body)-n]
					continue
				}
			}
			if n := trailingAtomLen(trimmed); n > 0 && noiseAtom(trimmed[len(trimmed)-n:]) {
				s = trimmed[:len(trimmed)-n]
				continue
			}
		}
		return trimmed
	}
}

// stripLeadingNoise is stripTrailingNoise for the value side.
func stripLeadingNoise(s string) string {
	for {
		t := strings.TrimLeft(s, " \t")
		switch {
		case strings.HasPrefix(t, `\s`), strings.HasPrefix(t, `\t`):
			t = t[2:]
		case strings.HasPrefix(t, "["):
			j := classEnd(t, 0)
			if j < 0 || !noiseAtom(t[:j+1]) {
				return t
			}
			t = t[j+1:]
		case t != "" && (t[0] == '"' || t[0] == '\''):
			t = t[1:]
		default:
			return t
		}
		for t != "" && (t[0] == '*' || t[0] == '?' || t[0] == '+') {
			t = t[1:]
		}
		s = t
	}
}

// paramName accepts an identifier a human would recognise as a setting:
// `top_p`, `presence_penalty`, `--chmod`, `runAsNonRoot`.
var paramName = regexp.MustCompile(`^-{0,2}[A-Za-z][A-Za-z0-9_.\-]{2,63}$`)

// classRange spots the `a-z` / `0-9` remnants of a character class that has
// been mistaken for an identifier.
var classRange = regexp.MustCompile(`[A-Za-z0-9]-[A-Za-z0-9]`)

func validParam(p string) bool {
	return paramName.MatchString(p) && !classRange.MatchString(p)
}

// paramsLeftOf reads the parameter names immediately left of an operator,
// accepting either a literal alternation group — `(temperature|top_p)` — or a
// single trailing identifier.
func paramsLeftOf(pattern string, at int) []string {
	s := stripTrailingNoise(pattern[:at])
	if s == "" {
		return nil
	}
	if s[len(s)-1] == ')' {
		open := groupStart(s)
		if open < 0 {
			return nil
		}
		inner := strings.TrimSuffix(s[open+1:], ")")
		inner = strings.TrimPrefix(inner, "?:")
		if i := strings.IndexByte(inner, ':'); i >= 0 && i < 6 && strings.HasPrefix(inner, "?") {
			inner = inner[i+1:]
		}
		var out []string
		for _, alt := range strings.Split(inner, "|") {
			if !validParam(alt) {
				return nil
			}
			out = append(out, alt)
		}
		return out
	}
	i := len(s)
	for i > 0 && (isWordByte(s[i-1]) || s[i-1] == '-' || s[i-1] == '.') {
		i--
	}
	// A run that begins right after `[` is the contents of a character class,
	// not an identifier: `[A-Za-z0-9]` must not read as a parameter named
	// "A-Za-z0-9".
	if i == len(s) || (i > 0 && s[i-1] == '[') {
		return nil
	}
	word := s[i:]
	if !validParam(word) {
		return nil
	}
	return []string{word}
}

// groupStart returns the index of the `(` matching the `)` that ends s.
func groupStart(s string) int {
	depth := 0
	for i := len(s) - 1; i >= 0; i-- {
		if i > 0 && s[i-1] == '\\' {
			continue
		}
		switch s[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// literalValue matches the leading literal a pattern pins its parameter to.
var literalValue = regexp.MustCompile(`^-?\d+(?:\.\d+)?|^[A-Za-z][A-Za-z0-9_.\-]*`)

// valueRightOf reads the literal value a pattern requires. It fails when the
// value is itself a group or a character class — `(?:0\.9[0-9]*[1-9]|1\.0+)`
// pins a RANGE, not a literal, and has nothing for this analysis to compare.
func valueRightOf(pattern string, at int) (string, bool) {
	s := stripLeadingNoise(pattern[at:])
	m := literalValue.FindString(s)
	if m == "" || classRange.MatchString(m) {
		return "", false
	}
	return m, true
}
