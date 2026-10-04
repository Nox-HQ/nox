package rules

import (
	"regexp"
	"regexp/syntax"
	"sync"
)

// A trailing boundary is how a pattern written for an engine with lookahead
// says "followed by a delimiter or the end" in RE2, which has none. The
// imported gitleaks rules end in
//
//	(?:[\x60'"\s;]|\\[nr]|$)
//
// and RE2 CONSUMES whichever alternative matched: a closing quote, a space, a
// semicolon, an escaped newline, or a real newline. Reported as part of the
// match, that delimiter is not part of the credential, and a newline put the
// end of an unquoted token on the next line. Dedup compares spans that start
// on the same line by column, so a span ending at column 1 of the next line
// overlapped nothing: SEC-251 survived beside the JWT owner in YAML, and
// SEC-161/162 beside SEC-166 in a .env file, each one token reported two or
// three times.
//
// The boundary is recognised structurally rather than by spelling, so the
// variants in the rule set (`\\[NRnr]`, `\b`, `\z`, `\B|[\s]|\z`, ...) are all
// covered: the pattern's last top-level element is not a capture, it can
// match the empty string at an assertion, and it is at most two characters
// wide.
// The empty alternative is the signature of a lookahead in disguise; a
// pattern whose credential ends in a character class has none.
//
// Which delimiter was consumed is not inferred from the text. A credential
// class can contain a delimiter character (SEC-251's signature class includes
// a backslash), so the split is asked of the engine: the matched text is
// re-matched against the pattern with the boundary as its own capture group.

var boundarySplitters sync.Map // pattern -> *regexp.Regexp (nil: no boundary)

// trailLen returns how many bytes at the end of match the pattern's trailing
// boundary consumed, or 0 when the pattern has none or the split is not
// recoverable from the matched text alone.
func trailLen(pattern string, match []byte) int {
	split := boundarySplitter(pattern)
	if split == nil {
		return 0
	}
	m := split.FindSubmatchIndex(match)
	start := 2 * split.NumSubexp() // the boundary is the last group
	if len(m) <= start || m[start] < 0 {
		return 0
	}
	return len(match) - m[start]
}

func boundarySplitter(pattern string) *regexp.Regexp {
	if v, ok := boundarySplitters.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re := buildBoundarySplitter(pattern)
	boundarySplitters.Store(pattern, re)
	return re
}

func buildBoundarySplitter(pattern string) *regexp.Regexp {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil || re.Op != syntax.OpConcat || len(re.Sub) < 2 {
		return nil
	}
	last := re.Sub[len(re.Sub)-1]
	if !isTrailingBoundary(last) {
		return nil
	}
	prefix := &syntax.Regexp{Op: syntax.OpConcat, Flags: re.Flags, Sub: re.Sub[:len(re.Sub)-1]}
	split, err := regexp.Compile(`\A(?:` + prefix.String() + `)(` + last.String() + `)\z`)
	if err != nil {
		return nil
	}
	return split
}

func isTrailingBoundary(re *syntax.Regexp) bool {
	if re.Op == syntax.OpCapture {
		return false
	}
	// A bare assertion (a trailing \b) consumes nothing, so there is nothing
	// to trim and no reason to pay for a second match.
	w, ok := maxWidth(re)
	return ok && w >= 1 && w <= 2 && hasEmptyAssertion(re)
}

func hasEmptyAssertion(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpEndText, syntax.OpEndLine, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if hasEmptyAssertion(s) {
				return true
			}
		}
	}
	return false
}

// maxWidth is the most characters re can match, for the node kinds a
// boundary is built from; anything else (a repetition, a capture) is not a
// boundary.
func maxWidth(re *syntax.Regexp) (int, bool) {
	switch re.Op {
	case syntax.OpEndText, syntax.OpEndLine, syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpEmptyMatch:
		return 0, true
	case syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return 1, true
	case syntax.OpLiteral:
		return len(re.Rune), true
	case syntax.OpConcat, syntax.OpAlternate:
		total := 0
		for _, s := range re.Sub {
			w, ok := maxWidth(s)
			if !ok {
				return 0, false
			}
			if re.Op == syntax.OpConcat {
				total += w
			} else if w > total {
				total = w
			}
		}
		return total, true
	}
	return 0, false
}
