package rules

import (
	"regexp"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Reading an endorsed value range out of remediation prose
// ---------------------------------------------------------------------------

// endorsement is one range a remediation recommends, with the text it was read
// from so a maintainer can check the reading.
type endorsement struct {
	low, high float64
	text      string
}

// rangeSpellings are the ways the built-in remediations write a recommended
// interval. The hyphen form is separate because `0.1-0.3` and `-2 to 0` cannot
// share one expression: a signed left operand and a hyphen separator are the
// same character.
var rangeSpellings = []*regexp.Regexp{
	regexp.MustCompile(`(?i)between\s+(-?\d+(?:\.\d+)?)\s+and\s+(-?\d+(?:\.\d+)?)`),
	regexp.MustCompile(`(?i)(-?\d+(?:\.\d+)?)\s*(?:to|\.\.|–|—)\s*(-?\d+(?:\.\d+)?)`),
	regexp.MustCompile(`(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)`),
}

// endorsingVerb is prose that recommends what follows.
var endorsingVerb = regexp.MustCompile(`(?i)\b(set|use|configure|prefer|recommend(?:ed)?|choose|specify|keep|restrict|limit)\b`)

// rejectingVerb is prose that names a value in order to reject it. It is
// checked first: "Replace failed_when: false", "Avoid force_destroy = true"
// and "removing validate_certs: false" all name the flagged value, and all
// three are correct remediations rather than contradictions. Without this,
// quoting the defect — which is good remediation writing — reads as endorsing
// it, which is what sank the wider self-match definition.
var rejectingVerb = regexp.MustCompile(`(?i)\b(avoid|remove|removing|never|not|don't|do not|instead of|rather than|replace|replacing|disable|disabling|reduce|below|under|above|over|exceed)\b`)

// proseWindow is how far from a parameter's name a range is still taken to be
// about that parameter. Measured against the built-in catalogue: the built-in
// remediations are one or two sentences, and 80 bytes covers "Set X (-2 to 0)"
// and "Use 0.1-0.3 for X" without reaching the next sentence's numbers.
const proseWindow = 80

// endorsedRanges returns the value ranges `remediation` recommends for `param`.
//
// A range counts only when an endorsing verb precedes it and no rejecting verb
// does. Both are read from the text between the start of the clause and the
// range itself, so "Use 0.1-0.3" endorses and "Avoid 0.1-0.3" does not.
func endorsedRanges(remediation, param string) []endorsement {
	lower := strings.ToLower(remediation)
	lparam := strings.ToLower(param)
	var out []endorsement
	for from := 0; ; {
		i := strings.Index(lower[from:], lparam)
		if i < 0 {
			break
		}
		at := from + i
		from = at + len(lparam)

		lo := at - proseWindow
		if lo < 0 {
			lo = 0
		}
		hi := from + proseWindow
		if hi > len(remediation) {
			hi = len(remediation)
		}
		window := remediation[lo:hi]
		for _, re := range rangeSpellings {
			for _, m := range re.FindAllStringSubmatchIndex(window, -1) {
				a, err1 := strconv.ParseFloat(window[m[2]:m[3]], 64)
				b, err2 := strconv.ParseFloat(window[m[4]:m[5]], 64)
				if err1 != nil || err2 != nil {
					continue
				}
				if !isEndorsed(window[:m[0]]) {
					continue
				}
				if a > b {
					a, b = b, a
				}
				out = append(out, endorsement{low: a, high: b, text: window[m[0]:m[1]]})
			}
		}
	}
	return out
}

// isEndorsed reads the clause leading up to a range and reports whether it
// recommends what follows. Only the text after the last sentence break is
// considered, so a rejection in an earlier sentence does not mute a later
// recommendation.
func isEndorsed(before string) bool {
	if i := strings.LastIndexAny(before, ".;"); i >= 0 {
		before = before[i+1:]
	}
	if rejectingVerb.MatchString(before) {
		return false
	}
	return endorsingVerb.MatchString(before)
}
