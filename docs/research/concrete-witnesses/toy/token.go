// Package toy is the practical reproduction for the concrete-witness research:
// a small token validator with one deliberately inconsistent path, a
// reference predicate written from the format description alone, and three
// ways of searching for disagreement between them.
//
// The format (the "specification", written first, before either function):
//
//	token  = prefix "_" body [ ".v2" ]
//	prefix = "acme"            ; an ABNF quoted string: case-INsensitive (RFC 5234 §2.3)
//	body   = 24 * base32char   ; RFC 4648 base32 alphabet, lowercase only
//	base32char = %x61-7A / "2" / "3" / "4" / "5" / "6" / "7"
//
// Validate is the "ordinary implementation", written the way a detector is
// written: normalise, then check pieces. Its deliberate defect is in the
// suffix branch.
package toy

import "strings"

// Validate is the implementation under test.
func Validate(s string) bool {
	if len(s) < 5 {
		return false
	}
	// Branch 1 — prefix. Normalises case before comparing. This is the
	// plausible edge case: it looks like a leak of uppercase input into an
	// otherwise lowercase format. It is not a defect, because the format's
	// prefix is an ABNF quoted string, and those are case-insensitive.
	if strings.ToLower(s[:5]) != "acme_" {
		return false
	}
	rest := s[5:]
	// Branch 2 — optional suffix.
	if strings.HasSuffix(rest, ".v2") {
		body := rest[:len(rest)-3]
		// The deliberate defect: the suffix branch re-derives the body
		// length from the remainder, and the two conditions are joined with
		// && where || was meant, so a 25-character body is accepted.
		if len(rest)-2 != 24+1 && len(body) != 25 {
			return false
		}
		return alphabetOK(body)
	}
	// Branch 3 — plain body.
	if len(rest) != 24 {
		return false
	}
	return alphabetOK(rest)
}

func alphabetOK(body string) bool {
	for _, c := range body {
		if !(c >= 'a' && c <= 'z') && !(c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}
