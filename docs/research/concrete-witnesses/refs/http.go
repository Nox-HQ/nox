package refs

import "strings"

// The CSP/ETag case. These references do not describe a credential; they
// describe values whose role an RFC fixes as something else. A value that
// parses as one of them, written in the position that RFC gives it, is not a
// credential whatever vendor is named nearby, so any secret finding on it is
// an FP witness.

// EntityTag is RFC 9110 §8.8.3: entity-tag = [ "W/" ] DQUOTE *etagc DQUOTE,
// etagc = %x21 / %x23-7E / obs-text. "An entity tag is an opaque validator
// for differentiating between multiple representations of the same resource".
func EntityTag(s string) bool {
	s = strings.TrimPrefix(s, "W/")
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for i := 1; i < len(s)-1; i++ {
		c := s[i]
		if !(c == 0x21 || (c >= 0x23 && c <= 0x7e) || c >= 0x80) {
			return false
		}
	}
	return true
}

// CSPHashSource is CSP Level 3 §2.3.1: hash-source = "'" hash-algorithm "-"
// base64-value "'", hash-algorithm = "sha256" / "sha384" / "sha512". It is a
// digest of an inline script the page allows to run.
func CSPHashSource(s string) bool {
	if len(s) < 3 || s[0] != '\'' || s[len(s)-1] != '\'' {
		return false
	}
	alg, v, ok := strings.Cut(s[1:len(s)-1], "-")
	if !ok || !oneOf(alg, "sha256", "sha384", "sha512") || v == "" {
		return false
	}
	return allIn(strings.TrimRight(v, "="), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_")
}

// Traceparent is W3C Trace Context §3.2: version "-" trace-id "-" parent-id
// "-" trace-flags, lowercase hex of 2, 32, 16 and 2 digits, ids not all zero.
func Traceparent(s string) bool {
	p := strings.Split(s, "-")
	if len(p) != 4 || len(p[0]) != 2 || len(p[1]) != 32 || len(p[2]) != 16 || len(p[3]) != 2 {
		return false
	}
	for _, x := range p {
		if !allIn(x, "0123456789abcdef") {
			return false
		}
	}
	return p[0] != "ff" && strings.Trim(p[1], "0") != "" && strings.Trim(p[2], "0") != ""
}

// UUID is RFC 9562 §4's string form, used as a request or correlation ID.
func UUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !allIn(s[i:i+1], hexDigits) {
				return false
			}
		}
	}
	return true
}
