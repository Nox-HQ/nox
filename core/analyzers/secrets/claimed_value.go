package secrets

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// claimedValue is the secret a finding claims, read by the finding's shape.
// Owner resolution and the unsecured-JWT refiner both ask "is this finding's
// value that token?", and the answer depends on where in the span the value
// sits:
//
//   - an Authorization header (or a curl command carrying one): the token
//     after the auth scheme, in the LAST such header, since earlier -H
//     options (Accept, Content-Type) are not credentials;
//   - a URL with userinfo: the password;
//   - otherwise: the right-hand side of the LAST binding, or the span itself
//     when it has none.
//
// assignedValue, the placeholder refiner's reader, cuts at the FIRST `=` or
// `:`, which is right for `KEY=value` and wrong for a curl command whose first
// header is `Accept: …`. Findings do not carry their rule's capture group past
// the engine, so the shape is read here instead. start is the value's byte
// offset within the match, -1 when it was not located.
func claimedValue(matched string) (value string, start int) {
	if m := lastSubmatchIndex(authHeaderValue, matched); m != nil {
		return matched[m[2]:m[3]], m[2]
	}
	if m := lastSubmatchIndex(bearerValue, matched); m != nil {
		return matched[m[2]:m[3]], m[2]
	}
	if m := urlUserinfoPassword.FindStringSubmatchIndex(matched); m != nil {
		return matched[m[2]:m[3]], m[2]
	}
	v, s := lastBindingValue(matched)
	return v, s
}

var (
	// An auth header: the name, optionally quoted, a `:` or `=`, a scheme
	// word, then the value up to a delimiter.
	authHeaderValue = regexp.MustCompile(`(?i)authorization["']?\s*[:=]\s*["']?(?:bearer|token|basic)\s+([^\s"'\x60,;]+)`)
	// A bare scheme with no header name: a span that starts at "Bearer".
	bearerValue = regexp.MustCompile(`(?i)\bbearer\s+([^\s"'\x60,;]+)`)
	// scheme://user:password@host — the password is the credential.
	urlUserinfoPassword = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@"']*:([^@\s/"']+)@`)
	// A binding operator followed by a value.
	bindingOp = regexp.MustCompile(`(?:=>|:=|=|:)\s*["'\x60]?`)
)

func lastSubmatchIndex(re *regexp.Regexp, s string) []int {
	all := re.FindAllStringSubmatchIndex(s, -1)
	if len(all) == 0 {
		return nil
	}
	return all[len(all)-1]
}

// lastBindingValue is the right-hand side of the last binding operator that
// has a non-empty value after it, so base64 padding (`abc==`) is not mistaken
// for a binding. Without a binding, the span is its own value.
func lastBindingValue(matched string) (value string, start int) {
	ops := bindingOp.FindAllStringIndex(matched, -1)
	for i := len(ops) - 1; i >= 0; i-- {
		start := ops[i][1]
		v := strings.TrimRight(strings.TrimSpace(matched[start:]), "\"'` },);")
		if strings.Trim(v, "=") != "" { // `abc==`: padding is not a binding
			return v, start + (len(matched[start:]) - len(strings.TrimLeft(matched[start:], " \t")))
		}
	}
	v := strings.Trim(strings.TrimSpace(matched), "\"'` },);")
	return v, strings.Index(matched, v)
}

// findingClaimedValue reads the claimed value of f from content, and the byte
// offset in content where it starts (-1 when not located).
func findingClaimedValue(content []byte, f *findings.Finding) (value string, offset int) {
	matched := matchedValue(content, f)
	v, rel := claimedValue(matched)
	if v == "" || rel < 0 {
		return v, -1
	}
	return v, lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn) + rel
}

// jwtRunAround widens the value at [start, start+len(v)) to the maximal run of
// base64url and dot characters around it on its line. A vendor rule may match
// only part of a token (two of its segments, or stop before an empty
// signature); whether it is an Unsecured JWT is a question about the whole
// dotted token it sits in.
func jwtRunAround(content []byte, v string, start int) string {
	if start < 0 || start+len(v) > len(content) {
		return v
	}
	lo, hi := start, start+len(v)
	for lo > 0 && isJWTRunByte(content[lo-1]) {
		lo--
	}
	for hi < len(content) && isJWTRunByte(content[hi]) {
		hi++
	}
	return string(content[lo:hi])
}

func isJWTRunByte(c byte) bool {
	return c == '.' || c == '-' || c == '_' ||
		('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}
