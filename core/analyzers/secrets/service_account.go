package secrets

import (
	"regexp"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// SEC-008 matches the line that declares a JSON document to be a Google
// service-account file. That line is not the credential: the document's
// private_key is. A sample of the file's shape, a template the deploy fills in
// and a redacted copy all carry the line and no key, and each was reported as
// a leaked critical credential.
//
// This reads the document the line sits in and withdraws the finding only when
// it has seen that document's own private_key field and the field cannot hold a
// key. Everything it cannot establish leaves the finding as it was: no
// enclosing object, an object that does not close, no private_key field
// holding a string literal, or an object that starts further back than
// objectWindow.

const (
	// objectWindow bounds the search for the enclosing object on either side
	// of the match. A service-account file is about 2.4 KiB.
	objectWindow = 64 << 10
	// objectCandidates bounds how many opening braces are tried. Each try
	// re-reads the bytes up to the match, so this keeps the work linear.
	objectCandidates = 64
	// shortestPrivateKey is the length of the shortest private key there is,
	// written the shortest way: 32 bytes in base64.
	shortestPrivateKey = 44

	serviceAccountKeyField = "private_key"
)

var pemArmour = regexp.MustCompile(`-{5}(?:BEGIN|END)[ A-Z0-9_-]{0,100}-{5}`)

// isKeylessServiceAccount reports whether f is SEC-008 on a document whose own
// private_key field is too short to be a private key.
func isKeylessServiceAccount(content []byte, f *findings.Finding) bool {
	if f.RuleID != "SEC-008" {
		return false
	}
	at := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	open, ok := enclosingObject(content, at)
	if !ok {
		return false
	}
	values, ok := ownStringFields(content, open, at+objectWindow, serviceAccountKeyField)
	if !ok || len(values) == 0 {
		return false
	}
	for _, v := range values {
		if keyMaterialLen(v) >= shortestPrivateKey {
			return false
		}
	}
	return true
}

// enclosingObject returns the offset of the brace that opens the innermost
// object containing at.
//
// Braces are tried nearest first and each is checked by reading forward from
// it: the right one reaches at one level deep and outside a string. A brace
// inside a string fails that check, because the walk from it has the quotes
// the wrong way round and arrives inside one.
func enclosingObject(content []byte, at int) (int, bool) {
	tried := 0
	for open := at - 1; open >= 0 && open >= at-objectWindow; open-- {
		if content[open] != '{' {
			continue
		}
		if tried == objectCandidates {
			return 0, false
		}
		tried++
		if depthAt(content, open, at) == 1 {
			return open, true
		}
	}
	return 0, false
}

// depthAt returns how many objects opened at or after open are still open at
// at, or -1 when at lies inside a string or after the object has closed.
func depthAt(content []byte, open, at int) int {
	depth := 0
	for i := open; i < at; {
		end, isString, ok := nextToken(content, i, at)
		if !ok {
			return -1
		}
		if !isString {
			depth += braceStep(content[i])
			if depth == 0 {
				return -1
			}
		}
		i = end
	}
	return depth
}

// ownStringFields returns the string values of the fields called name that
// belong to the object opening at open, not to an object nested in it. ok is
// false when the object does not close before limit.
func ownStringFields(content []byte, open, limit int, name string) (values []string, ok bool) {
	limit = min(limit, len(content))
	depth := 0
	for i := open; i < limit; {
		end, isString, closed := nextToken(content, i, limit)
		if !closed {
			return nil, false
		}
		if !isString {
			depth += braceStep(content[i])
			if depth == 0 {
				return values, true
			}
		} else if depth == 1 && string(content[i+1:end-1]) == name {
			if value, after, found := stringFieldValue(content, end, limit); found {
				values = append(values, value)
				end = after
			}
		}
		i = end
	}
	return nil, false
}

// stringFieldValue reads the value of the field whose name ends at i. found is
// false when the name is not followed by a colon and a string literal that
// closes before limit, which leaves a field holding anything else uncounted.
func stringFieldValue(content []byte, i, limit int) (value string, after int, found bool) {
	i = skipJSONSpace(content, i, limit)
	if i >= limit || content[i] != ':' {
		return "", i, false
	}
	i = skipJSONSpace(content, i+1, limit)
	if i >= limit || content[i] != '"' {
		return "", i, false
	}
	end, _, closed := nextToken(content, i, limit)
	if !closed {
		return "", i, false
	}
	return string(content[i+1 : end-1]), end, true
}

// nextToken steps over one string literal, or one byte outside a string, and
// returns where the next token starts. ok is false when a string that opens at
// i does not close before limit.
func nextToken(content []byte, i, limit int) (end int, isString, ok bool) {
	if content[i] != '"' {
		return i + 1, false, true
	}
	for j := i + 1; j < limit; j++ {
		switch content[j] {
		case '\\':
			j++
		case '"':
			return j + 1, true, true
		}
	}
	return limit, true, false
}

func braceStep(b byte) int {
	switch b {
	case '{':
		return 1
	case '}':
		return -1
	}
	return 0
}

func skipJSONSpace(content []byte, i, limit int) int {
	for i < limit && (content[i] == ' ' || content[i] == '\t' || content[i] == '\n' || content[i] == '\r') {
		i++
	}
	return i
}

// keyMaterialLen returns how many characters of v are left once the PEM armour
// and the line breaks, written out or escaped, are taken away.
func keyMaterialLen(v string) int {
	v = pemArmour.ReplaceAllString(v, "")
	n := 0
	for i := 0; i < len(v); i++ {
		switch {
		case v[i] == '\\' && i+1 < len(v) && (v[i+1] == 'n' || v[i+1] == 'r'):
			i++
		case v[i] == ' ' || v[i] == '\t' || v[i] == '\n' || v[i] == '\r':
		default:
			n++
		}
	}
	return n
}
