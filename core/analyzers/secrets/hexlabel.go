package secrets

import (
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// A hex string cannot be told from a digest by how random it is.
//
// SEC-163 is "High-entropy hex string detected (possible secret key)", gated by
// a secret-suggestive keyword anywhere on the line. Measured 2026-09-12 across
// the rule-diff corpus it produced 122 findings, and 117 of them were the value
// of a JSON field named `md5`:
//
//	"login":{"username":"heavyleopard105","password":"buffy","salt":"UKfGRyKe",
//	         "md5":"ff252d31f9d6a7e19f2b28521aa1f367","sha1":"…","sha256":"…"}
//
// in two generated test fixtures in metosin/reitit. The `"password"` field four
// keys to the left is what authorised every one of them, so bounding the
// keyword's distance — the fix SEC-696 got in #633 — would not have removed a
// single finding here: the hint really is 40 characters away. The rule is not
// misjudging distance. It is reporting a password HASH as a possible key.
//
// Entropy cannot separate the two, and the numbers say so rather than the
// argument: Shannon entropy over a 16-symbol alphabet cannot exceed 4.0 bits,
// and the 122 real candidates measured spanned 3.33 to 3.89. Every digest, every
// UUID, every commit id and every real key sits in that band together. What
// separates them is not the value, it is what the document calls it — which is
// why isLikelyNotSecret already carves out UUIDs and git SHAs by shape, one
// case at a time.
//
// These two refutations name the case rather than the shape.

// digestLabels are field and variable names that declare a value to BE a
// digest. A value under one of these names is the output of a hash function:
// publishing it is the point of computing it, and rotating it is not a concept.
var digestLabels = map[string]bool{
	"md5": true, "md5sum": true, "md5hash": true,
	"sha": true, "sha1": true, "sha1sum": true, "sha224": true,
	"sha256": true, "sha256sum": true, "sha384": true, "sha512": true,
	"sha3": true, "shasum": true,
	"blake2": true, "blake2b": true, "blake2s": true, "blake3": true,
	"crc": true, "crc32": true, "crc32c": true, "adler32": true,
	"checksum": true, "digest": true, "hash": true, "hashsum": true,
	"etag": true, "integrity": true, "fingerprint": true, "thumbprint": true,
	"contenthash": true, "content_hash": true, "filehash": true, "file_hash": true,
}

// isLabelledDigest reports whether a hex-valued finding sits under a field or
// variable name that declares it a digest.
//
// The label is the identifier immediately to the left of the value, across the
// punctuation that separates a key from its value in every format this meets:
// `"md5": "…"`, `md5 = "…"`, `md5=b"…"`, `- md5: …`. Nothing further left is
// consulted, because the whole point is that a keyword elsewhere on the line
// does not describe THIS value.
func isLabelledDigest(content []byte, f *findings.Finding) bool {
	value, line, col, ok := hexFindingValue(content, f)
	if !ok || value == "" {
		return false
	}
	// The label belongs to the whole hex run, not to the window a matcher
	// happened to cut out of it. SEC-696's pattern is `[a-zA-Z0-9]{32}`, so on
	// a 64-character sha256 it matches the SECOND half as well, and a candidate
	// starting 32 characters in has hex to its left rather than a key. Walking
	// back to the start of the run is what lets that half inherit `"sha256":`.
	for col > 1 && isHexByte(line[col-2]) {
		col--
	}
	return digestLabels[labelLeftOf(line, col)]
}

// inURLPath reports whether a hex-valued finding is a path segment of a URL.
//
// The remaining 4 of the 122 were one 32-character gist id, reported four times
// across amzn2-greengrass-cfn{,-pkg}.{json,yaml}, in a URL of the form
//
//	https://gist.github.com/<user>/<32 hex>
//
// inside a bash script folded into one CloudFormation `Fn::Sub` scalar, with
// `privateKeyPath` several hundred characters away in the same scalar doing the
// authorising. A gist id is how the URL names a public document.
//
// isLikelyNotSecret already drops a candidate that STARTS with http, but the hex
// tokenizer extracts the run on its own, so by the time entropy sees it the URL
// around it is gone. This asks the line instead.
func inURLPath(content []byte, f *findings.Finding) bool {
	value, line, col, ok := hexFindingValue(content, f)
	if !ok || value == "" {
		return false
	}
	// Walk left from the candidate over path characters. A URL is established
	// only by finding a scheme before any character that cannot appear in one.
	i := col - 1 // 0-based index of the candidate's first byte
	if i < 0 || i > len(line) {
		return false
	}
	for i > 0 {
		c := line[i-1]
		if c == '/' || c == '.' || c == '-' || c == '_' || c == '~' || c == '+' ||
			c == '%' || c == ':' || c == '@' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			i--
			continue
		}
		break
	}
	// Only the text BETWEEN the scheme and the candidate decides. Reading to
	// the end of the line instead would let a `/` that comes AFTER the value
	// close an authority the value is still inside.
	prefix := strings.ToLower(line[i : col-1])
	var authority string
	switch {
	case strings.HasPrefix(prefix, "https://"):
		authority = prefix[len("https://"):]
	case strings.HasPrefix(prefix, "http://"):
		authority = prefix[len("http://"):]
	default:
		return false
	}
	// PATH, not authority. A URL of the form `https://user:<32 hex>@host` puts a
	// real credential in the userinfo, and the only thing separating that from a
	// gist id is whether a `/` has closed the authority yet.
	return strings.Contains(authority, "/")
}

// hexFindingValue returns a finding's matched value, the source line holding
// it, and the value's 1-based column — but only when the value is entirely
// hexadecimal.
//
// The hex test is what keeps these refutations off every other secret rule. A
// provider token is not hex, so an anchored provider match cannot reach either
// check however it is labelled: `md5 = "ghp_…"` is still a leaked token.
func hexFindingValue(content []byte, f *findings.Finding) (value, line string, col int, ok bool) {
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	if start < 0 || end <= start || end > len(content) {
		return "", "", 0, false
	}
	value = string(content[start:end])
	if !isAllHex(value) {
		return "", "", 0, false
	}
	return value, lineOf(content, f.Location.StartLine), f.Location.StartColumn, true
}

// isAllHex reports whether s is a non-empty run of hexadecimal digits.
func isAllHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

// isHexByte reports whether c is a hexadecimal digit.
func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// labelLeftOf returns the lowercased identifier that labels the value starting
// at the 1-based column col, or "" if the value carries no label.
//
// It crosses exactly one run of separator punctuation — quotes, colon, equals,
// arrow, comma, brackets, whitespace — and then reads the identifier it lands
// on. A string-literal prefix (Python's `b"…"`, `r"…"`, `f"…"`, Go's backtick)
// is skipped rather than read as the label, because `token=b"…"` is labelled
// `token`, not `b`.
func labelLeftOf(line string, col int) string {
	i := col - 1 // 0-based index of the value's first byte
	if i < 0 || i > len(line) {
		return ""
	}
	for {
		// Cross the separators between a key and its value.
		for i > 0 && isLabelSeparator(line[i-1]) {
			i--
		}
		end := i
		for i > 0 && isIdentByte(line[i-1]) {
			i--
		}
		if i == end {
			return "" // No identifier there: the value is unlabelled.
		}
		word := strings.ToLower(line[i:end])
		if end < len(line) && isStringPrefix(word) && isQuote(line[end]) {
			// `b"…"`, `r'…'`, `f"…"`: a literal prefix, not the label.
			continue
		}
		return word
	}
}

// isLabelSeparator reports whether c can sit between a label and its value.
func isLabelSeparator(c byte) bool {
	switch c {
	case ' ', '\t', ':', '=', '>', ',', '(', '[', '{', '"', '\'', '`', '-', '|':
		return true
	}
	return false
}

// isIdentByte reports whether c can appear in an identifier or a header name.
func isIdentByte(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// isQuote reports whether c opens a string literal.
func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

// isStringPrefix reports whether word is a string-literal prefix rather than a
// label.
func isStringPrefix(word string) bool {
	switch word {
	case "b", "r", "f", "u", "rb", "br", "rf", "fr", "l", "ur":
		return true
	}
	return false
}
