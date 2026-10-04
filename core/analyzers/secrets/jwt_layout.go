package secrets

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// A JWT's header and claims are JSON, and RFC 7515 §3 and RFC 7519 §7.1 allow
// that JSON whitespace and line breaks with "no canonicalization". Only the
// compact `{"` + letter encodes as eyJ, which is what SEC-371 and every other
// JWT rule anchor on, so a signed token whose JSON was pretty-printed, spaced,
// empty or led by a non-letter key was matched by none of them.
//
// SEC-952 reports those. The leads below are the base64url of the first bytes
// such JSON can start with. Three input bytes become four characters, and the
// third character depends on the byte after `{`:
//
//	{"  + key byte 0x40-0x7F   eyJ   (the compact form, SEC-371's)
//	{"  + key byte 0x00-0x3F   eyI   (digits, $, -, space ...)
//	{"  + key byte 0x80-0xFF   ey[KL] (a UTF-8 key)
//	{   + space                ey[A-D]
//	{   + tab / LF / CR        ew[k-n] / ew[o-r] / ew[0-3]
//	{}                         e3[0-3]   (the empty object: claims only)
//
// and whitespace before the object, header or claims:
//
//	<SP>{ IH[s-v]   <TAB>{ CX[s-v]   <LF>{ Cn[s-v]   <CR>{ DX[s-v]   <CR><LF>{ DQp7
//
// The model's limit: a run of two or more whitespace characters before the
// object, other than CRLF, is not admitted. No JWT library observed emits one.
//
// SEC-952's pattern matches only tokens SEC-371's cannot: a non-compact header
// lead, or a compact header followed by non-compact claims. So the two never
// report one span, and a false start on a lead-shaped run (the leads are
// three-character base64 runs any text can contain) can only cost SEC-952,
// never a compact token.
const (
	ncObjectLead = `ey[A-DIKL]|ew[k-r0-3]`
	ncSpaceLead  = `IH[s-v]|CX[s-v]|Cn[s-v]|DX[s-v]|DQp7`
	ncLead       = ncObjectLead + `|` + ncSpaceLead
	jwtBody      = `[A-Za-z0-9_-]`

	// Claims after a non-compact header: any lead, the compact one included.
	anyClaims = `(?:e3[0-3]` + jwtBody + `*|(?:eyJ|` + ncLead + `)` + jwtBody + `{7,})`
	// Claims after a compact header: only a non-compact lead, or SEC-371
	// would match it too.
	ncClaims = `(?:e3[0-3]` + jwtBody + `*|(?:` + ncLead + `)` + jwtBody + `{7,})`

	// The minimums are SEC-371's: 11 after the header lead, 7 after the
	// claims lead; only the empty-object claims lead may stand alone.
	nonCompactJWTPattern = `(?:(?:` + ncLead + `)` + jwtBody + `{11,}\.` + anyClaims +
		`|eyJ` + jwtBody + `{11,}\.` + ncClaims + `)\.` + jwtBody + `+`
)

// nonCompactJWTKeywords is SEC-952's file pre-filter: every header lead the
// pattern can start with, lowercased, eyj included for the compact-header,
// non-compact-claims case.
func nonCompactJWTKeywords() []string {
	return []string{
		"eya", "eyb", "eyc", "eyd", "eyi", "eyj", "eyk", "eyl",
		"ewk", "ewl", "ewm", "ewn", "ewo", "ewp", "ewq", "ewr", "ew0", "ew1", "ew2", "ew3",
		"ihs", "iht", "ihu", "ihv", "cxs", "cxt", "cxu", "cxv",
		"cns", "cnt", "cnu", "cnv", "dxs", "dxt", "dxu", "dxv", "dqp7",
	}
}

// isUnsecuredJWTHeader reports whether a header segment decodes to a JOSE
// header whose alg is "none" (any case: RFC 7518 names it lowercase, and a
// verifier that compares case-insensitively accepts the others).
func isUnsecuredJWTHeader(seg string) bool {
	h, ok := decodeJSONObject(seg)
	if !ok {
		return false
	}
	alg, _ := h["alg"].(string)
	return strings.EqualFold(alg, "none")
}

// isUnsecuredJWTFinding reports whether a finding's VALUE is an Unsecured JWT
// (RFC 7519 §6): three segments whose header names alg "none". The value is
// read as the placeholder refiner reads it (assignedValue), so a name-bound or
// Bearer-header rule is judged by the token it carries, while a finding whose
// value is something else that merely contains a token (a database URL with
// a password before a token in its query) keeps its claim.
func isUnsecuredJWTFinding(content []byte, f *findings.Finding) bool {
	v := assignedValue(matchedValue(content, f))
	parts := strings.Split(v, ".")
	return len(parts) == 3 && isUnsecuredJWTHeader(parts[0])
}

// isSignedJWT reports whether s is a JWS compact serialisation whose header is a
// JSON object naming a signing algorithm other than "none", whose claims set is
// a JSON object, and whose signature is present. It is SEC-952's whole claim,
// and dedup's way to recognise a JWT that does not start eyJ.
func isSignedJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[2] == "" {
		return false
	}
	header, ok := decodeJSONObject(parts[0])
	if !ok {
		return false
	}
	alg, _ := header["alg"].(string)
	if alg == "" || strings.EqualFold(alg, "none") {
		return false
	}
	if _, ok := decodeJSONObject(parts[1]); !ok {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(parts[2])
	return err == nil
}

// decodeJSONObject decodes one base64url segment as a JSON object. "null"
// unmarshals into a nil map without error, so it is rejected explicitly.
func decodeJSONObject(seg string) (map[string]any, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}
