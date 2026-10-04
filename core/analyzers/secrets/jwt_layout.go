package secrets

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// A JWT's header and claims are JSON, and RFC 7515 §3 and RFC 7519 §7.1 allow
// that JSON whitespace and line breaks with "no canonicalization". Only the
// compact `{"` + letter encodes as eyJ, which is what every JWT rule anchored
// on, so a signed token whose JSON was pretty-printed, spaced or empty was
// matched by none of them: in prose and configuration it was not reported at
// all, and in an assignment only the generic entropy rule saw it.
//
// The leads below are the base64url of the first bytes such JSON can start
// with. Three input bytes become four characters, and the third character
// depends on the byte after `{`:
//
//	{"  + key byte 0x40-0x7F   eyJ   (the compact form: letters, _ )
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
// The leads say where a JWT may begin, not that one does: every match that is
// not the compact form must pass isSignedJWT, so the widened pattern cannot
// report a lookalike the compact one would not.
const (
	jwtObjectLead = `ey[A-DI-L]|ew[k-r0-3]`
	jwtSpaceLead  = `IH[s-v]|CX[s-v]|Cn[s-v]|DX[s-v]|DQp7`
	jwtHeaderLead = `(?:` + jwtObjectLead + `|` + jwtSpaceLead + `)`
	jwtClaimsLead = `(?:` + jwtObjectLead + `|` + jwtSpaceLead + `|e3[0-3])`

	// sec371Pattern is SEC-371's JWT pattern, defined once: SEC-100 and
	// SEC-105 take it too, because SEC-371 leaves every Supabase project key
	// to them, which is only safe while they match at least what SEC-371
	// matches (TestSupabaseRulesCoverEverythingSEC371Matches).
	//
	// The compact form's minimums are unchanged (11 after the header lead, 7
	// after the claims lead), so a compact JWT's match and fingerprint do not
	// move; only the empty-object claims lead may stand alone.
	sec371Pattern = jwtHeaderLead + `[A-Za-z0-9_-]{11,}\.` +
		`(?:e3[0-3][A-Za-z0-9_-]*|` + jwtClaimsLead + `[A-Za-z0-9_-]{7,})` +
		`\.[A-Za-z0-9_-]+`
)

// sec371Keywords returns the file pre-filter: every header lead, lowercased,
// so every JWT the pattern can match contains one of them. A function, not a
// shared slice, so a rule that appends to its copy cannot change another's.
func sec371Keywords() []string {
	return []string{
		"eya", "eyb", "eyc", "eyd", "eyi", "eyj", "eyk", "eyl",
		"ewk", "ewl", "ewm", "ewn", "ewo", "ewp", "ewq", "ewr", "ew0", "ew1", "ew2", "ew3",
		"ihs", "iht", "ihu", "ihv", "cxs", "cxt", "cxu", "cxv",
		"cns", "cnt", "cnu", "cnv", "dxs", "dxt", "dxu", "dxv", "dqp7",
	}
}

// isSEC371Match keeps SEC-371's compact matches as they were and holds every
// other layout to the structure that makes it a signed JWT.
//
// A compact match is not decoded beyond its header, on purpose: since #819 a
// truncated signature or an undecodable claims segment still leaks enough to
// report, and the compact pattern's minimums already carry the claim. What a
// compact match may not be is an unsecured JWT (RFC 7519 §6): alg "none" is
// minted by anyone, so it is not a credential in any layout (#820).
func isSEC371Match(m string) bool {
	header, rest, _ := strings.Cut(m, ".")
	if strings.HasPrefix(header, "eyJ") && strings.HasPrefix(rest, "eyJ") {
		return !isUnsecuredJWTHeader(header)
	}
	return isSignedJWT(m)
}

// isSEC105Match is SEC-105's claim: a publishable key by its documented
// prefix, or an anon key that is a JWT SEC-371 would report.
func isSEC105Match(m string) bool {
	if strings.HasPrefix(strings.Trim(m, `"'`), supabasePublishablePrefix) {
		return isSupabaseAnonKey(m)
	}
	return isSEC371Match(m) && isSupabaseAnonKey(m)
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

// isNotUnsecuredJWT is the veto SEC-084 and SEC-251, the other JWT rules,
// share with SEC-371: whatever else a match is, an alg-none header is not a
// credential.
func isNotUnsecuredJWT(m string) bool {
	header, _, _ := strings.Cut(strings.TrimLeft(m, "\"'"), ".")
	return !isUnsecuredJWTHeader(header)
}

// isSignedJWT reports whether s is a JWS compact serialisation whose header is a
// JSON object naming a signing algorithm other than "none", whose claims set is
// a JSON object, and whose signature is present. An unsecured JWT (RFC 7519 §6)
// is minted by anyone, so it is not a credential (see #820).
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
