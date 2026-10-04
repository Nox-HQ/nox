package secrets

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// A JWT's header and claims are JSON, and RFC 7515 §3 and RFC 7519 §7.1 allow
// that JSON whitespace and line breaks with "no canonicalization". Only the
// compact `{"` encodes as eyJ, which is what every JWT rule anchored on, so a
// signed token whose JSON is pretty-printed, spaced or empty was matched by
// none of them: in prose and configuration it was not reported at all, and in
// an assignment only the generic entropy rule saw it.
//
// The leads below are the base64url of the first bytes such JSON can start
// with. A JSON object's first three bytes encode as four base64 characters
// whose third depends on the byte after `{`:
//
//	{"   eyJ        {<SP>  ey[A-D]
//	{<TAB> ew[k-n]  {<LF>  ew[o-r]   {<CR>  ew[0-3]
//	{}   e3[0-3]   (empty object: claims only, a header must name "alg")
//	<SP>{  IH[s-v]  <LF>{  Cn[s-v]   (whitespace before the object: claims)
//
// The leads say where a JWT may begin, not that one does: every match whose
// header or claims is not the compact form must pass isSignedJWT, so the widened
// pattern cannot report a lookalike the compact one would not.
const (
	jwtHeaderLead = `(?:ey[A-DJ]|ew[k-r0-3])`
	jwtClaimsLead = `(?:ey[A-DJ]|ew[k-r0-3]|e3[0-3]|IH[s-v]|Cn[s-v])`

	// sec371Pattern keeps the compact form's minimums unchanged (11 after the
	// header lead, 7 after the claims lead), so a compact JWT's match and
	// fingerprint do not move; only the empty-object claims lead, e30, may stand
	// alone.
	sec371Pattern = jwtHeaderLead + `[A-Za-z0-9_-]{11,}\.` +
		`(?:e3[0-3][A-Za-z0-9_-]*|` + jwtClaimsLead + `[A-Za-z0-9_-]{7,})` +
		`\.[A-Za-z0-9_-]+`
)

// sec371Keywords are the file pre-filter: the lowercased header leads. Every
// JWT the pattern can match contains one of them.
var sec371Keywords = []string{"eyj", "eya", "eyb", "eyc", "eyd", "ewk", "ewl", "ewm", "ewn", "ewo", "ewp", "ewq", "ewr", "ew0", "ew1", "ew2", "ew3"}

// isSEC371Match keeps SEC-371's compact matches exactly as they were and holds
// every other layout to the structure that makes it a signed JWT.
func isSEC371Match(m string) bool {
	if header, claims, ok := strings.Cut(m, "."); ok && strings.HasPrefix(header, "eyJ") && strings.HasPrefix(claims, "eyJ") {
		return true
	}
	return isSignedJWT(m)
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
