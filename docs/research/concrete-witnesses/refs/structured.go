package refs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
)

// --- age secret keys -------------------------------------------------------

// Age models C2SP age.md: "identity = read(CSPRNG, 32) and encoded as Bech32
// with HRP AGE-SECRET-KEY-", Bech32 per BIP-173 "but without length limits",
// and "Bech32 strings can only be all uppercase or all lowercase". The PQ
// hybrid identity uses HRP AGE-SECRET-KEY-PQ- over a 32-byte seed.
var Age = Format{
	Name:        "age-secret-key",
	Proposition: "x is an age identity (X25519 or ML-KEM hybrid secret key)",
	Sources: []Source{
		{"https://github.com/C2SP/C2SP/blob/main/age.md", "Bech32 (not Bech32m), HRP AGE-SECRET-KEY- / AGE-SECRET-KEY-PQ-, 32-byte payload, single-case"},
		{"https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki", "Bech32 charset, polymod, checksum constant 1"},
	},
	Claims: []string{"SEC-077"},
	Hosts: append(tokenHosts,
		// What age-keygen writes: a comment header, then the identity.
		linePrefix("age-keygen-file", "txt", "# created: 2026-10-04T12:00:00+02:00\n", "\n")),
	Check: func(s string) string {
		hrp, data, ok := bech32Decode(s)
		if !ok {
			return "bech32"
		}
		if hrp != "age-secret-key-" && hrp != "age-secret-key-pq-" {
			return "hrp"
		}
		b, ok := convertBits(data, 5, 8, false)
		if !ok || len(b) != 32 {
			return "payload-length"
		}
		return ""
	},
	Valid: func(r *rand.Rand) []Named {
		mk := func(hrp string) string {
			b := make([]byte, 32)
			r.Read(b)
			d, _ := convertBits(b, 8, 5, true)
			return strings.ToUpper(bech32Encode(hrp, d))
		}
		x := mk("age-secret-key-")
		return []Named{
			{"x25519-uppercase", x},
			{"x25519-lowercase", strings.ToLower(mk("age-secret-key-"))},
			{"pq-hybrid-uppercase", mk("age-secret-key-pq-")},
		}
	},
	Mutate: func(r *rand.Rand, v string) []Named {
		flip := []byte(v)
		last := strings.IndexByte(strings.ToLower(bech32Charset), strings.ToLower(v[len(v)-1:])[0])
		flip[len(flip)-1] = strings.ToUpper(bech32Charset)[(last+1)%32]
		if v != strings.ToUpper(v) {
			flip[len(flip)-1] = bech32Charset[(last+1)%32]
		}
		return append(tokenMutants(r, v, strings.ToUpper(bech32Charset)),
			Named{"checksum-flipped", string(flip)},
			Named{"mixed-case", strings.ToLower(v[:20]) + v[20:]},
		)
	},
	Limits: []string{"upper case is shown by example only; the spec permits either single case"},
}

// --- PyPI API tokens -------------------------------------------------------

// PyPI models the issuer: warehouse serialises "pypi-" + pymacaroons' v2
// binary form, url-safe base64 with '=' stripped. The v2 binary grammar is
// libmacaroons' doc/format.txt.
var PyPI = Format{
	Name:        "pypi-api-token",
	Proposition: "x is a PyPI API token (a v2 macaroon for pypi.org or test.pypi.org)",
	Sources: []Source{
		{"https://pypi.org/help/#apitoken", "token value includes the pypi- prefix; can be inspected by base64-decoding"},
		{"https://github.com/pypi/warehouse/blob/main/warehouse/macaroons/services.py", "pymacaroons MACAROON_V2; f\"pypi-{m.serialize()}\" (issuer code, not documentation)"},
		{"https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt", "v2 grammar: VERSION opt_location IDENTIFIER EOS caveats EOS SIGNATURE; field = type, varint length, content"},
	},
	Claims: []string{"SEC-046", "SEC-302", "SEC-409", "SEC-503"},
	Hosts: append(tokenHosts,
		linePrefix("pypirc", "pypirc", "[pypi]\n  username = __token__\n  password = ", "\n")),
	Check: func(s string) string {
		if !strings.HasPrefix(s, "pypi-") {
			return "prefix"
		}
		body := s[5:]
		if strings.ContainsAny(body, "+/=") {
			return "base64-variant"
		}
		raw, ok := b64url(body)
		if !ok {
			return "base64"
		}
		loc, ok := parseMacaroonV2(raw)
		if !ok {
			return "macaroon"
		}
		if loc != "pypi.org" && loc != "test.pypi.org" {
			return "location"
		}
		return ""
	},
	Valid: func(r *rand.Rand) []Named {
		return []Named{
			{"pypi-org-one-caveat", "pypi-" + makePyPIToken(r, "pypi.org", 1)},
			{"pypi-org-two-caveats", "pypi-" + makePyPIToken(r, "pypi.org", 2)},
			{"test-pypi-org", "pypi-" + makePyPIToken(r, "test.pypi.org", 1)},
		}
	},
	Mutate: func(r *rand.Rand, v string) []Named {
		std := strings.NewReplacer("-", "+", "_", "/").Replace(v[5:])
		return append(tokenMutants(r, v, b64urlAlph),
			Named{"truncated-half", v[:len(v)/2]},
			Named{"std-base64", "pypi-" + std},
		)
	},
	Limits: []string{"the serialisation is the issuer's code, not a published specification"},
}

func putField(b []byte, typ byte, content []byte) []byte {
	b = append(b, typ)
	n := uint64(len(content))
	for n >= 0x80 {
		b = append(b, byte(n)|0x80)
		n >>= 7
	}
	b = append(b, byte(n))
	return append(b, content...)
}

func makePyPIToken(r *rand.Rand, location string, caveats int) string {
	b := []byte{2}
	b = putField(b, 1, []byte(location))
	id := fmt.Sprintf(`{"nonce": "%s", "version": 1}`, randFrom(r, "0123456789abcdef", 32))
	b = putField(b, 2, []byte(id))
	b = append(b, 0)
	for i := 0; i < caveats; i++ {
		c := fmt.Sprintf(`{"version": 1, "permissions": {"projects": ["%s"]}}`, randFrom(r, "abcdefghijklmnopqrstuvwxyz", 8))
		b = putField(b, 2, []byte(c))
		b = append(b, 0)
	}
	b = append(b, 0)
	sig := make([]byte, 32)
	r.Read(sig)
	b = putField(b, 6, sig)
	return base64.RawURLEncoding.EncodeToString(b)
}

func readVarint(b []byte, i int) (uint64, int, bool) {
	var v uint64
	for shift := uint(0); i < len(b) && shift < 64; shift += 7 {
		c := b[i]
		i++
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			return v, i, true
		}
	}
	return 0, i, false
}

// parseMacaroonV2 accepts exactly the libmacaroons v2 grammar and returns
// the location. Every byte must be consumed.
func parseMacaroonV2(b []byte) (location string, ok bool) {
	if len(b) == 0 || b[0] != 2 {
		return "", false
	}
	i := 1
	field := func() (typ byte, content []byte, ok bool) {
		if i >= len(b) {
			return 0, nil, false
		}
		typ = b[i]
		n, j, ok := readVarint(b, i+1)
		if !ok || uint64(len(b)-j) < n {
			return 0, nil, false
		}
		i = j + int(n)
		return typ, b[j:i], true
	}
	peek := func() byte {
		if i < len(b) {
			return b[i]
		}
		return 0xff
	}
	if peek() == 1 {
		_, c, ok := field()
		if !ok {
			return "", false
		}
		location = string(c)
	}
	if t, _, ok := field(); !ok || t != 2 {
		return "", false
	}
	if peek() != 0 {
		return "", false
	}
	i++
	for peek() != 0 { // caveats
		if peek() == 1 {
			if _, _, ok := field(); !ok {
				return "", false
			}
		}
		if t, _, ok := field(); !ok || t != 2 {
			return "", false
		}
		if peek() == 4 {
			if _, _, ok := field(); !ok {
				return "", false
			}
		}
		if peek() != 0 {
			return "", false
		}
		i++
	}
	if i >= len(b) {
		return "", false
	}
	i++
	t, sig, ok := field()
	if !ok || t != 6 || len(sig) != 32 || i != len(b) {
		return "", false
	}
	return location, true
}

// --- JWT (JWS compact serialisation) ---------------------------------------

// JWT models RFC 7515/7519 and the security proposition the rules make: a
// SIGNED token. An Unsecured JWT (RFC 7519 §6, alg "none", empty signature)
// is a JWT and is not a credential, since anyone can mint one; the reference
// rejects it as "unsecured", so a detector that ignores it is not an FN.
var JWT = Format{
	Name:        "jwt-jws-compact",
	Proposition: "x is a signed JWT in JWS compact serialisation",
	Sources: []Source{
		{"https://www.rfc-editor.org/rfc/rfc7515#section-2", "base64url \"with all trailing '=' characters omitted\"; no whitespace in the serialisation"},
		{"https://www.rfc-editor.org/rfc/rfc7515#section-3", "the JSON \"MAY contain whitespace and/or line breaks\""},
		{"https://www.rfc-editor.org/rfc/rfc7519#section-7.1", "\"whitespace is explicitly allowed ... no canonicalization\"; the claims set is a JSON object"},
		{"https://www.rfc-editor.org/rfc/rfc7519#section-6", "Unsecured JWT: alg none, empty signature"},
	},
	Claims: []string{"SEC-084", "SEC-251", "SEC-371"},
	Hosts: append(tokenHosts,
		linePrefix("curl-bearer", "sh", `curl -H "Authorization: Bearer `, "\" https://api.example.com/v1/me\n")),
	Check: jwsViolation,
	Valid: func(r *rand.Rand) []Named {
		claims := randomClaims(r, 3)
		return []Named{
			{"compact-hs256", makeJWS(r, `{"alg":"HS256","typ":"JWT"}`, claims, 32)},
			{"compact-es256", makeJWS(r, `{"alg":"ES256","typ":"JWT"}`, claims, 64)},
			{"rfc7519-3.1-header-crlf", makeJWS(r, "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}", claims, 32)},
			{"spaced-header", makeJWS(r, `{ "alg": "HS256", "typ": "JWT" }`, claims, 32)},
			{"pretty-header", makeJWS(r, "{\n  \"alg\": \"RS256\",\n  \"typ\": \"JWT\"\n}", claims, 256)},
			{"spaced-claims", makeJWS(r, `{"alg":"HS256"}`, " "+claims, 32)},
			{"empty-claims", makeJWS(r, `{"alg":"HS256"}`, `{}`, 32)},
		}
	},
	Mutate: func(r *rand.Rand, v string) []Named {
		p := strings.Split(v, ".")
		none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		return []Named{
			{"glued-left-alnum", "x" + v},
			{"unsecured-alg-none", none + "." + p[1] + "."},
			{"signature-dropped", p[0] + "." + p[1] + "."},
			{"padded-signature", v + "="},
			{"four-segments", v + "." + p[2]},
			{"payload-not-json", p[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("eyJ not json at all, just text")) + "." + p[2]},
		}
	},
	Limits: []string{"JWE (five segments) is out of scope", "the signature is not verified, only its presence and encoding"},
}

func randomClaims(r *rand.Rand, n int) string {
	keys := []string{"sub", "iss", "aud", "exp", "iat", "scope", "jti"}
	var parts []string
	for i := 0; i < n && i < len(keys); i++ {
		if keys[i] == "exp" || keys[i] == "iat" {
			parts = append(parts, fmt.Sprintf(`"%s":%d`, keys[i], 1700000000+r.Intn(100000000)))
		} else {
			parts = append(parts, fmt.Sprintf(`"%s":"%s"`, keys[i], randFrom(r, alnum, 12)))
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func makeJWS(r *rand.Rand, header, claims string, sigLen int) string {
	sig := make([]byte, sigLen)
	r.Read(sig)
	e := base64.RawURLEncoding
	return e.EncodeToString([]byte(header)) + "." + e.EncodeToString([]byte(claims)) + "." + e.EncodeToString(sig)
}

func jwsViolation(s string) string {
	p := strings.Split(s, ".")
	if len(p) != 3 {
		return "segments"
	}
	for _, seg := range p {
		if !allIn(seg, b64urlAlph) {
			return "base64url"
		}
	}
	h, ok1 := b64url(p[0])
	c, ok2 := b64url(p[1])
	if !ok1 || !ok2 {
		return "base64url"
	}
	var hdr map[string]any
	if json.Unmarshal(h, &hdr) != nil {
		return "header-json"
	}
	alg, _ := hdr["alg"].(string)
	if alg == "" {
		return "header-alg"
	}
	var claims map[string]any
	if json.Unmarshal(c, &claims) != nil {
		return "claims-json"
	}
	if alg == "none" || p[2] == "" {
		return "unsecured"
	}
	if _, ok := b64url(p[2]); !ok {
		return "base64url"
	}
	return ""
}
