package secrets

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// RFC 7515 §3 and RFC 7519 §7.1: the JOSE header and the claims set are JSON
// that "MAY contain whitespace and/or line breaks", and "no canonicalization
// need be performed". Only a compact `{"` encodes as eyJ, so a signed JWT whose
// JSON is pretty-printed, spaced or empty was matched by no JWT rule. These
// build such tokens from a seed and require SEC-371, the canonical owner, to
// report each one exactly once, in every host, without moving compact tokens.

func seededLayoutJWT(seed int64, header, claims string) string {
	r := rand.New(rand.NewSource(seed))
	enc := base64.RawURLEncoding.EncodeToString
	sig := make([]byte, 32)
	r.Read(sig)
	return enc([]byte(header)) + "." + enc([]byte(claims)) + "." + enc(sig)
}

func seededClaims(seed int64) string {
	r := rand.New(rand.NewSource(seed))
	return fmt.Sprintf(`{"sub":"u%d","iat":%d}`, r.Intn(1e9), 1759500000+r.Intn(1e6))
}

var rfcLayouts = []struct{ name, header, claims string }{
	{"pretty header (LF)", "{\n  \"alg\": \"RS256\",\n  \"typ\": \"JWT\"\n}", seededClaims(1)},
	{"pretty header (CRLF)", "{\r\n \"alg\":\"HS256\"}", seededClaims(2)},
	{"tab after brace", "{\t\"alg\":\"HS256\"}", seededClaims(3)},
	{"spaced header", `{ "alg": "HS256", "typ": "JWT" }`, seededClaims(4)},
	{"empty claims", `{"alg":"HS256"}`, `{}`},
	{"space before claims", `{"alg":"HS256"}`, " " + seededClaims(5)},
	{"newline before claims", `{"alg":"HS256"}`, "\n" + seededClaims(6)},
	{"pretty claims", `{"alg":"ES256"}`, "{\n  \"sub\": \"svc\",\n  \"scope\": \"read\"\n}"},
	{"tab before claims", `{"alg":"HS256"}`, "\t" + seededClaims(12)},
	{"CR before claims", `{"alg":"HS256"}`, "\r" + seededClaims(13)},
	{"CRLF before claims", `{"alg":"HS256"}`, "\r\n" + seededClaims(14)},
	{"space before header", ` {"alg":"HS256"}`, seededClaims(15)},
	{"LF before header", "\n{\"alg\":\"HS256\"}", seededClaims(16)},
	{"tab before header", "\t{\"alg\":\"HS256\"}", seededClaims(17)},
	{"CRLF before header", "\r\n{\"alg\":\"HS256\"}", seededClaims(18)},
	{"digit-led key in header", `{"1":0,"alg":"HS256"}`, seededClaims(19)},
	{"dollar-led key in claims", `{"alg":"HS256"}`, `{"$id":"x","sub":"u"}`},
	{"UTF-8 key in claims", `{"alg":"HS256"}`, "{\"ü\":1,\"sub\":\"u\"}"},
}

func layoutHosts(tok string) []struct{ name, file, content string } {
	return []struct{ name, file, content string }{
		{"assignment", "config.py", `value = "` + tok + `"` + "\n"},
		{"prose", "README.md", "Token: `" + tok + "`\n"},
		{"curl bearer", "call.sh", `curl -H "Authorization: Bearer ` + tok + `" https://api.example.com/v1/me` + "\n"},
		{"dotenv", ".env", "SESSION_TOKEN=" + tok + "\n"},
		{"yaml", "config.yaml", "session:\n  value: " + tok + "\n"},
	}
}

// jwtClaimingRules are the rules that claim a JWT, plus the generic entropy
// rules that report one when no JWT rule does.
var jwtClaimingRules = map[string]bool{"SEC-371": true, "SEC-084": true, "SEC-251": true, "SEC-161": true, "SEC-162": true}

func TestRFCValidJWTLayoutsAreOwnedBySEC371(t *testing.T) {
	for i, l := range rfcLayouts {
		tok := seededLayoutJWT(int64(7100+i), l.header, l.claims)
		if h, c, _ := strings.Cut(tok, "."); strings.HasPrefix(h, "eyJ") && strings.HasPrefix(c, "eyJ") {
			t.Fatalf("%s: seeded token is compact; the case tests nothing", l.name)
		}
		for _, h := range layoutHosts(tok) {
			t.Run(l.name+"/"+h.name, func(t *testing.T) {
				fs, _ := scanRecording(t, h.file, h.content)
				var got []string
				for _, f := range fs.Findings() {
					if jwtClaimingRules[f.RuleID] {
						got = append(got, f.RuleID)
					}
				}
				if len(got) != 1 || got[0] != "SEC-371" {
					t.Errorf("want exactly SEC-371 on the token, got %v", got)
				}
			})
		}
	}
}

// Widening the leads must not widen the claim: what is reported has to decode
// to a JOSE header naming a signing algorithm, with a signature present.
func TestJWTLayoutLookalikesAreNotReported(t *testing.T) {
	r := rand.New(rand.NewSource(7199))
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	rnd := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = b64[r.Intn(len(b64))]
		}
		return string(b)
	}
	enc := base64.RawURLEncoding.EncodeToString
	cases := []struct{ name, tok string }{
		{"ewog lead, header not JSON", "ewog" + rnd(30) + "." + "eyJ" + rnd(20) + "." + rnd(43)},
		{"e30 claims, header not JSON", "ew0K" + rnd(30) + ".e30." + rnd(43)},
		{"pretty header without alg", enc([]byte("{\n  \"typ\": \"JWT\"\n}")) + "." + enc([]byte(seededClaims(9))) + "." + rnd(43)},
		{"pretty header, alg none", enc([]byte("{\n  \"alg\": \"none\"\n}")) + "." + enc([]byte(seededClaims(10))) + "." + rnd(43)},
		{"pretty header, no signature", enc([]byte("{\n  \"alg\": \"HS256\"\n}")) + "." + enc([]byte(seededClaims(11))) + "."},
		{"spaced claims, not an object", enc([]byte(`{"alg":"HS256"}`)) + "." + enc([]byte(" [1,2,3]")) + "." + rnd(43)},
		// alg "none" in every case and layout (F4): an unsecured JWT is not a
		// credential, compact or not, under any JWT rule.
		{"compact, alg none", enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(seededClaims(20))) + "." + rnd(43)},
		{"compact, alg NONE", enc([]byte(`{"alg":"NONE","typ":"JWT"}`)) + "." + enc([]byte(seededClaims(21))) + "." + rnd(43)},
		{"spaced header, alg None", enc([]byte(`{ "alg": "None" }`)) + "." + enc([]byte(seededClaims(22))) + "." + rnd(43)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, _ := scanRecording(t, "README.md", "Token: `"+c.tok+"`\n")
			for _, f := range fs.Findings() {
				if f.RuleID == "SEC-371" || f.RuleID == "SEC-084" || f.RuleID == "SEC-251" {
					t.Errorf("%s reported a string that is not a signed JWT", f.RuleID)
				}
			}
		})
	}
}

// gluedHosts put a compact JWT where its left neighbour is lead-shaped: a
// base64 run containing ey[A-D] or ew[k-r] directly before it, or a preceding
// lead-led segment ending in a dot. RE2 returns the leftmost match, so a
// widened lead there started the match early; the validator rejected it, and
// the real token was never tried (review F1).
func gluedHosts(tok string) []struct{ name, file, content string } {
	return []struct{ name, file, content string }{
		{"glued after a base64 run containing eyA", "a.py", "cacheKeyA" + tok + "\n"},
		{"glued after an identifier containing ewp", "b.env", "newpass_" + tok + "\n"},
		{"after a lead-led segment and a dot", "c.md", "ref ewkAAAAAAAAAAAAAA." + tok + "\n"},
		{"after a CRLF-lead segment and a dot", "d.md", "x DQp7AAAAAAAAAAAAAA." + tok + "\n"},
	}
}

// TestCompactJWTsKeepSEC371WhenGlued: in every glued host the compact token is
// still SEC-371, at the same span and fingerprint as written alone.
func TestCompactJWTsKeepSEC371WhenGlued(t *testing.T) {
	for seed := int64(0); seed < 12; seed++ {
		tok := seededOwnerJWT(seed)
		for _, h := range gluedHosts(tok) {
			t.Run(fmt.Sprint(seed, "/", h.name), func(t *testing.T) {
				fs, _ := scanRecording(t, h.file, h.content)
				var got []string
				owned := false
				for _, f := range fs.Findings() {
					if !jwtClaimingRules[f.RuleID] {
						continue
					}
					got = append(got, f.RuleID)
					if f.RuleID == "SEC-371" {
						owned = true
						start := strings.Index(h.content, tok) + 1
						if f.Location.StartColumn != start {
							t.Errorf("SEC-371 starts at column %d, the token at %d", f.Location.StartColumn, start)
						}
					}
				}
				if !owned {
					t.Errorf("SEC-371 lost the compact token; JWT rules reporting: %v", got)
				}
			})
		}
	}
}

// A compact JWT's SEC-371 match, and therefore its fingerprint, must not move.
func TestSEC371MatchesCompactJWTsExactlyAsBefore(t *testing.T) {
	before := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{11,}\.eyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]+`)
	var after *regexp.Regexp
	for _, r := range NewAnalyzer().Rules().Rules() {
		if r.ID == "SEC-371" {
			after = regexp.MustCompile(r.Pattern)
		}
	}
	if after == nil {
		t.Fatal("SEC-371 not in the built rule set")
	}
	for seed := int64(0); seed < 40; seed++ {
		tok := seededOwnerJWT(seed)
		for _, h := range layoutHosts(tok) {
			b, a := before.FindAllStringIndex(h.content, -1), after.FindAllStringIndex(h.content, -1)
			if fmt.Sprint(a) != fmt.Sprint(b) {
				t.Fatalf("seed %d %s: compact match moved %v -> %v", seed, h.name, b, a)
			}
		}
	}
}

// TestIsSignedJWTGuards reaches each guard of isSignedJWT directly. Through a
// scan, several are shadowed: the pattern already requires a signature, so the
// empty-signature guard is only reachable from dedup's ownership check, which
// calls isSignedJWT on any rule's matched value (review F5).
func TestIsSignedJWTGuards(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	claims := enc(seededClaims(30))
	sig := enc("0123456789abcdef0123456789abcdef")
	cases := []struct {
		name, tok string
		want      bool
	}{
		{"signed", enc(`{"alg":"HS256"}`) + "." + claims + "." + sig, true},
		{"pretty signed", enc("{\n \"alg\": \"RS256\"\n}") + "." + claims + "." + sig, true},
		{"empty signature", enc(`{"alg":"HS256"}`) + "." + claims + ".", false},
		{"alg none", enc(`{"alg":"none"}`) + "." + claims + "." + sig, false},
		{"alg NONE", enc(`{"alg":"NONE"}`) + "." + claims + "." + sig, false},
		{"alg None", enc(`{"alg":"None"}`) + "." + claims + "." + sig, false},
		{"alg missing", enc(`{"typ":"JWT"}`) + "." + claims + "." + sig, false},
		{"alg not a string", enc(`{"alg":1}`) + "." + claims + "." + sig, false},
		// json.Unmarshal of "null" into a map succeeds with a nil map, so
		// decodeJSONObject must reject it explicitly.
		{"header null", enc(`null`) + "." + claims + "." + sig, false},
		{"claims null", enc(`{"alg":"HS256"}`) + "." + enc(`null`) + "." + sig, false},
		{"claims an array", enc(`{"alg":"HS256"}`) + "." + enc(`[1]`) + "." + sig, false},
		{"signature not base64url", enc(`{"alg":"HS256"}`) + "." + claims + ".a+b", false},
		{"two segments", enc(`{"alg":"HS256"}`) + "." + claims, false},
	}
	for _, c := range cases {
		if got := isSignedJWT(c.tok); got != c.want {
			t.Errorf("%s: isSignedJWT = %v, want %v", c.name, got, c.want)
		}
	}
}
