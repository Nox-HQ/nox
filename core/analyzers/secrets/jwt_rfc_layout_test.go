package secrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/discovery"
)

// RFC 7515 §3 and RFC 7519 §7.1: the JOSE header and the claims set are JSON
// that "MAY contain whitespace and/or line breaks", and "no canonicalization
// need be performed". Only a compact `{"` + letter encodes as eyJ, so a signed
// JWT whose JSON is pretty-printed, spaced, empty or led by a non-letter key
// was matched by no JWT rule. These build such tokens from a seed and require
// SEC-952 to report each one exactly once, in every host, while SEC-371 keeps
// main's exact behaviour on compact tokens.

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
var jwtClaimingRules = map[string]bool{"SEC-371": true, "SEC-952": true, "SEC-084": true, "SEC-251": true, "SEC-161": true, "SEC-162": true}

func TestRFCValidJWTLayoutsAreReportedBySEC952(t *testing.T) {
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
				if len(got) != 1 || got[0] != "SEC-952" {
					t.Errorf("want exactly SEC-952 on the token, got %v", got)
				}
			})
		}
	}
}

// Widening the leads must not widen the claim: what SEC-952 reports has to
// decode to a JOSE header naming a signing algorithm, with a signature present,
// and no JWT rule reports an alg "none" header in any layout or case.
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
		{"compact, alg none", enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(seededClaims(20))) + "." + rnd(43)},
		{"compact, alg NONE", enc([]byte(`{"alg":"NONE","typ":"JWT"}`)) + "." + enc([]byte(seededClaims(21))) + "." + rnd(43)},
		{"spaced header, alg None", enc([]byte(`{ "alg": "None" }`)) + "." + enc([]byte(seededClaims(22))) + "." + rnd(43)},
		// The review's case: a vetoed alg-none token whose header nests an
		// object that encodes, mid-header, as a fresh eyJ. Nothing may report
		// the inner run as a JWT starting mid-token.
		{"alg none, nested object in header", enc([]byte(`{"alg":"none","k":{"ab":"cdefghijklmn"}}`)) + "." + enc([]byte(seededClaims(23))) + "." + rnd(43)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, h := range layoutHosts(c.tok) {
				fs, _ := scanRecording(t, h.file, h.content)
				for _, f := range fs.Findings() {
					switch f.RuleID {
					case "SEC-371", "SEC-952", "SEC-084", "SEC-251", "SEC-100", "SEC-105":
						t.Errorf("%s: %s reported a string that is not a signed JWT (column %d)", h.name, f.RuleID, f.Location.StartColumn)
					}
				}
			}
		})
	}
}

// unsecuredHosts are the bindings that name a token as a credential: vendor
// rules keyed on the variable (AUTH0_TOKEN, GF_API_KEY), the Bearer-header
// rules, and plain assignments the entropy rules read.
func unsecuredHosts(tok string) []struct{ name, file, content string } {
	return []struct{ name, file, content string }{
		{"dotenv", ".env", "SESSION_TOKEN=" + tok + "\n"},
		{"assignment", "config.py", `id_token = "` + tok + `"` + "\n"},
		{"yaml", "config.yaml", "token: " + tok + "\n"},
		{"env JWT", "jwt.env", "JWT=" + tok + "\n"},
		{"curl bearer", "call.sh", `curl -H "Authorization: Bearer ` + tok + `" https://api.example.com/v1/me` + "\n"},
		{"auth0 token", "auth0.env", "AUTH0_TOKEN=" + tok + "\n"},
		{"grafana key", "grafana.env", "GF_API_KEY=" + tok + "\n"},
	}
}

// An Unsecured JWT (RFC 7519 §6) is not a credential under ANY rule: the
// refutation is about the token, so a vendor or Bearer rule keyed on the name
// it is bound to must not report it either (review F2). A signed token in the
// same hosts is still reported, so the refiner is not a blanket drop.
func TestUnsecuredJWTIsNoRulesCredential(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	for _, hdr := range []string{`{"alg":"none"}`, `{"alg":"NONE","typ":"JWT"}`, "{\n  \"alg\": \"None\"\n}"} {
		tok := enc([]byte(hdr)) + "." + enc([]byte(seededClaims(40))) + "." + enc([]byte("0123456789abcdef0123456789abcdef"))
		for _, h := range unsecuredHosts(tok) {
			t.Run(hdr+"/"+h.name, func(t *testing.T) {
				fs, _ := scanRecording(t, h.file, h.content)
				for _, f := range fs.Findings() {
					t.Errorf("%s reported an unsecured JWT (column %d)", f.RuleID, f.Location.StartColumn)
				}
			})
		}
	}
	signed := seededOwnerJWT(41)
	for _, h := range unsecuredHosts(signed) {
		t.Run("signed/"+h.name, func(t *testing.T) {
			fs, _ := scanRecording(t, h.file, h.content)
			if len(fs.Findings()) == 0 {
				t.Errorf("a signed JWT in %s is no longer reported", h.name)
			}
		})
	}
}

// Owner resolution drops a non-owner only when its value IS the token. A
// database URL whose password precedes a token in its query claims the
// password: SEC-073 must survive beside the JWT finding, compact or not
// (review F1; the compact half was a defect on main too).
func TestTokenOwnerDoesNotDropAURLCredentialAroundIt(t *testing.T) {
	for _, c := range []struct{ name, tok, owner string }{
		{"compact", seededOwnerJWT(50), "SEC-371"},
		{"non-compact", seededLayoutJWT(51, "{\n  \"alg\": \"HS256\"\n}", seededClaims(51)), "SEC-952"},
	} {
		t.Run(c.name, func(t *testing.T) {
			line := `DB = "postgres://svc:Xk9pQ2mZ7vR4tL8w@db.internal.io:5432/app?token=` + c.tok + `"` + "\n"
			fs, _ := scanRecording(t, "db.py", line)
			got := map[string]bool{}
			for _, f := range fs.Findings() {
				got[f.RuleID] = true
			}
			if !got["SEC-073"] {
				t.Errorf("the database credential (SEC-073) was dropped; got %v", got)
			}
			if !got[c.owner] {
				t.Errorf("the JWT (%s) was dropped; got %v", c.owner, got)
			}
		})
	}
}

// A non-compact header placed before a compact JWT decodes as header, claims
// and signature, so SEC-952's span overlaps SEC-371's on one token. The token
// is reported once, by its compact owner (review F3).
func TestNonCompactHeaderBeforeACompactJWTIsReportedOnce(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	tok := seededOwnerJWT(60)
	line := `t = "` + enc([]byte("{\n  \"alg\": \"HS256\"\n}")) + "." + tok + `"` + "\n"
	fs, _ := scanRecording(t, "t.py", line)
	var jwt []string
	for _, f := range fs.Findings() {
		if jwtClaimingRules[f.RuleID] {
			jwt = append(jwt, f.RuleID)
		}
	}
	if len(jwt) != 1 || jwt[0] != "SEC-371" {
		t.Errorf("want exactly SEC-371, got %v", jwt)
	}
}

// gluedHosts put a compact JWT where its left neighbour is lead-shaped. With a
// widened SEC-371 the leftmost match started there and was vetoed, losing the
// token (review F1). SEC-371 now keeps main's pattern, so this holds by
// construction; it stays as the regression guard.
func gluedHosts(tok string) []struct{ name, file, content string } {
	return []struct{ name, file, content string }{
		{"glued after a base64 run containing eyA", "a.py", "cacheKeyA" + tok + "\n"},
		{"glued after an identifier containing ewp", "b.env", "newpass_" + tok + "\n"},
		{"after a lead-led segment and a dot", "c.md", "ref ewkAAAAAAAAAAAAAA." + tok + "\n"},
		{"after a CRLF-lead segment and a dot", "d.md", "x DQp7AAAAAAAAAAAAAA." + tok + "\n"},
	}
}

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

// mainSEC371Pattern is SEC-371's pattern on main, written out: the rule must
// keep it exactly, so every compact match and fingerprint stays where it was.
const mainSEC371Pattern = `eyJ[A-Za-z0-9_-]{11,}\.eyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]+`

func TestSEC371KeepsMainsPattern(t *testing.T) {
	for _, r := range NewAnalyzer().Rules().Rules() {
		if r.ID == "SEC-371" {
			if r.Pattern != mainSEC371Pattern {
				t.Fatalf("SEC-371's pattern moved:\n got  %s\n want %s", r.Pattern, mainSEC371Pattern)
			}
			return
		}
	}
	t.Fatal("SEC-371 not in the built rule set")
}

// SEC-952 and SEC-371 never match one span: every SEC-952 match has a
// non-compact header or claims lead, and SEC-371's requires both compact.
func TestSEC952NeverMatchesACompactJWT(t *testing.T) {
	re := regexp.MustCompile(nonCompactJWTPattern)
	compact := regexp.MustCompile(mainSEC371Pattern)
	for seed := int64(0); seed < 40; seed++ {
		tok := seededOwnerJWT(seed)
		for _, h := range append(layoutHosts(tok), gluedHosts(tok)...) {
			for _, loc := range re.FindAllStringIndex(h.content, -1) {
				m := h.content[loc[0]:loc[1]]
				if compact.MatchString(m) && strings.Count(m, ".") == 2 {
					hd, c, _ := strings.Cut(m, ".")
					if strings.HasPrefix(hd, "eyJ") && strings.HasPrefix(c, "eyJ") {
						t.Fatalf("seed %d %s: SEC-952 matched a compact JWT %q", seed, h.name, m)
					}
				}
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

// An ARN list is validated as the whole greedy run (arn.go); a rule must not
// report an ARN that starts mid-run. The rejected engine retry did exactly
// that, reporting only the last role of the list.
func TestARNListIsNotReportedMidRun(t *testing.T) {
	const arn = "arn:aws:iam::123456789012:role/"
	line := `ROLES="` + arn + "alpha," + arn + "beta," + arn + "gamma" + `"` + "\n"
	fs, _ := scanRecording(t, "roles.env", line)
	first := strings.Index(line, "arn:") + 1
	for _, f := range fs.Findings() {
		if strings.HasPrefix(f.RuleID, "SEC-") && f.Location.StartColumn > first {
			t.Errorf("%s reports an ARN starting mid-list at column %d", f.RuleID, f.Location.StartColumn)
		}
	}
}

// TestAdversarialLinesScanInBoundedTime: lead-shaped junk must not make the
// scan superlinear. The JWT line is the review's input (an engine retry took
// 369 s on it at 100 KB); the ARN line exercises a validated rule the same
// way. The bound is generous: on main each takes well under a second.
func TestAdversarialLinesScanInBoundedTime(t *testing.T) {
	const size = 100 << 10
	lines := map[string]string{
		"jwt-leads.py": `x = "` + strings.Repeat("IHs", size/3) + `.eyJhYmNkZWZnaGlqa2xt.c2lnbmF0dXJl";` + "\n",
		"arn-junk.tf":  `x = "` + strings.Repeat("arn:aws:s3:::b:", size/15) + `"` + "\n",
		// SEC-952's worst case: one non-compact lead, a 100 KB run the
		// pattern accepts as a header, and a match the validator vetoes.
		"sec952-vetoed-run.md": "Token: `ewog" + strings.Repeat("A", size) + ".e30.c2lnbmF0dXJl`\n",
	}
	for name, content := range lines {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if _, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{{Path: name, AbsPath: path}}); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > 10*time.Second {
				t.Fatalf("scanning %d bytes took %s", len(content), d)
			}
		})
	}
}
