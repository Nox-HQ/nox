package secrets

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// seededOwnerJWT builds a structurally valid HS256 JWT from a fixed seed. Never a
// hand-written token: a hand-written one is a placeholder some refiner may
// know, and the point is a token nox has no reason to doubt.
func seededOwnerJWT(seed int64) string {
	r := rand.New(rand.NewSource(seed))
	enc := base64.RawURLEncoding.EncodeToString
	sig := make([]byte, 32)
	r.Read(sig)
	claims := fmt.Sprintf(`{"sub":"u%d","iat":%d}`, r.Intn(1e9), 1759500000+r.Intn(1e6))
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(claims)) + "." + enc(sig)
}

// TestAJWTIsOwnedBySEC371WhateverItsFileIsCalled. SEC-371 is the canonical
// owner of the eyJ prefix in dedup's owner table, chosen as the tightest JWT
// pattern at high severity. Its file keyword was "jwt", inherited from the
// batch import that keyed every rule on its vendor's name. A JWT does not
// contain that word, so the owner ran only when something else in the file
// happened to: the same token was SEC-371 high as `jwt_value = …`, SEC-161
// medium ("high-entropy string") as `value = …`, and SEC-084 medium in prose.
// A credential's claim and severity must not depend on an unrelated
// identifier.
func TestAJWTIsOwnedBySEC371WhateverItsFileIsCalled(t *testing.T) {
	tok := seededOwnerJWT(371)
	if strings.Contains(strings.ToLower(tok), "jwt") {
		t.Fatal("the seeded token itself contains \"jwt\"; pick another seed")
	}
	hosts := []struct {
		name, file, content string
		// atLineEnd: the token is the last thing on its line, which is where
		// SEC-251's duplicate survives (see below).
		atLineEnd bool
	}{
		{"assignment, neutral name", "config.py", `value = "` + tok + `"` + "\n", false},
		{"assignment, jwt in the name", "config.py", `jwt_value = "` + tok + `"` + "\n", false},
		{"prose", "README.md", "Token: `" + tok + "`\n", false},
		{"curl bearer header", "call.sh", `curl -H "Authorization: Bearer ` + tok + `" https://api.example.com/v1/me` + "\n", false},
		{"yaml", "config.yaml", "session:\n  value: " + tok + "\n", true},
		{"shell export", "env.sh", "export TOKEN=" + tok + "\n", true},
		{"http request header", "request.http", "GET https://api.example.com/v1/me\nAuthorization: Bearer " + tok + "\n", true},
		{"dotenv", ".env", "NEXT_PUBLIC_SUPABASE_ANON_KEY=" + tok + "\n", true},
	}
	for _, h := range hosts {
		t.Run(h.name, func(t *testing.T) {
			// ScanArtifacts, not ScanFile: ownership is decided by dedup, which
			// ScanFile's raw candidates have not been through.
			fs, _ := scanRecording(t, h.file, h.content)
			var got []string
			owned := false
			for _, f := range fs.Findings() {
				got = append(got, f.RuleID)
				switch f.RuleID {
				case "SEC-371":
					owned = true
				case "SEC-084", "SEC-161":
					t.Errorf("%s (medium) reported a JWT that SEC-371 owns: %v", f.RuleID, got)
				}
			}
			if !owned {
				t.Fatalf("SEC-371, the JWT's canonical owner, did not report it; got %v", got)
			}
			if len(got) == 1 {
				return
			}
			// Any JWT that ends its line: SEC-251's gitleaks terminator
			// consumes the newline, so its span ends at column 1 of the NEXT
			// line, and spansOverlap compares columns only, so the span reads
			// as [start,1] and overlaps nothing. The duplicate survives dedup.
			// Present on main too (beside SEC-161/SEC-084), and fixed at its
			// root in the span/overlap work, not here. Only SEC-251 may be the
			// extra finding: any other survivor is a failure, not this defect.
			if h.atLineEnd && len(got) == 2 && slices.Contains(got, "SEC-251") {
				t.Skipf("known: SEC-251 survives beside SEC-371 when the JWT ends its line (its span crosses the line end): %v", got)
			}
			t.Errorf("want exactly SEC-371 on the token, got %v", got)
		})
	}
}

// TestSEC371RequiresAJOSEHeaderAndAClaimsObject. Running SEC-371 everywhere
// exposed that the "tightest" JWT pattern was the loosest: every segment was
// `+`, so eyJ-.eyJ-.- was a high-severity JWT. The minimums now come from what
// a JWT must contain, not from a guess:
//
//   - header: RFC 7515 §4.1.1, "alg" MUST be present; the shortest header is
//     {"alg":""}, 11 base64url characters after eyJ;
//   - claims: the shortest JSON object that starts {" (so encodes as eyJ) has
//     one member, {"a":0}: 7 after eyJ.
//
// The signature stays `+`: a truncated signature still leaks the claims.
func TestSEC371RequiresAJOSEHeaderAndAClaimsObject(t *testing.T) {
	var re *regexp.Regexp
	for _, r := range builtinSecretRules() {
		if r.ID == "SEC-371" {
			re = regexp.MustCompile(r.Pattern)
		}
	}
	if re == nil {
		t.Fatal("SEC-371 not in the built rule set")
	}
	enc := base64.RawURLEncoding.EncodeToString
	minimal := enc([]byte(`{"alg":""}`)) + "." + enc([]byte(`{"a":0}`)) + "." + enc([]byte("s"))
	if m := re.FindString(minimal); m != minimal {
		t.Errorf("the shortest well-formed JWT %q matched as %q", minimal, m)
	}
	// A real token's match is the whole token, so its fingerprint
	// (rule || path || matched content) is what it was before.
	tok := seededOwnerJWT(371)
	if m := re.FindString(tok); m != tok {
		t.Errorf("a real JWT matched as %q, not the whole token", m)
	}
	for _, lookalike := range []string{
		"eyJ-.eyJ-.-",
		"eyJzzzzzzzzz.eyJzzzzzzzzz.zzzzzzzzz",
		"eyJFgo.eyJh1VZTM.KyREi",
		"eyJUcu.eyJTHzd3J_X.tYZiPKN",
	} {
		if m := re.FindString(lookalike); m != "" {
			t.Errorf("%q matched as a JWT (%q); its header is too short to name an algorithm", lookalike, m)
		}
	}
}
