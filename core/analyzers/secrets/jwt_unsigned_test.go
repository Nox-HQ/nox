package secrets

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"regexp"
	"slices"
	"testing"
)

// jwtRules are the rules whose description claims a JSON Web Token.
var jwtRules = []string{"SEC-084", "SEC-251", "SEC-371"}

// seededUnsignedJWTs returns a signed JWT and the two signature-less forms
// built from the same claims, from a fixed seed: never hand-written values.
func seededUnsignedJWTs(t *testing.T) (signed, unsecured, dropped string) {
	t.Helper()
	r := rand.New(rand.NewSource(251))
	enc := base64.RawURLEncoding.EncodeToString
	claims, err := json.Marshal(map[string]any{"sub": r.Int63(), "iat": 1759500000, "scope": "read"})
	if err != nil {
		t.Fatal(err)
	}
	hs := enc([]byte(`{"alg":"HS256","typ":"JWT"}`))
	none := enc([]byte(`{"alg":"none"}`))
	c := enc(claims)
	return hs + "." + c + "." + enc(randBytes(r, 32)), none + "." + c + ".", hs + "." + c + "."
}

func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	r.Read(b)
	return b
}

// TestUnsignedJWTsAreNotCredentials holds the claim the JWT rules make: "a JSON
// Web Token, which may lead to unauthorized access". An Unsecured JWT (RFC 7519
// §6: alg "none", empty signature) grants nothing its reader could not mint for
// themselves, and a signed token with its signature cut off is accepted by
// nothing. Neither is a credential, so no rule claiming a JWT reports one.
//
// SEC-251 made its signature segment optional and reported both at high in
// every file shape. Whether a SERVICE accepts alg "none" is a question about
// the verifier, not about a token, and it is not this rule's.
func TestUnsignedJWTsAreNotCredentials(t *testing.T) {
	signed, unsecured, dropped := seededUnsignedJWTs(t)
	// RFC 7519 §6.1's own example Unsecured JWT.
	const rfcExample = "eyJhbGciOiJub25lIn0." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

	hosts := []struct{ path, pre, post string }{
		{"app.py", `value = "`, "\"\n"},
		{"notes.md", "The token was `", "`.\n"},
		{"config.yaml", "value: ", "\n"},
		{"call.sh", `curl -H "Authorization: Bearer `, "\" https://api.example.com/v1/me\n"},
	}
	unsigned := map[string]string{"unsecured": unsecured, "signature-dropped": dropped, "rfc7519-6.1": rfcExample}
	for _, h := range hosts {
		for name, tok := range unsigned {
			for _, id := range idsFor(t, h.path, h.pre+tok+h.post) {
				if slices.Contains(jwtRules, id) {
					t.Errorf("%s reports a %s JWT in %s, which is not a credential", id, name, h.path)
				}
			}
		}
		got := idsFor(t, h.path, h.pre+signed+h.post)
		if !slices.ContainsFunc(got, func(id string) bool { return slices.Contains(jwtRules, id) }) {
			t.Errorf("no JWT rule reports a signed JWT in %s: ids=%v", h.path, got)
		}
	}
}

// TestSEC251MatchesSignedJWTsExactlyAsBefore: requiring the signature must not
// change one byte of what SEC-251 matches on a signed token, or the fingerprint
// of every existing finding would move. It compares against the pattern as it
// was, on the raw regexp, so span computation downstream (which this change
// does not touch) cannot make it pass or fail.
func TestSEC251MatchesSignedJWTsExactlyAsBefore(t *testing.T) {
	const before = `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)`
	var after string
	for _, r := range NewAnalyzer().Rules().Rules() {
		if r.ID == "SEC-251" {
			after = r.Pattern
		}
	}
	if after == "" {
		t.Fatal("SEC-251 is not in the rule set")
	}
	old, cur := regexp.MustCompile(before), regexp.MustCompile(after)

	signed, _, dropped := seededUnsignedJWTs(t)
	r := rand.New(rand.NewSource(7))
	enc := base64.RawURLEncoding.EncodeToString
	bodies := []string{
		`value = "` + signed + "\"\n",
		"value: " + signed + "\n",
		"The token was `" + signed + "`.\n",
		`curl -H "Authorization: Bearer ` + signed + `" https://x.example/`,
		`{"t":"` + signed + `"}` + "\n",
		signed + "==\n",
		signed + `\n` + "next",
		signed,
		// An 8-character signature, below SEC-251's 10: unmatched before and after.
		dropped + enc(randBytes(r, 6)) + "\n",
	}
	for _, n := range []int{32, 64, 256, 512} {
		bodies = append(bodies, dropped+enc(randBytes(r, n))+";\n")
	}
	for _, body := range bodies {
		a, b := old.FindAllStringSubmatchIndex(body, -1), cur.FindAllStringSubmatchIndex(body, -1)
		if !slices.EqualFunc(a, b, slices.Equal) {
			t.Errorf("SEC-251 matches a signed token differently:\n%q\nbefore %v\nafter  %v", body, a, b)
		}
	}
}
