package secrets

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"testing"
)

// seededJWT builds a structurally valid HS256 JWT from a seeded RNG, so the
// token is random enough to be a credential and identical on every run.
func seededJWT(seed int64) string {
	r := rand.New(rand.NewSource(seed))
	enc := base64.RawURLEncoding
	claims, _ := json.Marshal(map[string]any{"sub": r.Int63(), "iat": 1759500000 + r.Intn(1000)})
	sig := make([]byte, 32)
	r.Read(sig)
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc.EncodeToString(claims) + "." + enc.EncodeToString(sig)
}

// seededBody returns n characters drawn from alphabet by a seeded RNG.
func seededBody(seed int64, alphabet string, n int) string {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// TestOwnerResolutionWithoutTheOwner: the prefix table names a canonical
// owner per token type, and that owner does not always fire. SEC-371, the
// JWT owner, needs the file keyword "jwt"; a file holding `value = "eyJ…"`
// has none. With the owner absent, the generic SEC-161 anchored owner
// resolution and dropped every JWT rule on the span, so the same token was a
// high SEC-371 under `jwt_value` and a medium "high-entropy string" under
// `value`: the claim depended on a variable name (concrete-witness research,
// #814). A generic finding must never be what survives a provider token.
func TestOwnerResolutionWithoutTheOwner(t *testing.T) {
	jwt := seededJWT(814)
	const b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	digits := "0123456789"
	slack := "xoxb-" + seededBody(5, digits, 12) + "-" + seededBody(6, digits, 12) + "-" + seededBody(7, alnum, 24)
	cases := []struct {
		name, file, content string
		want                []string // one of these must report the token
	}{
		{"jwt, no owner keyword", "a.py", `value = "` + jwt + "\"\n", []string{"SEC-371"}},
		{"jwt, owner keyword present", "b.py", `jwt_value = "` + jwt + "\"\n", []string{"SEC-371"}},
		{"jwt in prose", "c.md", "Token: `" + jwt + "`\n", []string{"SEC-371"}},
		{"aws key id", "d.py", `value = "AKIA` + seededBody(1, b32, 16) + "\"\n", []string{"SEC-001", "SEC-508"}},
		{"github pat", "e.py", `value = "ghp_` + seededBody(2, alnum, 36) + "\"\n", []string{"SEC-003"}},
		{"gitlab pat", "f.py", `value = "glpat-` + seededBody(3, alnum, 20) + "\"\n", []string{"SEC-018"}},
		{"stripe live key", "g.py", `value = "sk_live_` + seededBody(4, alnum, 24) + "\"\n", []string{"SEC-030"}},
		{"slack bot token", "h.py", `value = "` + slack + "\"\n", []string{"SEC-023"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, _ := scanRecording(t, tc.file, tc.content)
			var got []string
			for _, f := range fs.Findings() {
				got = append(got, f.RuleID)
			}
			reported := false
			for _, id := range got {
				for _, w := range tc.want {
					reported = reported || id == w
				}
			}
			if !reported {
				t.Fatalf("want one of %v to report the token, got %v", tc.want, got)
			}
			for _, id := range got {
				if id == "SEC-161" || id == "SEC-162" || id == "SEC-163" {
					t.Errorf("generic %s survived beside a provider finding on the same token: %v", id, got)
				}
			}
		})
	}
}
