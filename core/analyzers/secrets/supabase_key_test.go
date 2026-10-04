package secrets

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// A Supabase project's legacy API keys are JWTs whose payload names the
// project and the Postgres role the key acts as (Supabase, "JWT Claims
// Reference": iss "supabase", ref, role "anon" or "service_role"). The two
// keys make opposite claims about exposure: the anon key is the publishable
// key, "safe to expose online", reaching only what Row Level Security allows;
// the service_role key "bypasses every Row Level Security policy" and must
// never leave the server. Until this was decoded, nox reported both as the
// same high "JWT token", which overstates one and understates the other.

// seededSupabaseJWT is a structurally valid HS256 JWT carrying payload, from
// a fixed seed. The signature is random bytes: these are never real keys.
func seededSupabaseJWT(seed int64, payload map[string]any) string {
	r := rand.New(rand.NewSource(seed))
	enc := base64.RawURLEncoding
	p, _ := json.Marshal(payload)
	sig := make([]byte, 32)
	r.Read(sig)
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString(p) + "." + enc.EncodeToString(sig)
}

func supabasePayload(role string) map[string]any {
	return map[string]any{"iss": "supabase", "ref": "qzkfwmhtbpxrvlndcsoa", "role": role, "iat": 1759500000, "exp": 2075076000}
}

func TestSupabaseKeyRole(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{"anon key", supabasePayload("anon"), "anon"},
		{"service_role key", supabasePayload("service_role"), "service_role"},
		// A signed-in user's session token: iss is the project's auth URL and
		// there is no ref. It is a bearer credential, not a project key.
		{"user session token", map[string]any{"iss": "https://qzkfwmhtbpxrvlndcsoa.supabase.co/auth/v1", "sub": "u1", "role": "authenticated"}, ""},
		{"another issuer's anon role", map[string]any{"iss": "https://auth.example.org", "role": "anon"}, ""},
		{"supabase issuer without a project ref", map[string]any{"iss": "supabase", "role": "anon"}, ""},
		{"supabase issuer, unknown role", map[string]any{"iss": "supabase", "ref": "qzkfwmhtbpxrvlndcsoa", "role": "authenticated"}, ""},
	}
	for i, c := range cases {
		tok := seededSupabaseJWT(int64(i), c.payload)
		if got := supabaseKeyRole(tok); got != c.want {
			t.Errorf("%s: role %q, want %q", c.name, got, c.want)
		}
		if got := supabaseKeyRole(`"` + tok + `"`); got != c.want {
			t.Errorf("%s quoted: role %q, want %q", c.name, got, c.want)
		}
	}
	for _, junk := range []string{"", "eyJ", "a.b.c", "eyJhbGciOiJIUzI1NiJ9.!!!.sig"} {
		if got := supabaseKeyRole(junk); got != "" {
			t.Errorf("%q: role %q, want none", junk, got)
		}
	}
}

// TestSupabaseKeysReportWhatTheyAre runs the full pipeline (refiners and
// dedup): the claim a user sees is the one that has to be right.
func TestSupabaseKeysReportWhatTheyAre(t *testing.T) {
	anon := seededSupabaseJWT(105, supabasePayload("anon"))
	svc := seededSupabaseJWT(100, supabasePayload("service_role"))
	other := seededSupabaseJWT(371, map[string]any{"iss": "https://auth.example.org", "sub": "u1", "role": "anon", "iat": 1759500000})

	type want struct {
		rule     string
		severity findings.Severity
	}
	cases := []struct {
		name, file, body string
		want             want
	}{
		{"anon key in a browser client", "client.ts", `export const supabase = createClient("https://qzkfwmhtbpxrvlndcsoa.supabase.co", "` + anon + `");` + "\n", want{"SEC-105", findings.SeverityLow}},
		{"anon key as a public env var", "web.env", "NEXT_PUBLIC_SUPABASE_ANON_KEY=" + anon + "\n", want{"SEC-105", findings.SeverityLow}},
		{"anon key, name-bound", "anon.env", "SUPABASE_ANON_KEY=" + anon + "\n", want{"SEC-105", findings.SeverityLow}},
		{"service_role key, name-bound", "svc.env", "SUPABASE_SERVICE_ROLE_KEY=" + svc + "\n", want{"SEC-100", findings.SeverityCritical}},
		{"service_role key in server code", "admin.ts", `const admin = createClient(url, "` + svc + `");` + "\n", want{"SEC-100", findings.SeverityCritical}},
		{"service_role key under an unrelated name", "ops.env", "DB_ADMIN_TOKEN=" + svc + "\n", want{"SEC-100", findings.SeverityCritical}},
		{"service_role key in prose", "notes.md", "Rotated key: `" + svc + "`\n", want{"SEC-100", findings.SeverityCritical}},
		// The variable name is not evidence; the decoded role is. A
		// service_role key placed in the anon slot is the documented mistake
		// that makes a project's data public, and must not be downgraded.
		{"service_role key in the anon slot", "mixup.env", "NEXT_PUBLIC_SUPABASE_ANON_KEY=" + svc + "\n", want{"SEC-100", findings.SeverityCritical}},
		{"anon key in the service_role slot", "mixup2.env", "SUPABASE_SERVICE_ROLE_KEY=" + anon + "\n", want{"SEC-105", findings.SeverityLow}},
		// Controls: only a Supabase project key is reclassified.
		{"another issuer's anon-role JWT", "other.ts", `const token = "` + other + `";` + "\n", want{"SEC-371", findings.SeverityHigh}},
	}
	for _, c := range cases {
		got := line1Findings(t, c.file, c.body)
		if len(got) != 1 {
			t.Errorf("%s: want exactly one finding (%s), got %v", c.name, c.want.rule, ids(got))
			continue
		}
		if got[0].RuleID != c.want.rule || got[0].Severity != c.want.severity {
			t.Errorf("%s: got %s/%s, want %s/%s", c.name, got[0].RuleID, got[0].Severity, c.want.rule, c.want.severity)
		}
		if c.want.rule == "SEC-105" && !strings.Contains(strings.ToLower(got[0].Message), "public") {
			t.Errorf("%s: the anon finding must say the key is public by design; got %q", c.name, got[0].Message)
		}
	}
}
