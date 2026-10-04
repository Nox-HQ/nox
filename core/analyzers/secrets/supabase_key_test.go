package secrets

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
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

// rawPayloadJWT signs nothing: it carries payload byte for byte, so case
// variants and duplicate keys reach the decoder exactly as written.
func rawPayloadJWT(payload string) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString([]byte(payload)) + "." + enc.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
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
	ambiguous := []string{
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"service_role","ROLE":"anon"}`,
		`{"ISS":"supabase","REF":"abcdefghijklmnopqrst","Role":"anon"}`,
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"service_role","role":"anon"}`,
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","Role":"anon"}`,
		`{"iss":"supabase","iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon"}`,
		`{"iss":"supabase","ref":["x"],"role":"anon"}`,
	}
	for _, payload := range ambiguous {
		tok := rawPayloadJWT(payload)
		if got := supabaseKeyRole(tok); got != "" {
			t.Errorf("ambiguous payload %s: role %q, want none (not a project key)", payload, got)
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
const sbAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

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
		// The variable name is not evidence of publicness either. SEC-775
		// reads the anon slot by name, so it may only lower what is evidently
		// public; a secret key or an opaque value there keeps the credential
		// claim.
		{"secret key in the anon slot", "s1.env", "NEXT_PUBLIC_SUPABASE_ANON_KEY=sb_secret_" + seededBody(775, sbAlphabet, 40) + "\n", want{"SEC-775", findings.SeverityHigh}},
		{"secret key in the anon slot, yaml", "s2.yaml", `supabase_anon_key: "sb_secret_` + seededBody(776, sbAlphabet, 40) + `"` + "\n", want{"SEC-775", findings.SeverityHigh}},
		{"opaque value in the anon slot", "s3.env", "SUPABASE_ANON_KEY=" + seededBody(777, sbAlphabet, 48) + "\n", want{"SEC-775", findings.SeverityHigh}},
		// The publishable key is public by its documented prefix.
		{"publishable key in the anon slot", "p1.env", "NEXT_PUBLIC_SUPABASE_ANON_KEY=sb_publishable_" + seededBody(105, sbAlphabet, 40) + "\n", want{"SEC-105", findings.SeverityLow}},
		{"publishable key in a browser client", "p2.ts", `createClient(url, "sb_publishable_` + seededBody(106, sbAlphabet, 40) + `");` + "\n", want{"SEC-105", findings.SeverityLow}},
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

// SEC-371 leaves every Supabase project key to SEC-100 and SEC-105. That is
// only safe while each of them matches at least what SEC-371 matches: a key
// SEC-371's pattern alone reached would be excluded there and claimed by
// nothing. So SEC-100/105 take SEC-371's pattern and keywords from one shared
// definition, and this holds the invariant on the BUILT rule set rather than
// on the source text: the pattern is SEC-371's or an alternation with it as
// a branch, and the keyword pre-filter contains every SEC-371 keyword.
func TestSupabaseRulesCoverEverythingSEC371Matches(t *testing.T) {
	byID := map[string]*rules.Rule{}
	for _, r := range NewAnalyzer().Rules().Rules() {
		byID[r.ID] = r
	}
	base := byID["SEC-371"]
	if base == nil {
		t.Fatal("SEC-371 is not in the built rule set")
	}
	norm := func(p string) string {
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatalf("%q: %v", p, err)
		}
		return re.Simplify().String()
	}
	want := norm(base.Pattern)
	for _, id := range []string{"SEC-100", "SEC-105"} {
		r := byID[id]
		if r == nil {
			t.Fatalf("%s is not in the built rule set", id)
		}
		re, _ := syntax.Parse(r.Pattern, syntax.Perl)
		re = re.Simplify()
		covered := re.String() == want
		if re.Op == syntax.OpAlternate {
			for _, sub := range re.Sub {
				if sub.String() == want {
					covered = true
				}
			}
		}
		if !covered {
			t.Errorf("%s's pattern %q does not contain SEC-371's %q as a branch", id, r.Pattern, base.Pattern)
		}
		kw := map[string]bool{}
		for _, k := range r.Keywords {
			kw[strings.ToLower(k)] = true
		}
		for _, k := range base.Keywords {
			if !kw[strings.ToLower(k)] {
				t.Errorf("%s lacks SEC-371's keyword %q, so its pre-filter skips files SEC-371 scans", id, k)
			}
		}
	}
}
