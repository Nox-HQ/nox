package secrets

import (
	"encoding/base64"
	"slices"
	"sort"
	"testing"
)

// These pin what a finding CLAIMS, as owner resolution and the unsecured-JWT
// refiner read it (claimedValue), on the shapes where the first `=` or `:` in
// the span is not the binding: a curl command whose first header is not
// Authorization, and a URL whose userinfo carries the credential.

const tokAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// ownedTokens are tokens with a canonical owner in dedup, built from seeds.
func ownedTokens() []struct{ name, tok, owner string } {
	return []struct{ name, tok, owner string }{
		{"github pat", "ghp_" + seededBody(901, tokAlnum, 36), "SEC-003"},
		{"gitlab pat", "glpat-" + seededBody(902, tokAlnum, 20), "SEC-018"},
		{"compact jwt", seededOwnerJWT(903), "SEC-371"},
	}
}

func scannedRuleIDs(t *testing.T, file, content string) []string {
	t.Helper()
	fs, _ := scanRecording(t, file, content)
	var ids []string
	for _, f := range fs.Findings() {
		ids = append(ids, f.RuleID)
	}
	sort.Strings(ids)
	return ids
}

// A curl command reports its token once, by the token's owner, however many
// headers precede Authorization. GitHub's own documentation writes the Accept
// header first.
func TestMultiHeaderCurlCollapsesOntoTheOwner(t *testing.T) {
	for _, tk := range ownedTokens() {
		for _, h := range []struct{ name, line string }{
			{"accept first", `curl -L -H "Accept: application/vnd.github+json" -H "Authorization: Bearer ` + tk.tok + `" https://api.github.com/user` + "\n"},
			{"content-type first", `curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ` + tk.tok + `" https://api.example.com/v1/items` + "\n"},
		} {
			t.Run(tk.name+"/"+h.name, func(t *testing.T) {
				got := scannedRuleIDs(t, "call.sh", h.line)
				if !slices.Contains(got, tk.owner) {
					t.Fatalf("the owner %s did not report the token; got %v", tk.owner, got)
				}
				if slices.Contains(got, "SEC-183") || slices.Contains(got, "SEC-082") {
					t.Errorf("the Bearer rules report the token a second time; got %v", got)
				}
			})
		}
	}
}

// A URL whose userinfo password IS an owned token reports it once, by the
// owner: the more specific claim, whose remediation is to rotate the token.
func TestURLUserinfoTokenCollapsesOntoTheOwner(t *testing.T) {
	gh, gl := ownedTokens()[0], ownedTokens()[1]
	cases := []struct{ name, line, owner, urlRule string }{
		{"git clone, github", "git clone https://x-access-token:" + gh.tok + "@github.com/acme/infra.git\n", gh.owner, "SEC-085"},
		{"git clone, gitlab", "git clone https://oauth2:" + gl.tok + "@gitlab.com/acme/infra.git\n", gl.owner, "SEC-085"},
		{"postgres, github", `DB = "postgres://svc:` + gh.tok + `@db.internal.io:5432/app"` + "\n", gh.owner, "SEC-073"},
		{"mysql, gitlab", `DB = "mysql://root:` + gl.tok + `@db.internal.io:3306/app"` + "\n", gl.owner, "SEC-073"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scannedRuleIDs(t, "conf.py", c.line)
			if !slices.Contains(got, c.owner) {
				t.Fatalf("the owner %s did not report the token; got %v", c.owner, got)
			}
			if slices.Contains(got, c.urlRule) {
				t.Errorf("%s reports the same token a second time; got %v", c.urlRule, got)
			}
		})
	}
}

// A URL with its own password and a token in its query holds two credentials:
// both are reported.
func TestQueryTokenBesideAURLPasswordKeepsBoth(t *testing.T) {
	for _, tk := range ownedTokens() {
		t.Run(tk.name, func(t *testing.T) {
			line := `DB = "postgres://svc:Xk9pQ2mZ7vR4tL8w@db.internal.io:5432/app?token=` + tk.tok + `"` + "\n"
			got := scannedRuleIDs(t, "db.py", line)
			if !slices.Contains(got, "SEC-073") || !slices.Contains(got, tk.owner) {
				t.Errorf("want SEC-073 and %s; got %v", tk.owner, got)
			}
		})
	}
}

func unsecuredToken(sig string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc([]byte(seededClaims(904))) + "." + sig
}

// The RFC 7519 §6 form ends in an empty signature, and a vendor rule may match
// only the first two segments of it, or a curl command may carry it behind
// other headers. Neither changes what the token is.
func TestUnsecuredJWTIsNoCredentialInAnyShape(t *testing.T) {
	for _, sig := range []string{"", base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))} {
		tok := unsecuredToken(sig)
		for _, h := range []struct{ name, file, line string }{
			{"auth0", "auth0.env", "AUTH0_TOKEN=" + tok + "\n"},
			{"grafana", "grafana.env", "GF_API_KEY=" + tok + "\n"},
			{"session", ".env", "SESSION_TOKEN=" + tok + "\n"},
			{"multi-header curl", "call.sh", `curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer ` + tok + `" https://api.example.com/v1/me` + "\n"},
		} {
			name := h.name + "/signed"
			if sig == "" {
				name = h.name + "/empty signature"
			}
			t.Run(name, func(t *testing.T) {
				if got := scannedRuleIDs(t, h.file, h.line); len(got) != 0 {
					t.Errorf("an unsecured JWT was reported: %v", got)
				}
			})
		}
	}
}

// The refiner refutes a finding whose CLAIMED value is in an unsecured JWT,
// not one that merely contains such a token: a database URL's own password
// is still a credential with an alg-none token in its query.
func TestURLPasswordBesideAnUnsecuredJWTSurvives(t *testing.T) {
	line := `DB = "postgres://svc:Xk9pQ2mZ7vR4tL8w@db.internal.io:5432/app?token=` + unsecuredToken("c2ln") + `"` + "\n"
	got := scannedRuleIDs(t, "db.py", line)
	if !slices.Contains(got, "SEC-073") {
		t.Errorf("the database password (SEC-073) was refuted with the token; got %v", got)
	}
	for _, id := range []string{"SEC-371", "SEC-952", "SEC-084", "SEC-251"} {
		if slices.Contains(got, id) {
			t.Errorf("%s reported the unsecured token; got %v", id, got)
		}
	}
}

func TestClaimedValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{`curl -L -H "Accept: application/json" -H "Authorization: Bearer abc.def.ghi" https://x`, "abc.def.ghi"},
		{`Authorization: Bearer tok123`, "tok123"},
		{`"Authorization": "token tok123"`, "tok123"},
		{`postgres://svc:pw123@db:5432/app?token=zzz`, "pw123"},
		{`https://oauth2:glpat-x@gitlab.com/a/b.git`, "glpat-x"},
		{`AUTH0_TOKEN=abc.def.`, "abc.def."},
		{`key: "value123"`, "value123"},
		{`aws_secret_access_key = abcd/efgh+ijk==`, "abcd/efgh+ijk=="},
		{`eyJhbGciOi.eyJzdWIi.c2ln`, "eyJhbGciOi.eyJzdWIi.c2ln"},
	}
	for _, c := range cases {
		if got, _ := claimedValue(c.in); got != c.want {
			t.Errorf("claimedValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
