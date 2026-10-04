package secrets

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// A Supabase project's legacy API keys are JWTs, and what each one may be
// trusted with is written in its payload. Supabase's JWT Claims Reference
// (https://supabase.com/docs/guides/auth/jwt-fields) gives both payloads:
//
//	{"iss": "supabase", "ref": "<project>", "role": "anon",         ...}
//	{"iss": "supabase", "ref": "<project>", "role": "service_role", ...}
//
// with `ref` a "Supabase project identifier" that "appears only in
// anon/service role tokens", anon described as "Public access with RLS
// policies" and service_role as "Admin privileges (server-side only)" --
// "Never expose service role tokens to client-side code".
//
// Supabase's API keys guide (https://supabase.com/docs/guides/getting-started/api-keys)
// states the consequence for each. The publishable key, whose legacy form is
// the anon JWT, is "Safe to expose online: web page, mobile or desktop app,
// GitHub actions, CLIs, source code" -- "Anyone can read it, so it only
// reaches what Row Level Security allows". A secret key, whose legacy form is
// the service_role JWT, "bypasses every Row Level Security policy you have.
// Never put one in a browser, a shipped application, or source control."
//
// So the two keys look identical to a pattern and make opposite claims about
// exposure. The role is decided here by decoding, never inferred from the
// variable a key is assigned to: a service_role key pasted into the anon
// slot is the mistake that makes a project's data public, and its name says
// "anon".

// Supabase key roles, as the payload's "role" claim spells them.
const (
	supabaseRoleAnon        = "anon"
	supabaseRoleServiceRole = "service_role"
)

// supabaseKeyRole returns "anon" or "service_role" when value is a Supabase
// project API key: a JWT whose base64url payload decodes to a JSON object
// with "iss" "supabase", a non-empty string "ref" and one of those two roles.
// Anything else -- a user session token (whose issuer is the project's auth
// URL and which carries no ref), another issuer's token, a lookalike that
// does not decode -- returns "", which claims nothing.
func supabaseKeyRole(value string) string {
	parts := strings.Split(strings.Trim(value, `"'`), ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var claims struct {
		Iss  string `json:"iss"`
		Ref  string `json:"ref"`
		Role string `json:"role"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	if claims.Iss != "supabase" || claims.Ref == "" {
		return ""
	}
	switch claims.Role {
	case supabaseRoleAnon, supabaseRoleServiceRole:
		return claims.Role
	}
	return ""
}

// isSupabaseAnonKey is SEC-105's claim: the value is a Supabase anon key.
func isSupabaseAnonKey(value string) bool { return supabaseKeyRole(value) == supabaseRoleAnon }

// isSupabaseServiceRoleKey is SEC-100's claim: the value is a Supabase
// service_role key.
func isSupabaseServiceRoleKey(value string) bool {
	return supabaseKeyRole(value) == supabaseRoleServiceRole
}

// isNotSupabaseProjectKey keeps SEC-371, the generic JWT rule, from claiming
// a token SEC-100 or SEC-105 claims more precisely. It is a JWT either way;
// what changes is which claim about it nox makes.
func isNotSupabaseProjectKey(value string) bool { return supabaseKeyRole(value) == "" }
