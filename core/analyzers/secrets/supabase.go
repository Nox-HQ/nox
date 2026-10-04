package secrets

import (
	"bytes"
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
//
// The three claims are read by exact key, once each. encoding/json's struct
// decoding matches keys case-insensitively and lets the last duplicate win,
// so {"role":"service_role","ROLE":"anon"} would have read as anon, while
// PostgREST reads "role" case-sensitively and acts as service_role. A payload
// that spells any of the three in another case, or repeats one, is ambiguous
// about the very thing being decided, so it is not treated as a project key
// at all and stays an ordinary JWT finding.
func supabaseKeyRole(value string) string {
	parts := strings.Split(strings.Trim(value, `"'`), ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	claims, ok := exactClaims(raw, "iss", "ref", "role")
	if !ok || claims["iss"] != "supabase" || claims["ref"] == "" {
		return ""
	}
	switch claims["role"] {
	case supabaseRoleAnon, supabaseRoleServiceRole:
		return claims["role"]
	}
	return ""
}

// exactClaims reads the named string members of the JSON object raw. It
// fails if raw is not one object, if a named member is not a string or
// appears more than once, or if any key equals a name under case folding
// without equalling it exactly.
func exactClaims(raw []byte, names ...string) (map[string]string, bool) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	out := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, _ := tok.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
		folded := strings.ToLower(key)
		if !want[folded] {
			continue
		}
		if key != folded {
			return nil, false // a case variant of a claim being decided
		}
		if _, dup := out[key]; dup {
			return nil, false
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			return nil, false
		}
		out[key] = s
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	return out, true
}

// supabasePublishablePrefix opens Supabase's current publishable key, the
// replacement for the anon JWT; the API keys guide documents the prefix
// ("sb_publishable_...") and that the key is safe to expose. The body is not
// documented, so the prefix is the whole claim.
const supabasePublishablePrefix = "sb_publishable_"

// isSupabaseAnonKey is SEC-105's claim: the value is a Supabase anon key
// (decoded) or a publishable key (by its documented prefix).
func isSupabaseAnonKey(value string) bool {
	v := strings.Trim(value, `"'`)
	return strings.HasPrefix(v, supabasePublishablePrefix) || supabaseKeyRole(v) == supabaseRoleAnon
}

// isNotEvidentlyPublicValue is SEC-775's veto. SEC-775 reads the anon slot by
// NAME, and a name is not evidence that what it holds is public: a secret key
// pasted there, or an opaque value nox cannot decode, keeps the credential
// claim. Only a value that is public on its face -- the documented
// publishable prefix -- is vetoed, and SEC-105 claims it instead. A decoded
// anon JWT never reaches here as a separate finding: SEC-105 owns its span.
func isNotEvidentlyPublicValue(match string) bool {
	i := strings.LastIndexAny(match, "=:")
	if i < 0 {
		return true
	}
	v := strings.Trim(strings.TrimSpace(match[i+1:]), `"'`)
	return !strings.HasPrefix(v, supabasePublishablePrefix)
}

// isSupabaseServiceRoleKey is SEC-100's claim: the value is a Supabase
// service_role key.
func isSupabaseServiceRoleKey(value string) bool {
	return supabaseKeyRole(value) == supabaseRoleServiceRole
}

// isNotSupabaseProjectKey keeps SEC-371, the generic JWT rule, from claiming
// a token SEC-100 or SEC-105 claims more precisely. It is a JWT either way;
// what changes is which claim about it nox makes.
func isNotSupabaseProjectKey(value string) bool { return supabaseKeyRole(value) == "" }
