package secrets

import (
	"regexp"
	"strings"
)

// This file implements an example/placeholder allowlist for the secrets
// analyzer. Documentation defaults such as "your-api-key-here", "changeme",
// "<your-smtp-password>", and "postgres://USER:PASSWORD@host" are not real
// credentials, yet the keyword- and provider-shaped regex rules readily fire
// on them. Every serious secret scanner (gitleaks, trufflehog, detect-secrets)
// ships such an allowlist; without one, .env.example files and config templates
// are a dominant false-positive source. We drop a finding when its matched
// value is an obvious placeholder — never when it is a plausibly real secret.

// placeholderTokens are substring markers that unambiguously indicate a
// documentation placeholder rather than a live credential — distinctive enough
// that their presence anywhere in a value is decisive. Matching is
// case-insensitive. These mirror the gitleaks/detect-secrets allowlists.
//
// Note: bare English words that also legitimately appear inside real token
// bodies (e.g. "example" inside the canonical AWS key AKIA...EXAMPLE) are NOT
// listed here — they live in placeholderWords and are matched word-boundaried
// so they never suppress a real anchored provider token.
var placeholderTokens = []string{
	"changeme",
	"change-me",
	"change_me",
	"replace-me",
	"replace_me",
	"replaceme",
	"your-", // your-api-key-here, your-token, ...
	"your_", // your_api_key
	"yourkey",
	"placeholder",
	"insertyourkeyhere",
	"xxxx",          // masked run
	"...",           // literal ellipsis stand-in
	"user:password", // credentials-in-URL template
	"username:password",
	"notarealsecret",
	"not-a-real",
}

// placeholderWords are generic English placeholder words matched only at word
// boundaries. They must NOT fire as bare substrings, because real token bodies
// can contain them (the canonical AWS example key AKIA...EXAMPLE ends in
// "EXAMPLE" yet is a required true positive).
var placeholderWords = []string{
	"example",
	"dummy",
	"todo",
	"redacted",
	"sample",
	"fixme",
}

// wordBoundaryRE matches any placeholderWord delimited by non-alphanumeric
// boundaries (start/end of string, punctuation, dashes, underscores). Built
// once from placeholderWords.
var wordBoundaryRE = buildPlaceholderWordRE()

func buildPlaceholderWordRE() *regexp.Regexp {
	alt := strings.Join(placeholderWords, "|")
	// (^|[^a-z0-9])word([^a-z0-9]|$) — a delimited standalone word.
	return regexp.MustCompile(`(?i)(^|[^a-z0-9])(` + alt + `)([^a-z0-9]|$)`)
}

// placeholderExactValues are matched-value strings that, after normalisation,
// are treated as placeholders in full. Kept separate from substring tokens so
// short generic words don't accidentally suppress a real embedded secret.
var placeholderExactValues = map[string]struct{}{
	"password":   {},
	"secret":     {},
	"token":      {},
	"apikey":     {},
	"api_key":    {},
	"key":        {},
	"test":       {},
	"foo":        {},
	"bar":        {},
	"baz":        {},
	"none":       {},
	"null":       {},
	"host":       {},
	"dbname":     {},
	"database":   {},
	"user":       {},
	"admin":      {},
	"root":       {},
	"credential": {},
}

// angleBracketPlaceholder matches a value that contains a <...> template
// marker, e.g. "<your-smtp-password>" or "${SECRET}"-style single tokens.
var angleBracketPlaceholder = regexp.MustCompile(`<[^>]*>`)

// quotedInner extracts the first single- or double-quoted string literal from
// a matched span. Keyword rules often match "PASSWORD = \"changeme\"" as a
// whole; the placeholder signal lives in the quoted value, so we look there.
var quotedInner = regexp.MustCompile(`["']([^"']*)["']`)

// urlUserPass matches a URL userinfo segment "user:password@" where both parts
// are placeholder-shaped (all-uppercase template names like USER:PASSWORD, or
// the literal lowercase user:password). Real leaked DSNs carry a random
// password, not these template tokens.
var urlUserPass = regexp.MustCompile(`(?i)://(user|username):(password|pass|secret|changeme)@`)

// isURLCredentialPlaceholderLine reports whether a source line contains a
// connection-string whose userinfo is an obvious template — "user:password@"
// or "USER:PASSWORD@". Real leaked DSNs carry a random password here; these
// template tokens are documentation defaults (postgres://USER:PASSWORD@host).
func isURLCredentialPlaceholderLine(line string) bool {
	return urlUserPass.MatchString(line)
}

// isPlaceholderValue reports whether a matched secret value is an obvious
// documentation placeholder that should be dropped rather than reported. The
// input is the raw matched span (which may include the assignment target and
// quotes); the function inspects both the whole span and any quoted inner
// value so keyword-rule and provider-rule matches are handled uniformly.
func isPlaceholderValue(matched string) bool {
	if placeholderCandidate(matched) {
		return true
	}
	// Keyword rules capture "NAME = \"value\"" — re-test the quoted inner value.
	if m := quotedInner.FindStringSubmatch(matched); m != nil {
		if placeholderCandidate(m[1]) {
			return true
		}
	}
	return false
}

// placeholderCandidate applies the placeholder heuristics to a single value.
func placeholderCandidate(raw string) bool {
	v := strings.TrimSpace(raw)
	if v == "" {
		return true
	}
	lower := strings.ToLower(v)

	// URL credential templates: postgres://USER:PASSWORD@host, ...
	if urlUserPass.MatchString(v) {
		return true
	}
	// Angle-bracket / template markers: "<your-smtp-password>", "${SECRET}".
	if angleBracketPlaceholder.MatchString(v) {
		return true
	}
	// Distinctive placeholder tokens anywhere in the value.
	for _, tok := range placeholderTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	// Generic English placeholder words, matched only at word boundaries so a
	// real token body containing the substring (e.g. AKIA...EXAMPLE) is kept.
	if wordBoundaryRE.MatchString(v) {
		return true
	}
	// Strip surrounding quotes for exact/shape checks.
	core := strings.Trim(v, `"'`)
	coreLower := strings.ToLower(core)
	if _, ok := placeholderExactValues[coreLower]; ok {
		return true
	}
	// Runs of a single repeated character (masked/example values like
	// "xxxxxxxx", "00000000", "----"), including test keys whose body is all
	// zeros such as "sk_test_0000000000000000".
	if isMaskedRun(core) {
		return true
	}
	return false
}

// isMaskedRun reports whether the value is a masked/example run: after
// dropping a known provider prefix (sk_test_, pk_test_, ...), the remaining
// body is a single character repeated (e.g. all-x, all-zero, all-dash). Such
// values are stand-ins, never live credentials.
func isMaskedRun(core string) bool {
	body := stripExamplePrefix(core)
	if len(body) < 8 {
		// Too short to be a confident masked-run signal on its own.
		return false
	}
	first := body[0]
	// Only treat runs of an obviously filler character as placeholders so a
	// legitimately low-variety secret isn't dropped.
	switch first {
	case 'x', 'X', '0', '-', '_', '.', '*':
	default:
		return false
	}
	for i := 0; i < len(body); i++ {
		if body[i] != first {
			return false
		}
	}
	return true
}

// examplePrefixes are provider key prefixes that denote an explicit test/example
// key namespace; the interesting placeholder signal is in the body after them.
var examplePrefixes = []string{
	"sk_test_",
	"pk_test_",
	"rk_test_",
	"sk-test-",
	"test_",
}

// stripExamplePrefix removes a leading test/example provider prefix so the
// masked-run check inspects the key body.
func stripExamplePrefix(v string) string {
	lower := strings.ToLower(v)
	for _, p := range examplePrefixes {
		if strings.HasPrefix(lower, p) {
			return v[len(p):]
		}
	}
	return v
}
