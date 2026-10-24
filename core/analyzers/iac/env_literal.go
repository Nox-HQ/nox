package iac

import (
	"regexp"
	"strings"
)

// A Kubernetes, Helm or Compose environment variable names its own value: the
// credential's NAME is the value of a `name:` key, not a mapping key, so every
// rule keyed on a `password:` or `token:` KEY - IAC-225, the generic secret
// assignment rules - reads `name: DB_PASSWORD` / `value: hunter2` as two
// unrelated scalars. The result was a scanner that stayed silent when a
// `valueFrom: secretKeyRef` was replaced by the literal it referenced, which is
// the exact change a reviewer most needs to be told about.
//
// The pattern finds a credential-NAMED variable followed by a value; the
// functions here decide whether the value is a literal. That is a question of
// the value's meaning (a path, a template, a placeholder, a count), which a
// regex over a whole file cannot answer without becoming unreadable.

// credentialWords are the name tokens that make an environment variable a
// credential. Matching is on whole tokens of the name split at `_`, `-` and
// `.`, so MAX_TOKENS (plural, a limit) and PASSWORD_POLICY_MIN (a number) are
// not credentials by accident of containing a substring.
var credentialWords = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true,
	"apikey": true, "credential": true, "credentials": true, "passphrase": true,
}

// credentialPairs are two-token names: API_KEY, PRIVATE_KEY, ACCESS_KEY,
// SECRET_KEY, AUTH_KEY and friends. The second token alone (`KEY`) is not a
// credential - CACHE_KEY, PRIMARY_KEY and SORT_KEY are not - so the pair is
// required.
var credentialPairs = map[string]bool{
	"api": true, "private": true, "access": true, "secret": true, "auth": true,
	"signing": true, "encryption": true, "master": true,
}

// descriptorWords end a name that REFERS to a credential rather than holding
// one: DB_PASSWORD_FILE is a path, OAUTH_TOKEN_URL an endpoint, API_KEY_HEADER a
// header name, AWS_ACCESS_KEY_ID an identifier, SECRET_NAME a reference. The
// last token decides, because the qualifier always trails.
var descriptorWords = map[string]bool{
	"file": true, "path": true, "dir": true, "url": true, "uri": true,
	"endpoint": true, "header": true, "name": true, "id": true, "ref": true,
	"location": true, "provider": true, "type": true, "algorithm": true,
	"issuer": true, "audience": true, "scope": true, "prefix": true,
	"enabled": true, "ttl": true, "expiry": true, "expires": true,
	"lifetime": true, "length": true, "timeout": true, "seconds": true,
}

// placeholderValues are literals a template author writes to mean "fill this
// in", not credentials. `changeme` is on the list on purpose: it is a weak
// default worth its own finding, but not this one - the claim here is that a
// real secret was committed.
var placeholderValues = map[string]bool{
	"changeme": true, "change-me": true, "change_me": true, "changeit": true,
	"replace-me": true, "replace_me": true, "replaceme": true, "redacted": true,
	"todo": true, "tbd": true, "placeholder": true, "example": true,
	"your-secret": true, "your_secret": true,
}

var (
	// block form: `name: X` then `value: Y` on the next line.
	envBlockRe = regexp.MustCompile(`(?is)name:[ \t]*["']?([^\s"',}]+)["']?[ \t]*\r?\n[ \t]*value:[ \t]*(.*)`)
	// flow form: `{name: X, value: Y}`.
	envFlowRe = regexp.MustCompile(`(?is)name:[ \t]*["']?([^\s"',}]+)["']?[ \t]*,[ \t]*value:[ \t]*(.*?)[ \t]*\}`)
	// placeholderPrefixRe is the way a template author tells the reader to
	// supply the value: INSERT_ETCD_DISCOVERY_TOKEN, REPLACE_WITH_KEY,
	// your-api-key, <...>. Measured on kubernetes/examples, where two etcd
	// manifests carry exactly this and are not leaked credentials.
	placeholderPrefixRe = regexp.MustCompile(`(?i)^(?:insert|replace|change|your|enter|fill|put|set|add|todo|example)[-_ ]`)
	// compose list form: `- NAME=value`.
	envComposeRe = regexp.MustCompile(`^\s*-\s*["']?([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$`)
)

// isCredentialName reports whether an environment variable name designates a
// credential, as opposed to a setting ABOUT one.
func isCredentialName(name string) bool {
	tokens := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	if len(tokens) == 0 {
		return false
	}
	if descriptorWords[tokens[len(tokens)-1]] {
		return false
	}
	for i, tok := range tokens {
		if credentialWords[tok] {
			return true
		}
		if tok == "key" && i > 0 && credentialPairs[tokens[i-1]] {
			return true
		}
	}
	return false
}

// isLiteralSecretValue reports whether a YAML or env scalar is a concrete
// value rather than an empty one, a reference, a template or a placeholder.
func isLiteralSecretValue(raw string) bool {
	v := strings.TrimSpace(raw)
	// A trailing comment is not part of the value.
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.Trim(v, `"'`)
	switch {
	case v == "":
		return false
	case strings.HasPrefix(v, "$"), strings.Contains(v, "${"), strings.Contains(v, "$("):
		return false // shell / Compose / Kubernetes expansion
	case strings.Contains(v, "{{"), strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">"):
		return false // Helm / Jinja template, or an angle-bracket placeholder
	case strings.HasPrefix(v, "/"), strings.HasPrefix(v, "file://"), strings.HasPrefix(v, "./"):
		return false // a path to the secret, not the secret
	case strings.HasPrefix(v, "!"), strings.HasPrefix(v, "*"), strings.HasPrefix(v, "&"):
		return false // YAML tag, alias or anchor
	case strings.HasPrefix(v, "http://"), strings.HasPrefix(v, "https://") && !strings.Contains(v, "@"):
		return false
	case nonSecretScalars[strings.ToLower(v)], placeholderValues[strings.ToLower(v)]:
		return false
	case placeholderPrefixRe.MatchString(v):
		return false // INSERT_TOKEN_HERE, REPLACE_ME, your-api-key
	case strings.Trim(v, "xX*.-_") == "":
		return false // xxxx, ****, ----
	case isAllDigits(v) && len(v) < 8:
		return false // a limit or a port, not a secret
	}
	return true
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// envNameValueIsLiteralCredential is the validate hook for IAC-502: a
// Kubernetes / Helm `name:` + `value:` pair, block or flow.
func envNameValueIsLiteralCredential(match string) bool {
	for _, re := range []*regexp.Regexp{envFlowRe, envBlockRe} {
		m := re.FindStringSubmatch(match)
		if m == nil {
			continue
		}
		// Only the first line of the value belongs to this pair.
		value, _, _ := strings.Cut(m[2], "\n")
		return isCredentialName(m[1]) && isLiteralSecretValue(value)
	}
	return false
}

// composeEnvIsLiteralCredential is the validate hook for IAC-503: a Compose
// `environment:` list entry, `- NAME=value`.
func composeEnvIsLiteralCredential(match string) bool {
	m := envComposeRe.FindStringSubmatch(match)
	if m == nil {
		return false
	}
	return isCredentialName(m[1]) && isLiteralSecretValue(m[2])
}
