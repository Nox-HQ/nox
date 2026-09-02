package secrets

import "strings"

// isURLCredentialLiteral is the ValidateMatch for the connection-string rules
// (SEC-073/074/076/085). The patterns accept any userinfo of the form
// user:password@, and the most common way that shape appears in a repository
// is the templated one -- `postgres://${DB_USER}:${DB_PASSWORD}@db:5432/app`
// in a compose file, `https://${GIT_USER}:${GIT_TOKEN}@github.com/...` in a
// Pipfile -- where the password is a placeholder to be filled in at runtime
// and nothing has leaked. Only a literal password is a finding.
func isURLCredentialLiteral(match string) bool {
	password, ok := urlPassword(match)
	if !ok {
		return true // shape not recognised; keep the pattern's verdict
	}
	return !isPlaceholder(password)
}

// urlPassword returns the password component of a user:password@host URL.
func urlPassword(url string) (string, bool) {
	rest := url
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return "", false
	}
	userinfo := rest[:at]
	colon := strings.IndexByte(userinfo, ':')
	if colon < 0 {
		return "", false
	}
	return userinfo[colon+1:], true
}

// isPlaceholder reports whether a password component is a template variable
// or a redaction rather than a value: shell/compose `$VAR` and `${VAR}`,
// Jinja/Helm/GitHub `{{ … }}`, printf/format `%s` / `%(name)s` / `{}` /
// `{0}`, `<password>`, and a run of asterisks or the word itself.
func isPlaceholder(password string) bool {
	p := strings.TrimSpace(password)
	if p == "" {
		return true
	}
	switch {
	case strings.HasPrefix(p, "$"),
		strings.HasPrefix(p, "{{") || strings.HasPrefix(p, "{%"),
		strings.HasPrefix(p, "%"),
		strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}"),
		strings.HasPrefix(p, "<") && strings.HasSuffix(p, ">"),
		strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]"),
		strings.Trim(p, "*") == "",
		strings.Trim(p, "x") == "" || strings.Trim(p, "X") == "",
		strings.Trim(p, ".") == "":
		return true
	}
	switch strings.ToLower(p) {
	case "password", "passwd", "pass", "pwd", "secret", "token", "your_password", "your-password", "yourpassword", "changeme", "redacted", "placeholder":
		return true
	}
	return false
}
