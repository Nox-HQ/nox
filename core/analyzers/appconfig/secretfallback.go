package appconfig

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// RuleSecretFallback (APPCFG-007) reports a secret setting in application
// configuration whose value is an environment placeholder with a literal
// default (CWE-798): `password: ${DB_PASSWORD:...}` in Spring,
// `JWT_SECRET: ${JWT_SECRET:-...}` in Compose. The placeholder reads as
// configuration taken from the environment, and the secrets rules treat it as
// a reference; the default is what the application runs with wherever the
// variable is unset, and it is in the repository. A placeholder without a
// default, with an empty one, with `:?` (Compose: the variable is required) or
// defaulting to another placeholder is not reported, nor is a setting that
// holds something about a secret rather than the secret (a TTL, a header name,
// a key-store type).
const RuleSecretFallback = "APPCFG-007"

var secretFallbackRules = []rule{{
	id: RuleSecretFallback, cwe: "CWE-798", severity: findings.SeverityMedium,
	confidence:  findings.ConfidenceMedium,
	message:     "Secret setting falls back to a literal when its environment variable is unset",
	description: "A password, secret, token, API key or credential in Spring application/bootstrap configuration or a Compose file is an environment placeholder with a literal default (${VAR:default}, ${VAR:-default})",
	remediation: "Remove the default so startup fails when the variable is missing (Spring: ${VAR}; Compose: ${VAR:?message}), and rotate the value that was committed.",
	tags:        []string{"secrets", "configuration", "owasp-a07"},
}}

var (
	// A key naming a secret, then `:` or `=`, then a placeholder with a
	// default. Group 1 is the key, group 2 the default's first character.
	secretFallbackLine = regexp.MustCompile(`(?i)^[ \t]*(?:-[ \t]*)?["']?([\w.-]*?(?:password|passwd|pwd|secret|token|api[-_]?key|apikey|credential|signing[-_]?key|private[-_]?key|access[-_]?key)[\w.-]*)["']?[ \t]*[:=][ \t]*["']?\$\{[ \t]*[A-Za-z_][\w.-]*[ \t]*:-?([^}$?\s])`)
	// Keys that hold something about a secret, not the secret.
	secretAboutKey = regexp.MustCompile(`(?i)(?:url|uri|path|file|dir|expir\w*|ttl|timeout|length|header|name|enabled|type|algorithm|validity|seconds|minutes|days|hours|location|endpoint|policy|prefix|cookie)$`)
)

// secretFallbackFile reports whether path is Spring application or bootstrap
// configuration, or a Compose file.
func secretFallbackFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasPrefix(base, "application") || strings.HasPrefix(base, "bootstrap"):
		return strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".properties")
	case strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose"):
		return strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")
	}
	return false
}

// scanSecretFallback reports each secret setting whose placeholder defaults to
// a literal. The literal is never put in the finding.
func scanSecretFallback(path string, content []byte) []findings.Finding {
	if !secretFallbackFile(path) || !bytes.Contains(content, []byte("${")) {
		return nil
	}
	r := secretFallbackRules[0]
	var out []findings.Finding
	for i, line := range strings.Split(string(content), "\n") {
		m := secretFallbackLine.FindStringSubmatch(line)
		if len(m) < 2 || secretAboutKey.MatchString(m[1]) {
			continue
		}
		out = append(out, findings.Finding{
			RuleID:     r.id,
			Severity:   r.severity,
			Confidence: r.conf(),
			Message:    r.message + " (" + m[1] + ")",
			Location:   findings.Location{FilePath: path, StartLine: i + 1, EndLine: i + 1},
			Metadata:   map[string]string{"cwe": r.cwe},
		})
	}
	return out
}
