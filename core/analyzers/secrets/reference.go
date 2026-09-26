package secrets

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// A reference to where a secret is stored is not the secret.
//
// `password: "{{ upassword }}"`, `'{{resolve:secretsmanager:…}}'` and
// `"${{ secrets.DOCKERHUB_TOKEN }}"` are what the remediation for a hardcoded
// password tells you to write. Reporting them reports the fix as the defect —
// on the rule-diff corpus, every one of SEC-080's 12 findings that no other
// password rule shared was one of these.
//
// The whole design is on the false-negative side. A value is a reference only
// when it is ENTIRELY a reference, because any literal part could be the
// credential:
//
//   - `{{ 'hunter2' }}` is a template that evaluates to a hardcoded literal, so
//     a quote anywhere inside the braces disqualifies it.
//   - `Summer2024!${SUFFIX}` has a literal prefix, so anchoring is total.
//   - `${DB_PASSWORD:-hunter2}` is an interpolation with a hardcoded FALLBACK,
//     which is what runs whenever the variable is unset — a hardcoded password.
//     Only an empty default is a pure reference.
//   - A bare `$name` is a reference only where the language expands it. YAML,
//     JSON and Python do not, so `$ecretP4ss` there is a password that happens
//     to start with a dollar sign.
var (
	// {{ … }} (Jinja, Ansible, Go templates, Handlebars, CloudFormation
	// dynamic references) and ${{ … }} (GitHub Actions expressions), with no
	// nested braces and no quote anywhere inside.
	templateReference = regexp.MustCompile(`^\$?\{\{[^{}'"]+\}\}$`)
	// ${NAME}, ${NAME-}, ${NAME:-}, and the ? forms, which abort when unset
	// rather than substituting anything. A non-empty `-`/`=`/`+` default is
	// excluded on purpose.
	bracedInterpolation = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-|:?\?[^}'"]*)?\}$`)
	// $NAME, meaningful only where the shell expands it.
	bareExpansion = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)
)

// shellExtensions are the files in which a bare `$name` inside a double-quoted
// string is expanded by the language itself.
var shellExtensions = map[string]bool{".sh": true, ".bash": true, ".zsh": true, ".ksh": true}

// isSecretReference reports whether value is entirely a reference to a secret
// stored elsewhere, rather than the secret.
func isSecretReference(value, path string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	if templateReference.MatchString(v) || bracedInterpolation.MatchString(v) {
		return true
	}
	return bareExpansion.MatchString(v) && shellExtensions[strings.ToLower(filepath.Ext(path))]
}

// referencedValue extracts the value a finding matched: the quoted literal when
// the rule matched `key = "value"`, otherwise the whole span with surrounding
// quotes trimmed.
func referencedValue(content []byte, f *findings.Finding) string {
	matched := matchedValue(content, f)
	if m := quotedInner.FindStringSubmatch(matched); m != nil {
		return m[1]
	}
	return strings.Trim(strings.TrimSpace(matched), `"'`)
}

// isReferenceFinding reports whether a finding's matched value is a reference.
func isReferenceFinding(content []byte, f *findings.Finding) bool {
	return isSecretReference(referencedValue(content, f), f.Location.FilePath)
}
