package secrets

import (
	"testing"
)

// A reference to where a secret is stored is not the secret.
//
// Measured 2026-09-26 on the 25-entry rule-diff corpus: SEC-080 "Generic
// password assignment" produced 12 findings where no other password rule fired,
// and all 12 were references — the remediation SEC-080 itself recommends
// ("use environment variables or a secrets manager"), reported as the defect:
//
//	4  '{{resolve:secretsmanager:…}}'     CloudFormation dynamic reference
//	3  "${{ secrets.DOCKERHUB_TOKEN }}"   GitHub Actions secret reference
//	3  "{{ upassword }}"                  Ansible / Jinja variable
//	2  "$hashed_password"                 shell variable, in a .sh file
//
// placeholderCandidate's comment claimed to handle "${SECRET}", but the regex
// beneath it is `<[^>]*>` and matches none of these.

func TestAWholeValueReferenceIsNotASecret(t *testing.T) {
	for name, tc := range map[string]struct{ path, value string }{
		"cloudformation dynamic reference": {"t.yaml", "{{resolve:secretsmanager:aurora-pw:SecretString:password}}"},
		"cloudformation ssm-secure":        {"t.yaml", "{{resolve:ssm-secure:/db/pw:1}}"},
		"github actions secret":            {"deploy.yml", "${{ secrets.DOCKERHUB_TOKEN }}"},
		"github actions var":               {"deploy.yml", "${{ vars.PASSWORD }}"},
		"jinja / ansible variable":         {"main.yml", "{{ upassword }}"},
		"jinja with filter":                {"main.yml", "{{ db_password | default(omit) }}"},
		"braced env interpolation":         {"compose.yml", "${DB_PASSWORD}"},
		"braced env with default":          {"compose.yml", "${DB_PASSWORD:-}"},
		"shell variable in a shell script": {"run.sh", "$hashed_password"},
	} {
		if !isSecretReference(tc.value, tc.path) {
			t.Errorf("%s: %q in %s is a reference to where a secret lives, not a secret", name, tc.value, tc.path)
		}
	}
}

// The false-negative side, which is the one that matters. A reference is only
// safe to refute when the value is ENTIRELY a reference: any literal part could
// be the credential.
func TestAValueContainingALiteralIsNotAReference(t *testing.T) {
	for name, tc := range map[string]struct{ path, value string }{
		// A template that evaluates to a hardcoded literal is a hardcoded literal.
		"jinja literal string":         {"main.yml", "{{ 'hunter2-summer-2024' }}"},
		"jinja double-quoted":          {"main.yml", `{{ "hunter2-summer-2024" }}`},
		"literal prefix + reference":   {"compose.yml", "Summer2024!${SUFFIX}"},
		"reference + literal suffix":   {"main.yml", "{{ base }}hunter2"},
		"two references and a literal": {"main.yml", "{{ a }}x{{ b }}"},
		// A reference with a hardcoded FALLBACK is a hardcoded password: the
		// default is what runs whenever the variable is unset.
		"env reference with literal default": {"compose.yml", "${DB_PASSWORD:-hunter2-summer}"},
		"jinja default filter with literal":  {"main.yml", "{{ db_password | default('hunter2') }}"},
		// `$` is literal outside a shell: YAML does not expand it, so a password
		// that happens to start with `$` is still a password.
		"dollar-leading password in yaml": {"config.yaml", "$ecretP4ss-2024"},
		"dollar-leading password in py":   {"settings.py", "$ecretP4ss-2024"},
		// An ordinary password.
		"plain password": {"config.yaml", "hunter2-summer-2024"},
	} {
		if isSecretReference(tc.value, tc.path) {
			t.Errorf("%s: %q in %s was treated as a reference, but it carries a literal "+
				"that could be the credential", name, tc.value, tc.path)
		}
	}
}

// End to end through the real entry point, on the exact lines from the corpus.
// scanAt runs ScanArtifacts; ScanFile would skip every refiner and pass
// whatever this does.
func TestSEC080NoLongerReportsItsOwnRemediation(t *testing.T) {
	for _, tc := range []struct{ path, line string }{
		{"db/tasks/main.yml", `    password: "{{ upassword }}"`},
		{"DMS.yaml", `        Password: '{{resolve:secretsmanager:aurora-source-enpoint-password:SecretString:password}}'`},
		{"deploy_docker_images.yml", `          password: "${{ secrets.DOCKERHUB_TOKEN }}"`},
		{"VSCodeServer.sh", `hashed-password: "$hashed_password"`},
	} {
		if firedRule(scanAt(t, tc.path, tc.line+"\n"), "SEC-080") {
			t.Errorf("SEC-080 reported a reference as a hardcoded password in %s:\n  %s", tc.path, tc.line)
		}
	}
}

// The control, without which the test above passes for a rule that has simply
// stopped firing. The same key with a literal value must still be reported.
func TestSEC080StillReportsAHardcodedPassword(t *testing.T) {
	for _, tc := range []struct{ path, line string }{
		{"db/tasks/main.yml", `    password: "Tr0ub4dor-and-3"`},
		{"settings.py", `DB_PASSWORD = "Tr0ub4dor-and-3"`},
		{"compose.yml", `      password: "Summer2024!${SUFFIX}"`},
	} {
		if !firedRule(scanAt(t, tc.path, tc.line+"\n"), "SEC-080") {
			t.Errorf("SEC-080 stopped reporting a hardcoded password in %s:\n  %s", tc.path, tc.line)
		}
	}
}
