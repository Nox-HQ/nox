package secrets

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/internal/testkey"
)

// pemKey is the private_key value of a real service-account file as it is
// written in JSON: a PKCS#8 PEM block with its newlines escaped. The body is
// generated, so the value is as random as a key is.
func pemKey(seed int64) string {
	body := seededBody(seed, base64Body, 1600)
	var b strings.Builder
	b.WriteString(`-----BEGIN PRIVATE KEY-----\n`)
	for i := 0; i < len(body); i += 64 {
		b.WriteString(body[i:i+64] + `\n`)
	}
	b.WriteString(`-----END PRIVATE KEY-----\n`)
	return b.String()
}

// serviceAccount is a service-account key file whose private_key field holds
// privateKey, laid out the way `gcloud iam service-accounts keys create`
// writes it.
func serviceAccount(indent, privateKey string) string {
	lines := []string{
		`{`,
		`  "type": "service_account",`,
		`  "project_id": "example-project",`,
		`  "private_key_id": "` + seededBody(3, lowerHex, 40) + `",`,
		`  "private_key": "` + privateKey + `",`,
		`  "client_email": "ci@example-project.iam.gserviceaccount.com",`,
		`  "token_uri": "https://oauth2.googleapis.com/token"`,
		`}`,
	}
	return indent + strings.Join(lines, "\n"+indent) + "\n"
}

func sec008(ff []findings.Finding) (findings.Finding, bool) { return findingFor(ff, "SEC-008") }

// SEC-008 matches the line that says a JSON document is a service-account
// file. The credential in that document is its private_key. A sample of the
// file's shape whose private_key is "..." was reported as a leaked critical
// credential, in documentation that exists to show the shape.
func TestServiceAccountSampleWithoutAKeyIsNotACredential(t *testing.T) {
	tests := []struct{ name, file, body string }{
		{"documentation sample in a docstring", "plugin.py",
			"\"\"\"\nExample service account key file:\n\n.. code-block:: json\n\n" + serviceAccount("   ", "...") + "\n\"\"\"\n"},
		{"angle-bracket placeholder", "README.md", "```json\n" + serviceAccount("", "<your-private-key>") + "```\n"},
		{"empty key", "sa.template.json", serviceAccount("", "")},
		{"a variable the deploy fills in", "sa.json.tmpl", serviceAccount("", "${GCP_PRIVATE_KEY}")},
		{"one line", "sa.min.json", `{"type": "service_account", "project_id": "p", "private_key": "REDACTED", "client_email": "x@p.iam.gserviceaccount.com"}` + "\n"},
		{"the key field comes first", "sa.json", `{"private_key": "REDACTED",` + "\n" + `  "type": "service_account"}` + "\n"},
		{"nested in a larger document", "config.json",
			`{"name": "app", "gcp": {"type": "service_account", "private_key": "CHANGEME"}, "region": "eu"}` + "\n"},
		{"the armour with the key left out", "README.md",
			"```json\n" + serviceAccount("", `-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY\n-----END PRIVATE KEY-----\n`) + "```\n"},
		{"one character short of the shortest key", "sa.json", serviceAccount("", seededBody(5, base64Body, shortestPrivateKey-1))},
		{"an escaped quote before it", "sa.json",
			`{"note": "the 5\" disk", "type": "service_account", "private_key": "REDACTED"}` + "\n"},
		{"a brace inside a string before it", "sa.json",
			`{"note": "see }{ below", "type": "service_account", "private_key": "REDACTED"}` + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if f, ok := sec008(scanAt(t, tc.file, tc.body)); ok {
				t.Errorf("reported as %s at line %d: the document holds no key", f.Severity, f.Location.StartLine)
			}
			_, store := scanWithReasoning(t, tc.file, tc.body)
			var said bool
			for _, subject := range store.Subjects() {
				for _, c := range store.About(subject).Claims {
					if c.Refutes() && strings.Contains(c.Statement, "private_key") {
						said = true
					}
				}
			}
			if !said {
				t.Error("nothing recorded why the candidate was dropped")
			}
		})
	}
}

// The counterexamples. A document that carries a key is still reported at the
// rule's rating, and so is every document this check cannot read to the end:
// it withdraws a finding only when it has seen the key field and what is in it.
func TestServiceAccountDocumentIsStillReported(t *testing.T) {
	key := pemKey(61)
	tests := []struct{ name, file, body string }{
		{"a real key file", "sa.json", serviceAccount("", key)},
		{"a real key file on one line", "sa.min.json",
			`{"type": "service_account", "private_key": "` + key + `", "client_email": "x@p.iam.gserviceaccount.com"}` + "\n"},
		{"a real key file indented in a document", "README.md", "```json\n" + serviceAccount("    ", key) + "```\n"},
		{"the marker line alone", "notes.txt", `"type": "service_account"` + "\n"},
		{"a value as long as the shortest key", "sa.json", serviceAccount("", seededBody(5, base64Body, shortestPrivateKey))},
		{"a key without its armour", "sa.json", serviceAccount("", seededBody(7, base64Body, 1600))},
		{"a brace in a string before a real key", "config.json",
			`{"private_key": "...", "gcp": {"note": "{", "type": "service_account", "private_key": "` + key + `"}}` + "\n"},
		{"no key field at all", "sa.json", `{"type": "service_account", "project_id": "p"}` + "\n"},
		{"the key is not a string here", "creds.js",
			`const sa = {"type": "service_account", "private_key": process.env.KEY};` + "\n"},
		{"the placeholder belongs to a sibling object", "config.json",
			`{"sample": {"private_key": "..."}, "gcp": {"type": "service_account", "private_key": "` + key + `"}}` + "\n"},
		{"the placeholder belongs to the enclosing object", "config.json",
			`{"private_key": "...", "gcp": {"type": "service_account", "private_key": "` + key + `"}}` + "\n"},
		{"only a nested object has a key field", "config.json",
			`{"type": "service_account", "example": {"private_key": "..."}}` + "\n"},
		{"the placeholder belongs to a nested object", "config.json",
			`{"type": "service_account", "old": {"private_key": "..."}, "private_key": "` + key + `"}` + "\n"},
		{"an unbalanced brace in a string, with a placeholder outside", "config.json",
			`{"private_key": "...", "gcp": {"note": "}", "type": "service_account", "private_key": "` + key + `"}}` + "\n"},
		{"two key fields, one of them real", "sa.json",
			`{"type": "service_account", "private_key": "...", "private_key": "` + key + `"}` + "\n"},
		{"the document is not closed", "sa.json", `{"type": "service_account", "private_key": "..."` + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := sec008(scanAt(t, tc.file, tc.body))
			if !ok {
				t.Fatal("SEC-008 reported nothing")
			}
			if f.Severity != findings.SeverityCritical {
				t.Errorf("severity = %s, want critical", f.Severity)
			}
		})
	}
}

// The check is about what SEC-008 claims. Another rule's finding in the same
// document claims something else and is not touched.
func TestKeylessServiceAccountKeepsOtherRulesFindings(t *testing.T) {
	body := `{"type": "service_account", "private_key": "...", "aws_access_key_id": "` + testkey.AWSAccessKeyID() + `"}` + "\n"
	ff := scanAt(t, "sa.json", body)
	if _, ok := sec008(ff); ok {
		t.Error("SEC-008 reported on a document with no key")
	}
	if _, ok := findingFor(ff, "SEC-001"); !ok {
		t.Error("SEC-001 was withdrawn along with SEC-008")
	}
}

// The check reads a document for SEC-008 only. Asked about another rule's
// finding at the very same place, it has nothing to say.
func TestKeylessServiceAccountIsAboutSEC008(t *testing.T) {
	content := []byte(serviceAccount("", "..."))
	at := findings.Location{FilePath: "sa.json", StartLine: 2, StartColumn: 3}
	if !isKeylessServiceAccount(content, &findings.Finding{RuleID: "SEC-008", Location: at}) {
		t.Fatal("the sample is not recognised for SEC-008, so this test would prove nothing")
	}
	if isKeylessServiceAccount(content, &findings.Finding{RuleID: "SEC-001", Location: at}) {
		t.Error("another rule's finding was judged by the service-account check")
	}
}

// A line longer than the window the check reads is not read at all: on a
// minified file there is no "nearby", and declining is the answer that cannot
// hide a key.
func TestServiceAccountCheckDeclinesALineItCannotBound(t *testing.T) {
	pad := `"pad": "` + strings.Repeat("a", objectWindow+10) + `", `
	body := `{` + pad + `"type": "service_account", "private_key": "..."}` + "\n"
	if _, ok := sec008(scanAt(t, "big.json", body)); !ok {
		t.Error("SEC-008 was withdrawn on a line too long to read to its start")
	}
}

// The search for the enclosing object tries a bounded number of braces. Past
// that it declines too, and one brace inside the bound it still answers.
func TestServiceAccountCheckDeclinesPastItsBraceBudget(t *testing.T) {
	doc := func(siblings int) string {
		return `{"history": [` + strings.Repeat(`{}, `, siblings) + `0], "type": "service_account", "private_key": "..."}` + "\n"
	}
	if _, ok := sec008(scanAt(t, "sa.json", doc(objectCandidates-1))); ok {
		t.Error("SEC-008 reported although the enclosing object is within the budget")
	}
	if _, ok := sec008(scanAt(t, "sa.json", doc(objectCandidates))); !ok {
		t.Error("SEC-008 was withdrawn past the budget of braces the check tries")
	}
}
