package secrets

import (
	"strings"
	"testing"
)

// The three precision follow-ups the credential-body audit recorded, done by
// its method: state the proposition, identify the evidence the detector
// observes, construct counterexamples and the true positive, run both.

func pemBody(lines int) string {
	var b strings.Builder
	for i := 0; i < lines; i++ {
		b.WriteString(blobBody(64, b64std))
		b.WriteString("\n")
	}
	return b.String()
}

// SEC-082 claimed a hard-coded bearer token from the word Bearer and any run
// of token characters after it. Every one of its 107 findings on the pinned
// corpus was a placeholder -- alice-token, real-secret, token123, x, null, and
// `BEDROCK_AUTH=bearer python` read as the token "python".
func TestBearerRuleNeedsAToken(t *testing.T) {
	for _, src := range []string{
		"BEDROCK_AUTH=bearer python examples/bedrock_runtime.py\n",
		"headers = {\"authorization\": \"Bearer alice-token\"}\n",
		"headers = {\"Authorization\": \"Bearer real-secret\"}\n",
		"headers = {\"Authorization\": \"Bearer token123\"}\n",
		"headers = {\"Authorization\": \"Bearer explicit-gateway-key\"}\n",
		"headers = {\"Authorization\": \"Bearer ASYNC_TOKEN\"}\n",
		"headers = {\"Authorization\": \"Bearer null\"}\n",
	} {
		if fs := scanOne(t, "client.py", src); firedRule(fs, "SEC-082") {
			t.Errorf("SEC-082 reported a placeholder as a bearer token:\n%s", src)
		}
	}
	for _, tok := range []string{
		"sk-" + "proj-" + blobBody(40, b64url),
		"ey" + "J" + blobBody(30, b64url) + "." + blobBody(40, b64url) + "." + blobBody(43, b64url),
		blobBody(40, alnum),
	} {
		src := "headers = {\"Authorization\": \"Bearer " + tok + "\"}\n"
		if fs := scanOne(t, "client.py", src); !firedRule(fs, "SEC-082") {
			t.Errorf("SEC-082 missed a real bearer token: [%s]\n%s", ruleIDs(fs), src)
		}
	}
}

// The PEM header rules claimed a private key from the header line alone.
// Counterexamples from the corpus: crewAI documents a private_key_pem argument
// as the header followed by an ellipsis, and vercel-ai's PEM parser declares the
// header as a constant. A key is reported by its body.
func TestPrivateKeyRulesNeedTheKey(t *testing.T) {
	headerOnly := []string{"SEC-004", "SEC-390", "SEC-426", "SEC-427", "SEC-391", "SEC-078", "SEC-392"}
	for _, src := range []string{
		"    ...     private_key_pem=\"-----BEGIN PRIVATE KEY-----...\",\n",
		"const pemHeader = '-----BEGIN PRIVATE KEY-----';\nconst pemFooter = '-----END PRIVATE KEY-----';\n",
		"if pem.startswith(\"-----BEGIN RSA PRIVATE KEY-----\"):\n    kind = \"rsa\"\n",
		"HEADERS = [\"-----BEGIN EC PRIVATE KEY-----\", \"-----BEGIN OPENSSH PRIVATE KEY-----\"]\n",
		"PGP = \"-----BEGIN PGP PRIVATE KEY BLOCK-----\"\n",
	} {
		fs := scanOne(t, "parse.py", src)
		for _, id := range headerOnly {
			if firedRule(fs, id) {
				t.Errorf("%s reported a header with no key:\n%s", id, src)
			}
		}
	}
	// Each true positive must be reported by a HEADER rule, not merely by
	// SEC-299 (which matches header to footer). Accepting either is how a
	// regex that could not match the escaped `\n` form of a JSON key passed
	// this test while the header rules missed it.
	cases := []struct{ name, file, src, rule string }{
		{"pem file", "client.key", "-----BEGIN PRIVATE KEY-----\n" + pemBody(6) + "-----END PRIVATE KEY-----\n", "SEC-004"},
		{"rsa pem file", "id_rsa.pem", "-----BEGIN RSA PRIVATE KEY-----\n" + pemBody(6) + "-----END RSA PRIVATE KEY-----\n", "SEC-004"},
		{"escaped in a json string", "sa.json", "{\"type\": \"service_" + "account\", \"private_key\": \"-----BEGIN PRIVATE KEY-----\\n" +
			blobBody(64, b64std) + "\\n" + blobBody(64, b64std) + "\\n-----END PRIVATE KEY-----\\n\"}\n", "SEC-004"},
		{"pgp with armor headers", "key.asc", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n" + pemBody(4) + "-----END PGP PRIVATE KEY BLOCK-----\n", "SEC-078"},
		{"openssh", "id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n" + pemBody(4) + "-----END OPENSSH PRIVATE KEY-----\n", "SEC-004"},
	}
	for _, tc := range cases {
		if fs := scanOne(t, tc.file, tc.src); !firedRule(fs, tc.rule) {
			t.Errorf("%s: %s did not report a real private key: [%s]", tc.name, tc.rule, ruleIDs(fs))
		}
	}
}

// SEC-469's bound value still reported documentation values. SEC-951, the other
// generic credential-name rule, already decides this with isRandomLookingValue:
// a value made of words, or a keyboard placeholder with a run of sequential
// digits, is not a credential. SEC-469 now asks the same question.
func TestEnvSecretRuleUsesTheGenericValueTest(t *testing.T) {
	for _, src := range []string{
		"export DATABRICKS_TOKEN=\"dapi1234567890abcdef\"\n",
		"SLACK_TOKEN=xoxb-your-slack-bot-token-here\n",
		"API_KEY=my-local-development-key\n",
	} {
		if fs := scanOne(t, "README.md", src); firedRule(fs, "SEC-469") {
			t.Errorf("SEC-469 reported a documentation value:\n%s", src)
		}
	}
	src := "API_KEY=" + blobBody(32, alnum) + "\n"
	if fs := scanOne(t, ".env", src); !firedRule(fs, "SEC-469") {
		t.Errorf("SEC-469 missed a real value: [%s]", ruleIDs(fs))
	}
}
