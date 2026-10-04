package secrets

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// The credential-body audit (roady: credential-body-audit-31-secret-rules-that-
// match-no-credential). Each of these rules asserted a hard-coded credential --
// CWE-798, High, "rotate the exposed credential" -- from a pattern with no
// credential in it: a resource identifier, a public key, a bare format prefix or
// a variable name. Each is audited the same way:
//
//  1. state the proposition the rule asserts;
//  2. identify the evidence the detector actually observes;
//  3. construct a counterexample where that evidence exists and the proposition
//     is false, and run it;
//  4. construct the true positive the rule must keep, and run that too.
//
// Rules are corrected by their claim, never removed. The tests below are the
// counterexamples and true positives, run through the real analyzer.

// tokenBody generates a credential-shaped run at test time, so no
// credential-like literal appears in this file for a scanner to report.
func tokenBody(n int, alphabet string) string {
	var b strings.Builder
	x := uint32(2463534242)
	for i := 0; i < n; i++ {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b.WriteByte(alphabet[int(x)%len(alphabet)])
	}
	return b.String()
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func findingFor(fs []findings.Finding, id string) (findings.Finding, bool) {
	for i := range fs {
		if fs[i].RuleID == id {
			return fs[i], true
		}
	}
	return findings.Finding{}, false
}

// A resource identifier is not a credential. The rule still reports it -- a
// hard-coded identifier is a real, if minor, observation -- but as what it is:
// informational, CWE-1051, nothing to rotate.
func TestAudit_ResourceIdentifiersAreNotCredentials(t *testing.T) {
	arn := "arn:" + "aws:"
	cases := []struct{ id, file, src string }{
		{"SEC-413", "main.tf", `resource "aws_s3_bucket" "b" {}` + "\nurl = \"https://assets.s3" + ".amazonaws.com/logo.png\"\n"},
		{"SEC-414", "main.tf", `resource "aws_rds_cluster" "db" {}` + "\nsource = \"" + arn + "rds:eu-west-1:123456789012:cluster:db\"\n"},
		{"SEC-418", "gke.tf", "# gke\nname = \"projects/my-proj-123/locations/europe-west1/" + "clusters/prod\"\n"},
		{"SEC-419", "azure.tf", "azure_subscription_id = var.sub\nscope = \"/" + "subscriptions/0b1f6471-1bf0-4dda-aec3-111122223333/resourceGroups/rg\"\n"},
		{"SEC-420", "azure.tf", "azure_tenant_id = var.t\nauthority = \"https://login.example/" + "tenants/72f988bf-86f1-41af-91ab-2d7cd011db47\"\n"},
		{"SEC-422", "kv.tf", "azure_keyvault_uri = \"https://myvault.vault" + ".azure.net/\"\n"},
		{"SEC-425", "auth.py", "ms_oauth_authority = \"https://login." + "microsoftonline.com/common\"\n"},
		{"SEC-434", "app.properties", "# kafka\nbootstrap" + ".servers=broker1:9092\n"},
		{"SEC-465", "iam.tf", `resource "aws_iam_role" "r" {}` + "\nrole = \"" + arn + "iam::123456789012:role/deploy\"\n"},
		{"SEC-466", "sm.tf", `resource "aws_secretsmanager_secret" "s" {}` + "\nsecret = \"" + arn + "secretsmanager:eu-west-1:123456789012:secret:db-AbCdEf\"\n"},
		{"SEC-511", "ecs.tf", `resource "aws_ecs_service" "s" {}` + "\ntask = \"" + arn + "ecs:eu-west-1:123456789012:task-definition/web:3\"\n"},
		{"SEC-512", "fn.tf", `resource "aws_lambda_permission" "p" {}` + "\nfn = \"" + arn + "lambda:eu-west-1:123456789012:function:worker\"\n"},
		{"SEC-513", "s3.tf", `resource "aws_s3_bucket_policy" "p" {}` + "\nres = \"" + arn + "s3:::my-bucket/*\"\n"},
		{"SEC-514", "rds.tf", `resource "aws_rds_cluster" "c" {}` + "\ndb = \"" + arn + "rds:eu-west-1:123456789012:db:main\"\n"},
		{"SEC-515", "ec2.tf", `resource "aws_ec2_tag" "t" {}` + "\nid = \"" + arn + "ec2:eu-west-1:123456789012:instance/i-0123456789abcdef0\"\n"},
		{"SEC-517", "ddb.tf", `resource "aws_dynamodb_table" "t" {}` + "\ntable = \"" + arn + "dynamodb:eu-west-1:123456789012:table/orders\"\n"},
		{"SEC-518", "sqs.tf", `resource "aws_sqs_queue" "q" {}` + "\nqueue = \"" + arn + "sqs:eu-west-1:123456789012:jobs\"\n"},
		// SEC-519 matched a misspelt service segment and could never fire. Fixing
		// the spelling alone would have made this ordinary subscription a High
		// credential finding; it lands with the corrected claim instead.
		{"SEC-519", "sns.tf", `resource "aws_sns_topic_subscription" "s" {` + "\n  topic_arn = \"" + arn + "sns:us-east-1:123456789012:ops-alerts\"\n}\n"},
		{"SEC-532", "oci.py", "# oracle\nendpoint = \"https://objectstorage.eu-frankfurt-1.oraclecloud" + ".com/n/ns/b/bucket\"\n"},
		// The same claim, outside the 31 the deviance research listed: identifier
		// rules whose pattern contains `://`, which its family classifier filed
		// as URL credentials. Found by applying this audit's method to the class.
		{"SEC-372", "assets.py", "# s3\nLOGO = \"https://bucket.s3" + ".amazonaws.com/img/logo.png\"\n"},
		{"SEC-373", "sync.sh", "# s3_bucket\naws s3 sync ./dist s3" + "://my-site-bucket/releases\n"},
		{"SEC-374", "assets.py", "# gcs\nURL = \"https://storage." + "googleapis.com/my-bucket/data.csv\"\n"},
		{"SEC-375", "assets.py", "# azure_blob\nURL = \"https://acct.blob.core." + "windows.net/container/file.bin\"\n"},
		{"SEC-417", "load.py", "# gcp_bucket\nsrc = \"gs" + "://my-data-bucket/2026/10/\"\n"},
		{"SEC-461", "settings.py", "# amqp\nBROKER = \"amqp" + "://rabbit.internal:5672/vhost\"\n"},
		{"SEC-462", "settings.py", "# smtp\nMAIL = \"smtp" + "://mail.internal:587\"\n"},
		{"SEC-516", "iam.tf", "# aws_iam_role\nrole_arn = \"arn:" + "aws:iam::123456789012:role/deploy\"\n"},
		{"SEC-520", "gcp.py", "# gcp\nparent = \"projects/my-proj-123/" + "locations/europe-west1\"\n"},
		{"SEC-521", "gke.py", "# gcp_gke\nAPI = \"https://container.googleapis" + ".com/v1/projects/my-proj/zones/z/clusters\"\n"},
		{"SEC-522", "gcs.py", "# gcp_storage\nAPI = \"https://storage.googleapis" + ".com/storage/v1/b/my-bucket\"\n"},
		{"SEC-523", "azure.py", "# azure\nrid = \"/subscriptions/0b1f6471-1bf0-4dda-aec3-111122223333/" + "resourceGroups/rg/providers/x\"\n"},
		{"SEC-534", "bce.py", "# baidu\nEP = \"https://bj-core.baidu" + "cloud.com\"\n"},
		{"SEC-535", "jd.py", "# jd\nEP = \"https://vpc.jd" + "cloud.com\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			f, ok := findingFor(scanOne(t, tc.file, tc.src), tc.id)
			if !ok {
				t.Fatalf("%s did not report the identifier it describes:\n%s", tc.id, tc.src)
			}
			if f.Severity != findings.SeverityInfo {
				t.Errorf("%s severity = %s; an identifier is not a credential and is informational", tc.id, f.Severity)
			}
			if f.Metadata["cwe"] != "CWE-1051" {
				t.Errorf("%s cwe = %q, want CWE-1051 (hard-coded network resource identifier)", tc.id, f.Metadata["cwe"])
			}
			if strings.Contains(strings.ToLower(f.Message), "rotate") {
				t.Errorf("%s message tells the operator to rotate something that is not a secret: %q", tc.id, f.Message)
			}
		})
	}
}

// Identifier rules that matched a fragment which does not establish even the
// identifier -- any `clusters/`, `/subscriptions/`, `/tenants/`, or a bare
// `gs://`, `amqp://`, `smtp://` scheme near the keyword. They now require the
// identifier itself.
func TestAudit_IdentifierFragmentsNeedTheIdentifier(t *testing.T) {
	cases := []struct{ id, file, src string }{
		{"SEC-418", "notes.md", "# gke\nSee docs/" + "clusters/overview.md for the clusters/ layout.\n"},
		{"SEC-419", "client.py", "azure_sub = client.get(base + \"/" + "subscriptions/\" + sub_id)\n"},
		{"SEC-420", "client.py", "azure_tenant = client.get(base + \"/" + "tenants/\" + tenant_id)\n"},
		{"SEC-417", "doc.md", "# gcp_bucket\nPaths use the gs" + ":// scheme.\n"},
		{"SEC-461", "doc.md", "# amqp\nThe broker accepts amqp" + ":// URLs.\n"},
		{"SEC-462", "doc.md", "# smtp\nOnly smtp" + ":// is supported.\n"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if _, ok := findingFor(scanOne(t, tc.file, tc.src), tc.id); ok {
				t.Errorf("%s reported a path fragment with no identifier in it:\n%s", tc.id, tc.src)
			}
		})
	}
}

// A public key is public. Reported as informational, never as a credential.
func TestAudit_PublicKeysAreNotCredentials(t *testing.T) {
	cases := []struct{ id, file, src string }{
		{"SEC-463", "authorized_keys", "ssh-rsa " + "AAAAB3NzaC1yc2E" + tokenBody(200, alnum) + " deploy@ci\n"},
		{"SEC-464", "key.asc", "# gpg\n-----BEGIN PGP " + "PUBLIC KEY BLOCK-----\n\nmQENBF" + tokenBody(60, alnum) + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			f, ok := findingFor(scanOne(t, tc.file, tc.src), tc.id)
			if !ok {
				t.Fatalf("%s did not report the public key", tc.id)
			}
			if f.Severity != findings.SeverityInfo || f.Metadata["cwe"] == "CWE-798" {
				t.Errorf("%s = %s/%s; a public key is not a hard-coded credential", tc.id, f.Severity, f.Metadata["cwe"])
			}
		})
	}
}

// A format prefix alone is not a credential: validation code checks prefixes
// all the time. The rule must need the credential body, and must find a real
// token in a file that never mentions the invented keyword it used to require.
func TestAudit_PrefixRulesNeedTheCredentialBody(t *testing.T) {
	cases := []struct {
		id, counter, real string
		// sibling: another rule already owns this format and dedup may give it
		// the span; the token must still be reported, by one of them.
		siblings []string
	}{
		{"SEC-436", `if token.startswith("glpat-"):` + "\n    kind = \"gitlab\"\n",
			"GITLAB_TOKEN = \"glpat-" + tokenBody(20, alnum) + "\"\n", []string{"SEC-018", "SEC-132", "SEC-225"}},
		{"SEC-438", `if key.startswith("sk_live_"):` + "\n    mode = \"stripe live\"\n",
			"STRIPE_KEY = \"sk_" + "live_" + tokenBody(24, alnum) + "\"\n", []string{"SEC-338", "SEC-030"}},
		{"SEC-439", `if key.startswith("SG.")` + ": # sendgrid\n    pass\n",
			"SENDGRID = \"SG." + tokenBody(22, alnum) + "." + tokenBody(43, alnum) + "\"\n", []string{"SEC-058", "SEC-153", "SEC-309"}},
		{"SEC-423", `if tok.startswith("ya29."):` + "\n    provider = \"google\"\n",
			"access_token = \"ya29." + tokenBody(120, alnum+"-_") + "\"\n", nil},
		{"SEC-424", "PREFIX = \"EAACEdEose0cBA\"  # facebook token prefix\n",
			"fb_token = \"EAACEdEose0cBA" + tokenBody(150, alnum) + "\"\n", nil},
		{"SEC-170", "PREFIX = \"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t\"\n",
			"AWS_BEARER_TOKEN_BEDROCK=bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t" + tokenBody(80, alnum) + "\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if _, ok := findingFor(scanOne(t, "check.py", tc.counter), tc.id); ok {
				t.Errorf("%s reported a bare format prefix with no credential:\n%s", tc.id, tc.counter)
			}
			fs := scanOne(t, "config.py", tc.real)
			owners := append([]string{tc.id}, tc.siblings...)
			found := false
			for _, id := range owners {
				if _, ok := findingFor(fs, id); ok {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: a real token was reported by none of %v; findings: %s", tc.id, owners, ruleIDs(fs))
			}
			if tc.siblings == nil {
				if _, ok := findingFor(fs, tc.id); !ok {
					t.Errorf("%s is the only rule for this format and did not report a real token: %s", tc.id, ruleIDs(fs))
				}
			}
		})
	}
}

// Name-only rules matched a key or variable name with no value behind it.
func TestAudit_NameOnlyRulesNeedTheValue(t *testing.T) {
	val := tokenBody(32, alnum)
	cases := []struct {
		id, file      string
		counters      []string
		real          string
		informational bool
	}{
		{"SEC-469", ".env", []string{
			"TOKEN=\n",
			"API_KEY=${API_KEY}\n",
			"SECRET=$SECRET_FROM_VAULT\n",
			"API_KEY=your-api-key-here\n",
		}, "API_KEY=" + val + "\n", false},
		{"SEC-410", "login.sh", []string{
			"docker login -u _json_key -p \"$(cat key.json)\" https://gcr.io\n",
			"docker login -u _json_key --password-stdin https://gcr.io < key.json\n",
		}, "docker login -u _json_key -p '{\"type\": \"service_" + "account\", \"project_id\": \"p\"}' https://gcr.io\n", false},
		{"SEC-416", "sa.tf", []string{
			"service_account = google_service_account.app.email\n",
		}, "service_account = \"deployer@my-project-123.iam." + "gserviceaccount.com\"\n", true},
		{"SEC-468", "setup.sh", []string{
			"kubectl create secret generic db --from-file=./password.txt\n",
			"kubectl create secret generic db --from-literal=password=$DB_PASSWORD\n",
			"kubectl create secret generic db --from-literal=password=changeme\n",
		}, "kubectl create secret generic db --from-literal=password=" + val + "\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			for _, c := range tc.counters {
				if _, ok := findingFor(scanOne(t, tc.file, c), tc.id); ok {
					t.Errorf("%s reported a name with no value:\n%s", tc.id, c)
				}
			}
			f, ok := findingFor(scanOne(t, tc.file, tc.real), tc.id)
			if !ok {
				t.Fatalf("%s did not report the value it exists for:\n%s", tc.id, tc.real)
			}
			if tc.informational && f.Severity != findings.SeverityInfo {
				t.Errorf("%s severity = %s; an identifier is informational", tc.id, f.Severity)
			}
			if !tc.informational && f.Severity == findings.SeverityInfo {
				t.Errorf("%s reports a real credential as informational", tc.id)
			}
		})
	}
}

// The identifier remediation promises that a credential embedded in a URL is
// reported separately. For AMQP and SMTP URLs it was not: SEC-085 matched
// http(s) only. Found by reading the corpus A/B -- agent-go's
// `amqp://guest:guest@localhost` had been reported as a High "AMQP Connection
// URL" credential by SEC-461, and the corrected identifier claim would have
// called it "not a credential". The promise is made true rather than reworded.
func TestAudit_CredentialsInBrokerURLsAreStillCredentials(t *testing.T) {
	pass := tokenBody(16, alnum)
	for _, tc := range []struct{ file, src string }{
		{"queue.py", "# amqp\nBROKER = \"amqp" + "://svc:" + pass + "@rabbit.internal:5672/vhost\"\n"},
		{"mail.py", "# smtp\nMAIL = \"smtp" + "://mailer:" + pass + "@mail.internal:587\"\n"},
	} {
		fs := scanOne(t, tc.file, tc.src)
		f, ok := findingFor(fs, "SEC-085")
		if !ok {
			t.Errorf("%s: a password in the URL was not reported as a credential: [%s]", tc.file, ruleIDs(fs))
			continue
		}
		if f.Severity == findings.SeverityInfo {
			t.Errorf("%s: an embedded password reported as informational", tc.file)
		}
		for _, id := range []string{"SEC-461", "SEC-462"} {
			if _, ok := findingFor(fs, id); ok {
				t.Errorf("%s: %s, the informational identifier rule, also claimed a URL that carries a credential", tc.file, id)
			}
		}
	}
}

// Counterexamples the corpus supplied for the bound rules.
func TestAudit_BoundRulesIgnorePlaceholders(t *testing.T) {
	for _, tc := range []struct{ id, file, src string }{
		// vcrpy-style scrubbing writes FILTERED where the token was.
		{"SEC-423", "cassette.py", "body = '{\"access_token\": \"ya29.FILTERED_ACCESS_TOKEN_VALUE\"}'\n"},
		{"SEC-469", ".env.example", "LLM_API_KEY=gsk_1234567890\n"},
		{"SEC-469", "nb.py", "%env OPENAI_API_KEY=OPENAI_API_KEY\n"},
	} {
		if fs := scanOne(t, tc.file, tc.src); firedRule(fs, tc.id) {
			t.Errorf("%s reported a placeholder:\n%s", tc.id, tc.src)
		}
	}
}

// SEC-469 reports the line the variable is on, not the one before it.
func TestAudit_EnvSecretIsOnItsOwnLine(t *testing.T) {
	src := "export HOST=\"https://example.invalid\"\nexport DATABRICKS_TOKEN=\"" + tokenBody(32, alnum) + "\"\n"
	f, ok := findingFor(scanOne(t, "setup.sh", src), "SEC-469")
	if !ok {
		t.Fatal("SEC-469 did not report the token")
	}
	if f.Location.StartLine != 2 {
		t.Errorf("SEC-469 reported line %d; the token is on line 2", f.Location.StartLine)
	}
}
