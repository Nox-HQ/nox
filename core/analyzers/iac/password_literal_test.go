package iac

import "testing"

// IAC-225 required the password value to be QUOTED, and that was the whole gap.
//
// Measured on geerlingguy/ansible-for-devops when it joined the corpus:
// `MYSQL_ROOT_PASSWORD: root` and `MYSQL_PASSWORD: flask` in a docker_container
// env block were reported by nothing once the Serverless family stopped
// applying to every YAML file (#636) — IAC-351 is scoped to CI files, and this
// rule wanted a quote. YAML does not require one, and an unquoted password is
// not less hardcoded for it.
//
// Every line below was measured before it was written. The negatives are not
// hypothetical: each one is a false positive the first attempt produced.

const passwordFixture = `- name: db
  docker_container:
    env:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_PASSWORD: flask
      QUOTED_PASSWORD: "hunter2"
      VAULTED_PASSWORD: "{{ vault_db_password }}"
      TEMPLATED_PASSWORD: {{ inline_var }}
      ENV_PASSWORD: $DB_PASSWORD
      EMPTY_PASSWORD: ""
      OMITTED_PASSWORD: omit
      BOOL_PASSWORD: false
      NULL_PASSWORD: null
      password_file: /etc/mysql/pw
`

// TestIAC225ReportsLiteralsAndNothingElse is both directions in one document:
// three literal passwords and nine values that are not one.
func TestIAC225ReportsLiteralsAndNothingElse(t *testing.T) {
	var lines []int
	a := NewAnalyzer()
	fs, err := a.ScanFile("playbook.yml", []byte(passwordFixture))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	for _, f := range fs {
		if f.RuleID == "IAC-225" {
			lines = append(lines, f.Location.StartLine)
		}
	}
	want := map[int]string{4: "unquoted", 5: "unquoted", 6: "quoted"}
	for _, got := range lines {
		if _, ok := want[got]; !ok {
			t.Errorf("IAC-225 fired on line %d, which carries no literal password", got)
		}
		delete(want, got)
	}
	for line, kind := range want {
		t.Errorf("IAC-225 missed the %s password on line %d", kind, line)
	}
}

// TestAValueOnTheNextLineIsNotThisKeysValue. `\s*` crosses newlines and the
// engine matches whole-file content, so the first attempt read
// `DomainJoinUserPassword:` in a CloudFormation template and took whatever the
// NEXT line began with as its value. IAC-351 carries the same note for the same
// reason; `[ \t]*` is what fixes it.
func TestAValueOnTheNextLineIsNotThisKeysValue(t *testing.T) {
	const split = `Parameters:
  DomainJoinUserPassword:
    Type: String
    NoEcho: true
`
	if n := countRule(t, "template.yaml", split, "IAC-225"); n != 0 {
		t.Errorf("IAC-225 fired %d times on a key whose value is on another line", n)
	}
}

// TestPasswordInsideALongerTokenIsNotAKey. Unanchored, `password` matched
// inside CloudFormation's dynamic reference —
// `'{{resolve:secretsmanager:…-password:SecretString:…}}'` — which is the
// CORRECT way to avoid hardcoding one. The rule read `password:` out of the
// secret's NAME and `SecretString` as its value. Anchoring to the start of a
// line makes the match a YAML mapping key, which is the only thing the rule is
// about.
func TestPasswordInsideALongerTokenIsNotAKey(t *testing.T) {
	const dynamic = `Resources:
  Instance:
    Properties:
      Password: '{{resolve:secretsmanager:aurora-source-endpoint-password:SecretString:password}}'
`
	if n := countRule(t, "template.yaml", dynamic, "IAC-225"); n != 0 {
		t.Errorf("IAC-225 fired %d times on a Secrets Manager dynamic reference, which "+
			"is the fix for this finding rather than an instance of it", n)
	}
}

// TestPasswordValueIsLiteral states the keyword list directly. A charset cannot
// exclude these — `omit` and `false` are made of exactly the characters a
// password is made of — so the decision is in Go where the list is readable.
func TestPasswordValueIsLiteral(t *testing.T) {
	for _, tc := range []struct {
		match string
		want  bool
	}{
		{"PASSWORD: root", true},
		{`PASSWORD: "hunter2"`, true},
		{"password: s3cr3t", true},
		{"password: omit", false},
		{"password: false", false},
		{"password: NULL", false},
		{"password: ~", false},
		{"password: absent", false},
		{`password: ""`, false},
		{"password:", false},
	} {
		if got := passwordValueIsLiteral(tc.match); got != tc.want {
			t.Errorf("passwordValueIsLiteral(%q) = %v, want %v", tc.match, got, tc.want)
		}
	}
}

// TestIAC225IsNotNamedForAFormatItDoesNotDetect. The rule's subject is a YAML
// mapping key with a literal value, which is not an Ansible concept — the
// measurement found real hits in Kubernetes Secrets and a Cassandra config.
// Calling those "Ansible variable with hardcoded password" is the wrong-family
// reporting #636 and #637 exist to remove.
func TestIAC225IsNotNamedForAFormatItDoesNotDetect(t *testing.T) {
	r, ok := NewAnalyzer().Rules().ByID("IAC-225")
	if !ok {
		t.Fatal("IAC-225 not found")
	}
	for _, tag := range r.Tags {
		if documentFormatTags[tag] {
			t.Errorf("IAC-225 claims the %q document format, but it fires on Kubernetes "+
				"Secrets and Cassandra configs too", tag)
		}
	}
	if want := "Hardcoded password in a YAML configuration value"; r.Description != want {
		t.Errorf("description is %q, want %q", r.Description, want)
	}
}

// TestIAC225StillFiresOnAKubernetesSecret is the recall case the rename is
// about: a base64 CHAP password in a Secret was reported by nothing before.
// Base64 is an encoding, not encryption.
func TestIAC225StillFiresOnAKubernetesSecret(t *testing.T) {
	const secret = `apiVersion: v1
kind: Secret
metadata:
  name: chap-secret
type: kubernetes.io/iscsi-chap
data:
  discovery.sendtargets.auth.username: ZGVtbw==
  discovery.sendtargets.auth.password: ZGVtbw==
`
	if n := countRule(t, "chap-secret.yaml", secret, "IAC-225"); n != 1 {
		t.Errorf("IAC-225 fired %d times on an iSCSI CHAP secret; want 1 — the password "+
			"key, not the username", n)
	}
}
