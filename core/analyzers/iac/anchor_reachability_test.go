package iac

import (
	"regexp"
	"strings"
	"testing"
)

// A rule anchored with `$` and no `(?m)` can only fire on the last line of a
// file.
//
// Go's regexp treats `$` as end of TEXT unless the multi-line flag is set, and
// rule patterns are compiled with a bare regexp.Compile against whole-file
// content (core/rules/matcher.go). IAC-031, "Container image uses latest tag
// in Kubernetes manifest", shipped as
//
//	(?i)image\s*:\s*["']?[a-zA-Z0-9._/-]+:latest["']?\s*$
//
// so it matched a manifest only where the image line happened to be the last
// line in it. Measured 2026-09-12 across every YAML file in the rule-diff
// corpus it fired ZERO times, while kubernetes/examples carried
// `image: mysql:latest` and `image: minio/minio:latest` twice, unreported —
// three real findings from a rule that was in the catalogue, in the rule
// count, and in the documentation the whole time.
//
// This is the same class as entropy_reachability_test.go: not a rule that is
// wrong, a rule that cannot fire. Nothing in a per-rule fixture catches it,
// because a fixture written to exercise one pattern tends to put the
// interesting line last.

// TestIAC031FiresWhenTheImageLineIsNotLast is the measured case. The trailing
// lines are the whole test: with the shipped anchor this manifest produces no
// IAC-031 at all, and moving the image line to the end makes it pass against
// the unfixed code.
func TestIAC031FiresWhenTheImageLineIsNotLast(t *testing.T) {
	const manifest = `apiVersion: v1
kind: Pod
metadata:
  name: mysql
spec:
  containers:
    - name: mysql
      image: mysql:latest
      env:
        - name: MYSQL_ROOT_PASSWORD
          value: rootpw
      ports:
        - containerPort: 3306
`
	if ids := scanIDs(t, "mysql-pod.yaml", manifest); !contains(ids, "IAC-031") {
		t.Errorf("IAC-031 did not report `image: mysql:latest` because the line is "+
			"not the last in the file; got %v", ids)
	}
}

// TestIAC031IsAnchoredPerLine states the defect directly rather than through
// its symptom, so a later edit that drops the flag fails here with the reason
// attached instead of silently taking the rule off the air again.
func TestIAC031IsAnchoredPerLine(t *testing.T) {
	r, ok := NewAnalyzer().Rules().ByID("IAC-031")
	if !ok {
		t.Fatal("IAC-031 not found")
	}
	if !strings.HasSuffix(r.Pattern, "$") {
		return // No end anchor, nothing to require.
	}
	re := regexp.MustCompile(`^\(\?[a-z]*m[a-z]*\)`)
	if !re.MatchString(r.Pattern) {
		t.Errorf("IAC-031 ends in `$` but is not compiled multi-line, so it can only "+
			"match on the last line of a file: %s", r.Pattern)
	}
}

// TestNoIaCRuleIsAnchoredToEndOfText is the general form, and it is absolute:
// every `$` in the IaC catalogue is now per-line.
//
// Eight rules carried the defect. Seven are fixed here and in the preceding
// commit; the eighth, MCP-008, is in the AI analyzer, has no test of any kind,
// and the corpus contains no MCP server, so fixing it would be unmeasurable —
// it is named in the commit message instead of being changed unwitnessed.
//
// A per-rule fixture cannot replace this. The defect is invisible in a fixture
// written to exercise one pattern, because such a fixture tends to end with the
// interesting line; only asking the whole catalogue the question finds them.
func TestNoIaCRuleIsAnchoredToEndOfText(t *testing.T) {
	multiline := regexp.MustCompile(`\(\?[a-zA-Z]*m[a-zA-Z]*\)`)
	for _, r := range NewAnalyzer().Rules().Rules() {
		p := r.Pattern
		if p == "" || !strings.HasSuffix(p, "$") || strings.HasSuffix(p, `\$`) {
			continue
		}
		if !multiline.MatchString(p) {
			t.Errorf("%s ends in `$` without (?m), so it can only match on the last "+
				"line of a file: %s", r.ID, p)
		}
	}
}

// TestTheFourMechanicalAnchorsFire. Each fixture carries content AFTER the line
// the rule is about, which is the whole test: with the shipped anchor every one
// of these produces nothing.
func TestTheFourMechanicalAnchorsFire(t *testing.T) {
	const compose = `services:
  web:
    image: nginx:1.25
    user: root
    ports:
      - "8080:80"
`
	// The Serverless fixtures must declare service/provider or the document-kind
	// gate correctly refuses them before the anchor is ever consulted.
	const serverless = `service: my-api
provider:
  name: aws
  runtime: nodejs18.x
  apiKeys:
    - myKey
functions:
  hello:
    handler: handler.hello
    onError:
    kmsKeyArn:
    events:
      - http: GET /hello
`
	for _, tc := range []struct{ rule, path, body string }{
		{"IAC-184", "docker-compose.yml", compose},
		{"IAC-260", "serverless.yml", serverless},
		{"IAC-261", "serverless.yml", serverless},
		{"IAC-262", "serverless.yml", serverless},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			if ids := scanIDs(t, tc.path, tc.body); !contains(ids, tc.rule) {
				t.Errorf("%s did not fire on a document that declares exactly what it "+
					"describes, because the line is not the file's last; got %v", tc.rule, ids)
			}
		})
	}
}
