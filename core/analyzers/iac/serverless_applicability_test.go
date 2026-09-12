package iac

import (
	"strings"
	"testing"
)

// A filename is a discovery hint. It is not evidence that a rule applies.
//
// builtinServerlessRules scoped its whole family with
//
//	{"serverless.yml", "serverless.yaml", "serverless.ts", "*.yml", "*.yaml"}
//
// where the last two entries make the first three meaningless: every Serverless
// Framework rule applied to every YAML file in any repository. Measured
// 2026-09-12 on MacPaw/OpenAI@0.5.1, a Swift package: IAC-254 ("Serverless
// environment variable with hardcoded secret", CRITICAL) fired 268 times on
// openapi.yaml, matching Ruby documentation samples of the form
//
//	openai = OpenAI::Client.new(api_key: "My API Key")
//
// and advising the reader to use ${ssm:/path/to/secret} in a file that has no
// such concept.
//
// The fix is structural and applies to the family at once: a Serverless rule
// fires only where the document IS a Serverless Framework manifest, decided by
// parsing it rather than by reading its name.

const serverlessManifest = `service: my-api
provider:
  name: aws
  runtime: nodejs18.x
  environment:
    API_KEY: "hardcoded-value-123"
functions:
  hello:
    handler: handler.hello
`

// openapiSpec is the shape that produced the 268 findings: a YAML file that is
// not a Serverless manifest and contains a credential-shaped documentation
// sample.
// The word "environment" in the description is load-bearing and is why this
// fixture reproduces where an earlier one did not. IAC-254's keywords
// ("environment", "PASSWORD", "SECRET") gate at FILE level, so a single
// occurrence anywhere in a 2.8MB specification makes every `api_key:` in it
// eligible. Three independent things had to line up for the 268 findings:
// the *.yaml catch-all, the file-level keyword, and the pattern.
const openapiSpec = `openapi: 3.0.0
info:
  title: OpenAI API
  version: 2.3.0
  description: Works in any environment
paths:
  /assistants:
    get:
      x-codeSamples:
        - lang: ruby
          ruby: |-
            require "openai"

            openai = OpenAI::Client.new(api_key: "My API Key")

            page = openai.beta.assistants.list
`

func scanIDs(t *testing.T, path, body string) []string {
	t.Helper()
	a := NewAnalyzer()
	fs, err := a.ScanFile(path, []byte(body))
	if err != nil {
		t.Fatalf("ScanFile(%s): %v", path, err)
	}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestAServerlessRuleFiresOnAServerlessManifest guards the recall direction. A
// structural gate that excludes everything is not a fix.
func TestAServerlessRuleFiresOnAServerlessManifest(t *testing.T) {
	ids := scanIDs(t, "serverless.yml", serverlessManifest)
	if !contains(ids, "IAC-254") {
		t.Errorf("IAC-254 did not fire on a real Serverless manifest with a hardcoded "+
			"environment secret; got %v", ids)
	}
}

// TestAServerlessRuleDoesNotFireOnAnOpenAPISpec is the measured case.
func TestAServerlessRuleDoesNotFireOnAnOpenAPISpec(t *testing.T) {
	ids := scanIDs(t, "openapi.yaml", openapiSpec)
	for _, id := range ids {
		if strings.HasPrefix(id, "IAC-") && isServerlessRuleID(t, id) {
			t.Errorf("%s is a Serverless Framework rule and fired on an OpenAPI spec; "+
				"the filename was treated as evidence that the rule applies", id)
		}
	}
}

// TestTheNameAloneDoesNotMakeItAServerlessManifest. The instruction is that a
// filename is a discovery hint, so the gate must hold even for the name the
// family is built around: a file called serverless.yml that is not one gets no
// Serverless findings.
func TestTheNameAloneDoesNotMakeItAServerlessManifest(t *testing.T) {
	ids := scanIDs(t, "serverless.yml", openapiSpec)
	for _, id := range ids {
		if isServerlessRuleID(t, id) {
			t.Errorf("%s fired on a file named serverless.yml whose content is an "+
				"OpenAPI spec; the name decided applicability", id)
		}
	}
}

// TestTheWholeFamilyIsGatedAtOnce. The point of a structural fix is that it is
// not per-rule: a Serverless rule added tomorrow inherits it.
func TestTheWholeFamilyIsGatedAtOnce(t *testing.T) {
	a := NewAnalyzer()
	var family int
	for _, r := range a.Rules().Rules() {
		for _, tag := range r.Tags {
			if tag == "serverless" {
				family++
			}
		}
	}
	if family < 5 {
		t.Fatalf("expected a Serverless rule family, found %d rules tagged serverless", family)
	}
	// Not one of them may fire on a document that is not a Serverless manifest.
	ids := scanIDs(t, "docker-compose.yml", "version: '3'\nservices:\n  api:\n    environment:\n      API_KEY: \"abc123\"\n")
	for _, id := range ids {
		if isServerlessRuleID(t, id) {
			t.Errorf("%s fired on a docker-compose file", id)
		}
	}
}

// isServerlessRuleID reports whether a rule ID belongs to the Serverless family.
func isServerlessRuleID(t *testing.T, id string) bool {
	t.Helper()
	r, ok := NewAnalyzer().Rules().ByID(id)
	if !ok {
		return false
	}
	for _, tag := range r.Tags {
		if tag == "serverless" {
			return true
		}
	}
	return false
}
