package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// Serverless rule count
// ---------------------------------------------------------------------------

func TestServerlessRules_Count(t *testing.T) {
	rules := builtinServerlessRules()
	if got := len(rules); got != 20 {
		t.Errorf("expected 20 Serverless rules, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// IAC-246: IAM wildcard action (Action: '*')
// ---------------------------------------------------------------------------

func TestDetect_ServerlessIAMWildcardAction(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`service: my-service
provider:
  name: aws
  iamRoleStatements:
    - Effect: Allow
      Action: '*'
      Resource: arn:aws:s3:::my-bucket
`)

	results, err := a.ScanFile("serverless.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-246" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-246 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-248: Excessive timeout (>900s)
// ---------------------------------------------------------------------------

func TestDetect_ServerlessExcessiveTimeout(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)timeout:\s*(?:9[0-9][0-9]|[0-9]{4,})
	// 900 matches 9[0-9][0-9], 1000 matches [0-9]{4,}
	content := []byte(`service: my-service
provider:
  name: aws
functions:
  longRunner:
    handler: handler.run
    timeout: 900
`)

	results, err := a.ScanFile("serverless.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-248" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-248 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-250: HTTP endpoint (verify authorization)
// ---------------------------------------------------------------------------

func TestDetect_ServerlessHTTPEndpoint(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)-\s*http:\s*\n\s*path:
	content := []byte(`service: my-service
provider:
  name: aws
functions:
  api:
    handler: handler.api
    events:
      - http:
          path: /users
          method: get
`)

	results, err := a.ScanFile("serverless.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-250" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-250 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-254: Hardcoded secret in environment variable
// ---------------------------------------------------------------------------

func TestDetect_ServerlessHardcodedSecret(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)(?:PASSWORD|SECRET_KEY|API_KEY|DB_PASSWORD)\s*:\s*['"]?[A-Za-z0-9]
	// Keywords: ["environment", "PASSWORD", "SECRET"] -- "environment" is lowercase.
	content := []byte(`service: my-service
provider:
  name: aws
  environment:
    DB_PASSWORD: supersecret123
    SECRET_KEY: mykey456
`)

	results, err := a.ScanFile("serverless.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-254" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-254 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-263: Hardcoded production stage
// ---------------------------------------------------------------------------

func TestDetect_ServerlessHardcodedProdStage(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)stage:\s*['"]?prod
	// Keywords: ["stage", "prod"] -- all lowercase, passes keyword filter.
	content := []byte(`service: my-service
provider:
  name: aws
  stage: production
`)

	results, err := a.ScanFile("serverless.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-263" {
			found = true
			if f.Severity != findings.SeverityLow {
				t.Errorf("expected severity low, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-263 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-247: IAM wildcard resource
// ---------------------------------------------------------------------------

func TestDetect_ServerlessIAMWildcardResource(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`service: my-service
provider:
  name: aws
  iamRoleStatements:
    - Effect: Allow
      Action:
        - s3:GetObject
      Resource: '*'
`)

	results, err := a.ScanFile("serverless.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-247" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-247 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-251: CORS enabled for all origins
// ---------------------------------------------------------------------------

func TestDetect_ServerlessCORSAllOrigins(t *testing.T) {
	a := NewAnalyzer()
	// Keywords: ["cors"] -- all lowercase, passes keyword filter.
	content := []byte(`service: my-service
functions:
  api:
    handler: handler.api
    events:
      - http:
          path: /data
          method: get
          cors: true
`)

	results, err := a.ScanFile("serverless.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-251" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-251 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-257: Deprecated runtime
// ---------------------------------------------------------------------------

func TestDetect_ServerlessDeprecatedRuntime(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)runtime:\s*['"]?(?:python2|nodejs[0-9]|ruby2\.5|dotnetcore2)
	// Keywords: ["runtime", "deprecated"] -- "runtime" is lowercase, passes filter.
	content := []byte(`service: my-service
provider:
  name: aws
  runtime: nodejs8
`)

	results, err := a.ScanFile("serverless.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-257" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-257 to be detected")
	}
}

// ---------------------------------------------------------------------------
// No false positives on clean Serverless content
// ---------------------------------------------------------------------------

func TestNoFalsePositives_CleanServerless(t *testing.T) {
	a := NewAnalyzer()
	// Use runtime: provided (not matching deprecated pattern nodejs[0-9])
	// Avoid any patterns that would match serverless rules.
	content := []byte(`service: my-service
provider:
  name: aws
  runtime: provided.al2023
  stage: ${opt:stage, 'dev'}
functions:
  hello:
    handler: handler.hello
    timeout: 30
    memorySize: 256
`)

	results, err := a.ScanFile("serverless.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Filter to only Serverless rules (IAC-246 to IAC-265).
	for _, f := range results {
		if f.RuleID >= "IAC-246" && f.RuleID <= "IAC-265" {
			t.Errorf("unexpected Serverless finding %s on clean content", f.RuleID)
		}
	}
}
