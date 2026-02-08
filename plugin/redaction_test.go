package plugin

import (
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

func TestRedactor_AWSAccessKey(t *testing.T) {
	r := NewRedactor()
	input := "Found key AKIAIOSFODNN7EXAMPLE in config"
	got, redacted := r.redactString(input)
	if !redacted {
		t.Error("expected redaction for AWS access key")
	}
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key should be redacted, got %q", got)
	}
	if !strings.Contains(got, redactedPlaceholder) {
		t.Errorf("should contain placeholder, got %q", got)
	}
}

func TestRedactor_AWSSecretKey(t *testing.T) {
	r := NewRedactor()
	input := "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY0"
	got, redacted := r.redactString(input)
	if !redacted {
		t.Error("expected redaction for AWS secret key")
	}
	if strings.Contains(got, "wJalrXUtnFEMI") {
		t.Errorf("AWS secret should be redacted, got %q", got)
	}
}

func TestRedactor_GitHubToken(t *testing.T) {
	r := NewRedactor()
	input := "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
	got, redacted := r.redactString(input)
	if !redacted {
		t.Error("expected redaction for GitHub token")
	}
	if strings.Contains(got, "ghp_") {
		t.Errorf("GitHub token should be redacted, got %q", got)
	}
}

func TestRedactor_PrivateKey(t *testing.T) {
	r := NewRedactor()
	input := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
	got, redacted := r.redactString(input)
	if !redacted {
		t.Error("expected redaction for private key")
	}
	if strings.Contains(got, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("private key header should be redacted, got %q", got)
	}
}

func TestRedactor_GenericAPIKey(t *testing.T) {
	r := NewRedactor()
	input := `api_key = "sk1234567890abcdef"`
	got, redacted := r.redactString(input)
	if !redacted {
		t.Error("expected redaction for generic API key")
	}
	if strings.Contains(got, "sk1234567890abcdef") {
		t.Errorf("API key should be redacted, got %q", got)
	}
}

func TestRedactor_CleanText(t *testing.T) {
	r := NewRedactor()
	input := "This is a normal log message with no secrets"
	got, redacted := r.redactString(input)
	if redacted {
		t.Error("clean text should not be redacted")
	}
	if got != input {
		t.Errorf("clean text should be unchanged, got %q", got)
	}
}

func TestRedactor_NilResponse(t *testing.T) {
	r := NewRedactor()
	got, redacted := r.RedactResponse(nil)
	if got != nil {
		t.Error("nil response should return nil")
	}
	if redacted {
		t.Error("nil response should return false")
	}
}

func TestRedactor_FullResponse(t *testing.T) {
	r := NewRedactor()
	resp := &pluginv1.InvokeToolResponse{
		Findings: []*pluginv1.Finding{
			{
				Id:       "f-1",
				RuleId:   "SEC-001",
				Severity: pluginv1.Severity_SEVERITY_HIGH,
				Message:  "Found AKIAIOSFODNN7EXAMPLE in source",
				Metadata: map[string]string{
					"clean": "normal value",
					"leak":  "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl",
				},
				Fingerprint: "fp-keep-this",
			},
			{
				Id:      "f-2",
				Message: "Clean finding with no secrets",
			},
		},
		Packages: []*pluginv1.Package{
			{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
		},
		AiComponents: []*pluginv1.AIComponent{
			{
				Name: "agent",
				Type: "agent",
				Path: "agents/main.yaml",
				Details: map[string]string{
					"secret": "-----BEGIN PRIVATE KEY-----",
					"safe":   "just a description",
				},
			},
		},
		Diagnostics: []*pluginv1.Diagnostic{
			{
				Severity: pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING,
				Message:  `Found api-key = "abcdef1234567890abcd" in output`,
				Source:   "test-plugin",
			},
		},
	}

	out, redacted := r.RedactResponse(resp)
	if !redacted {
		t.Error("response with secrets should be flagged as redacted")
	}

	// Finding message should be redacted.
	if strings.Contains(out.GetFindings()[0].GetMessage(), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS key in finding message should be redacted")
	}
	if !strings.Contains(out.GetFindings()[0].GetMessage(), redactedPlaceholder) {
		t.Error("finding message should contain placeholder")
	}

	// Finding metadata value should be redacted.
	if strings.Contains(out.GetFindings()[0].GetMetadata()["leak"], "ghp_") {
		t.Error("GitHub token in metadata should be redacted")
	}
	if out.GetFindings()[0].GetMetadata()["clean"] != "normal value" {
		t.Error("clean metadata should be unchanged")
	}

	// Fingerprint should be preserved.
	if out.GetFindings()[0].GetFingerprint() != "fp-keep-this" {
		t.Errorf("fingerprint should be preserved, got %q", out.GetFindings()[0].GetFingerprint())
	}

	// Clean finding should be unchanged.
	if out.GetFindings()[1].GetMessage() != "Clean finding with no secrets" {
		t.Errorf("clean finding message changed: %q", out.GetFindings()[1].GetMessage())
	}

	// Packages should be passed through.
	if len(out.GetPackages()) != 1 || out.GetPackages()[0].GetName() != "express" {
		t.Error("packages should be passed through unchanged")
	}

	// AI component detail should be redacted.
	if strings.Contains(out.GetAiComponents()[0].GetDetails()["secret"], "BEGIN PRIVATE KEY") {
		t.Error("private key in AI component detail should be redacted")
	}
	if out.GetAiComponents()[0].GetDetails()["safe"] != "just a description" {
		t.Error("safe AI component detail should be unchanged")
	}

	// Diagnostic message should be redacted.
	if strings.Contains(out.GetDiagnostics()[0].GetMessage(), "abcdef1234567890abcd") {
		t.Error("API key in diagnostic should be redacted")
	}
}

func TestRedactor_EmptyResponse(t *testing.T) {
	r := NewRedactor()
	resp := &pluginv1.InvokeToolResponse{}
	out, redacted := r.RedactResponse(resp)
	if redacted {
		t.Error("empty response should not be flagged as redacted")
	}
	if out == nil {
		t.Error("empty response should return non-nil")
	}
}
