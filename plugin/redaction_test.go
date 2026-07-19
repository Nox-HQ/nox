package plugin

import (
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
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

// TestRedactResponse_PreservesEnrichmentsAndGraphs is the regression test for
// silent data loss.
//
// RedactResponse rebuilds the response rather than mutating it, and it copied
// findings, packages, AI components and diagnostics — but not enrichments or
// graphs. Every enrichment and graph a plugin produced was therefore discarded
// on the main scan path, with no error: reachability annotations and call
// graphs simply never arrived. The post-scan path masked it by bypassing
// redaction entirely, which is why the loss was invisible.
//
// Any field added to InvokeToolResponse needs a case here, or it will be
// dropped the same way.
func TestRedactResponse_PreservesEnrichmentsAndGraphs(t *testing.T) {
	t.Parallel()

	resp := &pluginv1.InvokeToolResponse{
		Enrichments: []*pluginv1.Enrichment{{
			FindingFingerprint: "fp-1",
			Kind:               "reachability",
			Title:              "Reachable from main",
			Body:               "call path: main -> handler -> sink",
			Confidence:         pluginv1.Confidence_CONFIDENCE_HIGH,
			Source:             "nox/reachability",
			Metadata:           map[string]string{"depth": "3"},
		}},
		Graphs: []*pluginv1.Graph{{
			Name:        "call-graph",
			Description: "static call graph",
			Nodes: []*pluginv1.GraphNode{{
				Id: "fn-a", Kind: pluginv1.NodeKind_NODE_KIND_FUNCTION,
				Label: "funcA", FilePath: "app/a.go",
				Properties: map[string]string{"pkg": "app"},
			}},
			Edges: []*pluginv1.GraphEdge{{
				Source: "fn-a", Target: "fn-b",
				Kind: pluginv1.EdgeKind_EDGE_KIND_CALLS, Label: "calls",
				Properties: map[string]string{"line": "42"},
			}},
		}},
	}

	out, _ := NewRedactor().RedactResponse(resp)

	if len(out.GetEnrichments()) != 1 {
		t.Fatalf("enrichments were dropped by redaction: got %d, want 1", len(out.GetEnrichments()))
	}
	e := out.GetEnrichments()[0]
	if e.GetFindingFingerprint() != "fp-1" || e.GetKind() != "reachability" {
		t.Errorf("enrichment identity lost: %+v", e)
	}
	if e.GetTitle() != "Reachable from main" || e.GetBody() == "" {
		t.Errorf("enrichment text lost: title=%q body=%q", e.GetTitle(), e.GetBody())
	}
	if e.GetSource() != "nox/reachability" || e.GetMetadata()["depth"] != "3" {
		t.Errorf("enrichment attribution or metadata lost: %+v", e)
	}

	if len(out.GetGraphs()) != 1 {
		t.Fatalf("graphs were dropped by redaction: got %d, want 1", len(out.GetGraphs()))
	}
	g := out.GetGraphs()[0]
	if g.GetName() != "call-graph" || g.GetDescription() != "static call graph" {
		t.Errorf("graph identity lost: %+v", g)
	}
	if len(g.GetNodes()) != 1 || len(g.GetEdges()) != 1 {
		t.Fatalf("graph topology lost: %d nodes, %d edges", len(g.GetNodes()), len(g.GetEdges()))
	}
	n := g.GetNodes()[0]
	if n.GetFilePath() != "app/a.go" || n.GetProperties()["pkg"] != "app" {
		t.Errorf("graph node fields lost: %+v", n)
	}
	ed := g.GetEdges()[0]
	if ed.GetLabel() != "calls" || ed.GetProperties()["line"] != "42" {
		t.Errorf("graph edge fields lost: %+v", ed)
	}
}

// TestRedactResponse_RedactsEnrichmentText confirms the newly-preserved fields
// are actually redacted, not merely copied through — carrying a secret in an
// enrichment body would be a worse outcome than dropping it.
func TestRedactResponse_RedactsEnrichmentText(t *testing.T) {
	t.Parallel()

	const secret = "AKIAIOSFODNN7EXAMPLE" // nox:ignore SEC-102 -- redaction test fixture
	resp := &pluginv1.InvokeToolResponse{
		Enrichments: []*pluginv1.Enrichment{{
			Title:    "found " + secret,
			Body:     "in config: " + secret,
			Metadata: map[string]string{"key": secret},
		}},
		Graphs: []*pluginv1.Graph{{
			Description: "graph for " + secret,
			Nodes:       []*pluginv1.GraphNode{{Id: "n1", Label: secret}},
		}},
	}

	out, redacted := NewRedactor().RedactResponse(resp)
	if !redacted {
		t.Error("expected the redaction flag to be set")
	}

	e := out.GetEnrichments()[0]
	for name, got := range map[string]string{
		"title": e.GetTitle(), "body": e.GetBody(), "metadata": e.GetMetadata()["key"],
		"graph description": out.GetGraphs()[0].GetDescription(),
		"node label":        out.GetGraphs()[0].GetNodes()[0].GetLabel(),
	} {
		if strings.Contains(got, secret) {
			t.Errorf("%s was not redacted: %q", name, got)
		}
	}
}

// TestRedactResponse_DropsNoField is the structural guard against this bug
// class recurring.
//
// RedactResponse rebuilds the response rather than mutating it, so any field it
// forgets is silently discarded — which is exactly how every enrichment and
// graph came to be dropped. Enumerating fields by hand in a test has the same
// weakness as the function itself: the test author forgets alongside the
// implementer.
//
// This walks the message with protobuf reflection instead, so a field added to
// InvokeToolResponse tomorrow fails here until the redactor handles it.
func TestRedactResponse_DropsNoField(t *testing.T) {
	t.Parallel()

	in := &pluginv1.InvokeToolResponse{
		Findings:     []*pluginv1.Finding{{Id: "f1", RuleId: "R-1", Message: "m"}},
		Packages:     []*pluginv1.Package{{Name: "pkg", Version: "1.0.0", Ecosystem: "npm"}},
		AiComponents: []*pluginv1.AIComponent{{Name: "agent", Type: "agent", Path: "a.yaml"}},
		Diagnostics:  []*pluginv1.Diagnostic{{Severity: pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, Message: "d", Source: "s"}},
		Graphs:       []*pluginv1.Graph{{Name: "g", Nodes: []*pluginv1.GraphNode{{Id: "n"}}}},
		Enrichments:  []*pluginv1.Enrichment{{FindingFingerprint: "fp", Kind: "k", Title: "t"}},
	}

	// Guard the guard: if a field is added to the proto and not to this
	// fixture, the walk below would pass vacuously.
	wantPopulated := in.ProtoReflect().Descriptor().Fields().Len()
	gotPopulated := 0
	in.ProtoReflect().Range(func(protoreflect.FieldDescriptor, protoreflect.Value) bool {
		gotPopulated++
		return true
	})
	if gotPopulated != wantPopulated {
		t.Fatalf("this test's fixture populates %d of %d InvokeToolResponse fields; "+
			"add the missing field to the fixture, then make sure RedactResponse copies it",
			gotPopulated, wantPopulated)
	}

	out, _ := NewRedactor().RedactResponse(in)

	in.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		if !out.ProtoReflect().Has(fd) {
			t.Errorf("field %q was populated in the input and is missing from the redacted output; "+
				"RedactResponse silently drops it", fd.Name())
		}
		return true
	})
}
