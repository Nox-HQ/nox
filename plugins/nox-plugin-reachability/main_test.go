package main

import (
	"context"
	"net"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}

func TestTrackConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunForTrack(t, srv, registry.TrackCoreAnalysis)
}

func TestAnalyzeReachabilityReachable(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:      "VULN-001",
					Severity:    sdk.SeverityCritical,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "CVE-2021-44228 in log4j",
					Fingerprint: "fp-vuln-001",
					Metadata: map[string]string{
						"vuln_id":   "CVE-2021-44228",
						"package":   "github.com/example/vuln",
						"version":   "1.0.0",
						"ecosystem": "Go",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	// Without a real workspace, the Go package won't be found → REACH-001 (unreachable).
	if len(resp.GetFindings()) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.GetFindings()))
	}

	f := resp.GetFindings()[0]
	if f.GetRuleId() != "REACH-001" {
		t.Errorf("rule_id = %q, want REACH-001", f.GetRuleId())
	}
	if f.GetMetadata()["reachable"] != "false" {
		t.Errorf("reachable = %q, want false", f.GetMetadata()["reachable"])
	}

	// Should also produce an enrichment for the original finding.
	if len(resp.GetEnrichments()) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(resp.GetEnrichments()))
	}

	e := resp.GetEnrichments()[0]
	if e.GetFindingFingerprint() != "fp-vuln-001" {
		t.Errorf("fingerprint = %q, want fp-vuln-001", e.GetFindingFingerprint())
	}
	if e.GetKind() != "reachability" {
		t.Errorf("kind = %q, want reachability", e.GetKind())
	}
	if e.GetSource() != "nox/reachability" {
		t.Errorf("source = %q, want nox/reachability", e.GetSource())
	}
}

func TestAnalyzeReachabilityUnsupportedEcosystem(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:      "VULN-001",
					Severity:    sdk.SeverityHigh,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "CVE-2024-0001 in some-pkg",
					Fingerprint: "fp-vuln-packagist",
					Metadata: map[string]string{
						"vuln_id":   "CVE-2024-0001",
						"package":   "vendor/some-pkg",
						"version":   "0.5.0",
						"ecosystem": "Packagist",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetFindings()) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.GetFindings()))
	}

	f := resp.GetFindings()[0]
	if f.GetRuleId() != "REACH-003" {
		t.Errorf("rule_id = %q, want REACH-003", f.GetRuleId())
	}
	if f.GetMetadata()["reachable"] != "undetermined" {
		t.Errorf("reachable = %q, want undetermined", f.GetMetadata()["reachable"])
	}
}

func TestAnalyzeReachabilityNoVulnFindings(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:     "SEC-001",
					Severity:   sdk.SeverityHigh,
					Confidence: sdk.ConfidenceHigh,
					Message:    "Hardcoded secret",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected 0 findings for non-VULN input, got %d", len(resp.GetFindings()))
	}
	if len(resp.GetEnrichments()) != 0 {
		t.Errorf("expected 0 enrichments, got %d", len(resp.GetEnrichments()))
	}
}

func TestAnalyzeReachabilityMultipleFindings(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:      "VULN-001",
					Severity:    sdk.SeverityCritical,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "CVE-1 in pkg-a",
					Fingerprint: "fp-1",
					Metadata: map[string]string{
						"vuln_id": "CVE-1", "package": "pkg-a",
						"version": "1.0", "ecosystem": "Go",
					},
				},
				{
					RuleId:      "VULN-002",
					Severity:    sdk.SeverityMedium,
					Confidence:  sdk.ConfidenceMedium,
					Message:     "typosquat in pkg-b",
					Fingerprint: "fp-2",
					Metadata: map[string]string{
						"vuln_id": "TYPO-1", "package": "pkg-b",
						"version": "1.0", "ecosystem": "npm",
					},
				},
				{
					RuleId:      "VULN-003",
					Severity:    sdk.SeverityHigh,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "malicious pkg-c",
					Fingerprint: "fp-3",
					Metadata: map[string]string{
						"vuln_id": "MAL-1", "package": "pkg-c",
						"version": "1.0", "ecosystem": "RubyGems",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	// Should produce 3 findings: REACH-001 (Go, not imported), REACH-001 (npm, not imported), REACH-003 (RubyGems).
	if len(resp.GetFindings()) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(resp.GetFindings()))
	}

	// Verify all have enrichments.
	if len(resp.GetEnrichments()) != 3 {
		t.Fatalf("expected 3 enrichments, got %d", len(resp.GetEnrichments()))
	}
}

func TestAnalyzeReachabilityEmptyContext(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "analyze_reachability",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected 0 findings with no context, got %d", len(resp.GetFindings()))
	}
}

// --- Domain logic unit tests ---

func TestAnalyzeFunction(t *testing.T) {
	imports := NewImportSet()
	imports.Add("Go", "github.com/vuln/pkg")
	imports.Add("PyPI", "flask")
	imports.Add("npm", "express")

	vulns := []VulnInfo{
		{Fingerprint: "fp1", Package: "github.com/vuln/pkg", Ecosystem: "Go", VulnID: "CVE-1"},
		{Fingerprint: "fp2", Package: "requests", Ecosystem: "PyPI", VulnID: "CVE-2"},
		{Fingerprint: "fp3", Package: "express", Ecosystem: "npm", VulnID: "CVE-3"},
		{Fingerprint: "fp4", Package: "some-pkg", Ecosystem: "Packagist", VulnID: "CVE-4"},
	}

	results := Analyze(vulns, imports)

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	// Go package is imported → REACH-002.
	if results[0].RuleID != "REACH-002" {
		t.Errorf("results[0].RuleID = %q, want REACH-002", results[0].RuleID)
	}
	if results[0].Status != ReachReachable {
		t.Errorf("results[0].Status = %d, want ReachReachable", results[0].Status)
	}

	// PyPI package "requests" not imported → REACH-001.
	if results[1].RuleID != "REACH-001" {
		t.Errorf("results[1].RuleID = %q, want REACH-001", results[1].RuleID)
	}

	// npm "express" is imported → REACH-002.
	if results[2].RuleID != "REACH-002" {
		t.Errorf("results[2].RuleID = %q, want REACH-002", results[2].RuleID)
	}

	// Packagist (PHP) unsupported → REACH-003.
	if results[3].RuleID != "REACH-003" {
		t.Errorf("results[3].RuleID = %q, want REACH-003", results[3].RuleID)
	}
}

func TestNormalizePackageName(t *testing.T) {
	tests := []struct {
		pkg  string
		eco  string
		want string
	}{
		{"github.com/foo/bar", "Go", "github.com/foo/bar"},
		{"Pillow", "PyPI", "PIL"},
		{"scikit-learn", "PyPI", "sklearn"},
		{"flask", "PyPI", "flask"},
		{"my-pkg", "PyPI", "my_pkg"},
		{"express", "npm", "express"},
		{"@scope/pkg", "npm", "@scope/pkg"},
	}

	for _, tt := range tests {
		got := normalizePackageName(tt.pkg, tt.eco)
		if got != tt.want {
			t.Errorf("normalizePackageName(%q, %q) = %q, want %q", tt.pkg, tt.eco, got, tt.want)
		}
	}
}

func TestExtractVulnFindings(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:      "VULN-001",
			Fingerprint: "fp1",
			Metadata: map[string]string{
				"package": "pkg-a", "ecosystem": "Go", "vuln_id": "CVE-1",
			},
		},
		{
			RuleId: "SEC-001",
			Metadata: map[string]string{
				"type": "secret",
			},
		},
		{
			RuleId:      "VULN-002",
			Fingerprint: "fp2",
			Metadata: map[string]string{
				"package": "pkg-b", "ecosystem": "npm", "vuln_id": "CVE-2",
			},
		},
		{
			RuleId: "VULN-003",
			// Missing metadata.
		},
	}

	vulns := extractVulnFindings(findings)
	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(vulns))
	}
	if vulns[0].Package != "pkg-a" {
		t.Errorf("vulns[0].Package = %q, want pkg-a", vulns[0].Package)
	}
	if vulns[1].Package != "pkg-b" {
		t.Errorf("vulns[1].Package = %q, want pkg-b", vulns[1].Package)
	}
}

// --- helpers ---

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}
