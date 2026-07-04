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
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackPolicyGovernance)
}

func TestAssessNoFrameworks(t *testing.T) {
	client := testClient(t)
	input, _ := structpb.NewStruct(map[string]any{})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "assess",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) == 0 {
		t.Fatal("expected at least one finding for empty frameworks")
	}
	found := findByRule(resp.GetFindings(), "GRC-002")
	if len(found) == 0 {
		t.Fatal("expected GRC-002 finding for missing frameworks")
	}
}

func TestAssessWithFramework(t *testing.T) {
	client := testClient(t)
	input, _ := structpb.NewStruct(map[string]any{
		"frameworks": []any{"soc2"},
	})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "assess",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	// Without context findings, SOC2 should have gaps.
	if len(resp.GetFindings()) == 0 {
		t.Fatal("expected findings for SOC2 assessment without scan context")
	}
}

func TestGapReportNoFramework(t *testing.T) {
	client := testClient(t)
	input, _ := structpb.NewStruct(map[string]any{})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "gap_report",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty gap_report request, got %d", len(resp.GetFindings()))
	}
}

func TestGapReportWithFramework(t *testing.T) {
	client := testClient(t)
	input, _ := structpb.NewStruct(map[string]any{
		"framework": "gdpr",
	})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "gap_report",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	// Without scan context, all controls should be uncovered.
	if len(resp.GetFindings()) == 0 {
		t.Fatal("expected findings for GDPR gap report without scan context")
	}
}

func TestEvidenceNoFramework(t *testing.T) {
	client := testClient(t)
	input, _ := structpb.NewStruct(map[string]any{})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "evidence",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty evidence request, got %d", len(resp.GetFindings()))
	}
}

func TestEvidenceNoEvidence(t *testing.T) {
	client := testClient(t)
	input, _ := structpb.NewStruct(map[string]any{
		"framework": "soc2",
	})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "evidence",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	found := findByRule(resp.GetFindings(), "GRC-001")
	if len(found) == 0 {
		t.Fatal("expected GRC-001 finding for missing evidence")
	}
}

func TestFrameworksByName(t *testing.T) {
	expected := []string{"soc2", "iso27001", "gdpr", "fedramp-low", "fedramp-moderate", "fedramp-high", "hipaa", "pci-dss", "nist-800-53", "nist-csf", "cis-v8", "cmmc", "nist-ai-rmf", "iso42001", "eu-ai-act"}
	for _, id := range expected {
		if _, ok := frameworksByName[id]; !ok {
			t.Errorf("framework %q not found in frameworksByName", id)
		}
	}
	if len(frameworksByName) != 15 {
		t.Errorf("expected 15 frameworks, got %d", len(frameworksByName))
	}
}

// The AI-governance frameworks must actually map to the AI/agent rule families
// (not just be empty shells) — e.g. EU AI Act Art.14 "human oversight" should be
// evidenced by AGENT-002 (agent settings that disable the human-in-the-loop
// gate). Guards against the mapping silently referencing rules that don't exist.
func TestAIGovernanceFrameworksMapAgentRules(t *testing.T) {
	controlHasRule := func(fwID, ctrlID, ruleID string) bool {
		fw, ok := frameworksByName[fwID]
		if !ok {
			return false
		}
		for _, c := range fw.Controls {
			if c.ID != ctrlID {
				continue
			}
			for _, r := range c.NoxRules {
				if r == ruleID {
					return true
				}
			}
		}
		return false
	}

	cases := []struct{ fw, ctrl, rule string }{
		{"eu-ai-act", "Art.14", "AGENT-002"},        // human oversight
		{"eu-ai-act", "Art.15.5", "AGENT-001"},      // cybersecurity / manipulation
		{"iso42001", "A.6.2.6", "AGENT-003"},        // deployment access controls
		{"nist-ai-rmf", "MEASURE-2.7", "AI-PI-001"}, // adversarial security
	}
	for _, tc := range cases {
		if !controlHasRule(tc.fw, tc.ctrl, tc.rule) {
			t.Errorf("%s control %s should map to %s", tc.fw, tc.ctrl, tc.rule)
		}
	}
}

func TestFedRAMPBaselineInclusion(t *testing.T) {
	lowControls := make(map[string]bool)
	for _, c := range fedrampLow.Controls {
		lowControls[c.ID] = true
	}
	modControls := make(map[string]bool)
	for _, c := range fedrampModerate.Controls {
		modControls[c.ID] = true
	}
	highControls := make(map[string]bool)
	for _, c := range fedrampHigh.Controls {
		highControls[c.ID] = true
	}

	// Moderate must include all Low controls.
	for id := range lowControls {
		if !modControls[id] {
			t.Errorf("FedRAMP Moderate missing Low control %s", id)
		}
	}
	// High must include all Moderate controls.
	for id := range modControls {
		if !highControls[id] {
			t.Errorf("FedRAMP High missing Moderate control %s", id)
		}
	}
}

func TestFedRAMPControlCounts(t *testing.T) {
	tests := []struct {
		name     string
		fw       Framework
		expected int
	}{
		{"Low", fedrampLow, 25},
		{"Moderate", fedrampModerate, 38},
		{"High", fedrampHigh, 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(tt.fw.Controls); got != tt.expected {
				t.Errorf("FedRAMP %s: expected %d controls, got %d", tt.name, tt.expected, got)
			}
		})
	}
}

// --- helpers ---

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
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

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
