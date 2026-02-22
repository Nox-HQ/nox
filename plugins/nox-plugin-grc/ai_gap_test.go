package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	plannerllm "github.com/felixgeelhaar/agent-go/contrib/planner-llm"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

type mockProvider struct {
	response string
	err      error
}

func (m *mockProvider) Complete(_ context.Context, _ plannerllm.CompletionRequest) (plannerllm.CompletionResponse, error) {
	if m.err != nil {
		return plannerllm.CompletionResponse{}, m.err
	}
	return plannerllm.CompletionResponse{
		ID:    "mock-id",
		Model: "mock-model",
		Message: plannerllm.Message{
			Role:    "assistant",
			Content: m.response,
		},
	}, nil
}

func (m *mockProvider) Name() string { return "mock" }

func TestAIGapAnalysisEnhancesFindings(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:   "GRC-001",
			Severity: sdk.SeverityHigh,
			Message:  "Critical control gap: SOC2 CC6.1",
			Metadata: map[string]string{"framework": "soc2", "category": "control-gap"},
		},
	}

	suggestions := []gapSuggestion{
		{
			FindingRuleID:   "GRC-001",
			Framework:       "soc2",
			Priority:        "critical",
			RemediationPlan: "Implement MFA and role-based access control",
			ControlMapping:  "Map SEC-001 and EXPLAIN-003 findings as partial evidence",
			RiskAssessment:  "High risk of audit failure without access control evidence",
		},
	}
	respJSON, _ := json.Marshal(suggestions)

	provider := &mockProvider{response: string(respJSON)}
	aiGapAnalysis(context.Background(), provider, "mock-model", findings)

	f := findings[0]
	if f.Metadata["ai_assessed"] != "true" {
		t.Error("expected ai_assessed=true metadata")
	}
	if f.Metadata["ai_remediation_plan"] == "" {
		t.Error("expected ai_remediation_plan to be set")
	}
	if f.Metadata["ai_control_mapping"] == "" {
		t.Error("expected ai_control_mapping to be set")
	}
	if f.Metadata["ai_risk_assessment"] == "" {
		t.Error("expected ai_risk_assessment to be set")
	}
	if f.Metadata["ai_priority"] != "critical" {
		t.Errorf("expected ai_priority=critical, got %q", f.Metadata["ai_priority"])
	}
}

func TestAIGapAnalysisGracefulDegradation(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:   "GRC-002",
			Severity: sdk.SeverityMedium,
			Message:  "test gap",
			Metadata: map[string]string{"framework": "soc2"},
		},
	}

	provider := &mockProvider{err: errors.New("connection refused")}
	aiGapAnalysis(context.Background(), provider, "mock-model", findings)

	if findings[0].Metadata["ai_gap_error"] == "" {
		t.Error("expected ai_gap_error metadata on failure")
	}
}

func TestAIGapAnalysisMalformedResponse(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:   "GRC-001",
			Severity: sdk.SeverityHigh,
			Message:  "test gap",
			Metadata: map[string]string{"framework": "gdpr"},
		},
	}

	provider := &mockProvider{response: "not valid json"}
	aiGapAnalysis(context.Background(), provider, "mock-model", findings)

	if findings[0].Metadata["ai_gap_error"] == "" {
		t.Error("expected ai_gap_error metadata on malformed response")
	}
}

func TestAIGapAnalysisEmptyFindings(t *testing.T) {
	provider := &mockProvider{err: errors.New("should not be called")}
	aiGapAnalysis(context.Background(), provider, "mock-model", nil)
}

func TestParseGapResponseValid(t *testing.T) {
	input := `[{"finding_rule_id":"GRC-001","framework":"soc2","priority":"high","remediation_plan":"fix","control_mapping":"map","risk_assessment":"risky"}]`
	suggestions, err := parseGapResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
}

func TestParseGapResponseInvalid(t *testing.T) {
	_, err := parseGapResponse("not json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseGapResponseMarkdown(t *testing.T) {
	inner := `[{"finding_rule_id":"GRC-001","framework":"soc2","priority":"high","remediation_plan":"fix","control_mapping":"map","risk_assessment":"risky"}]`
	wrapped := "```json\n" + inner + "\n```"
	suggestions, err := parseGapResponse(wrapped)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
}
