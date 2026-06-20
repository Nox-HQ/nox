package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
	plannerllm "go.klarlabs.de/agent/contrib/planner-llm"
)

type mockProvider struct {
	response string
	err      error
}

func (m *mockProvider) Name() string { return "mock" }

func (m *mockProvider) Complete(_ context.Context, _ plannerllm.CompletionRequest) (plannerllm.CompletionResponse, error) {
	if m.err != nil {
		return plannerllm.CompletionResponse{}, m.err
	}
	return plannerllm.CompletionResponse{
		Message: plannerllm.Message{
			Role:    "assistant",
			Content: m.response,
		},
	}, nil
}

func TestAIAttackAnalysis(t *testing.T) {
	paths := []aiAttackPath{
		{
			ChainID:             "REDTEAM-AI-001",
			Title:               "Multi-stage auth bypass",
			Description:         "An attacker can chain weak auth with data exposure",
			Severity:            "critical",
			ExploitationOrder:   "THREAT-001 -> THREAT-004",
			BlastRadius:         "full-application",
			Prerequisites:       "Network access to target",
			DetectionDifficulty: "difficult",
		},
	}
	data, _ := json.Marshal(paths)

	provider := &mockProvider{response: string(data)}
	chains := []*pluginv1.Finding{
		{RuleId: "REDTEAM-001", Severity: sdk.SeverityCritical, Message: "Multi-step attack chain detected"},
	}
	sources := []*pluginv1.Finding{
		{RuleId: "THREAT-001", Severity: sdk.SeverityMedium},
		{RuleId: "THREAT-004", Severity: sdk.SeverityHigh},
	}

	result := aiAttackAnalysis(context.Background(), provider, "test-model", chains, sources)
	if len(result) != 1 {
		t.Fatalf("expected 1 AI finding, got %d", len(result))
	}
	if result[0].GetRuleId() != "REDTEAM-AI-001" {
		t.Errorf("expected REDTEAM-AI-001, got %s", result[0].GetRuleId())
	}
	meta := result[0].GetMetadata()
	if meta["ai_analyzed"] != "true" {
		t.Error("expected ai_analyzed=true")
	}
	if meta["detection_difficulty"] != "difficult" {
		t.Errorf("expected detection_difficulty=difficult, got %s", meta["detection_difficulty"])
	}
}

func TestAIAttackAnalysisGracefulDegradation(t *testing.T) {
	provider := &mockProvider{err: fmt.Errorf("API timeout")}
	chains := []*pluginv1.Finding{
		{RuleId: "REDTEAM-001", Severity: sdk.SeverityCritical},
	}

	result := aiAttackAnalysis(context.Background(), provider, "test-model", chains, nil)
	if result != nil {
		t.Errorf("expected nil on LLM failure, got %d findings", len(result))
	}
	meta := chains[0].GetMetadata()
	if meta["ai_redteam_error"] == "" {
		t.Error("expected ai_redteam_error metadata on LLM failure")
	}
}

func TestAIAttackAnalysisMalformedResponse(t *testing.T) {
	provider := &mockProvider{response: "this is not json"}
	chains := []*pluginv1.Finding{
		{RuleId: "REDTEAM-001", Severity: sdk.SeverityCritical},
	}

	result := aiAttackAnalysis(context.Background(), provider, "test-model", chains, nil)
	if result != nil {
		t.Errorf("expected nil on malformed response, got %d findings", len(result))
	}
	meta := chains[0].GetMetadata()
	if !strings.Contains(meta["ai_redteam_error"], "parse") {
		t.Errorf("expected parse error metadata, got %q", meta["ai_redteam_error"])
	}
}

func TestParseAttackResponseValid(t *testing.T) {
	paths := []aiAttackPath{
		{ChainID: "REDTEAM-AI-001", Title: "Test", Severity: "high"},
	}
	data, _ := json.Marshal(paths)

	result, err := parseAttackResponse(string(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 path, got %d", len(result))
	}
	if result[0].ChainID != "REDTEAM-AI-001" {
		t.Errorf("expected REDTEAM-AI-001, got %s", result[0].ChainID)
	}
}

func TestParseAttackResponseMarkdownFences(t *testing.T) {
	paths := []aiAttackPath{
		{ChainID: "REDTEAM-AI-002", Title: "Fenced", Severity: "medium"},
	}
	data, _ := json.Marshal(paths)
	fenced := "```json\n" + string(data) + "\n```"

	result, err := parseAttackResponse(fenced)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 || result[0].ChainID != "REDTEAM-AI-002" {
		t.Error("failed to parse markdown-fenced response")
	}
}

func TestParseAttackResponseInvalid(t *testing.T) {
	_, err := parseAttackResponse("not json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestConvertPathsToFindings(t *testing.T) {
	paths := []aiAttackPath{
		{
			ChainID:             "REDTEAM-AI-001",
			Title:               "Auth bypass",
			Description:         "Complex attack",
			Severity:            "critical",
			ExploitationOrder:   "1,2,3",
			BlastRadius:         "full",
			Prerequisites:       "network",
			DetectionDifficulty: "very_difficult",
		},
		{
			ChainID:  "REDTEAM-AI-002",
			Title:    "Data leak",
			Severity: "unknown",
		},
	}

	findings := convertPathsToFindings(paths)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].GetSeverity() != sdk.SeverityCritical {
		t.Errorf("expected CRITICAL, got %v", findings[0].GetSeverity())
	}
	if findings[1].GetSeverity() != sdk.SeverityHigh {
		t.Error("expected HIGH default for unknown severity")
	}

	meta := findings[0].GetMetadata()
	if meta["blast_radius"] != "full" {
		t.Errorf("expected blast_radius=full, got %s", meta["blast_radius"])
	}
}

func TestMarkRedTeamError(t *testing.T) {
	findings := []*pluginv1.Finding{
		{RuleId: "REDTEAM-001"},
		{RuleId: "REDTEAM-002", Metadata: map[string]string{"existing": "value"}},
	}

	markRedTeamError(findings, "test error")

	for _, f := range findings {
		if f.Metadata["ai_redteam_error"] != "test error" {
			t.Errorf("expected ai_redteam_error=test error, got %s", f.Metadata["ai_redteam_error"])
		}
	}
	if findings[1].Metadata["existing"] != "value" {
		t.Error("existing metadata should be preserved")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  pluginv1.Severity
	}{
		{"critical", sdk.SeverityCritical},
		{"CRITICAL", sdk.SeverityCritical},
		{"high", sdk.SeverityHigh},
		{"medium", sdk.SeverityMedium},
		{"low", sdk.SeverityLow},
		{"info", sdk.SeverityInfo},
		{"unknown", pluginv1.Severity(0)},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseSeverity(tc.input)
			if got != tc.want {
				t.Errorf("parseSeverity(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestBuildAttackPrompt(t *testing.T) {
	chains := []*pluginv1.Finding{
		{
			RuleId:   "REDTEAM-001",
			Severity: sdk.SeverityCritical,
			Message:  "Attack chain detected",
			Metadata: map[string]string{
				"chain_steps":  "1. Step one\n2. Step two",
				"blast_radius": "full-application",
			},
		},
	}
	sources := []*pluginv1.Finding{
		{RuleId: "THREAT-001", Severity: sdk.SeverityMedium, Message: "Weak auth"},
	}

	prompt := buildAttackPrompt(chains, sources)
	if !strings.Contains(prompt, "1 attack chains") {
		t.Error("expected chain count in prompt")
	}
	if !strings.Contains(prompt, "1 source findings") {
		t.Error("expected source count in prompt")
	}
	if !strings.Contains(prompt, "REDTEAM-001") {
		t.Error("expected chain rule ID in prompt")
	}
	if !strings.Contains(prompt, "THREAT-001") {
		t.Error("expected source rule ID in prompt")
	}
}
