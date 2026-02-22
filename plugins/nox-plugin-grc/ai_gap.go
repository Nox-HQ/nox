package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	plannerllm "github.com/felixgeelhaar/agent-go/contrib/planner-llm"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

const gapAnalysisSystemPrompt = `You are a GRC (Governance, Risk & Compliance) specialist. You analyze compliance gaps and provide prioritized remediation guidance.

You receive compliance assessment findings including:
- Framework coverage gaps
- Missing control evidence
- Specific control deficiencies

For each gap, provide:
- "finding_rule_id": string (the original GRC finding rule ID)
- "framework": string (the framework ID)
- "priority": string (one of: "critical", "high", "medium", "low")
- "remediation_plan": string (specific, actionable remediation steps)
- "control_mapping": string (suggested control mappings or alternative evidence sources)
- "risk_assessment": string (business risk assessment of the gap)

Respond ONLY with a JSON array. Do not include any text outside the JSON array.`

// gapSuggestion represents a single LLM-generated gap analysis suggestion.
type gapSuggestion struct {
	FindingRuleID   string `json:"finding_rule_id"`
	Framework       string `json:"framework"`
	Priority        string `json:"priority"`
	RemediationPlan string `json:"remediation_plan"`
	ControlMapping  string `json:"control_mapping"`
	RiskAssessment  string `json:"risk_assessment"`
}

// aiGapAnalysis sends GRC findings to an LLM for prioritized remediation guidance.
func aiGapAnalysis(ctx context.Context, provider plannerllm.Provider, model string, findings []*pluginv1.Finding) {
	if len(findings) == 0 {
		return
	}

	userMsg := buildGapPrompt(findings)

	resp, err := provider.Complete(ctx, plannerllm.CompletionRequest{
		Model: model,
		Messages: []plannerllm.Message{
			{Role: "system", Content: gapAnalysisSystemPrompt},
			{Role: "user", Content: userMsg},
		},
		Temperature: 0.3,
		MaxTokens:   8192,
	})
	if err != nil {
		log.Printf("ai_gap: LLM call failed: %v", err)
		markGapError(findings, fmt.Sprintf("LLM call failed: %v", err))
		return
	}

	suggestions, err := parseGapResponse(resp.Message.Content)
	if err != nil {
		log.Printf("ai_gap: failed to parse LLM response: %v", err)
		markGapError(findings, fmt.Sprintf("failed to parse LLM response: %v", err))
		return
	}

	applyGapSuggestions(findings, suggestions)
}

// buildGapPrompt serializes GRC findings into a user message.
func buildGapPrompt(findings []*pluginv1.Finding) string {
	type findingSummary struct {
		RuleID    string `json:"rule_id"`
		Severity  string `json:"severity"`
		Message   string `json:"message"`
		Framework string `json:"framework"`
		Category  string `json:"category"`
	}

	summaries := make([]findingSummary, len(findings))
	for i, f := range findings {
		meta := f.GetMetadata()
		summaries[i] = findingSummary{
			RuleID:    f.GetRuleId(),
			Severity:  f.GetSeverity().String(),
			Message:   f.GetMessage(),
			Framework: meta["framework"],
			Category:  meta["category"],
		}
	}

	data, _ := json.MarshalIndent(summaries, "", "  ")
	return fmt.Sprintf("Please analyze the following %d compliance gaps and provide remediation guidance:\n\n%s", len(findings), string(data))
}

// parseGapResponse extracts suggestions from the LLM response.
func parseGapResponse(content string) ([]gapSuggestion, error) {
	content = strings.TrimSpace(content)

	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
		if len(lines) >= 2 {
			lines = lines[1:]
		}
		if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[len(lines)-1]), "```") {
			lines = lines[:len(lines)-1]
		}
		content = strings.Join(lines, "\n")
	}

	var suggestions []gapSuggestion
	if err := json.Unmarshal([]byte(content), &suggestions); err != nil {
		return nil, fmt.Errorf("invalid JSON in LLM response: %w", err)
	}
	return suggestions, nil
}

// applyGapSuggestions modifies findings in-place with LLM-generated suggestions.
func applyGapSuggestions(findings []*pluginv1.Finding, suggestions []gapSuggestion) {
	// Build lookup by rule_id + framework.
	type key struct {
		ruleID    string
		framework string
	}
	lookup := make(map[key]gapSuggestion, len(suggestions))
	for _, s := range suggestions {
		lookup[key{s.FindingRuleID, s.Framework}] = s
	}

	for _, f := range findings {
		meta := f.GetMetadata()
		sg, ok := lookup[key{f.GetRuleId(), meta["framework"]}]
		if !ok {
			continue
		}

		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["ai_assessed"] = "true"
		if sg.RemediationPlan != "" {
			f.Metadata["ai_remediation_plan"] = sg.RemediationPlan
		}
		if sg.ControlMapping != "" {
			f.Metadata["ai_control_mapping"] = sg.ControlMapping
		}
		if sg.RiskAssessment != "" {
			f.Metadata["ai_risk_assessment"] = sg.RiskAssessment
		}
		if sg.Priority != "" {
			f.Metadata["ai_priority"] = sg.Priority
		}
	}
}

// markGapError adds ai_gap_error metadata to all findings when LLM fails.
func markGapError(findings []*pluginv1.Finding, errMsg string) {
	for _, f := range findings {
		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["ai_gap_error"] = errMsg
	}
}
