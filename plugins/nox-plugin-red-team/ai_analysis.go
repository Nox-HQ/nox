package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
	plannerllm "go.klarlabs.de/agent/contrib/planner-llm"
)

const attackAnalysisSystemPrompt = `You are a red team security analyst. You analyze attack chains and generate sophisticated attack path assessments.

You receive:
- Detected attack chains with steps and blast radius
- Source security findings that contributed to the chains

For each chain, provide:
- "chain_id": string (e.g., "REDTEAM-AI-001")
- "title": string (attack scenario title)
- "description": string (detailed attack narrative)
- "severity": string (one of: "critical", "high", "medium", "low")
- "exploitation_order": string (recommended order of exploitation)
- "blast_radius": string (estimated impact scope)
- "prerequisites": string (what the attacker needs before starting)
- "detection_difficulty": string (one of: "trivial", "moderate", "difficult", "very_difficult")

Respond ONLY with a JSON array. Do not include any text outside the JSON array.`

// aiAttackPath represents a single LLM-generated attack path analysis.
type aiAttackPath struct {
	ChainID             string `json:"chain_id"`
	Title               string `json:"title"`
	Description         string `json:"description"`
	Severity            string `json:"severity"`
	ExploitationOrder   string `json:"exploitation_order"`
	BlastRadius         string `json:"blast_radius"`
	Prerequisites       string `json:"prerequisites"`
	DetectionDifficulty string `json:"detection_difficulty"`
}

// aiAttackAnalysis sends attack chains to an LLM for enhanced analysis.
func aiAttackAnalysis(ctx context.Context, provider plannerllm.Provider, model string, chainFindings, sourceFindings []*pluginv1.Finding) []*pluginv1.Finding {
	userMsg := buildAttackPrompt(chainFindings, sourceFindings)

	resp, err := provider.Complete(ctx, plannerllm.CompletionRequest{
		Model: model,
		Messages: []plannerllm.Message{
			{Role: "system", Content: attackAnalysisSystemPrompt},
			{Role: "user", Content: userMsg},
		},
		Temperature: 0.4,
		MaxTokens:   16384,
	})
	if err != nil {
		log.Printf("ai_attack: LLM call failed: %v", err)
		markRedTeamError(chainFindings, fmt.Sprintf("LLM call failed: %v", err))
		return nil
	}

	paths, err := parseAttackResponse(resp.Message.Content)
	if err != nil {
		log.Printf("ai_attack: failed to parse LLM response: %v", err)
		markRedTeamError(chainFindings, fmt.Sprintf("failed to parse LLM response: %v", err))
		return nil
	}

	return convertPathsToFindings(paths)
}

// buildAttackPrompt creates the user message with chains and source findings.
func buildAttackPrompt(chainFindings, sourceFindings []*pluginv1.Finding) string {
	type summary struct {
		RuleID      string `json:"rule_id"`
		Severity    string `json:"severity"`
		Message     string `json:"message"`
		Steps       string `json:"steps,omitempty"`
		BlastRadius string `json:"blast_radius,omitempty"`
	}

	chains := make([]summary, len(chainFindings))
	for i, f := range chainFindings {
		meta := f.GetMetadata()
		chains[i] = summary{
			RuleID:      f.GetRuleId(),
			Severity:    f.GetSeverity().String(),
			Message:     f.GetMessage(),
			Steps:       meta["chain_steps"],
			BlastRadius: meta["blast_radius"],
		}
	}

	sources := make([]summary, 0, len(sourceFindings))
	for _, f := range sourceFindings {
		sources = append(sources, summary{
			RuleID:   f.GetRuleId(),
			Severity: f.GetSeverity().String(),
			Message:  f.GetMessage(),
		})
	}

	chainData, _ := json.MarshalIndent(chains, "", "  ")
	sourceData, _ := json.MarshalIndent(sources, "", "  ")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Analyze %d attack chains with %d source findings.\n\n", len(chains), len(sources)))
	sb.WriteString("## Attack Chains\n\n")
	sb.WriteString(string(chainData))
	sb.WriteString("\n\n## Source Findings\n\n")
	sb.WriteString(string(sourceData))
	return sb.String()
}

// parseAttackResponse extracts attack paths from the LLM response.
func parseAttackResponse(content string) ([]aiAttackPath, error) {
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

	var paths []aiAttackPath
	if err := json.Unmarshal([]byte(content), &paths); err != nil {
		return nil, fmt.Errorf("invalid JSON in LLM response: %w", err)
	}
	return paths, nil
}

// convertPathsToFindings converts AI-generated attack paths to proto findings.
func convertPathsToFindings(paths []aiAttackPath) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, p := range paths {
		sev := parseSeverity(p.Severity)
		if sev == pluginv1.Severity(0) {
			sev = sdk.SeverityHigh
		}

		result = append(result, &pluginv1.Finding{
			RuleId:     p.ChainID,
			Severity:   sev,
			Confidence: sdk.ConfidenceMedium,
			Message:    fmt.Sprintf("%s: %s", p.Title, p.Description),
			Metadata: map[string]string{
				"ai_analyzed":          "true",
				"category":             "ai-attack-path",
				"exploitation_order":   p.ExploitationOrder,
				"blast_radius":         p.BlastRadius,
				"prerequisites":        p.Prerequisites,
				"detection_difficulty": p.DetectionDifficulty,
			},
		})
	}
	return result
}

// markRedTeamError adds ai_redteam_error metadata to all findings when LLM fails.
func markRedTeamError(findings []*pluginv1.Finding, errMsg string) {
	for _, f := range findings {
		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["ai_redteam_error"] = errMsg
	}
}

// parseSeverity converts a severity string to the protobuf enum value.
func parseSeverity(s string) pluginv1.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return sdk.SeverityCritical
	case "high":
		return sdk.SeverityHigh
	case "medium":
		return sdk.SeverityMedium
	case "low":
		return sdk.SeverityLow
	case "info":
		return sdk.SeverityInfo
	default:
		return pluginv1.Severity(0)
	}
}
