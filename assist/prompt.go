package assist

import (
	"fmt"
	"strings"

	core "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/findings"
)

// systemPrompt returns the system message that instructs the LLM on how to
// analyze and explain Nox scan findings.
func systemPrompt() string {
	return `You are a security expert analyzing findings from Nox, a security scanner.
For each finding, provide a JSON array with objects containing these fields:
- "finding_id": the finding ID (string)
- "rule_id": the rule ID (string)
- "title": a concise title for the issue (string)
- "explanation": what this finding means in plain language (string)
- "impact": why this matters and what could go wrong (string)
- "remediation": specific, actionable steps to fix the issue (string)
- "references": relevant URLs for further reading (array of strings, optional)

Respond ONLY with a valid JSON array. Do not include markdown fences or other text.
Be concise and actionable. Focus on practical remediation advice.`
}

// formatFindings converts a batch of findings into structured text for the LLM.
func formatFindings(ff []findings.Finding) string {
	var b strings.Builder
	for i, f := range ff {
		if i > 0 {
			b.WriteString("\n---\n")
		}
		fmt.Fprintf(&b, "Finding ID: %s\n", f.ID)
		fmt.Fprintf(&b, "Rule ID: %s\n", f.RuleID)
		fmt.Fprintf(&b, "Severity: %s\n", f.Severity)
		fmt.Fprintf(&b, "Confidence: %s\n", f.Confidence)
		fmt.Fprintf(&b, "File: %s\n", f.Location.FilePath)
		if f.Location.StartLine > 0 {
			fmt.Fprintf(&b, "Line: %d\n", f.Location.StartLine)
		}
		fmt.Fprintf(&b, "Message: %s\n", f.Message)
		if len(f.Metadata) > 0 {
			for k, v := range f.Metadata {
				fmt.Fprintf(&b, "Metadata %s: %s\n", k, v)
			}
		}
	}
	return b.String()
}

// formatContext summarises the scan result ecosystem for the LLM so it can
// provide contextually aware explanations.
func formatContext(result *core.ScanResult) string {
	var b strings.Builder
	b.WriteString("Scan context:\n")

	// Findings by severity.
	counts := map[findings.Severity]int{}
	for _, f := range result.Findings.Findings() {
		counts[f.Severity]++
	}
	fmt.Fprintf(&b, "Total findings: %d\n", len(result.Findings.Findings()))
	for _, sev := range []findings.Severity{
		findings.SeverityCritical,
		findings.SeverityHigh,
		findings.SeverityMedium,
		findings.SeverityLow,
		findings.SeverityInfo,
	} {
		if c := counts[sev]; c > 0 {
			fmt.Fprintf(&b, "  %s: %d\n", sev, c)
		}
	}

	// Dependencies by ecosystem.
	ecosystems := map[string]int{}
	for _, pkg := range result.Inventory.Packages() {
		ecosystems[pkg.Ecosystem]++
	}
	if len(ecosystems) > 0 {
		b.WriteString("Dependencies:\n")
		for eco, count := range ecosystems {
			fmt.Fprintf(&b, "  %s: %d packages\n", eco, count)
		}
	}

	// AI components.
	if len(result.AIInventory.Components) > 0 {
		fmt.Fprintf(&b, "AI components: %d\n", len(result.AIInventory.Components))
	}

	return b.String()
}

// summaryPrompt returns a user message asking the LLM to produce an executive
// summary of all explained findings.
func summaryPrompt(explanations []FindingExplanation) string {
	var b strings.Builder
	b.WriteString("Based on these security findings, provide a 2-3 sentence executive summary ")
	b.WriteString("of the overall security posture. Highlight the most critical issues.\n\n")
	for _, e := range explanations {
		fmt.Fprintf(&b, "- [%s] %s: %s\n", e.RuleID, e.Title, e.Explanation)
	}
	b.WriteString("\nRespond with ONLY the summary text, no JSON.")
	return b.String()
}
