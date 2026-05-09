package assist

import (
	"fmt"
	"strings"
)

// TriageContext is the input to BuildTriagePrompt: the finding being assessed
// plus surrounding code (if available). Empty CodeContext is allowed.
type TriageContext struct {
	RuleID       string
	Title        string
	Severity     string
	FilePath     string
	Line         int
	Snippet      string
	CodeContext  string
	BaseScore    float64
	Confidence   string
	BusinessTags []string
}

const triageSystemPrompt = `You are a senior application-security engineer triaging static-analysis findings.
Your job is to assess each finding's true severity given the surrounding code context, and to recommend whether to block, fix-soon, or defer.

Output strictly valid JSON of the form:
{
  "classification": "true_positive" | "false_positive" | "needs_review",
  "adjusted_severity": "critical" | "high" | "medium" | "low" | "info",
  "rationale": "<one or two sentences>",
  "recommended_action": "block" | "fix_soon" | "defer"
}

Rules:
- Be conservative: only mark false_positive when context clearly proves the finding cannot be exploited.
- Lower severity only when surrounding code adds a mitigating control (e.g. authn check, sanitization).
- Raise severity when surrounding code amplifies blast radius (e.g. user-controlled input flowing directly to the sink).
- Never invent CWE numbers, never claim certainty without supporting evidence in the snippet.`

// BuildTriagePrompt returns the system+user message pair for triage.
// Callers append the result to a Provider.Complete call.
func BuildTriagePrompt(ctx TriageContext) []Message {
	var b strings.Builder
	fmt.Fprintf(&b, "Finding %s — %s\n", ctx.RuleID, ctx.Title)
	if ctx.Severity != "" {
		fmt.Fprintf(&b, "Reported severity: %s\n", ctx.Severity)
	}
	if ctx.Confidence != "" {
		fmt.Fprintf(&b, "Confidence: %s\n", ctx.Confidence)
	}
	if ctx.BaseScore > 0 {
		fmt.Fprintf(&b, "Base score: %.1f\n", ctx.BaseScore)
	}
	if ctx.FilePath != "" {
		fmt.Fprintf(&b, "Location: %s", ctx.FilePath)
		if ctx.Line > 0 {
			fmt.Fprintf(&b, ":%d", ctx.Line)
		}
		b.WriteByte('\n')
	}
	if len(ctx.BusinessTags) > 0 {
		fmt.Fprintf(&b, "Business tags: %s\n", strings.Join(ctx.BusinessTags, ", "))
	}
	if ctx.Snippet != "" {
		b.WriteString("\nMatched snippet:\n```\n")
		b.WriteString(ctx.Snippet)
		if !strings.HasSuffix(ctx.Snippet, "\n") {
			b.WriteByte('\n')
		}
		b.WriteString("```\n")
	}
	if ctx.CodeContext != "" {
		b.WriteString("\nSurrounding code:\n```\n")
		b.WriteString(ctx.CodeContext)
		if !strings.HasSuffix(ctx.CodeContext, "\n") {
			b.WriteByte('\n')
		}
		b.WriteString("```\n")
	}
	b.WriteString("\nReturn the JSON triage assessment.")

	return []Message{
		{Role: RoleSystem, Content: triageSystemPrompt},
		{Role: RoleUser, Content: b.String()},
	}
}
