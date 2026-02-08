package assist

import (
	"context"
	"encoding/json"
	"fmt"

	core "github.com/felixgeelhaar/hardline/core"
)

const defaultBatchSize = 10

// Explainer orchestrates LLM-based explanation of scan findings. It batches
// findings, sends them to a Provider, and assembles an ExplanationReport.
type Explainer struct {
	provider  Provider
	batchSize int
}

// Option configures an Explainer.
type Option func(*Explainer)

// WithBatchSize sets how many findings are sent per LLM call (default 10).
func WithBatchSize(n int) Option {
	return func(e *Explainer) {
		if n > 0 {
			e.batchSize = n
		}
	}
}

// NewExplainer creates an Explainer with the given provider and options.
func NewExplainer(provider Provider, opts ...Option) *Explainer {
	e := &Explainer{
		provider:  provider,
		batchSize: defaultBatchSize,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Explain analyses all findings in the scan result and returns an
// ExplanationReport with per-finding explanations and an executive summary.
//
// If the provider returns an error for a batch, the explainer degrades
// gracefully: it returns the explanations gathered so far and records the
// error in the summary field.
func (e *Explainer) Explain(ctx context.Context, result *core.ScanResult) (*ExplanationReport, error) {
	report := &ExplanationReport{
		SchemaVersion: "1.0.0",
	}

	ff := result.Findings.Findings()
	if len(ff) == 0 {
		report.Summary = "No findings to explain."
		return report, nil
	}

	ctxMsg := formatContext(result)
	sysMsgs := []Message{
		{Role: RoleSystem, Content: systemPrompt()},
		{Role: RoleUser, Content: ctxMsg},
	}

	var providerErr error

	// Process findings in batches.
	for i := 0; i < len(ff); i += e.batchSize {
		end := i + e.batchSize
		if end > len(ff) {
			end = len(ff)
		}
		batch := ff[i:end]

		messages := make([]Message, len(sysMsgs)+1)
		copy(messages, sysMsgs)
		messages[len(sysMsgs)] = Message{
			Role:    RoleUser,
			Content: "Explain these findings:\n\n" + formatFindings(batch),
		}

		resp, err := e.provider.Complete(ctx, messages)
		if err != nil {
			providerErr = err
			break
		}

		report.Usage.PromptTokens += resp.PromptTokens
		report.Usage.CompletionTokens += resp.CompletionTokens
		report.Usage.TotalTokens += resp.PromptTokens + resp.CompletionTokens
		report.Usage.RequestCount++

		explanations, err := parseExplanations(resp.Content)
		if err != nil {
			providerErr = fmt.Errorf("parsing LLM response: %w", err)
			break
		}

		report.Explanations = append(report.Explanations, explanations...)
	}

	// Generate summary.
	if providerErr != nil {
		report.Summary = fmt.Sprintf("Partial results: %d of %d findings explained. Error: %v",
			len(report.Explanations), len(ff), providerErr)
	} else if len(report.Explanations) > 0 {
		summary, err := e.generateSummary(ctx, report.Explanations)
		if err != nil {
			report.Summary = fmt.Sprintf("Generated explanations for %d findings. Summary generation failed: %v",
				len(report.Explanations), err)
		} else {
			report.Summary = summary
			// Usage from summary call is already counted inside generateSummary.
		}
	}

	return report, nil
}

// generateSummary asks the provider for an executive summary of all
// explained findings.
func (e *Explainer) generateSummary(ctx context.Context, explanations []FindingExplanation) (string, error) {
	messages := []Message{
		{Role: RoleSystem, Content: "You are a security expert summarising scan results."},
		{Role: RoleUser, Content: summaryPrompt(explanations)},
	}

	resp, err := e.provider.Complete(ctx, messages)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

// parseExplanations extracts FindingExplanation values from the LLM's JSON
// response.
func parseExplanations(raw string) ([]FindingExplanation, error) {
	var explanations []FindingExplanation
	if err := json.Unmarshal([]byte(raw), &explanations); err != nil {
		return nil, fmt.Errorf("invalid JSON from LLM: %w", err)
	}
	return explanations, nil
}
