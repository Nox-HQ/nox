// Package assist provides optional LLM-based explanations of Hardline scan
// findings. It consumes a core.ScanResult and produces human-friendly
// explanations of what each finding means, why it matters, and how to fix it.
//
// The package is strictly side-effect-free: it never affects scan results and
// is opt-in only.
package assist

import (
	"encoding/json"
	"fmt"
	"os"
)

// ExplanationReport is the top-level output of the explain pipeline.
type ExplanationReport struct {
	SchemaVersion string               `json:"schema_version"`
	Explanations  []FindingExplanation `json:"explanations"`
	Summary       string               `json:"summary"`
	Usage         UsageStats           `json:"usage"`
	PluginContext *PluginContextInfo   `json:"plugin_context,omitempty"`
}

// PluginContextInfo records which plugin capabilities and enrichment tools
// were available during explanation generation.
type PluginContextInfo struct {
	Capabilities []string `json:"capabilities"`
	Enrichments  []string `json:"enrichment_tools,omitempty"`
}

// FindingExplanation holds the LLM-generated explanation for a single finding.
type FindingExplanation struct {
	FindingID   string   `json:"finding_id"`
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}

// UsageStats tracks LLM token consumption across all provider calls.
type UsageStats struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
	RequestCount     int `json:"request_count"`
}

// JSON returns the report as pretty-printed JSON bytes.
func (r *ExplanationReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// WriteFile writes the report to the given file path.
func (r *ExplanationReport) WriteFile(path string) error {
	data, err := r.JSON()
	if err != nil {
		return fmt.Errorf("marshalling explanation report: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
