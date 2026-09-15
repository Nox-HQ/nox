package secrets

import (
	"encoding/json"
	"os"
	"testing"
)

// TestDumpRuleSet writes the BUILT secret rule set for offline analysis.
//
//	NOX_RULE_DUMP=/tmp/secrules.json go test ./core/analyzers/secrets -run TestDumpRuleSet
//
// It exists because the alternative — extracting rules from source text with
// regexes — gave wrong answers twice while the secret-rule inventory was being
// built: it paired one rule's `id:` with a different rule's `pattern:`, and it
// found 3 English-word keywords where the built set has 11. Source text is not
// the rule set. Anything reasoning about what rules actually do must read them
// from the engine that runs them.
//
// It dumps EVERY field that can change what a rule matches. Three separate
// wrong conclusions in this workstream came from a dump that omitted one:
// RequireContextKeywords (so proximity-gated rules read as file-gated), then
// Metadata (so SEC-161's 5.0-bit threshold and candidate_kinds were invisible
// and it was filed as a bare-token rule). A partial dump does not produce a
// partial answer, it produces a confident wrong one.
//
// Consumed by scripts/secret-rule-inventory.py; see
// docs/design/secret-rule-inventory.md.
func TestDumpRuleSet(t *testing.T) {
	path := os.Getenv("NOX_RULE_DUMP")
	if path == "" {
		t.Skip("set NOX_RULE_DUMP=<path> to dump the built rule set")
	}
	type dumped struct {
		ID                     string            `json:"id"`
		Description            string            `json:"description"`
		Pattern                string            `json:"pattern"`
		MatcherType            string            `json:"matcher_type"`
		Keywords               []string          `json:"keywords"`
		RequireContextKeywords []string          `json:"require_context_keywords"`
		ExcludeContextKeywords []string          `json:"exclude_context_keywords"`
		HasValidateMatch       bool              `json:"has_validate_match"`
		Severity               string            `json:"severity"`
		Confidence             string            `json:"confidence"`
		Tags                   []string          `json:"tags"`
		Metadata               map[string]string `json:"metadata"`
		FilePatterns           []string          `json:"file_patterns"`
		IgnoreFilePatterns     []string          `json:"ignore_file_patterns"`
		IgnoreInComments       bool              `json:"ignore_in_comments"`
		Version                string            `json:"version"`
		Remediation            string            `json:"remediation"`
	}
	var out []dumped
	for _, r := range NewAnalyzer().Rules().Rules() {
		out = append(out, dumped{
			ID: r.ID, Description: r.Description, Pattern: r.Pattern,
			MatcherType: r.MatcherType, Keywords: r.Keywords,
			RequireContextKeywords: r.RequireContextKeywords,
			ExcludeContextKeywords: r.ExcludeContextKeywords,
			HasValidateMatch:       r.ValidateMatch != nil,
			Severity:               string(r.Severity),
			Confidence:             string(r.Confidence),
			Tags:                   r.Tags,
			Metadata:               r.Metadata,
			FilePatterns:           r.FilePatterns,
			IgnoreFilePatterns:     r.IgnoreFilePatterns,
			IgnoreInComments:       r.IgnoreInComments,
			Version:                r.Version,
			Remediation:            r.Remediation,
		})
	}
	if len(out) == 0 {
		t.Fatal("the built rule set is empty; the dump would describe nothing")
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d rules to %s", len(out), path)
}
