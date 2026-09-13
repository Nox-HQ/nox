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
// Consumed by scripts/secret-rule-inventory.py; see
// docs/design/secret-rule-inventory.md.
func TestDumpRuleSet(t *testing.T) {
	path := os.Getenv("NOX_RULE_DUMP")
	if path == "" {
		t.Skip("set NOX_RULE_DUMP=<path> to dump the built rule set")
	}
	type dumped struct {
		ID                     string   `json:"id"`
		Description            string   `json:"description"`
		Pattern                string   `json:"pattern"`
		MatcherType            string   `json:"matcher_type"`
		Keywords               []string `json:"keywords"`
		RequireContextKeywords []string `json:"require_context_keywords"`
		ExcludeContextKeywords []string `json:"exclude_context_keywords"`
		HasValidateMatch       bool     `json:"has_validate_match"`
		Severity               string   `json:"severity"`
		Confidence             string   `json:"confidence"`
		Tags                   []string `json:"tags"`
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
