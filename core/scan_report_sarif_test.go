package core

import (
	"encoding/json"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// A Reporter either embeds the rule catalog (Rules, for a library caller that
// asks for it) or only consults it (Declared, which nox's own surfaces use).
// Both must name a finding by the same descriptor, which needs the rule's
// declared severity: without it, a finding at its rule's own severity is
// reported under `<rule>/<severity>` by one and under `<rule>` by the other, and
// an alert uploaded from one would not match the other.
func TestSARIFReporterNamesAFindingAsTheCLIDoes(t *testing.T) {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{ID: "SEC-001", Version: "1", Description: "d",
		Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
		MatcherType: "regex", Pattern: "x"})

	ruleIDs := func(embed bool) []string {
		fs := findings.NewFindingSet()
		fs.Add(findings.Finding{RuleID: "SEC-001", Severity: findings.SeverityHigh, Message: "m",
			Location: findings.Location{FilePath: "a.go", StartLine: 1}})
		fs.Add(findings.Finding{RuleID: "SEC-001", Severity: findings.SeverityInfo, Message: "m",
			Location: findings.Location{FilePath: "b.go", StartLine: 1}})
		res := &ScanResult{Rules: rs, Findings: fs}
		rep := res.SARIFReporter("t")
		if embed {
			rep.Rules = res.Rules
		}
		data, err := rep.Generate(fs)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		var doc struct {
			Runs []struct {
				Results []struct {
					RuleID string `json:"ruleId"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		var ids []string
		for _, r := range doc.Runs[0].Results {
			ids = append(ids, r.RuleID)
		}
		return ids
	}

	cli, mcp := ruleIDs(true), ruleIDs(false)
	want := []string{"SEC-001", "SEC-001/info"}
	for name, got := range map[string][]string{"cli": cli, "mcp": mcp} {
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("%s ruleIds = %v, want %v", name, got, want)
		}
	}
}
