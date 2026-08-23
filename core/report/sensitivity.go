package report

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// DataRuleStats counts one DATA-* rule's findings and the unique files it
// touched.
type DataRuleStats struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Count       int      `json:"count"`
	Files       []string `json:"files"`
}

// DataSensitivityReport is the PII / sensitive-data projection over a scan's
// findings: the DATA-* findings grouped by rule, and the set of files they
// touch.
type DataSensitivityReport struct {
	TotalFindings int             `json:"total_findings"`
	Rules         []DataRuleStats `json:"rules"`
	AffectedFiles []string        `json:"affected_files"`
}

// BuildDataSensitivityReport groups a scan's DATA-* findings by rule, with unique
// per-rule and overall file lists, in deterministic order.
//
// It lived only inside the MCP handler, so this business projection — the
// DATA- prefix, the per-rule file dedup, the sort that makes the output
// deterministic — could not be tested outside MCP or reused by any other
// surface. The rule DESCRIPTION source is injected (describe) rather than
// imported, so the projection stays a pure findings transform: the caller wires
// in the catalog, and core does not gain a dependency on it.
func BuildDataSensitivityReport(ff []findings.Finding, describe func(ruleID string) string) DataSensitivityReport {
	byRule := map[string]*DataRuleStats{}
	seenPerRule := map[string]map[string]bool{}
	allFiles := map[string]bool{}

	for i := range ff {
		f := &ff[i]
		if !strings.HasPrefix(f.RuleID, "DATA-") {
			continue
		}
		rs, ok := byRule[f.RuleID]
		if !ok {
			desc := f.RuleID
			if describe != nil {
				if d := describe(f.RuleID); d != "" {
					desc = d
				}
			}
			rs = &DataRuleStats{RuleID: f.RuleID, Description: desc}
			byRule[f.RuleID] = rs
			seenPerRule[f.RuleID] = map[string]bool{}
		}
		rs.Count++

		fp := f.Location.FilePath
		allFiles[fp] = true
		if !seenPerRule[f.RuleID][fp] {
			seenPerRule[f.RuleID][fp] = true
			rs.Files = append(rs.Files, fp)
		}
	}

	rules := make([]DataRuleStats, 0, len(byRule))
	total := 0
	for _, rs := range byRule {
		sort.Strings(rs.Files)
		rules = append(rules, *rs)
		total += rs.Count
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })

	affected := make([]string, 0, len(allFiles))
	for fp := range allFiles {
		affected = append(affected, fp)
	}
	sort.Strings(affected)

	return DataSensitivityReport{TotalFindings: total, Rules: rules, AffectedFiles: affected}
}
