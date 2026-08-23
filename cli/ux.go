package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/catalog"

	"github.com/nox-hq/nox/core/findings"
)

// familyOf maps a rule ID to a human-readable family label. Operators
// see family labels rather than 11 distinct rule-ID prefixes; the
// prefixes themselves stay stable for tooling that joins on RuleID.
func familyOf(ruleID string) string { return catalog.Family(ruleID).Label }

// familySummary returns a one-line "Secrets:23, Infrastructure:12, ..." // nox:ignore SEC-163 -- code comment
// breakdown of active findings sorted by descending count. Returns "" on
// empty input.
func familySummary(items []findings.Finding) string {
	if len(items) == 0 {
		return ""
	}
	counts := map[string]int{}
	for i := range items {
		counts[familyOf(items[i].RuleID)]++
	}

	type kv struct {
		family string
		count  int
	}
	pairs := make([]kv, 0, len(counts))
	for f, c := range counts {
		pairs = append(pairs, kv{f, c})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].family < pairs[j].family
	})

	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s:%d", p.family, p.count))
	}
	return strings.Join(parts, ", ")
}

// printNextStepTips surfaces actionable follow-ups based on what the
// scan produced. Tips fire only when the relevant signal is present so
// repeat operators don't see noise.
func printNextStepTips(items []findings.Finding, outputDir string) {
	if len(items) == 0 {
		return
	}

	hasFixable := 0
	hasVuln := false
	for i := range items {
		f := &items[i]
		if f.RuleID == "VULN-001" {
			hasVuln = true
			if f.Metadata["fixed_in"] != "" {
				hasFixable++
			}
		}
	}

	if hasFixable > 0 {
		fmt.Printf("[tip] %d dependency findings have a fixed_in version. Apply with:\n", hasFixable)
		fmt.Printf("      nox fix --input %s/findings.json --dry-run\n", outputDir)
	}
	if hasVuln {
		fmt.Printf("[tip] Baseline these findings as OpenVEX waivers:\n")
		fmt.Printf("      nox vex init --input %s/findings.json\n", outputDir)
	}
	fmt.Printf("[tip] Block future regressions in CI with a pre-commit hook:\n")
	fmt.Printf("      nox install-hook\n")
}
