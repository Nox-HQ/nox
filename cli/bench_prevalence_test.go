package main

import "testing"

// Raw fire count ranks the corpus as much as the rule.
//
// crewAI carries its documentation in four languages across two released
// versions, so one matched line in one authored page is counted eight times.
// Ranked on raw findings, a docs-matching rule outranks a rule that fires once
// in every repository scanned -- and the second is the one that is wrong on
// real software.
//
// Measured on the pinned corpus: AI-022 reported `temperature=0.8` 224 times,
// which is the same handful of authored lines multiplied by locale and version
// copies; DATA-001 reported 969 findings over 177 distinct addresses.
//
// AI-022 has since been removed (docs/design/ai-rule-proposition.md), which is
// itself the point: on the raw ranking it looked like the fourth-worst rule in
// the scanner, and the corrected ranking put it twelfth. Its sample counts are
// kept here as fixture data because they are the measurement that showed the
// two rankings disagree.

func TestNormaliseSitePathCollapsesLocaleAndVersion(t *testing.T) {
	same := []string{
		"docs/edge/ar/tools/ai-ml/daytona.mdx",
		"docs/edge/en/tools/ai-ml/daytona.mdx",
		"docs/edge/ko/tools/ai-ml/daytona.mdx",
		"docs/edge/pt-BR/tools/ai-ml/daytona.mdx",
		"docs/v1.14.4/en/tools/ai-ml/daytona.mdx",
		"docs/1.10.0/zh-Hans/tools/ai-ml/daytona.mdx",
		"docs/latest/tools/ai-ml/daytona.mdx",
	}
	want := normaliseSitePath(same[0])
	for _, p := range same[1:] {
		if got := normaliseSitePath(p); got != want {
			t.Errorf("normaliseSitePath(%q) = %q, want %q — translated and versioned "+
				"copies of one authored page must collapse to one site", p, got, want)
		}
	}
	if want != "docs/tools/ai-ml/daytona.mdx" {
		t.Errorf("collapsed path = %q, want docs/tools/ai-ml/daytona.mdx", want)
	}
}

// TestNormaliseSitePathKeepsOrdinaryDirectories. The collapse must not eat a
// real directory that happens to be short.
func TestNormaliseSitePathKeepsOrdinaryDirectories(t *testing.T) {
	for _, p := range []string{
		"src/ui/button.ts",
		"internal/db/conn.go",
		"pkg/io/reader.go",
		"lib/crewai/tests/cassettes/test_x.yaml",
	} {
		if got := normaliseSitePath(p); got != p {
			t.Errorf("normaliseSitePath(%q) = %q — an ordinary directory was dropped", p, got)
		}
	}
}

// TestDistinctPathsStayDistinct guards the other direction: two genuinely
// different pages must not collapse into one site.
func TestDistinctPathsStayDistinct(t *testing.T) {
	a := normaliseSitePath("docs/en/tools/daytona.mdx")
	b := normaliseSitePath("docs/en/tools/serper.mdx")
	if a == b {
		t.Errorf("two different pages collapsed to the same site: %q", a)
	}
}

// TestPrevalenceCarriesAllThreeNumbers. A report that serialises only findings
// invites ranking on the number that measures the corpus.
func TestPrevalenceCarriesAllThreeNumbers(t *testing.T) {
	report := BenchReport{
		Projects: []ProjectSummary{
			{ByRule: map[string]int{"AI-022": 224}, BySite: map[string]int{"AI-022": 28}},
			{ByRule: map[string]int{"AI-022": 8}, BySite: map[string]int{"AI-022": 8}},
			{ByRule: map[string]int{"SEC-161": 3}, BySite: map[string]int{"SEC-161": 3}},
		},
	}
	aggregateRuleFireRates(&report)
	got := report.RulePrevalence["AI-022"]
	if got == nil {
		t.Fatal("no prevalence recorded")
	}
	if got.Repos != 2 || got.Findings != 232 || got.Sites != 36 {
		t.Errorf("AI-022 prevalence = %+v, want {Repos:2 Findings:232 Sites:36}", *got)
	}
	if report.RuleFireRate["AI-022"] != 2 {
		t.Errorf("rule_fire_rate = %d, want 2 (it counts repositories)", report.RuleFireRate["AI-022"])
	}
}
