package catalog

import (
	"strings"
	"testing"
)

// Every prefix the MCP summary used to collapse into "other" must now resolve
// to a real family. This is the drift the consolidation fixes: an agent sizing
// up a scan through the MCP summary previously saw these whole categories vanish.
func TestPreviouslyCollapsedPrefixesHaveRealFamilies(t *testing.T) {
	cases := map[string]string{
		"CRYPTO-001":    "weak-crypto",
		"TAINT-004":     "taint-flow",
		"PROV-002":      "provenance",
		"LIC-001":       "license",
		"SLOP-003":      "slopsquatting",
		"VARIANT-010":   "cve-variants",
		"REACH-001":     "reachability",
		"HARDEN-002":    "transport-security",
		"AGENTFLOW-001": "agentic-dataflow",
	}
	for ruleID, wantKey := range cases {
		if got := Family(ruleID).Key; got != wantKey {
			t.Errorf("Family(%q).Key = %q, want %q (this prefix used to collapse to \"other\")", ruleID, got, wantKey)
		}
		if got := Family(ruleID).Key; got == "other" {
			t.Errorf("%s still falls to \"other\"", ruleID)
		}
	}
}

// The specific-before-generic ordering must hold: an AI prompt-injection or
// embedding rule must NOT be swallowed by the generic AI family, which is
// exactly what the MCP's split-on-first-dash did.
func TestAISubfamiliesAreNotSwallowed(t *testing.T) {
	cases := map[string]string{
		"AI-PI-001":    "ai-prompt-injection",
		"AI-EMBED-002": "ai-embedding",
		"AI-AGENT-003": "ai-agent-lattice",
		"AI-999":       "ai", // generic AI falls through to the base family
	}
	for ruleID, wantKey := range cases {
		if got := Family(ruleID).Key; got != wantKey {
			t.Errorf("Family(%q).Key = %q, want %q", ruleID, got, wantKey)
		}
	}
	// AGENTFLOW must not be swallowed by AGENT.
	if got := Family("AGENTFLOW-001").Key; got != "agentic-dataflow" {
		t.Errorf("AGENTFLOW-001 = %q, want agentic-dataflow (AGENT- must not swallow it)", got)
	}
	if got := Family("AGENT-003").Key; got != "agent-config" {
		t.Errorf("AGENT-003 = %q, want agent-config", got)
	}
}

// AI family labels carry the OWASP LLM (2025) category, sourced from the
// canonical catalog. Pin the current edition so a future accidental regression
// to the 2023 numbers (LLM06 for embedding, LLM07 for agent lattice) fails here.
func TestAIFamilyLabelsUse2025LLMNumbers(t *testing.T) {
	if !strings.Contains(Family("AI-EMBED-001").Label, string(LLM08VectorEmbedding)) {
		t.Errorf("AI-EMBED label = %q, want the 2025 LLM08 number", Family("AI-EMBED-001").Label)
	}
	if !strings.Contains(Family("AI-AGENT-001").Label, string(LLM06ExcessiveAgency)) {
		t.Errorf("AI-AGENT label = %q, want the 2025 LLM06 number", Family("AI-AGENT-001").Label)
	}
	if !strings.Contains(Family("AI-PI-001").Label, string(LLM01PromptInjection)) {
		t.Errorf("AI-PI label = %q, want LLM01", Family("AI-PI-001").Label)
	}
}

func TestUnknownPrefixFallsToOther(t *testing.T) {
	f := Family("WIDGET-001")
	if f.Key != "other" || f.Label != "Other" {
		t.Errorf("unknown prefix = %+v, want other/Other", f)
	}
}

// Key and Label must both be populated for every catalogued family, and keys
// must be unique so the MCP by_family map cannot silently merge two families.
func TestFamilyTableIsWellFormed(t *testing.T) {
	seenKey := map[string]bool{}
	for _, r := range familyRules {
		if r.family.Key == "" || r.family.Label == "" {
			t.Errorf("prefix %q has an incomplete family %+v", r.prefix, r.family)
		}
		if seenKey[r.family.Key] {
			t.Errorf("duplicate family key %q — two prefixes would merge in by_family", r.family.Key)
		}
		seenKey[r.family.Key] = true
		if !strings.HasSuffix(r.prefix, "-") {
			t.Errorf("prefix %q should end with a dash", r.prefix)
		}
	}
}
