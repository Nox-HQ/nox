package catalog

import "strings"

// RuleFamily groups a rule ID into a category for display and aggregation.
//
// It exists as one function because two entry points grouped findings by family
// and had drifted badly apart: the CLI summary knew twenty-one families while
// the MCP summary knew six and collapsed everything else — weak crypto, taint
// flow, provenance, license, slopsquatting, reachability — into "other". Worse,
// the MCP split on the first dash, so AI-PI-001 lost its prompt-injection family
// and TAINT-001 fell through entirely. An agent sizing up a scan through the MCP
// summary saw whole security categories vanish into an opaque bucket. One
// taxonomy, here, ends that.
type RuleFamily struct {
	// Key is the lowercase slug for machine-readable output (the MCP summary's
	// by_family map).
	Key string
	// Label is the human title for the CLI summary line.
	Label string
}

// familyRule maps a rule-ID prefix to its family. Order matters: the more
// specific AI-PI-/AI-EMBED-/AI-AGENT- and AGENTFLOW- prefixes must be tested
// before the shorter AI-/AGENT- ones, so a prompt-injection rule is not
// swallowed by the generic AI family. This is exactly the distinction the MCP's
// split-on-first-dash destroyed.
type familyRule struct {
	prefix string
	family RuleFamily
}

// familyRules is the canonical prefix->family table, most-specific first.
var familyRules = []familyRule{
	{"SEC-", RuleFamily{"secrets", "Secrets"}},
	{"DATA-", RuleFamily{"privacy", "Privacy / PII"}},
	{"IAC-", RuleFamily{"infrastructure", "Infrastructure"}},
	{"CONT-", RuleFamily{"containers", "Container"}},
	{"VULN-", RuleFamily{"dependencies", "Dependencies"}},
	{"VARIANT-", RuleFamily{"cve-variants", "CVE Variants"}},
	{"PROV-", RuleFamily{"provenance", "Provenance"}},
	{"LIC-", RuleFamily{"license", "License"}},
	{"SLOP-", RuleFamily{"slopsquatting", "Slopsquatting"}},
	{"AGENTFLOW-", RuleFamily{"agentic-dataflow", "Agentic Dataflow"}},
	{"AGENT-", RuleFamily{"agent-config", "Agent Config"}},
	{"MCP-", RuleFamily{"mcp-hardening", "MCP Hardening"}},
	// AI families carry their OWASP LLM (2025) category in the label, sourced
	// from the canonical catalog so the numbering cannot drift from the rest of
	// the codebase — the AI-EMBED and AI-AGENT numbers here were stale (LLM06 /
	// LLM07, the 2023 edition) before consolidation.
	{"AI-PI-", RuleFamily{"ai-prompt-injection", "AI / Prompt Injection (" + string(LLM01PromptInjection) + ")"}},
	{"AI-EMBED-", RuleFamily{"ai-embedding", "AI / Embedding Leakage (" + string(LLM08VectorEmbedding) + ")"}},
	{"AI-AGENT-", RuleFamily{"ai-agent-lattice", "AI / Agent Lattice (" + string(LLM06ExcessiveAgency) + ")"}},
	{"AI-", RuleFamily{"ai", "AI Security"}},
	{"REACH-", RuleFamily{"reachability", "Reachability"}},
	{"TAINT-", RuleFamily{"taint-flow", "Taint Flow"}},
	{"HARDEN-", RuleFamily{"transport-security", "Transport Security"}},
	{"CRYPTO-", RuleFamily{"weak-crypto", "Weak Crypto"}},
	{"PERM-", RuleFamily{"file-permissions", "File Permissions"}},
	{"MEMSAFE-", RuleFamily{"memory-safety", "Memory Safety"}},
}

// unknownFamily is the fallback for a rule whose prefix is not catalogued. It is
// "other", but a rule landing here is a signal that familyRules needs an entry —
// see TestNoBuiltinRuleFallsToOther, which fails if a shipped rule has no family.
var unknownFamily = RuleFamily{"other", "Other"}

// Family returns the family a rule ID belongs to. The match is the first
// prefix in familyRules the ID starts with, so specificity is decided by table
// order, not by string length.
func Family(ruleID string) RuleFamily {
	for _, r := range familyRules {
		if strings.HasPrefix(ruleID, r.prefix) {
			return r.family
		}
	}
	return unknownFamily
}
