package main

import (
	"fmt"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

// attackChain represents a detected multi-step attack path.
type attackChain struct {
	RuleID      string
	Severity    pluginv1.Severity
	Message     string
	Steps       string
	BlastRadius string
}

// chainPattern defines a pattern for detecting attack chains from combinations of findings.
type chainPattern struct {
	RuleID      string
	Name        string
	Severity    pluginv1.Severity
	Required    []string // rule IDs that must all be present
	Steps       string
	BlastRadius string
}

var chainPatterns = []chainPattern{
	{
		RuleID:      "REDTEAM-001",
		Name:        "Authentication bypass to data exposure",
		Severity:    sdk.SeverityCritical,
		Required:    []string{"THREAT-001", "THREAT-004"},
		Steps:       "1. Exploit weak authentication (THREAT-001)\n2. Access sensitive data endpoints\n3. Extract exposed data (THREAT-004)",
		BlastRadius: "full-application",
	},
	{
		RuleID:      "REDTEAM-002",
		Name:        "Privilege escalation via weak auth and role assignment",
		Severity:    sdk.SeverityHigh,
		Required:    []string{"THREAT-001", "THREAT-005"},
		Steps:       "1. Bypass authentication (THREAT-001)\n2. Escalate to admin role (THREAT-005)\n3. Access all protected resources",
		BlastRadius: "full-application",
	},
	{
		RuleID:      "REDTEAM-003",
		Name:        "SQL injection to data exfiltration",
		Severity:    sdk.SeverityHigh,
		Required:    []string{"TAINT-001"},
		Steps:       "1. Identify SQL injection point (TAINT-001)\n2. Enumerate database schema\n3. Extract sensitive data via UNION/blind injection",
		BlastRadius: "database",
	},
	{
		RuleID:      "REDTEAM-004",
		Name:        "Container escape via privileged container and host namespace",
		Severity:    sdk.SeverityHigh,
		Required:    []string{"KRUNT-002", "KRUNT-003"},
		Steps:       "1. Exploit privileged container (KRUNT-002)\n2. Access host namespace (KRUNT-003)\n3. Pivot to other workloads",
		BlastRadius: "cluster",
	},
	{
		RuleID:      "REDTEAM-005",
		Name:        "Authentication bypass via command injection",
		Severity:    sdk.SeverityCritical,
		Required:    []string{"TAINT-002"},
		Steps:       "1. Identify command injection point (TAINT-002)\n2. Execute arbitrary commands\n3. Bypass authentication and access controls",
		BlastRadius: "server",
	},
	{
		RuleID:      "REDTEAM-001",
		Name:        "Multi-step: weak auth + missing rate limit",
		Severity:    sdk.SeverityCritical,
		Required:    []string{"EXPLAIN-001", "THREAT-001"},
		Steps:       "1. Identify weak authentication (EXPLAIN-001)\n2. Exploit authentication bypass (THREAT-001)\n3. Brute force credentials without rate limiting",
		BlastRadius: "user-accounts",
	},
	{
		RuleID:      "REDTEAM-003",
		Name:        "Data exfiltration via XSS and data exposure",
		Severity:    sdk.SeverityHigh,
		Required:    []string{"TAINT-003", "THREAT-004"},
		Steps:       "1. Inject XSS payload (TAINT-003)\n2. Capture exposed sensitive data (THREAT-004)\n3. Exfiltrate via attacker-controlled endpoint",
		BlastRadius: "user-sessions",
	},
}

// detectAttackChains analyzes findings to identify multi-step attack chains.
func detectAttackChains(findings []*pluginv1.Finding) []attackChain {
	if len(findings) == 0 {
		return nil
	}

	ruleSet := make(map[string]bool)
	for _, f := range findings {
		ruleSet[f.GetRuleId()] = true
	}

	seen := make(map[string]bool)
	var chains []attackChain

	for _, pattern := range chainPatterns {
		allPresent := true
		for _, req := range pattern.Required {
			if !ruleSet[req] {
				allPresent = false
				break
			}
		}
		if !allPresent {
			continue
		}

		key := pattern.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		chains = append(chains, attackChain{
			RuleID:      pattern.RuleID,
			Severity:    pattern.Severity,
			Message:     fmt.Sprintf("Multi-step attack chain detected: %s (involves %s)", pattern.Name, strings.Join(pattern.Required, ", ")),
			Steps:       pattern.Steps,
			BlastRadius: pattern.BlastRadius,
		})
	}

	return chains
}
