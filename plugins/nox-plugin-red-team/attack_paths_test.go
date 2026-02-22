package main

import (
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

func TestDetectAttackChainAuthToDataExposure(t *testing.T) {
	findings := []*pluginv1.Finding{
		{RuleId: "THREAT-001", Severity: sdk.SeverityMedium},
		{RuleId: "THREAT-004", Severity: sdk.SeverityHigh},
	}

	chains := detectAttackChains(findings)
	if len(chains) == 0 {
		t.Fatal("expected at least one attack chain for THREAT-001 + THREAT-004")
	}

	found := false
	for _, c := range chains {
		if c.RuleID == "REDTEAM-001" {
			found = true
			if c.Severity != sdk.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %v", c.Severity)
			}
			if c.BlastRadius != "full-application" {
				t.Errorf("expected full-application blast radius, got %q", c.BlastRadius)
			}
		}
	}
	if !found {
		t.Error("expected REDTEAM-001 chain")
	}
}

func TestDetectAttackChainPrivEsc(t *testing.T) {
	findings := []*pluginv1.Finding{
		{RuleId: "THREAT-001", Severity: sdk.SeverityMedium},
		{RuleId: "THREAT-005", Severity: sdk.SeverityHigh},
	}

	chains := detectAttackChains(findings)
	found := false
	for _, c := range chains {
		if c.RuleID == "REDTEAM-002" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected REDTEAM-002 privilege escalation chain")
	}
}

func TestDetectAttackChainSQLi(t *testing.T) {
	findings := []*pluginv1.Finding{
		{RuleId: "TAINT-001", Severity: sdk.SeverityHigh},
	}

	chains := detectAttackChains(findings)
	found := false
	for _, c := range chains {
		if c.RuleID == "REDTEAM-003" {
			found = true
			if c.BlastRadius != "database" {
				t.Errorf("expected database blast radius, got %q", c.BlastRadius)
			}
		}
	}
	if !found {
		t.Fatal("expected REDTEAM-003 SQL injection chain")
	}
}

func TestDetectAttackChainContainerEscape(t *testing.T) {
	findings := []*pluginv1.Finding{
		{RuleId: "KRUNT-002", Severity: sdk.SeverityHigh},
		{RuleId: "KRUNT-003", Severity: sdk.SeverityHigh},
	}

	chains := detectAttackChains(findings)
	found := false
	for _, c := range chains {
		if c.RuleID == "REDTEAM-004" {
			found = true
			if c.BlastRadius != "cluster" {
				t.Errorf("expected cluster blast radius, got %q", c.BlastRadius)
			}
		}
	}
	if !found {
		t.Fatal("expected REDTEAM-004 container escape chain")
	}
}

func TestDetectAttackChainCmdInjection(t *testing.T) {
	findings := []*pluginv1.Finding{
		{RuleId: "TAINT-002", Severity: sdk.SeverityHigh},
	}

	chains := detectAttackChains(findings)
	found := false
	for _, c := range chains {
		if c.RuleID == "REDTEAM-005" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected REDTEAM-005 command injection chain")
	}
}

func TestDetectAttackChainNone(t *testing.T) {
	findings := []*pluginv1.Finding{
		{RuleId: "DATA-001", Severity: sdk.SeverityLow},
	}

	chains := detectAttackChains(findings)
	if len(chains) != 0 {
		t.Errorf("expected no chains for unrelated findings, got %d", len(chains))
	}
}

func TestDetectAttackChainEmpty(t *testing.T) {
	chains := detectAttackChains(nil)
	if chains != nil {
		t.Errorf("expected nil for nil findings, got %v", chains)
	}
}

func TestDetectAttackChainNoDuplicates(t *testing.T) {
	// THREAT-001 + THREAT-004 triggers "auth bypass to data exposure"
	// and THREAT-001 + EXPLAIN-001 triggers "weak auth + missing rate limit"
	// Both use REDTEAM-001, but should deduplicate by name.
	findings := []*pluginv1.Finding{
		{RuleId: "THREAT-001"},
		{RuleId: "THREAT-004"},
		{RuleId: "EXPLAIN-001"},
	}

	chains := detectAttackChains(findings)

	names := make(map[string]int)
	for _, c := range chains {
		names[c.Message]++
	}
	for name, count := range names {
		if count > 1 {
			t.Errorf("duplicate chain: %q appeared %d times", name, count)
		}
	}
}
