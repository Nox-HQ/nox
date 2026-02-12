package compliance

import (
	"testing"
)

func TestGetMappings(t *testing.T) {
	mappings := GetMappings()

	if len(mappings) == 0 {
		t.Fatal("expected non-empty mappings")
	}

	// Verify some known rules have mappings.
	for _, ruleID := range []string{"SEC-001", "IAC-004", "VULN-001", "AI-001"} {
		if _, ok := mappings[ruleID]; !ok {
			t.Errorf("expected mapping for %s", ruleID)
		}
	}
}

func TestFilterByFramework(t *testing.T) {
	mappings := GetMappings()

	pci := FilterByFramework(PCIDSS, mappings)
	if len(pci) == 0 {
		t.Fatal("expected PCI-DSS mappings")
	}

	// All returned controls should be PCI-DSS.
	for ruleID, controls := range pci {
		for _, c := range controls {
			if c.Framework != PCIDSS {
				t.Errorf("rule %s: expected PCI-DSS, got %s", ruleID, c.Framework)
			}
		}
	}
}

func TestFilterByFramework_CaseInsensitive(t *testing.T) {
	mappings := GetMappings()

	// Use lowercase.
	result := FilterByFramework("pci-dss", mappings)
	if len(result) == 0 {
		t.Error("expected case-insensitive matching to work")
	}
}

func TestRulesForFramework(t *testing.T) {
	rules := RulesForFramework(OWASPTop)
	if len(rules) == 0 {
		t.Fatal("expected OWASP Top 10 rules")
	}

	// Check that a known rule is in the list.
	found := false
	for _, r := range rules {
		if r == "VULN-001" {
			found = true
		}
	}
	if !found {
		t.Error("expected VULN-001 in OWASP Top 10 rules")
	}
}

func TestGenerateReport(t *testing.T) {
	triggered := []string{"SEC-001", "IAC-004", "VULN-001"}

	report := GenerateReport(PCIDSS, triggered)

	if report.Framework != PCIDSS {
		t.Errorf("expected PCI-DSS framework, got %s", report.Framework)
	}

	if report.TotalControls == 0 {
		t.Error("expected non-zero total controls")
	}

	if len(report.Violations) == 0 {
		t.Error("expected violations for triggered rules")
	}

	// Verify at least one violation has rule IDs.
	foundRules := false
	for _, v := range report.Violations {
		if len(v.RuleIDs) > 0 {
			foundRules = true
		}
	}
	if !foundRules {
		t.Error("expected violations to contain rule IDs")
	}
}

func TestGenerateReport_NoViolations(t *testing.T) {
	report := GenerateReport(PCIDSS, []string{"NONEXISTENT-RULE"})

	if len(report.Violations) != 0 {
		t.Error("expected no violations for non-matching rules")
	}
}

func TestSupportedFrameworks(t *testing.T) {
	if len(SupportedFrameworks) != 6 {
		t.Errorf("expected 6 supported frameworks, got %d", len(SupportedFrameworks))
	}
}
