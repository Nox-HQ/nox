package vex

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestLoadVEX(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vex.json")
	data := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "test-vex",
		"statements": [
			{
				"vulnerability": "CVE-2024-1234",
				"status": "not_affected",
				"justification": "component_not_present"
			},
			{
				"vulnerability": "CVE-2024-5678",
				"status": "under_investigation"
			}
		]
	}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	doc, err := LoadVEX(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(doc.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(doc.Statements))
	}

	if doc.Statements[0].VulnerabilityID != "CVE-2024-1234" {
		t.Errorf("unexpected vuln ID: %s", doc.Statements[0].VulnerabilityID)
	}

	if doc.Statements[0].Status != StatusNotAffected {
		t.Errorf("unexpected status: %s", doc.Statements[0].Status)
	}
}

func TestLoadVEX_FileNotFound(t *testing.T) {
	_, err := LoadVEX("/nonexistent/vex.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadVEX_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{invalid`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadVEX(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestApplyVEX(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:   "VULN-001",
		Severity: findings.SeverityHigh,
		Message:  "CVE-2024-1234 in lodash@4.17.20",
		Metadata: map[string]string{
			"vuln_id":   "GHSA-xxxx",
			"aliases":   "CVE-2024-1234",
			"package":   "lodash",
			"version":   "4.17.20",
			"ecosystem": "npm",
		},
		Location: findings.Location{FilePath: "package-lock.json", StartLine: 1},
	})
	fs.Add(findings.Finding{
		RuleID:   "VULN-001",
		Severity: findings.SeverityMedium,
		Message:  "CVE-2024-9999 in express@4.0",
		Metadata: map[string]string{
			"vuln_id":   "CVE-2024-9999",
			"package":   "express",
			"version":   "4.0",
			"ecosystem": "npm",
		},
		Location: findings.Location{FilePath: "package-lock.json", StartLine: 2},
	})
	fs.Add(findings.Finding{
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Message:  "AWS key detected",
		Location: findings.Location{FilePath: "config.env", StartLine: 3},
	})

	doc := &Document{
		Statements: []Statement{
			{VulnerabilityID: "CVE-2024-1234", Status: StatusNotAffected, Justification: "inline_mitigations_already_exist"},
			{VulnerabilityID: "CVE-2024-5678", Status: StatusFixed},
		},
	}

	applied := ApplyVEX(fs, doc)

	if applied != 1 {
		t.Errorf("expected 1 applied, got %d", applied)
	}

	items := fs.Findings()
	if items[0].Status != findings.StatusVEXNotAffected {
		t.Errorf("expected VEX not_affected status, got %q", items[0].Status)
	}

	// Second VULN-001 should be unchanged (no matching VEX statement).
	if items[1].Status == findings.StatusVEXNotAffected {
		t.Error("second finding should not be VEX-marked")
	}

	// SEC-001 should be unchanged.
	if items[2].Status == findings.StatusVEXNotAffected {
		t.Error("non-VULN finding should not be VEX-marked")
	}
}

func TestApplyVEX_NilDocument(t *testing.T) {
	fs := findings.NewFindingSet()
	applied := ApplyVEX(fs, nil)
	if applied != 0 {
		t.Errorf("expected 0 applied, got %d", applied)
	}
}

func TestApplyVEX_UnderInvestigation(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:   "VULN-001",
		Severity: findings.SeverityHigh,
		Message:  "CVE-2024-5678",
		Metadata: map[string]string{"vuln_id": "CVE-2024-5678"},
		Location: findings.Location{FilePath: "go.sum", StartLine: 1},
	})

	doc := &Document{
		Statements: []Statement{
			{VulnerabilityID: "CVE-2024-5678", Status: StatusUnderInvestigation},
		},
	}

	applied := ApplyVEX(fs, doc)
	if applied != 1 {
		t.Errorf("expected 1 applied, got %d", applied)
	}

	if fs.Findings()[0].Status != findings.StatusVEXUnderInvestigation {
		t.Errorf("expected under_investigation status, got %q", fs.Findings()[0].Status)
	}
}

func TestSummary(t *testing.T) {
	doc := &Document{
		Statements: []Statement{
			{VulnerabilityID: "CVE-1", Status: StatusNotAffected},
			{VulnerabilityID: "CVE-2", Status: StatusNotAffected},
			{VulnerabilityID: "CVE-3", Status: StatusFixed},
		},
	}

	s := Summary(doc)
	if s == "" {
		t.Error("expected non-empty summary")
	}

	if Summary(nil) != "no VEX document" {
		t.Error("expected nil doc message")
	}
}

func TestCollectVulnIDs(t *testing.T) {
	f := findings.Finding{
		Metadata: map[string]string{
			"vuln_id": "GHSA-xxxx",
			"aliases": "CVE-2024-1234,CVE-2024-5678",
		},
	}

	ids := collectVulnIDs(&f)
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(ids))
	}

	// No metadata.
	f2 := findings.Finding{}
	ids2 := collectVulnIDs(&f2)
	if len(ids2) != 0 {
		t.Errorf("expected 0 IDs, got %d", len(ids2))
	}
}
