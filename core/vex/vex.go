// Package vex implements OpenVEX document parsing and application to findings.
//
// VEX (Vulnerability Exploitability eXchange) allows projects to communicate
// the status of vulnerabilities in their products. When a VEX document marks
// a CVE as "not_affected", the corresponding finding's status is updated so
// it no longer counts toward policy failures.
package vex

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// Status represents the VEX status of a vulnerability.
type Status string

// VEX status values per the OpenVEX specification.
const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// Statement is a single VEX statement declaring the status of a vulnerability
// for a specific product.
type Statement struct {
	VulnerabilityID string `json:"vulnerability"`
	Status          Status `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
}

// Document is a simplified OpenVEX document.
type Document struct {
	Context    string      `json:"@context,omitempty"`
	ID         string      `json:"@id,omitempty"`
	Author     string      `json:"author,omitempty"`
	Timestamp  string      `json:"timestamp,omitempty"`
	Statements []Statement `json:"statements"`
}

// LoadVEX reads and parses a VEX document from the given path.
func LoadVEX(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading VEX document %s: %w", path, err)
	}

	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing VEX document %s: %w", path, err)
	}

	return &doc, nil
}

// ApplyVEX matches VEX statements to findings by CVE/GHSA ID in the finding's
// Metadata and updates their status accordingly. Only VULN-001 findings with
// a vuln_id or aliases metadata key are eligible for VEX matching.
func ApplyVEX(fs *findings.FindingSet, doc *Document) int {
	if doc == nil || len(doc.Statements) == 0 {
		return 0
	}

	// Build a lookup from vulnerability ID to VEX status.
	stmtMap := make(map[string]Statement, len(doc.Statements))
	for _, stmt := range doc.Statements {
		stmtMap[strings.ToUpper(stmt.VulnerabilityID)] = stmt
	}

	applied := 0
	items := fs.Findings()
	for i := range items {
		if items[i].RuleID != "VULN-001" {
			continue
		}

		// Check vuln_id and aliases for a VEX match.
		ids := collectVulnIDs(&items[i])
		for _, id := range ids {
			stmt, ok := stmtMap[strings.ToUpper(id)]
			if !ok {
				continue
			}

			switch stmt.Status {
			case StatusNotAffected:
				fs.SetStatus(i, findings.StatusVEXNotAffected)
				applied++
			case StatusUnderInvestigation:
				fs.SetStatus(i, findings.StatusVEXUnderInvestigation)
				applied++
			case StatusFixed:
				fs.SetStatus(i, findings.StatusVEXFixed)
				applied++
			}
			break // first match wins
		}
	}

	return applied
}

// Summary returns a human-readable summary of the VEX document.
func Summary(doc *Document) string {
	if doc == nil {
		return "no VEX document"
	}
	counts := make(map[Status]int)
	for _, stmt := range doc.Statements {
		counts[stmt.Status]++
	}
	parts := make([]string, 0, len(counts))
	for status, count := range counts {
		parts = append(parts, fmt.Sprintf("%d %s", count, status))
	}
	return fmt.Sprintf("VEX: %d statements (%s)", len(doc.Statements), strings.Join(parts, ", "))
}

// collectVulnIDs extracts all vulnerability identifiers from a finding's metadata.
func collectVulnIDs(f *findings.Finding) []string {
	var ids []string
	if f.Metadata == nil {
		return ids
	}
	if vulnID := f.Metadata["vuln_id"]; vulnID != "" {
		ids = append(ids, vulnID)
	}
	if aliases := f.Metadata["aliases"]; aliases != "" {
		for _, a := range strings.Split(aliases, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				ids = append(ids, a)
			}
		}
	}
	return ids
}
