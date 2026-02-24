package main

import (
	"fmt"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// Framework represents a compliance framework with its controls and nox rule mappings.
type Framework struct {
	ID        string
	Name      string
	Controls  []Control
	Threshold float64 // minimum acceptable coverage percentage
}

// Control represents a single framework control or requirement.
type Control struct {
	ID          string
	Description string
	Priority    string // "high", "medium", "low"
	NoxRules    []string
}

// frameworkSpecificFinding represents a rule-specific finding for a framework.
type frameworkSpecificFinding struct {
	RuleID   string
	Severity pluginv1.Severity
	Message  string
	Category string
}

var frameworks = []Framework{
	{
		ID: "soc2", Name: "SOC 2", Threshold: 70,
		Controls: []Control{
			{ID: "CC6.1", Description: "Logical and physical access controls", Priority: "high", NoxRules: []string{"SEC-001", "SEC-002", "EXPLAIN-001", "THREAT-001"}},
			{ID: "CC6.2", Description: "System credentials and authentication", Priority: "high", NoxRules: []string{"SEC-003", "SEC-004", "SEC-005"}},
			{ID: "CC6.3", Description: "Access authorization and removal", Priority: "high", NoxRules: []string{"EXPLAIN-003", "THREAT-005"}},
			{ID: "CC6.6", Description: "Encryption of data in transit", Priority: "high", NoxRules: []string{"EXPLAIN-004", "THREAT-004"}},
			{ID: "CC6.7", Description: "Transmission integrity", Priority: "medium", NoxRules: []string{"THREAT-002"}},
			{ID: "CC7.1", Description: "Detection of vulnerabilities", Priority: "high", NoxRules: []string{"VULN-001", "VULN-002", "VULN-003"}},
			{ID: "CC7.2", Description: "Monitoring of system components", Priority: "medium", NoxRules: []string{"THREAT-003"}},
			{ID: "CC8.1", Description: "Change management controls", Priority: "medium", NoxRules: []string{"IAC-001", "IAC-002"}},
		},
	},
	{
		ID: "iso27001", Name: "ISO 27001", Threshold: 65,
		Controls: []Control{
			{ID: "A.5.1", Description: "Information security policies", Priority: "high", NoxRules: []string{}},
			{ID: "A.8.2", Description: "Access rights management", Priority: "high", NoxRules: []string{"EXPLAIN-003", "THREAT-005", "IAC-050"}},
			{ID: "A.8.5", Description: "Secure authentication", Priority: "high", NoxRules: []string{"SEC-001", "SEC-002", "EXPLAIN-001", "THREAT-001"}},
			{ID: "A.8.9", Description: "Configuration management", Priority: "medium", NoxRules: []string{"IAC-001", "IAC-002", "IAC-003"}},
			{ID: "A.8.12", Description: "Data leakage prevention", Priority: "high", NoxRules: []string{"EXPLAIN-002", "THREAT-004", "DATA-001"}},
			{ID: "A.8.24", Description: "Cryptography", Priority: "high", NoxRules: []string{"EXPLAIN-004", "SEC-100"}},
			{ID: "A.8.25", Description: "Secure development lifecycle", Priority: "medium", NoxRules: []string{"VULN-001", "TAINT-001", "TAINT-002"}},
			{ID: "A.8.28", Description: "Secure coding", Priority: "medium", NoxRules: []string{"TAINT-001", "TAINT-002", "TAINT-003", "TAINT-004", "TAINT-005"}},
		},
	},
	{
		ID: "gdpr", Name: "GDPR", Threshold: 75,
		Controls: []Control{
			{ID: "Art.5", Description: "Principles relating to processing of personal data", Priority: "high", NoxRules: []string{"DATA-001", "DATA-002", "DATA-003"}},
			{ID: "Art.25", Description: "Data protection by design and by default", Priority: "high", NoxRules: []string{"DATA-004", "DATA-005", "DATA-006"}},
			{ID: "Art.32", Description: "Security of processing", Priority: "high", NoxRules: []string{"SEC-001", "SEC-002", "EXPLAIN-004"}},
			{ID: "Art.33", Description: "Notification of personal data breach", Priority: "high", NoxRules: []string{"THREAT-003"}},
			{ID: "Art.35", Description: "Data protection impact assessment", Priority: "medium", NoxRules: []string{"DATA-007", "DATA-008"}},
			{ID: "Art.44", Description: "Transfer of personal data to third countries", Priority: "high", NoxRules: []string{}},
		},
	},
	fedrampLow,
	fedrampModerate,
	fedrampHigh,
	{
		ID: "hipaa", Name: "HIPAA", Threshold: 75,
		Controls: []Control{
			{ID: "164.308(a)(1)", Description: "Security management process", Priority: "high", NoxRules: []string{"VULN-001", "VULN-002"}},
			{ID: "164.308(a)(3)", Description: "Workforce security", Priority: "high", NoxRules: []string{"EXPLAIN-003", "THREAT-005"}},
			{ID: "164.308(a)(4)", Description: "Information access management", Priority: "high", NoxRules: []string{"SEC-001", "SEC-002", "EXPLAIN-001"}},
			{ID: "164.312(a)(1)", Description: "Access control", Priority: "high", NoxRules: []string{"EXPLAIN-003", "THREAT-001"}},
			{ID: "164.312(c)(1)", Description: "Integrity controls", Priority: "medium", NoxRules: []string{"THREAT-002"}},
			{ID: "164.312(d)", Description: "Person or entity authentication", Priority: "high", NoxRules: []string{"SEC-001", "EXPLAIN-001"}},
			{ID: "164.312(e)(1)", Description: "Transmission security", Priority: "high", NoxRules: []string{"EXPLAIN-004"}},
		},
	},
	{
		ID: "pci-dss", Name: "PCI-DSS", Threshold: 80,
		Controls: []Control{
			{ID: "Req.2", Description: "Secure default configurations", Priority: "high", NoxRules: []string{"IAC-001", "IAC-002", "IAC-003"}},
			{ID: "Req.3", Description: "Protect stored cardholder data", Priority: "high", NoxRules: []string{"DATA-001", "DATA-002", "SEC-100"}},
			{ID: "Req.4", Description: "Encrypt transmission of cardholder data", Priority: "high", NoxRules: []string{"EXPLAIN-004", "THREAT-002"}},
			{ID: "Req.6", Description: "Develop and maintain secure systems", Priority: "high", NoxRules: []string{"VULN-001", "VULN-002", "TAINT-001", "TAINT-002"}},
			{ID: "Req.7", Description: "Restrict access by business need-to-know", Priority: "high", NoxRules: []string{"EXPLAIN-003", "THREAT-005"}},
			{ID: "Req.8", Description: "Identify and authenticate access", Priority: "high", NoxRules: []string{"SEC-001", "SEC-002", "EXPLAIN-001"}},
			{ID: "Req.10", Description: "Track and monitor network access", Priority: "high", NoxRules: []string{"THREAT-003"}},
		},
	},
	{
		ID: "nist-800-53", Name: "NIST 800-53", Threshold: 60,
		Controls: []Control{
			{ID: "AC-2", Description: "Account management", Priority: "high", NoxRules: []string{"EXPLAIN-003", "THREAT-005"}},
			{ID: "AU-2", Description: "Audit events", Priority: "medium", NoxRules: []string{"THREAT-003"}},
			{ID: "IA-2", Description: "Identification and authentication", Priority: "high", NoxRules: []string{"SEC-001", "SEC-002", "EXPLAIN-001"}},
			{ID: "RA-5", Description: "Vulnerability monitoring and scanning", Priority: "high", NoxRules: []string{"VULN-001", "VULN-002", "VULN-003"}},
			{ID: "SA-11", Description: "Developer testing and evaluation", Priority: "medium", NoxRules: []string{"TAINT-001", "TAINT-002", "TAINT-003"}},
			{ID: "SC-8", Description: "Transmission confidentiality and integrity", Priority: "high", NoxRules: []string{"EXPLAIN-004"}},
			{ID: "SC-13", Description: "Cryptographic protection", Priority: "high", NoxRules: []string{"EXPLAIN-004"}},
			{ID: "SI-10", Description: "Information input validation", Priority: "medium", NoxRules: []string{"TAINT-001", "TAINT-002", "TAINT-003", "TAINT-004"}},
		},
	},
	{
		ID: "nist-csf", Name: "NIST CSF", Threshold: 60,
		Controls: []Control{
			{ID: "ID.AM", Description: "Asset management", Priority: "medium", NoxRules: []string{"VULN-001", "CONT-001"}},
			{ID: "ID.RA", Description: "Risk assessment", Priority: "high", NoxRules: []string{"VULN-001", "VULN-002", "VULN-003"}},
			{ID: "PR.AC", Description: "Identity management and access control", Priority: "high", NoxRules: []string{"SEC-001", "SEC-002", "EXPLAIN-001", "EXPLAIN-003"}},
			{ID: "PR.DS", Description: "Data security", Priority: "high", NoxRules: []string{"EXPLAIN-004", "DATA-001", "DATA-002"}},
			{ID: "PR.IP", Description: "Information protection processes", Priority: "medium", NoxRules: []string{"IAC-001", "IAC-002"}},
			{ID: "DE.CM", Description: "Continuous monitoring", Priority: "high", NoxRules: []string{"THREAT-003", "VULN-001"}},
			{ID: "RS.AN", Description: "Analysis", Priority: "medium", NoxRules: []string{}},
		},
	},
	{
		ID: "cis-v8", Name: "CIS Controls v8", Threshold: 60,
		Controls: []Control{
			{ID: "CIS.1", Description: "Inventory and control of enterprise assets", Priority: "high", NoxRules: []string{"CONT-001", "CONT-002"}},
			{ID: "CIS.2", Description: "Inventory and control of software assets", Priority: "high", NoxRules: []string{"VULN-001", "LIC-001"}},
			{ID: "CIS.3", Description: "Data protection", Priority: "high", NoxRules: []string{"DATA-001", "DATA-002", "EXPLAIN-004"}},
			{ID: "CIS.4", Description: "Secure configuration", Priority: "high", NoxRules: []string{"IAC-001", "IAC-002", "IAC-003"}},
			{ID: "CIS.5", Description: "Account management", Priority: "high", NoxRules: []string{"EXPLAIN-003", "THREAT-005"}},
			{ID: "CIS.6", Description: "Access control management", Priority: "high", NoxRules: []string{"SEC-001", "SEC-002", "EXPLAIN-001"}},
			{ID: "CIS.7", Description: "Continuous vulnerability management", Priority: "high", NoxRules: []string{"VULN-001", "VULN-002", "VULN-003"}},
			{ID: "CIS.8", Description: "Audit log management", Priority: "medium", NoxRules: []string{"THREAT-003"}},
			{ID: "CIS.16", Description: "Application software security", Priority: "high", NoxRules: []string{"TAINT-001", "TAINT-002", "TAINT-003", "TAINT-004", "TAINT-005"}},
		},
	},
	{
		ID: "cmmc", Name: "CMMC", Threshold: 65,
		Controls: []Control{
			{ID: "AC.L1-3.1.1", Description: "Authorized access control", Priority: "high", NoxRules: []string{"EXPLAIN-003", "THREAT-005"}},
			{ID: "AC.L1-3.1.2", Description: "Transaction and function control", Priority: "high", NoxRules: []string{"SEC-001", "SEC-002"}},
			{ID: "AU.L2-3.3.1", Description: "System auditing", Priority: "medium", NoxRules: []string{"THREAT-003"}},
			{ID: "IA.L1-3.5.1", Description: "Identification", Priority: "high", NoxRules: []string{"SEC-001", "EXPLAIN-001"}},
			{ID: "SC.L1-3.13.1", Description: "Boundary protection", Priority: "high", NoxRules: []string{"IAC-001", "IAC-002"}},
			{ID: "SC.L2-3.13.8", Description: "CUI encryption", Priority: "high", NoxRules: []string{"EXPLAIN-004"}},
			{ID: "SI.L1-3.14.1", Description: "Flaw remediation", Priority: "high", NoxRules: []string{"VULN-001", "VULN-002"}},
		},
	},
}

// frameworksByName provides lookup by framework ID.
var frameworksByName = func() map[string]Framework {
	m := make(map[string]Framework, len(frameworks))
	for _, fw := range frameworks {
		m[fw.ID] = fw
	}
	return m
}()

// assessFrameworkSpecific returns framework-specific findings based on the assessment.
func assessFrameworkSpecific(fw Framework, assessment *AssessmentResult) []frameworkSpecificFinding {
	var findings []frameworkSpecificFinding

	switch fw.ID {
	case "gdpr":
		if !assessment.HasEvidenceFor("Art.32") {
			findings = append(findings, frameworkSpecificFinding{
				RuleID:   "GRC-005",
				Severity: pluginv1.Severity(3), // High
				Message:  "Missing data protection controls (GDPR Art. 32): no evidence of appropriate security measures",
				Category: "data-protection",
			})
		}
	case "soc2":
		if !assessment.HasEvidenceFor("CC6.1") {
			findings = append(findings, frameworkSpecificFinding{
				RuleID:   "GRC-006",
				Severity: pluginv1.Severity(3), // High
				Message:  "Insufficient access control evidence (SOC2 CC6): no findings mapped to access control criteria",
				Category: "access-control",
			})
		}
	case "fedramp-moderate", "fedramp-high":
		if !assessment.HasEvidenceFor("SC-28") {
			findings = append(findings, frameworkSpecificFinding{
				RuleID:   "GRC-007",
				Severity: pluginv1.Severity(3), // High
				Message:  fmt.Sprintf("Missing encryption at rest evidence (%s SC-28): no findings demonstrate data-at-rest protection", fw.Name),
				Category: "encryption",
			})
		}
	case "nist-csf":
		if !assessment.HasEvidenceFor("DE.CM") {
			findings = append(findings, frameworkSpecificFinding{
				RuleID:   "GRC-009",
				Severity: pluginv1.Severity(2), // Medium
				Message:  "Missing continuous monitoring controls (NIST CSF DE.CM): no monitoring evidence detected",
				Category: "monitoring",
			})
		}
	case "cmmc":
		uncoveredHighPriority := 0
		for _, c := range fw.Controls {
			if c.Priority == "high" && !assessment.HasEvidenceFor(c.ID) {
				uncoveredHighPriority++
			}
		}
		if uncoveredHighPriority > len(fw.Controls)/2 {
			findings = append(findings, frameworkSpecificFinding{
				RuleID:   "GRC-010",
				Severity: pluginv1.Severity(2), // Medium
				Message:  fmt.Sprintf("CMMC maturity level gap: %d of %d high-priority controls lack evidence", uncoveredHighPriority, len(fw.Controls)),
				Category: "maturity-gap",
			})
		}
	}

	return findings
}
