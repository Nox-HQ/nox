package data

import (
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// dataRule is a compact representation used to define built-in rules in a
// table. Each entry is converted to a rules.Rule by builtinDataRules().
type dataRule struct {
	id          string
	severity    findings.Severity
	confidence  findings.Confidence
	pattern     string
	description string
	cwe         string
	keywords    []string
	remediation string
	references  []string
}

// builtinDataRules returns all built-in data sensitivity detection rules.
func builtinDataRules() []rules.Rule {
	defs := []dataRule{
		// -----------------------------------------------------------------
		// Personal Identifiable Information (DATA-001 to DATA-012)
		// -----------------------------------------------------------------
		{
			id: "DATA-001", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)["'=:]\s*[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			description: "Email address in code or config",
			cwe:         "CWE-359", keywords: []string{"@"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "DATA-002", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
			description: "US Social Security Number pattern",
			cwe:         "CWE-359", keywords: []string{"-"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "DATA-003", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`,
			description: "Credit card number (Visa/MC/Amex/Discover)",
			cwe:         "CWE-311", keywords: []string{"4", "5", "3", "6"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/311.html"},
		},
		{
			id: "DATA-004", severity: findings.SeverityLow, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(?:phone|tel|mobile|cell)\s*[=:]\s*['"]?\+?1?\s*\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`,
			description: "US phone number in configuration",
			cwe:         "CWE-359", keywords: []string{"phone", "tel", "mobile", "cell"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "DATA-005", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(?:ip|host|server|addr)\s*[=:]\s*['"]?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`,
			description: "Hardcoded public IP address in configuration",
			cwe:         "CWE-200", keywords: []string{"ip", "host", "server", "addr"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
		},
		{
			id: "DATA-006", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(?:birth|dob|date_of_birth|dateOfBirth)\s*[=:]\s*['"]?\d{4}[-/]\d{2}[-/]\d{2}`,
			description: "Date of birth field with value",
			cwe:         "CWE-359", keywords: []string{"birth", "dob", "date_of_birth", "dateofbirth"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "DATA-007", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b`,
			description: "IBAN number",
			cwe:         "CWE-359", keywords: []string{"iban", "de", "gb", "fr", "nl"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "DATA-008", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`,
			description: "UK National Insurance Number",
			cwe:         "CWE-359", keywords: []string{"nino", "national_insurance", "ni_number"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "DATA-009", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(?:tax_?id|steuer_?id|tin|steuernummer)\s*[=:]\s*['"]?\d{2,3}[/\s]?\d{3}[/\s]?\d{4,5}`,
			description: "Tax ID (German/EU)",
			cwe:         "CWE-359", keywords: []string{"tax_id", "taxid", "steuer_id", "steuerid", "tin", "steuernummer"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "DATA-010", severity: findings.SeverityHigh, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(?:mrn|medical_record|patient_id|health_id)\s*[=:]\s*['"]?[A-Z0-9-]{6,20}`,
			description: "Health record identifier (MRN/patient_id)",
			cwe:         "CWE-359", keywords: []string{"mrn", "medical_record", "patient_id", "health_id"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "DATA-011", severity: findings.SeverityHigh, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(?:driver_?license|dl_?number|license_?number)\s*[=:]\s*['"]?[A-Z0-9-]{6,15}`,
			description: "Driver's license number pattern",
			cwe:         "CWE-359", keywords: []string{"driver_license", "driverlicense", "dl_number", "dlnumber", "license_number", "licensenumber"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "DATA-012", severity: findings.SeverityHigh, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(?:passport|passport_?number|passport_?no)\s*[=:]\s*['"]?[A-Z0-9]{6,12}`,
			description: "Passport number pattern",
			cwe:         "CWE-359", keywords: []string{"passport", "passport_number", "passportnumber", "passport_no", "passportno"},
			remediation: "Remove or externalize PII data. Never hard-code sensitive personal information in source code or configuration files. Use environment variables, encrypted vaults, or database references.",
			references:  []string{"https://cwe.mitre.org/data/definitions/359.html"},
		},
	}

	out := make([]rules.Rule, len(defs))
	for i := range defs {
		out[i] = rules.Rule{
			ID:          defs[i].id,
			Version:     "1.0",
			Description: defs[i].description,
			Severity:    defs[i].severity,
			Confidence:  defs[i].confidence,
			MatcherType: "regex",
			Pattern:     defs[i].pattern,
			Keywords:    defs[i].keywords,
			Tags:        []string{"data-sensitivity", "pii"},
			Metadata:    map[string]string{"cwe": defs[i].cwe},
			Remediation: defs[i].remediation,
			References:  defs[i].references,
		}
	}
	return out
}
