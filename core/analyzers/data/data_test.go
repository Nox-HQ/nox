package data

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// writeFile creates a file under dir with the given name and content. It
// returns the absolute path to the created file.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// Rule count
// ---------------------------------------------------------------------------

func TestBuiltinDataRules(t *testing.T) {
	a := NewAnalyzer()
	rules := a.Rules().Rules()
	if len(rules) != 12 {
		t.Errorf("expected 12 data rules, got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// All rules compile
// ---------------------------------------------------------------------------

func TestAllRules_Compile(t *testing.T) {
	for _, r := range builtinDataRules() {
		t.Run(r.ID, func(t *testing.T) {
			_, err := regexp.Compile(r.Pattern)
			if err != nil {
				t.Fatalf("rule %s: pattern does not compile: %v", r.ID, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Positive and negative match tests for each DATA-* rule
// ---------------------------------------------------------------------------

func TestDataRuleMatches(t *testing.T) {
	tests := []struct {
		name     string
		ruleID   string
		severity findings.Severity
		positive string
		negative string
	}{
		{
			name:     "DATA-001: Email address in config",
			ruleID:   "DATA-001",
			severity: findings.SeverityMedium,
			positive: "admin_email = user@example.com\n",
			negative: "// TODO: add email support later\n",
		},
		{
			name:     "DATA-002: US Social Security Number",
			ruleID:   "DATA-002",
			severity: findings.SeverityHigh,
			positive: "ssn = 123-45-6789\n",
			negative: "version = 1.2.3\n",
		},
		{
			name:     "DATA-003: Credit card Visa",
			ruleID:   "DATA-003",
			severity: findings.SeverityHigh,
			positive: "card_number = 4111111111111111\n",
			negative: "id = 12345\n",
		},
		{
			name:     "DATA-003: Credit card MasterCard",
			ruleID:   "DATA-003",
			severity: findings.SeverityHigh,
			positive: "cc = 5105105105105100\n",
			negative: "count = 42\n",
		},
		{
			name:     "DATA-003: Credit card Amex",
			ruleID:   "DATA-003",
			severity: findings.SeverityHigh,
			positive: "amex = 378282246310005\n",
			negative: "phone = 5551234\n",
		},
		{
			name:     "DATA-004: US phone number",
			ruleID:   "DATA-004",
			severity: findings.SeverityLow,
			positive: "phone = '555-123-4567'\n",
			negative: "description = 'call us anytime'\n",
		},
		{
			name:     "DATA-005: Hardcoded IP address",
			ruleID:   "DATA-005",
			severity: findings.SeverityMedium,
			positive: "server = '192.168.1.100'\n",
			negative: "message = 'the server is running'\n",
		},
		{
			name:     "DATA-006: Date of birth",
			ruleID:   "DATA-006",
			severity: findings.SeverityMedium,
			positive: "date_of_birth = '1990-01-15'\n",
			negative: "created_at = '2024-01-15'\n",
		},
		{
			name:     "DATA-007: IBAN number",
			ruleID:   "DATA-007",
			severity: findings.SeverityHigh,
			positive: "iban = DE89370400440532013000\n",
			negative: "code = ABCDE12345\n",
		},
		{
			name:     "DATA-008: UK National Insurance Number",
			ruleID:   "DATA-008",
			severity: findings.SeverityHigh,
			positive: "nino = AB123456C\n",
			negative: "ref = ZZ000000E\n",
		},
		{
			name:     "DATA-009: Tax ID (German/EU)",
			ruleID:   "DATA-009",
			severity: findings.SeverityHigh,
			positive: "tax_id = 12/345/67890\n",
			negative: "order_id = 99887766\n",
		},
		{
			name:     "DATA-010: Health record identifier",
			ruleID:   "DATA-010",
			severity: findings.SeverityHigh,
			positive: "patient_id = 'MRN-123456'\n",
			negative: "user_id = 42\n",
		},
		{
			name:     "DATA-011: Driver's license number",
			ruleID:   "DATA-011",
			severity: findings.SeverityHigh,
			positive: "driver_license = 'D1234567'\n",
			negative: "version = '1.0.0'\n",
		},
		{
			name:     "DATA-012: Passport number",
			ruleID:   "DATA-012",
			severity: findings.SeverityHigh,
			positive: "passport_number = 'AB1234567'\n",
			negative: "ticket_number = 'TK999'\n",
		},
	}

	a := NewAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name+" positive", func(t *testing.T) {
			results, err := a.ScanFile("test.txt", []byte(tt.positive))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			found := false
			for _, f := range results {
				if f.RuleID == tt.ruleID {
					found = true
					if f.Severity != tt.severity {
						t.Errorf("expected severity %s, got %s", tt.severity, f.Severity)
					}
				}
			}
			if !found {
				t.Fatalf("rule %s did not match positive example: %q", tt.ruleID, tt.positive)
			}
		})

		t.Run(tt.name+" negative", func(t *testing.T) {
			results, err := a.ScanFile("test.txt", []byte(tt.negative))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, f := range results {
				if f.RuleID == tt.ruleID {
					t.Fatalf("rule %s should not match negative example: %q", tt.ruleID, tt.negative)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Positive match for all rules via builtinDataRules
// ---------------------------------------------------------------------------

func TestAllRules_PositiveMatch(t *testing.T) {
	examples := map[string]string{
		"DATA-001": "email = user@example.com\n",
		"DATA-002": "ssn = 123-45-6789\n",
		"DATA-003": "card = 4111111111111111\n",
		"DATA-004": "phone = '555-123-4567'\n",
		"DATA-005": "server = '10.0.0.1'\n",
		"DATA-006": "dob = '1990-01-15'\n",
		"DATA-007": "iban = DE89370400440532013000\n",
		"DATA-008": "nino = AB123456C\n",
		"DATA-009": "tax_id = 12/345/67890\n",
		"DATA-010": "patient_id = 'MRN-123456'\n",
		"DATA-011": "driver_license = 'D1234567'\n",
		"DATA-012": "passport = 'AB1234567'\n",
	}

	a := NewAnalyzer()
	for _, r := range builtinDataRules() {
		t.Run(r.ID, func(t *testing.T) {
			example, ok := examples[r.ID]
			if !ok {
				t.Fatalf("no positive example for rule %s", r.ID)
			}
			results, err := a.ScanFile("test.txt", []byte(example))
			if err != nil {
				t.Fatalf("scan error: %v", err)
			}
			found := false
			for _, f := range results {
				if f.RuleID == r.ID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("rule %s did not match its positive example", r.ID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// No false positives on clean files
// ---------------------------------------------------------------------------

func TestNoFalsePositives_CleanFile(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`package main

import "fmt"

func main() {
	name := "Alice"
	age := 30
	fmt.Printf("Hello, %s! You are %d years old.\n", name, age)
}
`)

	results, err := a.ScanFile("main.go", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		for _, f := range results {
			t.Logf("unexpected finding: %s at %s:%d", f.RuleID, f.Location.FilePath, f.Location.StartLine)
		}
		t.Fatalf("expected 0 findings on clean file, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// Line number accuracy
// ---------------------------------------------------------------------------

func TestScanFile_CorrectLineNumbers(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("line 1: nothing\nline 2: nothing\nline 3: ssn = 123-45-6789\nline 4: nothing\n")

	results, err := a.ScanFile("test.txt", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(results))
	}

	// The SSN finding should be on line 3.
	found := false
	for _, f := range results {
		if f.RuleID == "DATA-002" {
			found = true
			if f.Location.StartLine != 3 {
				t.Fatalf("expected finding on line 3, got %d", f.Location.StartLine)
			}
			if f.Location.FilePath != "test.txt" {
				t.Fatalf("expected file path test.txt, got %s", f.Location.FilePath)
			}
		}
	}
	if !found {
		t.Fatal("expected DATA-002 finding for SSN pattern")
	}
}

// ---------------------------------------------------------------------------
// ScanArtifacts with temp directory containing mixed files
// ---------------------------------------------------------------------------

func TestScanArtifacts_MixedFiles(t *testing.T) {
	dir := t.TempDir()

	// File with PII (email address).
	piiFile := writeFile(t, dir, "config.env", "admin_email = user@example.com\n")
	// Clean file with no PII.
	cleanFile := writeFile(t, dir, "clean.go", "package main\n\nfunc main() {}\n")
	// File with SSN.
	ssnFile := writeFile(t, dir, "data.csv", "name,ssn\nJohn,123-45-6789\n")

	artifacts := []discovery.Artifact{
		{Path: "config.env", AbsPath: piiFile, Type: discovery.Config, Size: 40},
		{Path: "clean.go", AbsPath: cleanFile, Type: discovery.Source, Size: 30},
		{Path: "data.csv", AbsPath: ssnFile, Type: discovery.Unknown, Size: 30},
	}

	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	allFindings := fs.Findings()
	if len(allFindings) < 2 {
		t.Fatalf("expected at least 2 findings (email + SSN), got %d", len(allFindings))
	}

	// Verify we have findings from different rules.
	ruleIDs := make(map[string]bool)
	for _, f := range allFindings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["DATA-001"] {
		t.Fatal("expected a finding with RuleID DATA-001 (Email)")
	}
	if !ruleIDs["DATA-002"] {
		t.Fatal("expected a finding with RuleID DATA-002 (SSN)")
	}
}

// ---------------------------------------------------------------------------
// ScanArtifacts deduplication
// ---------------------------------------------------------------------------

func TestScanArtifacts_Deduplicates(t *testing.T) {
	dir := t.TempDir()

	// Two files with identical content should produce findings that are
	// NOT deduplicated because they have different file paths (different
	// fingerprints).
	file1 := writeFile(t, dir, "a.env", "email = user@example.com\n")
	file2 := writeFile(t, dir, "b.env", "email = user@example.com\n")

	artifacts := []discovery.Artifact{
		{Path: "a.env", AbsPath: file1, Type: discovery.Config, Size: 30},
		{Path: "b.env", AbsPath: file2, Type: discovery.Config, Size: 30},
	}

	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same PII in two different files should produce 2 distinct findings.
	allFindings := fs.Findings()
	if len(allFindings) != 2 {
		t.Fatalf("expected 2 findings from 2 different files, got %d", len(allFindings))
	}
}

// ---------------------------------------------------------------------------
// ScanArtifacts with unreadable file
// ---------------------------------------------------------------------------

func TestScanArtifacts_UnreadableFile(t *testing.T) {
	artifacts := []discovery.Artifact{
		{Path: "nonexistent.txt", AbsPath: "/nonexistent/path/file.txt", Type: discovery.Unknown, Size: 0},
	}

	a := NewAnalyzer()
	_, err := a.ScanArtifacts(artifacts)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

// ---------------------------------------------------------------------------
// Tags validation
// ---------------------------------------------------------------------------

func TestAllRules_HaveCorrectTags(t *testing.T) {
	for _, r := range builtinDataRules() {
		t.Run(r.ID, func(t *testing.T) {
			hasDS := false
			hasPII := false
			for _, tag := range r.Tags {
				if tag == "data-sensitivity" {
					hasDS = true
				}
				if tag == "pii" {
					hasPII = true
				}
			}
			if !hasDS {
				t.Errorf("rule %s missing 'data-sensitivity' tag", r.ID)
			}
			if !hasPII {
				t.Errorf("rule %s missing 'pii' tag", r.ID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Metadata CWE validation
// ---------------------------------------------------------------------------

func TestAllRules_HaveCWEMetadata(t *testing.T) {
	for _, r := range builtinDataRules() {
		t.Run(r.ID, func(t *testing.T) {
			cwe, ok := r.Metadata["cwe"]
			if !ok || cwe == "" {
				t.Errorf("rule %s missing CWE metadata", r.ID)
			}
		})
	}
}
