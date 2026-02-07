package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/felixgeelhaar/hardline/core/discovery"
	"github.com/felixgeelhaar/hardline/core/findings"
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
// SEC-001: AWS Access Key ID
// ---------------------------------------------------------------------------

func TestDetect_AWSAccessKeyID(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")

	results, err := a.ScanFile("config.env", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	f := results[0]
	if f.RuleID != "SEC-001" {
		t.Fatalf("expected RuleID SEC-001, got %s", f.RuleID)
	}
	if f.Severity != findings.SeverityHigh {
		t.Fatalf("expected severity high, got %s", f.Severity)
	}
	if f.Confidence != findings.ConfidenceHigh {
		t.Fatalf("expected confidence high, got %s", f.Confidence)
	}
}

// ---------------------------------------------------------------------------
// SEC-002: AWS Secret Access Key
// ---------------------------------------------------------------------------

func TestDetect_AWSSecretAccessKey(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")

	results, err := a.ScanFile("credentials", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	f := results[0]
	if f.RuleID != "SEC-002" {
		t.Fatalf("expected RuleID SEC-002, got %s", f.RuleID)
	}
	if f.Severity != findings.SeverityCritical {
		t.Fatalf("expected severity critical, got %s", f.Severity)
	}
	if f.Confidence != findings.ConfidenceHigh {
		t.Fatalf("expected confidence high, got %s", f.Confidence)
	}
}

// ---------------------------------------------------------------------------
// SEC-003: GitHub Token (ghp_ and ghs_ prefixes)
// ---------------------------------------------------------------------------

func TestDetect_GitHubToken_PersonalAccessToken(t *testing.T) {
	a := NewAnalyzer()
	// ghp_ followed by 36+ alphanumeric/underscore characters.
	content := []byte("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n")

	results, err := a.ScanFile("ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	f := results[0]
	if f.RuleID != "SEC-003" {
		t.Fatalf("expected RuleID SEC-003, got %s", f.RuleID)
	}
	if f.Severity != findings.SeverityHigh {
		t.Fatalf("expected severity high, got %s", f.Severity)
	}
}

func TestDetect_GitHubToken_ServerToServer(t *testing.T) {
	a := NewAnalyzer()
	// ghs_ prefix for server-to-server tokens.
	content := []byte("token: ghs_1234567890abcdefghijklmnopqrstuvwxyz12\n")

	results, err := a.ScanFile("config.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	f := results[0]
	if f.RuleID != "SEC-003" {
		t.Fatalf("expected RuleID SEC-003, got %s", f.RuleID)
	}
}

// ---------------------------------------------------------------------------
// SEC-004: Private Key Header
// ---------------------------------------------------------------------------

func TestDetect_PrivateKeyHeader(t *testing.T) {
	a := NewAnalyzer()

	tests := []struct {
		name    string
		content string
	}{
		{"RSA", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA..."},
		{"EC", "-----BEGIN EC PRIVATE KEY-----\nMHQC..."},
		{"DSA", "-----BEGIN DSA PRIVATE KEY-----\nMIIBuw..."},
		{"OPENSSH", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn..."},
		{"generic", "-----BEGIN PRIVATE KEY-----\nMIIEvg..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := a.ScanFile("id_rsa", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 finding for %s key, got %d", tt.name, len(results))
			}

			f := results[0]
			if f.RuleID != "SEC-004" {
				t.Fatalf("expected RuleID SEC-004, got %s", f.RuleID)
			}
			if f.Severity != findings.SeverityCritical {
				t.Fatalf("expected severity critical, got %s", f.Severity)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SEC-005: Generic API Key Assignment
// ---------------------------------------------------------------------------

func TestDetect_GenericAPIKeyAssignment(t *testing.T) {
	a := NewAnalyzer()

	tests := []struct {
		name    string
		content string
	}{
		{"api_key equals", `api_key = "abcdef1234567890abcdef"`},
		{"apikey colon", `apikey: "ABCDEF1234567890ABCDEF"`},
		{"api-secret equals", `api-secret = "secretvalue12345678"`},
		{"API_KEY upper", `API_KEY = "MySecretKeyValue1234"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := a.ScanFile("config.go", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 finding for %q, got %d", tt.name, len(results))
			}

			f := results[0]
			if f.RuleID != "SEC-005" {
				t.Fatalf("expected RuleID SEC-005, got %s", f.RuleID)
			}
			if f.Severity != findings.SeverityMedium {
				t.Fatalf("expected severity medium, got %s", f.Severity)
			}
			if f.Confidence != findings.ConfidenceMedium {
				t.Fatalf("expected confidence medium, got %s", f.Confidence)
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
		t.Fatalf("expected 0 findings on clean file, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// Line number accuracy
// ---------------------------------------------------------------------------

func TestScanFile_CorrectLineNumbers(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("line 1: nothing\nline 2: nothing\nline 3: AKIAIOSFODNN7EXAMPLE\nline 4: nothing\n")

	results, err := a.ScanFile("test.txt", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	f := results[0]
	if f.Location.StartLine != 3 {
		t.Fatalf("expected finding on line 3, got %d", f.Location.StartLine)
	}
	if f.Location.FilePath != "test.txt" {
		t.Fatalf("expected file path test.txt, got %s", f.Location.FilePath)
	}
}

// ---------------------------------------------------------------------------
// ScanArtifacts with temp directory containing mixed files
// ---------------------------------------------------------------------------

func TestScanArtifacts_MixedFiles(t *testing.T) {
	dir := t.TempDir()

	// File with a secret (AWS key).
	secretFile := writeFile(t, dir, "secret.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	// Clean file with no secrets.
	cleanFile := writeFile(t, dir, "clean.go", "package main\n\nfunc main() {}\n")
	// File with a private key header.
	keyFile := writeFile(t, dir, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----\n")

	artifacts := []discovery.Artifact{
		{Path: "secret.env", AbsPath: secretFile, Type: discovery.Config, Size: 40},
		{Path: "clean.go", AbsPath: cleanFile, Type: discovery.Source, Size: 30},
		{Path: "id_rsa", AbsPath: keyFile, Type: discovery.Unknown, Size: 60},
	}

	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	allFindings := fs.Findings()
	if len(allFindings) < 2 {
		t.Fatalf("expected at least 2 findings (AWS key + private key), got %d", len(allFindings))
	}

	// Verify we have findings from different rules.
	ruleIDs := make(map[string]bool)
	for _, f := range allFindings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["SEC-001"] {
		t.Fatal("expected a finding with RuleID SEC-001 (AWS Access Key ID)")
	}
	if !ruleIDs["SEC-004"] {
		t.Fatal("expected a finding with RuleID SEC-004 (Private Key)")
	}
}

// ---------------------------------------------------------------------------
// ScanArtifacts deduplication
// ---------------------------------------------------------------------------

func TestScanArtifacts_Deduplicates(t *testing.T) {
	dir := t.TempDir()

	// Two files with identical content should produce findings that are
	// deduplicated by the FindingSet because they have different file paths,
	// so they should NOT be deduplicated (different fingerprints).
	file1 := writeFile(t, dir, "a.env", "KEY=AKIAIOSFODNN7EXAMPLE\n")
	file2 := writeFile(t, dir, "b.env", "KEY=AKIAIOSFODNN7EXAMPLE\n")

	artifacts := []discovery.Artifact{
		{Path: "a.env", AbsPath: file1, Type: discovery.Config, Size: 30},
		{Path: "b.env", AbsPath: file2, Type: discovery.Config, Size: 30},
	}

	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same secret in two different files should produce 2 distinct findings.
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
