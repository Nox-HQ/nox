package secrets

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
			if len(results) < 1 {
				t.Fatalf("expected at least 1 finding for %q, got %d", tt.name, len(results))
			}

			// SEC-005 should be among the findings.
			found := false
			for _, f := range results {
				if f.RuleID == "SEC-005" {
					found = true
					if f.Severity != findings.SeverityMedium {
						t.Fatalf("expected severity medium, got %s", f.Severity)
					}
					if f.Confidence != findings.ConfidenceMedium {
						t.Fatalf("expected confidence medium, got %s", f.Confidence)
					}
				}
			}
			if !found {
				t.Fatalf("expected SEC-005 among findings for %q", tt.name)
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

// ---------------------------------------------------------------------------
// Expanded rule coverage
// ---------------------------------------------------------------------------

// TestAllRules_Compile verifies that every built-in rule's regex pattern
// compiles without error.
func TestAllRules_Compile(t *testing.T) {
	for _, r := range builtinSecretRules() {
		t.Run(r.ID, func(t *testing.T) {
			_, err := regexp.Compile(r.Pattern)
			if err != nil {
				t.Fatalf("rule %s: pattern does not compile: %v", r.ID, err)
			}
		})
	}
}

// TestAllRules_PositiveMatch runs a table-driven test with one positive
// example per rule, ensuring every rule can produce at least one match.
func TestAllRules_PositiveMatch(t *testing.T) {
	// Test examples use string concatenation to prevent GitHub Push
	// Protection from flagging synthetic test values as real secrets.
	examples := map[string]string{
		"SEC-001": "aws_access_key_id = " + "AKIA" + "IOSFODNN7EXAMPLE\n",
		"SEC-002": "AWS_SECRET_ACCESS_KEY = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
		"SEC-003": "token=" + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n",
		"SEC-004": "-----BEGIN RSA " + "PRIVATE KEY-----\n",
		"SEC-005": "api_key = \"" + "abcdef1234567890abcdef\"\n",
		"SEC-006": "amzn" + ".mws." + "12345678-1234-1234-1234-123456789abc\n",
		"SEC-007": "AIza" + "SyD-abcdefghijklmnopqrstuvwxyz12345\n",
		"SEC-008": "\"type\": \"" + "service_account\"\n",
		"SEC-009": "client_secret = \"" + "abcdefghijklmnopqrstuvwxyz1234567890\"\n",
		"SEC-010": "dop_v1_" + "aabbccddeeff0011223344" + "5566778899aabbccddeeff00112233445566778899\n",
		"SEC-011": "doo_v1_" + "aabbccddeeff0011223344" + "5566778899aabbccddeeff00112233445566778899\n",
		"SEC-012": "heroku_api_key= " + "12345678-1234-1234-1234-123456789abc\n",
		"SEC-013": "LTAI" + "ABCDEFGHIJKLMNOP\n",
		"SEC-014": "ibm_api_key= " + "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH\n",
		"SEC-015": "dapi" + "1234567890abcdef1234567890abcdef\n",
		"SEC-016": "github_pat_" + "11AAAAAA01234567890123456789" + "01234567890123456789012345678901234567890123456789ABCD\n",
		"SEC-017": "ghu_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n",
		"SEC-018": "glpat-" + "ABCDEF1234567890abcd\n",
		"SEC-019": "glptt-" + "ABCDEF1234567890abcd\n",
		"SEC-020": "glrt-" + "ABCDEF1234567890abcde\n",
		"SEC-021": "bitbucket_client_secret = \"" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\"\n",
		"SEC-022": "bbdc-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n",
		"SEC-023": "xoxb-" + "1234567890-1234567890-" + "ABCDEFGHIJKLMNOPQRSTUVWX\n",
		"SEC-024": "xoxp-" + "1234567890-1234567890-1234567890-" + "abcdef1234567890abcdef1234567890\n",
		"SEC-025": "https://hooks.slack.com/" + "services/T12345678/B12345678/" + "ABCDEFGHIJKLMNOPQRSTUVWXy\n",
		"SEC-026": "discord_bot_token = \"" + "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.ABCDEF." + "abcdefghijklmnopqrstuvwxyz12345678901234567\"\n",
		"SEC-027": "https://discord.com/api/" + "webhooks/1234567890/" + "ABCDEFghijklMNOP\n",
		"SEC-028": "telegram bot " + "123456789:" + "ABCDEFghijklmnopqrstuvwxyz123456789\n",
		"SEC-029": "https://myorg" + ".webhook.office.com/" + "webhookb2/12345678-1234-1234-1234-123456789abc\n",
		"SEC-030": "sk_live_" + "ABCDEFGHIJKLMNOPQRSTa\n",
		"SEC-031": "whsec_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg=\n",
		"SEC-032": "sq0atp-" + "ABCDEFGHIJKLMNOPQRSTUV\n",
		"SEC-033": "sq0csp-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq\n",
		"SEC-034": "shpss_" + "aabbccddeeff00112233445566778899\n",
		"SEC-035": "shpat_" + "aabbccddeeff00112233445566778899\n",
		"SEC-036": "shpca_" + "aabbccddeeff00112233445566778899\n",
		"SEC-037": "shppa_" + "aabbccddeeff00112233445566778899\n",
		"SEC-038": "access_token" + "$production$" + "abcdef1234567890$abcdef1234567890abcdef1234567890\n",
		"SEC-039": "sk-" + "ABCDEFGHIJKLMNOPQRSt" + "T3BlbkFJ" + "ABCDEFGHIJKLMNOPQRST\n",
		"SEC-040": "sk-proj-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst" + "uvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234\n",
		"SEC-041": "sk-ant-api" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst" + "uvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n",
		"SEC-042": "hf_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n",
		"SEC-043": "r8_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\n",
		"SEC-044": "cohere_api_key= " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\n",
		"SEC-045": "npm_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl\n",
		"SEC-046": "pypi-" + "ABCDEFGHIJKLMNOPa\n",
		"SEC-047": "rubygems_" + "aabbccddeeff00112233445566778899aabbccddeeff0011\n",
		"SEC-048": "oy2" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr\n",
		"SEC-049": "dckr_pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZa\n",
		"SEC-050": "ABCDEFghijklmn" + ".atlasv1." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz12345678\n",
		"SEC-051": "hvs." + "ABCDEFGHIJKLMNOPQRSTUVWXyz\n",
		"SEC-052": "hvb." + "ABCDEFGHIJKLMNOPQRSTUVWXyz\n",
		"SEC-053": "fastly_api_key = \"" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\"\n",
		"SEC-054": "dp.pt." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr\n",
		"SEC-055": "cio" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl\n",
		"SEC-056": "glc_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg=\n",
		"SEC-057": "SK" + "1234567890abcdef1234567890abcdef\n",
		"SEC-058": "SG." + "ABCDEFghijklmnopqrstuv." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv\n",
		"SEC-059": "abcdef1234567890abcdef1234567890" + "-us12\n",
		"SEC-060": "mailgun_api_key = \"" + "key-abcdef1234567890abcdef1234567890\"\n",
		"SEC-061": "datadog_api_key = \"" + "abcdef1234567890abcdef1234567890\"\n",
		"SEC-062": "NRAK-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1\n",
		"SEC-063": "pagerduty_api_key = \"" + "ABCDEFGHIJKLMNOPQRSTa\"\n",
		"SEC-064": "airtable_api_key = \"" + "keyABCDEFGHIJKLMN\"\n",
		"SEC-065": "algolia_api_key = \"" + "abcdef1234567890abcdef1234567890\"\n",
		"SEC-066": "lin_api_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\n",
		"SEC-067": "PMAK-" + "ABCDEFGHIJKLMNOPQRSTUVWx-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n",
		"SEC-068": "okta_api_token = \"" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\"\n",
		"SEC-069": "contentful_delivery_token = \"" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv\"\n",
		"SEC-070": "live_" + "abcdef1234567890abcdef1234567890\n",
		"SEC-071": "sbp_" + "aabbccddeeff00112233445566778899aabbccdd\n",
		"SEC-072": "confluent_api_key = \"" + "ABCDEFGHIJKLMNOP\"\n",
		"SEC-073": "postgres://" + "admin:s3cret@localhost:5432/db\n",
		"SEC-074": "mongodb+srv://" + "user:pass@cluster0.example.net/mydb\n",
		"SEC-075": "firebase_api_key = \"" + "AIza" + "SyD-abcdefghijklmnopqrstuvwxyz12345\"\n",
		"SEC-076": "redis://" + "default:mypassword@redis.example.com:6379\n",
		"SEC-077": "AGE-SECRET-KEY-" + "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" + "QPZRY9X8GF2TVDW0S3JN54KHCE6M\n",
		"SEC-078": "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\n",
		"SEC-079": "password = \"mysecret\" " + "cert.p12\n",
		"SEC-080": "password = \"" + "mysecretpassword\"\n",
		"SEC-081": "secret = \"" + "ABCDEFGHIJKLMNOP\"\n",
		"SEC-082": "authorization = \"Bearer " + "eyABCDEFGHIJKLMNOPQRSTUV.WXY=\"\n",
		"SEC-083": "authorization = \"Basic " + "dXNlcjpwYXNzd29yZA==\"\n",
		"SEC-084": "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "ABCDEFGHIJKLmnopqr\n",
		"SEC-085": "https://" + "admin:s3cret@internal.example.com/api\n",
		"SEC-086": "db_password = \"" + "mysecretdbpass\"\n",
	}

	a := NewAnalyzer()
	for _, r := range builtinSecretRules() {
		t.Run(r.ID, func(t *testing.T) {
			example, ok := examples[r.ID]
			if !ok {
				t.Fatalf("no positive example for rule %s", r.ID)
			}
			results, err := a.ScanFile("test.txt", []byte(example))
			if err != nil {
				t.Fatalf("scan error: %v", err)
			}
			// Check that this specific rule produced a finding.
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

// TestAllRules_Count verifies we have exactly 86 built-in secret rules.
func TestAllRules_Count(t *testing.T) {
	rules := builtinSecretRules()
	if len(rules) != 86 {
		t.Fatalf("expected 86 built-in secret rules, got %d", len(rules))
	}
}

// TestNoFalsePositives_GenericPatterns verifies generic patterns do not
// match common safe patterns.
func TestNoFalsePositives_GenericPatterns(t *testing.T) {
	a := NewAnalyzer()

	safeContent := []string{
		// Variable declarations without values
		`var apiKey string`,
		`password := os.Getenv("DB_PASSWORD")`,
		// Short values below min length
		`api_key = "short"`,
		// Comments mentioning keywords
		`// Set the api_key in environment variables`,
		// Config templates with placeholders
		`api_key = "${API_KEY}"`,
	}

	for _, content := range safeContent {
		results, err := a.ScanFile("safe.go", []byte(content+"\n"))
		if err != nil {
			t.Fatalf("scan error: %v", err)
		}
		// Generic rules (SEC-005, SEC-080, SEC-081) should not match.
		for _, f := range results {
			switch f.RuleID {
			case "SEC-005", "SEC-080", "SEC-081":
				t.Errorf("false positive: rule %s matched safe content: %q", f.RuleID, content)
			}
		}
	}
}

// TestDetect_UpgradedSEC001_ASIA verifies the expanded AWS key prefix pattern.
func TestDetect_UpgradedSEC001_ASIA(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("temp_key = ASIAJEXAMPLEKEYHERE7\n")

	results, err := a.ScanFile("config.env", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "SEC-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected SEC-001 to match ASIA prefix")
	}
}
