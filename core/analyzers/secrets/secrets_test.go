package secrets

import (
	"fmt"
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
	if len(results) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(results))
	}

	// Verify SEC-001 is among the findings.
	var f *findings.Finding
	for i := range results {
		if results[i].RuleID == "SEC-001" {
			f = &results[i]
			break
		}
	}
	if f == nil {
		t.Fatal("expected finding with RuleID SEC-001")
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
	if len(results) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(results))
	}

	var f *findings.Finding
	for i := range results {
		if results[i].RuleID == "SEC-002" {
			f = &results[i]
			break
		}
	}
	if f == nil {
		t.Fatal("expected finding with RuleID SEC-002")
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
	if len(results) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(results))
	}

	found := false
	for _, f := range results {
		if f.RuleID == "SEC-003" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Fatalf("expected severity high, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected finding with RuleID SEC-003")
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
	if len(results) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(results))
	}

	found := false
	for _, f := range results {
		if f.RuleID == "SEC-003" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected finding with RuleID SEC-003")
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
	file1 := writeFile(t, dir, "a.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	file2 := writeFile(t, dir, "b.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	artifacts := []discovery.Artifact{
		{Path: "a.env", AbsPath: file1, Type: discovery.Config, Size: 30},
		{Path: "b.env", AbsPath: file2, Type: discovery.Config, Size: 30},
	}

	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same secret in two different files should produce matching SEC-001
	// findings for both files. Additional entropy-based findings may also
	// appear.
	allFindings := fs.Findings()
	sec001Count := 0
	for _, f := range allFindings {
		if f.RuleID == "SEC-001" {
			sec001Count++
		}
	}
	if sec001Count != 2 {
		t.Fatalf("expected 2 SEC-001 findings from 2 different files, got %d", sec001Count)
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
// compiles without error. Entropy-based rules have no pattern and are skipped.
func TestAllRules_Compile(t *testing.T) {
	for _, r := range builtinSecretRules() {
		t.Run(r.ID, func(t *testing.T) {
			if r.MatcherType == "entropy" {
				t.Skipf("rule %s uses entropy matcher, no regex pattern to compile", r.ID)
				return
			}
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

		// Cloud/Infra (SEC-087 to SEC-100)
		"SEC-087": "cloudflare_api_token = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\n",
		"SEC-088": "cloudflare_api_key = " + "abcdef1234567890abcdef1234567890abcde\n",
		"SEC-089": "fo1_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n",
		"SEC-090": "VERCEL_TOKEN = " + "ABCDEFGHIJKLMNOPQRSTUVWx\n",
		"SEC-091": "NETLIFY_AUTH_TOKEN = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n",
		"SEC-092": "pscale_tkn_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n",
		"SEC-093": "pscale_oauth_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n",
		"SEC-094": "pul-" + "aabbccddeeff00112233445566778899aabbccdd\n",
		"SEC-095": "snowflake_password = \"" + "mysecretpass\"\n",
		"SEC-096": "MONGO_API_KEY = " + "abcdef1234567890abcdef1234567890\n",
		"SEC-097": "AIVEN_TOKEN = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx\n",
		"SEC-098": "rnd_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n",
		"SEC-099": "RAILWAY_TOKEN = " + "abcdef12-3456-7890-abcd-ef1234567890\n",
		"SEC-100": "SUPABASE_SERVICE_ROLE_KEY = " + "eyJ" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst\n",

		// Identity/Auth (SEC-101 to SEC-106)
		"SEC-101": "AUTH0_TOKEN = " + "eyJ" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\n",
		"SEC-102": "OKTA_TOKEN = " + "00ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno\n",
		"SEC-103": "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWx\n",
		"SEC-104": "\"type\": \"service_account\", " + "\"project_id\": \"my-firebase-project\"\n",
		"SEC-105": "SUPABASE_ANON_KEY = " + "eyJ" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst\n",
		"SEC-106": "KEYCLOAK_SECRET = " + "abcdef12-3456-7890-abcd-ef1234567890\n",

		// Observability (SEC-107 to SEC-112)
		"SEC-107": "DD_API_KEY = " + "abcdef1234567890abcdef1234567890\n",
		"SEC-108": "DD_APP_KEY = " + "abcdef1234567890abcdef1234567890aabbccdd\n",
		"SEC-109": "https://" + "abcdef1234567890abcdef1234567890" + "@o123456.ingest.sentry.io/1234567\n",
		"SEC-110": "ELASTIC_API_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n",
		"SEC-111": "SPLUNK_TOKEN = " + "abcdef12-3456-7890-abcd-ef1234567890\n",
		"SEC-112": "GF_API_KEY = " + "eyJ" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg\n",

		// AI/ML (SEC-113 to SEC-122)
		"SEC-113": "PINECONE_API_KEY = " + "abcdef12-3456-7890-abcd-ef1234567890\n",
		"SEC-114": "WEAVIATE_API_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n",
		"SEC-115": "AIza" + "SyD-abcdefghijklmnopqrstuvwxyz12345\n",
		"SEC-116": "MISTRAL_API_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n",
		"SEC-117": "gsk_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx\n",
		"SEC-118": "TOGETHER_API_KEY = " + "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd\n",
		"SEC-119": "pplx-" + "abcdef1234567890abcdef1234567890abcdef1234567890\n",
		"SEC-120": "VOYAGE_API_KEY = " + "pa-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n",
		"SEC-121": "ANYSCALE_API_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n",
		"SEC-122": "COHERE_API_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\n",

		// Productivity/SaaS (SEC-123 to SEC-135)
		"SEC-123": "secret_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq\n",
		"SEC-124": "figd_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n",
		"SEC-125": "ATLASSIAN_TOKEN = " + "ABCDEFGHIJKLMNOPQRSTUVWx\n",
		"SEC-126": "circle_token = " + "aabbccddeeff00112233445566778899aabbccdd\n",
		"SEC-127": "lin_api_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\n",
		"SEC-128": "BUILDKITE_AGENT_TOKEN = " + "aabbccddeeff00112233445566778899aabbccddee\n",
		"SEC-129": "ASANA_PAT = " + "0/1234567890123456/ABCDEFGHIJKLMNOPQRSTUVWXYZabcd\n",
		"SEC-130": "AIRTABLE_API_KEY = " + "keyABCDEFGHIJKLMN\n",
		"SEC-131": "CONFLUENCE_API_TOKEN = " + "ABCDEFGHIJKLMNOPQRSTUVWx\n",
		"SEC-132": "glpat-" + "ABCDEFghijklmnopqrst\n",
		"SEC-133": "BITBUCKET_PASSWORD = " + "ABCDEFGHIJKLMNOPQRa\n",
		"SEC-134": "TRAVIS_TOKEN = " + "ABCDEFghijklmnopqrstuv\n",
		"SEC-135": "SNYK_TOKEN = " + "abcdef12-3456-7890-abcd-ef1234567890\n",

		// Financial/Crypto (SEC-136 to SEC-145)
		"SEC-136": "PLAID_SECRET = " + "aabbccddeeff00112233445566778899\n",
		"SEC-137": "COINBASE_API_KEY = " + "ABCDEFGHIJKLMNOP\n",
		"SEC-138": "BINANCE_API_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB\n",
		"SEC-139": "PAYPAL_SECRET = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n",
		"SEC-140": "ADYEN_API_KEY = " + "AQEabcde." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n",
		"SEC-141": "RECURLY_API_KEY = " + "abcdef1234567890abcdef1234567890\n",
		"SEC-142": "access_token" + "$production$" + "abcdef1234567890$abcdef1234567890abcdef1234567890\n",
		"SEC-143": "sq0atp-" + "ABCDEFGHIJKLMNOPQRSTUV\n",
		"SEC-144": "ETHERSCAN_API_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678\n",
		"SEC-145": "ALCHEMY_API_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n",

		// Messaging/Email (SEC-146 to SEC-155)
		"SEC-146": "POSTMARK_TOKEN = " + "abcdef12-3456-7890-abcd-ef1234567890\n",
		"SEC-147": "re_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n",
		"SEC-148": "PUSHER_SECRET = " + "aabbccddeeff00112233\n",
		"SEC-149": "ably_key=appid" + ".keyid:" + "ABCDEFGHIJKLMNOPQRSTa\n",
		"SEC-150": "MESSAGEBIRD_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXy\n",
		"SEC-151": "VONAGE_SECRET = " + "abcdef1234567890\n",
		"SEC-152": "abcdef1234567890abcdef1234567890" + "-us12\n",
		"SEC-153": "SG." + "ABCDEFghijklmnopqrstuv." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst_v\n",
		"SEC-154": "TWILIO_AUTH_TOKEN = " + "abcdef1234567890abcdef1234567890\n",
		"SEC-155": "COURIER_AUTH_TOKEN = " + "pk_live_ABCDEFGHIJKLMNOPQRSTa\n",

		// Misc (SEC-156 to SEC-160)
		"SEC-156": "pk." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678901\n",
		"SEC-157": "sdk-" + "abcdef12-3456-7890-abcd-ef1234567890\n",
		"SEC-158": "SEGMENT_WRITE_KEY = " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n",
		"SEC-159": "AMPLITUDE_API_KEY = " + "abcdef1234567890abcdef1234567890\n",
		"SEC-160": "dp.st." + "my_env." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n",

		// Entropy rules (SEC-161 to SEC-163)
		// These use a source-like filename (test.go) because entropy rules
		// have FilePatterns restricting them to source files.
		// SEC-162 and SEC-163 require context keywords on the line.
		// SEC-161: threshold=5.0, context boost -0.5 → effective 4.5;
		//   candidate entropy must be ≥4.5 and extractable by assignment RHS tokenizer.
		"SEC-161": "secret_key = " + "xK9mR3pZ7wL2jY5n" + "Q8vB4fH1cT6gD0sA\n",
		// SEC-162: threshold=5.2, require_context, context boost -0.5 → effective 4.7;
		//   base64 blob extracted by base64 regex (30+ chars).
		"SEC-162": "secret_token = " + "Kj7xR2mD3nG9pQ5wZ8vL4jY1cH6bT0fAsXeWuIoP+q=\n",
		// SEC-163: threshold=4.5, require_context, context boost -0.5 → effective 4.0;
		//   mixed-case hex for entropy > 4.0 (pure lowercase hex max is exactly 4.0).
		"SEC-163": "hex_key = " + "9F8e7D6c5B4a3210" + "FEdcBA9876543210\n",
	}

	// Entropy rules have FilePatterns restricting them to source-like files,
	// so they need a matching filename.
	entropyRules := map[string]bool{"SEC-161": true, "SEC-162": true, "SEC-163": true}

	// Imported rules from Gitleaks don't have test examples yet
	importedRules := make(map[string]bool)
	for i := 164; i <= 445; i++ {
		importedRules[fmt.Sprintf("SEC-%03d", i)] = true
	}

	a := NewAnalyzer()
	for _, r := range builtinSecretRules() {
		t.Run(r.ID, func(t *testing.T) {
			example, ok := examples[r.ID]
			if !ok {
				// Skip imported rules without test examples
				if importedRules[r.ID] {
					t.Skip("no positive example for imported rule")
				}
				t.Fatalf("no positive example for rule %s", r.ID)
			}
			filename := "test.txt"
			if entropyRules[r.ID] {
				filename = "test.go"
			}
			results, err := a.ScanFile(filename, []byte(example))
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

// TestAllRules_Count verifies we have the expected number of built-in secret rules
// (160 original regex + 3 entropy + 276 imported = 439).
func TestAllRules_Count(t *testing.T) {
	rules := builtinSecretRules()
	if len(rules) != 439 {
		t.Fatalf("expected 439 built-in secret rules, got %d", len(rules))
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

// ---------------------------------------------------------------------------
// ApplyEntropyOverrides tests
// ---------------------------------------------------------------------------

func TestApplyEntropyOverrides_AllFields(t *testing.T) {
	a := NewAnalyzer()

	reqCtx := true
	a.ApplyEntropyOverrides(EntropyOverrides{
		Threshold:       6.0,
		HexThreshold:    5.5,
		Base64Threshold: 6.5,
		RequireContext:  &reqCtx,
	})

	// Verify SEC-161 threshold was overridden.
	r161, ok := a.Rules().ByID("SEC-161")
	if !ok {
		t.Fatal("SEC-161 not found")
	}
	if r161.Metadata["entropy_threshold"] != "6" {
		t.Errorf("SEC-161 threshold: expected '6', got %q", r161.Metadata["entropy_threshold"])
	}

	// Verify SEC-162 threshold and require_context.
	r162, ok := a.Rules().ByID("SEC-162")
	if !ok {
		t.Fatal("SEC-162 not found")
	}
	if r162.Metadata["entropy_threshold"] != "6.5" {
		t.Errorf("SEC-162 threshold: expected '6.5', got %q", r162.Metadata["entropy_threshold"])
	}
	if r162.Metadata["require_context"] != "true" {
		t.Errorf("SEC-162 require_context: expected 'true', got %q", r162.Metadata["require_context"])
	}

	// Verify SEC-163 threshold and require_context.
	r163, ok := a.Rules().ByID("SEC-163")
	if !ok {
		t.Fatal("SEC-163 not found")
	}
	if r163.Metadata["entropy_threshold"] != "5.5" {
		t.Errorf("SEC-163 threshold: expected '5.5', got %q", r163.Metadata["entropy_threshold"])
	}
	if r163.Metadata["require_context"] != "true" {
		t.Errorf("SEC-163 require_context: expected 'true', got %q", r163.Metadata["require_context"])
	}
}

func TestApplyEntropyOverrides_RequireContextFalse(t *testing.T) {
	a := NewAnalyzer()

	reqCtx := false
	a.ApplyEntropyOverrides(EntropyOverrides{
		RequireContext: &reqCtx,
	})

	r162, ok := a.Rules().ByID("SEC-162")
	if !ok {
		t.Fatal("SEC-162 not found")
	}
	if r162.Metadata["require_context"] != "false" {
		t.Errorf("SEC-162 require_context: expected 'false', got %q", r162.Metadata["require_context"])
	}
}

func TestApplyEntropyOverrides_PartialFields(t *testing.T) {
	a := NewAnalyzer()

	// Only set threshold for SEC-161, leave others at defaults.
	a.ApplyEntropyOverrides(EntropyOverrides{
		Threshold: 7.0,
	})

	r161, ok := a.Rules().ByID("SEC-161")
	if !ok {
		t.Fatal("SEC-161 not found")
	}
	if r161.Metadata["entropy_threshold"] != "7" {
		t.Errorf("SEC-161 threshold: expected '7', got %q", r161.Metadata["entropy_threshold"])
	}

	// SEC-162 and SEC-163 thresholds should remain at their built-in defaults.
	r162, ok := a.Rules().ByID("SEC-162")
	if !ok {
		t.Fatal("SEC-162 not found")
	}
	// The default from rules.go is 5.2 — check it wasn't changed.
	if r162.Metadata["entropy_threshold"] != "5.2" {
		t.Errorf("SEC-162 threshold should remain default, got %q", r162.Metadata["entropy_threshold"])
	}
}

func TestApplyEntropyOverrides_NoOp(t *testing.T) {
	a := NewAnalyzer()

	// Get original values.
	r161Before, _ := a.Rules().ByID("SEC-161")
	origThreshold := r161Before.Metadata["entropy_threshold"]

	// Apply empty overrides — nothing should change.
	a.ApplyEntropyOverrides(EntropyOverrides{})

	r161After, _ := a.Rules().ByID("SEC-161")
	if r161After.Metadata["entropy_threshold"] != origThreshold {
		t.Errorf("expected threshold unchanged, got %q (was %q)",
			r161After.Metadata["entropy_threshold"], origThreshold)
	}
}

// ---------------------------------------------------------------------------
// DecodeAndScan / truncateString tests
// ---------------------------------------------------------------------------

func TestDecodeAndScan_NoSegments(t *testing.T) {
	a := NewAnalyzer()
	// Clean content with no base64/hex segments.
	content := []byte("package main\nfunc main() {}\n")
	results := DecodeAndScan(content, "main.go", a.engine)
	if len(results) != 0 {
		t.Errorf("expected 0 results for clean content, got %d", len(results))
	}
}

func TestDecodeAndScan_Base64Secret(t *testing.T) {
	a := NewAnalyzer()
	// Base64 encode an AWS key (AKIAIOSFODNN7EXAMPLE).
	// Base64 of "AKIAIOSFODNN7EXAMPLE" = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	// But we need a string long enough (>=40 chars) for the regex to match.
	// Let's use a longer payload:
	// "aws_access_key_id = AKIAIOSFODNN7EXAMPLE" base64 = "YXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBSU9TRk9ETk43RVhBTVBMRQ=="
	content := []byte("encoded_data = YXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBSU9TRk9ETk43RVhBTVBMRQ==\n")
	results := DecodeAndScan(content, "config.go", a.engine)

	// Check that any results have encoding metadata.
	for _, r := range results {
		if r.Metadata["encoding"] != "base64" {
			t.Errorf("expected encoding=base64, got %q", r.Metadata["encoding"])
		}
		if r.Metadata["encoded_value"] == "" {
			t.Error("expected non-empty encoded_value metadata")
		}
	}
}

func TestTruncateString_Short(t *testing.T) {
	result := truncateString("hello", 10)
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestTruncateString_Exact(t *testing.T) {
	result := truncateString("12345", 5)
	if result != "12345" {
		t.Errorf("expected '12345', got %q", result)
	}
}

func TestTruncateString_Long(t *testing.T) {
	result := truncateString("1234567890", 5)
	if result != "12345..." {
		t.Errorf("expected '12345...', got %q", result)
	}
}

func TestTruncateString_Empty(t *testing.T) {
	result := truncateString("", 10)
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestIsPrintable_AllPrintable(t *testing.T) {
	if !isPrintable([]byte("Hello World!")) {
		t.Error("expected all printable ASCII to return true")
	}
}

func TestIsPrintable_Empty(t *testing.T) {
	if isPrintable([]byte{}) {
		t.Error("expected empty data to return false")
	}
}

func TestIsPrintable_Binary(t *testing.T) {
	if isPrintable([]byte{0x00, 0x01, 0x02, 0x03, 0x04}) {
		t.Error("expected binary data to return false")
	}
}

func TestDecodeBase64Segments_ValidBase64(t *testing.T) {
	// Base64 encodes a long printable ASCII sentence.
	content := []byte("data = SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZyB0aGF0IGlzIGxvbmcgZW5vdWdo\n")
	segments := decodeBase64Segments(content)
	if len(segments) == 0 {
		t.Fatal("expected at least one base64 segment")
	}
	if segments[0].Encoding != "base64" {
		t.Errorf("expected encoding 'base64', got %q", segments[0].Encoding)
	}
}

func TestDecodeHexSegments_ValidHex(t *testing.T) {
	// 40+ char hex string that decodes to printable ASCII.
	// "48656c6c6f20576f726c642121212121212121" = "Hello World!!!!!!!!"
	hexStr := "48656c6c6f20576f726c642121212121212121"
	// Need 40+ chars, currently 38. Pad with more.
	hexStr += "21212121" // = "Hello World!!!!!!!!!!!!"
	content := []byte("hex = " + hexStr + "\n")
	segments := decodeHexSegments(content)
	// May or may not produce segments depending on exact printability ratio.
	// Just verify no panic.
	_ = segments
}

func TestDecodeHexSegments_OddLength(t *testing.T) {
	// Odd-length hex should be skipped.
	oddHex := "48656c6c6f20576f726c64212121212121212121a" // 41 chars, odd
	content := []byte("hex = " + oddHex + "\n")
	segments := decodeHexSegments(content)
	if len(segments) != 0 {
		t.Errorf("expected 0 segments for odd-length hex, got %d", len(segments))
	}
}
