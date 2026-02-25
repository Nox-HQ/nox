package rules

import (
	"testing"
)

// FuzzScanFile fuzzes arbitrary content through the rule engine with a
// representative set of rules. This exercises regex matching, keyword
// filtering, and the entire ScanFile code path with random inputs.
func FuzzScanFile(f *testing.F) {
	// nox:ignore SEC-001,SEC-078,SEC-100 -- fuzz seed corpus with intentional security patterns
	f.Add([]byte("AKIAIOSFODNN7EXAMPLE"), "main.go")
	f.Add([]byte("password = 'secret123'"), "config.py")
	f.Add([]byte("{}"), "test.json")
	f.Add([]byte(""), "empty.txt")
	f.Add([]byte("BEGIN RSA PRIVATE KEY"), "key.pem")
	f.Add([]byte("\x00\x01\x02binary"), "file.bin")
	f.Add([]byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"), "token.txt")
	f.Add([]byte("resource \"aws_s3_bucket\" {}"), "main.tf")

	// Build a RuleSet with representative rules for fuzzing.
	rs := NewRuleSet()
	rs.Add(&Rule{
		ID:          "FUZZ-001",
		Description: "Test regex rule",
		Severity:    "high",
		MatcherType: "regex",
		Pattern:     `(?i)password\s*[:=]\s*['"][^'"]+['"]`,
		Version:     "1.0",
	})
	rs.Add(&Rule{
		ID:          "FUZZ-002",
		Description: "Test keyword rule",
		Severity:    "medium",
		MatcherType: "regex",
		Pattern:     `AKIA[0-9A-Z]{16}`,
		Keywords:    []string{"AKIA"},
		Version:     "1.0",
	})
	rs.Add(&Rule{
		ID:           "FUZZ-003",
		Description:  "Test file pattern rule",
		Severity:     "low",
		MatcherType:  "regex",
		Pattern:      `BEGIN.*PRIVATE KEY`,
		FilePatterns: []string{"*.pem", "*.key"},
		Version:      "1.0",
	})

	engine := NewEngine(rs)

	f.Fuzz(func(t *testing.T, content []byte, path string) {
		// Must not panic regardless of input.
		_, _ = engine.ScanFile(path, content)
	})
}

// FuzzContainsAnyKeyword fuzzes the keyword matching function with
// arbitrary content and keyword combinations.
func FuzzContainsAnyKeyword(f *testing.F) {
	f.Add([]byte("api_key"), "api_key")
	f.Add([]byte("password"), "password")
	f.Add([]byte("nothing here"), "secret")
	f.Add([]byte(""), "")
	f.Add([]byte("mixed CASE content"), "case")

	f.Fuzz(func(t *testing.T, content []byte, keyword string) {
		if keyword == "" {
			return
		}
		_ = containsAnyKeyword(content, []string{keyword})
	})
}
