package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// RuleSet tests
// ---------------------------------------------------------------------------

func TestRuleSet_Add_and_Rules(t *testing.T) {
	rs := NewRuleSet()
	r := Rule{ID: "TEST-001", MatcherType: "regex", Severity: "high"}
	rs.Add(r)

	if got := len(rs.Rules()); got != 1 {
		t.Fatalf("expected 1 rule, got %d", got)
	}
	if rs.Rules()[0].ID != "TEST-001" {
		t.Fatalf("expected rule ID TEST-001, got %s", rs.Rules()[0].ID)
	}
}

func TestRuleSet_ByID(t *testing.T) {
	rs := NewRuleSet()
	rs.Add(Rule{ID: "A", MatcherType: "regex", Severity: "low"})
	rs.Add(Rule{ID: "B", MatcherType: "regex", Severity: "high"})

	t.Run("existing", func(t *testing.T) {
		r, ok := rs.ByID("B")
		if !ok {
			t.Fatal("expected to find rule B")
		}
		if r.ID != "B" {
			t.Fatalf("expected ID B, got %s", r.ID)
		}
	})

	t.Run("missing", func(t *testing.T) {
		_, ok := rs.ByID("Z")
		if ok {
			t.Fatal("expected rule Z to not be found")
		}
	})
}

func TestRuleSet_ByTag(t *testing.T) {
	rs := NewRuleSet()
	rs.Add(Rule{ID: "A", MatcherType: "regex", Severity: "low", Tags: []string{"secret", "aws"}})
	rs.Add(Rule{ID: "B", MatcherType: "regex", Severity: "high", Tags: []string{"secret"}})
	rs.Add(Rule{ID: "C", MatcherType: "regex", Severity: "medium", Tags: []string{"sql"}})

	t.Run("tag with multiple rules", func(t *testing.T) {
		got := rs.ByTag("secret")
		if len(got) != 2 {
			t.Fatalf("expected 2 rules with tag 'secret', got %d", len(got))
		}
	})

	t.Run("tag with single rule", func(t *testing.T) {
		got := rs.ByTag("aws")
		if len(got) != 1 {
			t.Fatalf("expected 1 rule with tag 'aws', got %d", len(got))
		}
		if got[0].ID != "A" {
			t.Fatalf("expected rule A, got %s", got[0].ID)
		}
	})

	t.Run("nonexistent tag", func(t *testing.T) {
		got := rs.ByTag("nonexistent")
		if got != nil {
			t.Fatalf("expected nil for nonexistent tag, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// YAML loading tests
// ---------------------------------------------------------------------------

const validYAML = `rules:
  - id: "SEC-001"
    version: "1.0"
    description: "Hardcoded password detected"
    severity: "high"
    confidence: "medium"
    matcher_type: "regex"
    pattern: "password\\s*=\\s*\"[^\"]+\""
    file_patterns:
      - "*.go"
      - "*.py"
    tags:
      - "secret"
      - "password"
    metadata:
      cwe: "CWE-798"
  - id: "SEC-002"
    version: "1.0"
    description: "AWS access key"
    severity: "critical"
    confidence: "high"
    matcher_type: "regex"
    pattern: "AKIA[0-9A-Z]{16}"
    tags:
      - "secret"
      - "aws"
`

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return p
}

func TestLoadRulesFromFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := writeTemp(t, dir, "rules.yaml", validYAML)

	rs, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rs.Rules()) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rs.Rules()))
	}

	r, ok := rs.ByID("SEC-001")
	if !ok {
		t.Fatal("expected to find SEC-001")
	}
	if r.Severity != findings.SeverityHigh {
		t.Fatalf("expected severity high, got %s", r.Severity)
	}
	if r.Confidence != findings.ConfidenceMedium {
		t.Fatalf("expected confidence medium, got %s", r.Confidence)
	}
	if len(r.FilePatterns) != 2 {
		t.Fatalf("expected 2 file patterns, got %d", len(r.FilePatterns))
	}
	if r.Metadata["cwe"] != "CWE-798" {
		t.Fatalf("expected metadata cwe=CWE-798, got %s", r.Metadata["cwe"])
	}
}

func TestLoadRulesFromFile_EmptyID(t *testing.T) {
	yaml := `rules:
  - id: ""
    matcher_type: "regex"
    severity: "high"
    pattern: "test"
`
	dir := t.TempDir()
	path := writeTemp(t, dir, "bad.yaml", yaml)

	_, err := LoadRulesFromFile(path)
	if err == nil {
		t.Fatal("expected error for empty rule ID")
	}
}

func TestLoadRulesFromFile_InvalidMatcherType(t *testing.T) {
	yaml := `rules:
  - id: "BAD-001"
    matcher_type: "xpath"
    severity: "high"
    pattern: "//password"
`
	dir := t.TempDir()
	path := writeTemp(t, dir, "bad.yaml", yaml)

	_, err := LoadRulesFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid matcher_type")
	}
}

func TestLoadRulesFromFile_InvalidSeverity(t *testing.T) {
	yaml := `rules:
  - id: "BAD-002"
    matcher_type: "regex"
    severity: "extreme"
    pattern: "test"
`
	dir := t.TempDir()
	path := writeTemp(t, dir, "bad.yaml", yaml)

	_, err := LoadRulesFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestLoadRulesFromFile_NonexistentFile(t *testing.T) {
	_, err := LoadRulesFromFile("/nonexistent/path/rules.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadRulesFromDir(t *testing.T) {
	dir := t.TempDir()

	yaml1 := `rules:
  - id: "DIR-001"
    matcher_type: "regex"
    severity: "low"
    pattern: "TODO"
    tags:
      - "todo"
`
	yaml2 := `rules:
  - id: "DIR-002"
    matcher_type: "regex"
    severity: "medium"
    pattern: "FIXME"
    tags:
      - "todo"
`
	writeTemp(t, dir, "a_rules.yaml", yaml1)
	writeTemp(t, dir, "b_rules.yml", yaml2)
	// Non-YAML file should be ignored.
	writeTemp(t, dir, "readme.txt", "this is not yaml")

	rs, err := LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rs.Rules()) != 2 {
		t.Fatalf("expected 2 rules from directory, got %d", len(rs.Rules()))
	}

	// Verify deterministic order (a_rules.yaml before b_rules.yml).
	if rs.Rules()[0].ID != "DIR-001" {
		t.Fatalf("expected first rule DIR-001, got %s", rs.Rules()[0].ID)
	}
	if rs.Rules()[1].ID != "DIR-002" {
		t.Fatalf("expected second rule DIR-002, got %s", rs.Rules()[1].ID)
	}
}

func TestLoadRulesFromDir_Nonexistent(t *testing.T) {
	_, err := LoadRulesFromDir("/nonexistent/dir")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

// ---------------------------------------------------------------------------
// RegexMatcher tests
// ---------------------------------------------------------------------------

func TestRegexMatcher_BasicMatch(t *testing.T) {
	m := NewRegexMatcher()
	content := []byte("line one\npassword = \"secret123\"\nline three\n")
	rule := Rule{Pattern: `password\s*=\s*"[^"]+"`}

	results := m.Match(content, rule)
	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}
	if results[0].Line != 2 {
		t.Fatalf("expected match on line 2, got %d", results[0].Line)
	}
	if results[0].Column != 1 {
		t.Fatalf("expected column 1, got %d", results[0].Column)
	}
	if results[0].MatchText != `password = "secret123"` {
		t.Fatalf("unexpected match text: %s", results[0].MatchText)
	}
}

func TestRegexMatcher_MultipleMatches(t *testing.T) {
	m := NewRegexMatcher()
	content := []byte("TODO: fix this\nsome code\nTODO: and this\n")
	rule := Rule{Pattern: `TODO`}

	results := m.Match(content, rule)
	if len(results) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(results))
	}
	if results[0].Line != 1 {
		t.Fatalf("expected first match on line 1, got %d", results[0].Line)
	}
	if results[1].Line != 3 {
		t.Fatalf("expected second match on line 3, got %d", results[1].Line)
	}
}

func TestRegexMatcher_NoMatch(t *testing.T) {
	m := NewRegexMatcher()
	content := []byte("nothing interesting here\n")
	rule := Rule{Pattern: `AKIA[0-9A-Z]{16}`}

	results := m.Match(content, rule)
	if len(results) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(results))
	}
}

func TestRegexMatcher_InvalidPattern(t *testing.T) {
	m := NewRegexMatcher()
	content := []byte("test content\n")
	rule := Rule{Pattern: `[invalid`}

	results := m.Match(content, rule)
	if results != nil {
		t.Fatalf("expected nil for invalid pattern, got %v", results)
	}
}

func TestRegexMatcher_ColumnPosition(t *testing.T) {
	m := NewRegexMatcher()
	content := []byte("    secret_key = AKIA1234567890ABCDEF\n")
	rule := Rule{Pattern: `AKIA[0-9A-Z]{16}`}

	results := m.Match(content, rule)
	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}
	if results[0].Column != 18 {
		t.Fatalf("expected column 18, got %d", results[0].Column)
	}
}

// ---------------------------------------------------------------------------
// MatcherRegistry tests
// ---------------------------------------------------------------------------

func TestDefaultMatcherRegistry(t *testing.T) {
	reg := NewDefaultMatcherRegistry()

	for _, mt := range []string{"regex", "jsonpath", "yamlpath", "heuristic"} {
		if reg.Get(mt) == nil {
			t.Fatalf("expected matcher for type %q", mt)
		}
	}
	if reg.Get("unknown") != nil {
		t.Fatal("expected nil for unknown matcher type")
	}
}

// ---------------------------------------------------------------------------
// Engine tests
// ---------------------------------------------------------------------------

func TestEngine_ScanFile(t *testing.T) {
	yaml := `rules:
  - id: "SCAN-001"
    version: "1.0"
    description: "Hardcoded password"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "password\\s*=\\s*\"[^\"]+\""
    tags:
      - "secret"
`
	dir := t.TempDir()
	path := writeTemp(t, dir, "rules.yaml", yaml)

	rs, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}

	engine := NewEngine(rs)
	content := []byte("func main() {\n\tpassword = \"hunter2\"\n}\n")

	results, err := engine.ScanFile("main.go", content)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	f := results[0]
	if f.RuleID != "SCAN-001" {
		t.Fatalf("expected RuleID SCAN-001, got %s", f.RuleID)
	}
	if f.Severity != findings.SeverityHigh {
		t.Fatalf("expected severity high, got %s", f.Severity)
	}
	if f.Location.StartLine != 2 {
		t.Fatalf("expected start line 2, got %d", f.Location.StartLine)
	}
	if f.Location.FilePath != "main.go" {
		t.Fatalf("expected file path main.go, got %s", f.Location.FilePath)
	}
	if f.Fingerprint == "" {
		t.Fatal("expected non-empty fingerprint")
	}
}

func TestEngine_ScanFile_FilePatternFiltering(t *testing.T) {
	yaml := `rules:
  - id: "GO-001"
    description: "Go-only rule"
    severity: "medium"
    confidence: "medium"
    matcher_type: "regex"
    pattern: "fmt\\.Println"
    file_patterns:
      - "*.go"
`
	dir := t.TempDir()
	path := writeTemp(t, dir, "rules.yaml", yaml)

	rs, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}

	engine := NewEngine(rs)
	content := []byte("fmt.Println(\"hello\")\n")

	t.Run("matching file", func(t *testing.T) {
		results, err := engine.ScanFile("main.go", content)
		if err != nil {
			t.Fatalf("scan error: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 finding for .go file, got %d", len(results))
		}
	})

	t.Run("non-matching file", func(t *testing.T) {
		results, err := engine.ScanFile("main.py", content)
		if err != nil {
			t.Fatalf("scan error: %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("expected 0 findings for .py file, got %d", len(results))
		}
	})
}

func TestEngine_ScanFile_NoFilePatterns_MatchesAll(t *testing.T) {
	yaml := `rules:
  - id: "ALL-001"
    description: "Applies to all files"
    severity: "info"
    confidence: "low"
    matcher_type: "regex"
    pattern: "TODO"
`
	dir := t.TempDir()
	path := writeTemp(t, dir, "rules.yaml", yaml)

	rs, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}

	engine := NewEngine(rs)
	content := []byte("// TODO: implement\n")

	for _, file := range []string{"main.go", "script.py", "config.yaml", "README.md"} {
		results, err := engine.ScanFile(file, content)
		if err != nil {
			t.Fatalf("scan error for %s: %v", file, err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 finding for %s, got %d", file, len(results))
		}
	}
}

func TestEngine_ScanFile_MultipleRules(t *testing.T) {
	yaml := `rules:
  - id: "MULTI-001"
    description: "Find TODO"
    severity: "low"
    confidence: "high"
    matcher_type: "regex"
    pattern: "TODO"
  - id: "MULTI-002"
    description: "Find FIXME"
    severity: "medium"
    confidence: "high"
    matcher_type: "regex"
    pattern: "FIXME"
`
	dir := t.TempDir()
	path := writeTemp(t, dir, "rules.yaml", yaml)

	rs, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}

	engine := NewEngine(rs)
	content := []byte("// TODO: first\n// FIXME: second\n")

	results, err := engine.ScanFile("code.go", content)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(results))
	}

	// Verify both rules produced findings.
	ruleIDs := map[string]bool{}
	for _, f := range results {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["MULTI-001"] || !ruleIDs["MULTI-002"] {
		t.Fatalf("expected findings from both rules, got rule IDs: %v", ruleIDs)
	}
}

func TestEngine_ScanFile_NoMatches(t *testing.T) {
	yaml := `rules:
  - id: "NOMATCH-001"
    description: "Will not match"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "AKIA[0-9A-Z]{16}"
`
	dir := t.TempDir()
	path := writeTemp(t, dir, "rules.yaml", yaml)

	rs, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}

	engine := NewEngine(rs)
	content := []byte("clean code with no secrets\n")

	results, err := engine.ScanFile("main.go", content)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// Keyword pre-filtering tests
// ---------------------------------------------------------------------------

func TestEngine_ScanFile_KeywordFiltering(t *testing.T) {
	rs := NewRuleSet()
	rs.Add(Rule{
		ID:          "KW-001",
		Description: "Has keywords, should match",
		Severity:    "high",
		Confidence:  "high",
		MatcherType: "regex",
		Pattern:     `AKIA[0-9A-Z]{16}`,
		Keywords:    []string{"akia"},
	})
	rs.Add(Rule{
		ID:          "KW-002",
		Description: "Has keywords, should NOT match",
		Severity:    "high",
		Confidence:  "high",
		MatcherType: "regex",
		Pattern:     `ghp_[A-Za-z0-9]{36}`,
		Keywords:    []string{"ghp_"},
	})
	rs.Add(Rule{
		ID:          "KW-003",
		Description: "No keywords, always runs",
		Severity:    "low",
		Confidence:  "low",
		MatcherType: "regex",
		Pattern:     `TODO`,
	})

	engine := NewEngine(rs)
	content := []byte("secret = AKIAIOSFODNN7EXAMPLE\n// TODO: fix\n")

	results, err := engine.ScanFile("test.go", content)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	ruleIDs := map[string]bool{}
	for _, f := range results {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["KW-001"] {
		t.Fatal("expected KW-001 (keyword matched)")
	}
	if ruleIDs["KW-002"] {
		t.Fatal("KW-002 should have been skipped (keyword not present)")
	}
	if !ruleIDs["KW-003"] {
		t.Fatal("expected KW-003 (no keywords, always runs)")
	}
}

func TestEngine_ScanFile_KeywordCaseInsensitive(t *testing.T) {
	rs := NewRuleSet()
	rs.Add(Rule{
		ID:          "KW-CI",
		Description: "Case-insensitive keyword",
		Severity:    "high",
		Confidence:  "high",
		MatcherType: "regex",
		Pattern:     `AKIA[0-9A-Z]{16}`,
		Keywords:    []string{"akia"},
	})

	engine := NewEngine(rs)
	// Content has uppercase AKIA, keyword is lowercase akia.
	content := []byte("key = AKIAIOSFODNN7EXAMPLE\n")

	results, err := engine.ScanFile("test.txt", content)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding (case-insensitive keyword match), got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// fileMatchesRule tests
// ---------------------------------------------------------------------------

func TestFileMatchesRule(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		filePatterns []string
		want         bool
	}{
		{
			name:         "empty patterns match everything",
			path:         "anything.txt",
			filePatterns: nil,
			want:         true,
		},
		{
			name:         "glob matches base name",
			path:         "src/main.go",
			filePatterns: []string{"*.go"},
			want:         true,
		},
		{
			name:         "glob does not match different extension",
			path:         "src/main.py",
			filePatterns: []string{"*.go"},
			want:         false,
		},
		{
			name:         "multiple patterns first matches",
			path:         "app.js",
			filePatterns: []string{"*.go", "*.js"},
			want:         true,
		},
		{
			name:         "exact filename match",
			path:         "Dockerfile",
			filePatterns: []string{"Dockerfile"},
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{FilePatterns: tt.filePatterns}
			got := fileMatchesRule(tt.path, rule)
			if got != tt.want {
				t.Fatalf("fileMatchesRule(%q, %v) = %v, want %v", tt.path, tt.filePatterns, got, tt.want)
			}
		})
	}
}
