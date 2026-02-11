package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile creates a file in the given directory with the specified content.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("creating parent dirs for %s: %v", p, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", p, err)
	}
	return p
}

// customRuleYAML defines a custom regex rule that matches "CUSTOM_SECRET_"
// followed by 16 hex characters. This pattern does not overlap with any
// built-in rule, making it safe for testing custom rule loading.
const customRuleYAML = `rules:
  - id: "CUSTOM-001"
    version: "1.0"
    description: "Custom secret pattern"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "CUSTOM_SECRET_[0-9a-f]{16}"
    tags:
      - "custom"
`

func TestScan_CustomRulesFile(t *testing.T) {
	// Set up a scan target with a file containing the custom secret pattern.
	scanDir := t.TempDir()
	writeFile(t, scanDir, "app.go", `package main

func main() {
	secret := "CUSTOM_SECRET_abcdef0123456789"
}
`)
	// Write the custom rule to a separate temp file.
	rulesDir := t.TempDir()
	rulesFile := writeFile(t, rulesDir, "custom.yaml", customRuleYAML)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--rules", rulesFile, "--output", outDir, "scan", scanDir})
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings detected), got %d", code)
	}

	// Parse findings.json and verify the custom rule triggered.
	data, err := os.ReadFile(filepath.Join(outDir, "findings.json"))
	if err != nil {
		t.Fatalf("reading findings.json: %v", err)
	}
	if !strings.Contains(string(data), "CUSTOM-001") {
		t.Fatal("expected findings.json to contain custom rule CUSTOM-001")
	}
}

func TestScan_CustomRulesDir(t *testing.T) {
	// Set up a scan target with content matching two custom rules.
	scanDir := t.TempDir()
	writeFile(t, scanDir, "config.py", `
CUSTOM_SECRET_abcdef0123456789 = True
CUSTOM_TOKEN_abcdef0123456789ab = "value"
`)

	// Write two rule files to a directory.
	rulesDir := t.TempDir()
	writeFile(t, rulesDir, "secrets.yaml", customRuleYAML)
	writeFile(t, rulesDir, "tokens.yaml", `rules:
  - id: "CUSTOM-002"
    version: "1.0"
    description: "Custom token pattern"
    severity: "medium"
    confidence: "medium"
    matcher_type: "regex"
    pattern: "CUSTOM_TOKEN_[0-9a-f]{18}"
    tags:
      - "custom"
`)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--rules", rulesDir, "--output", outDir, "scan", scanDir})
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings detected), got %d", code)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "findings.json"))
	if err != nil {
		t.Fatalf("reading findings.json: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "CUSTOM-001") {
		t.Fatal("expected findings.json to contain CUSTOM-001")
	}
	if !strings.Contains(content, "CUSTOM-002") {
		t.Fatal("expected findings.json to contain CUSTOM-002")
	}
}

func TestScan_InvalidRulesPath(t *testing.T) {
	scanDir := t.TempDir()
	writeFile(t, scanDir, "main.go", "package main\nfunc main() {}\n")

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--rules", "/nonexistent/rules.yaml", "--output", outDir, "scan", scanDir})
	if code != 2 {
		t.Fatalf("expected exit code 2 (error) for nonexistent rules path, got %d", code)
	}
}

func TestScan_InvalidRuleYAML(t *testing.T) {
	scanDir := t.TempDir()
	writeFile(t, scanDir, "main.go", "package main\nfunc main() {}\n")

	rulesDir := t.TempDir()
	writeFile(t, rulesDir, "bad.yaml", `rules: [[[not valid yaml`)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--rules", filepath.Join(rulesDir, "bad.yaml"), "--output", outDir, "scan", scanDir})
	if code != 2 {
		t.Fatalf("expected exit code 2 (error) for malformed YAML, got %d", code)
	}
}

func TestScan_MergedRules(t *testing.T) {
	// Create a target that triggers both a built-in rule (SEC-001, AWS key)
	// and a custom rule.
	scanDir := t.TempDir()
	writeFile(t, scanDir, "secrets.env", `AWS_KEY=AKIAIOSFODNN7EXAMPLE
CUSTOM_SECRET_abcdef0123456789=leaked
`)

	rulesDir := t.TempDir()
	rulesFile := writeFile(t, rulesDir, "custom.yaml", customRuleYAML)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--rules", rulesFile, "--output", outDir, "scan", scanDir})
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings detected), got %d", code)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "findings.json"))
	if err != nil {
		t.Fatalf("reading findings.json: %v", err)
	}

	content := string(data)
	// Built-in SEC-001 should detect the AWS key.
	if !strings.Contains(content, "SEC-001") {
		t.Fatal("expected findings.json to contain built-in rule SEC-001")
	}
	// Custom CUSTOM-001 should detect the custom secret pattern.
	if !strings.Contains(content, "CUSTOM-001") {
		t.Fatal("expected findings.json to contain custom rule CUSTOM-001")
	}
}

func TestScan_DuplicateRuleID(t *testing.T) {
	scanDir := t.TempDir()
	writeFile(t, scanDir, "main.go", "package main\nfunc main() {}\n")

	// SEC-001 is a built-in rule ID; using it in a custom rule should fail.
	rulesDir := t.TempDir()
	rulesFile := writeFile(t, rulesDir, "duplicate.yaml", `rules:
  - id: "SEC-001"
    version: "1.0"
    description: "Duplicate of built-in rule"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "test"
    tags:
      - "test"
`)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--rules", rulesFile, "--output", outDir, "scan", scanDir})
	if code != 2 {
		t.Fatalf("expected exit code 2 (error) for duplicate rule ID, got %d", code)
	}
}

func TestScan_CustomRulesFromConfig(t *testing.T) {
	// Verify that rules_dir in .nox.yaml loads custom rules when --rules
	// is not provided on the command line.
	scanDir := t.TempDir()
	writeFile(t, scanDir, "app.txt", "CUSTOM_SECRET_abcdef0123456789\n")

	// Create custom rules directory inside the scan target.
	customDir := filepath.Join(scanDir, "custom-rules")
	if err := os.Mkdir(customDir, 0o755); err != nil {
		t.Fatalf("creating custom-rules dir: %v", err)
	}
	writeFile(t, customDir, "rules.yaml", customRuleYAML)

	// Write .nox.yaml with rules_dir pointing to the custom rules directory.
	writeFile(t, scanDir, ".nox.yaml", `scan:
  rules_dir: custom-rules
`)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--output", outDir, "scan", scanDir})
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings from config rules_dir), got %d", code)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "findings.json"))
	if err != nil {
		t.Fatalf("reading findings.json: %v", err)
	}
	if !strings.Contains(string(data), "CUSTOM-001") {
		t.Fatal("expected findings.json to contain CUSTOM-001 from config rules_dir")
	}
}

func TestScan_CLIRulesOverridesConfig(t *testing.T) {
	// When both --rules and .nox.yaml rules_dir are set, the CLI flag
	// should take precedence.
	scanDir := t.TempDir()
	writeFile(t, scanDir, "app.txt", "CUSTOM_SECRET_abcdef0123456789\nCLI_PATTERN_deadbeefcafebabe\n")

	// Config points to a directory with a rule that will NOT match.
	configRulesDir := filepath.Join(scanDir, "config-rules")
	if err := os.Mkdir(configRulesDir, 0o755); err != nil {
		t.Fatalf("creating config-rules dir: %v", err)
	}
	writeFile(t, configRulesDir, "rules.yaml", `rules:
  - id: "CONFIG-001"
    version: "1.0"
    description: "Config rule (should not run)"
    severity: "low"
    confidence: "low"
    matcher_type: "regex"
    pattern: "CONFIG_ONLY_PATTERN_NEVER_MATCHES"
    tags:
      - "config"
`)

	writeFile(t, scanDir, ".nox.yaml", `scan:
  rules_dir: config-rules
`)

	// CLI points to a file with a rule that WILL match.
	cliRulesDir := t.TempDir()
	cliRulesFile := writeFile(t, cliRulesDir, "cli.yaml", `rules:
  - id: "CLI-001"
    version: "1.0"
    description: "CLI rule"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "CLI_PATTERN_[0-9a-f]{16}"
    tags:
      - "cli"
`)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--rules", cliRulesFile, "--output", outDir, "scan", scanDir})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "findings.json"))
	if err != nil {
		t.Fatalf("reading findings.json: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "CLI-001") {
		t.Fatal("expected CLI-001 finding from --rules flag")
	}
	// CONFIG-001 should NOT appear because CLI flag overrides config.
	if strings.Contains(content, "CONFIG-001") {
		t.Fatal("CONFIG-001 should not appear when --rules overrides config")
	}
}

func TestScan_CustomRulesNoFindings(t *testing.T) {
	// A custom rule that does not match any content should not produce
	// findings, and the scan should exit with code 0.
	scanDir := t.TempDir()
	writeFile(t, scanDir, "main.go", "package main\nfunc main() {}\n")

	rulesDir := t.TempDir()
	rulesFile := writeFile(t, rulesDir, "no_match.yaml", `rules:
  - id: "NOMATCH-001"
    version: "1.0"
    description: "Will not match anything"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "WILL_NEVER_MATCH_ANYTHING_12345"
    tags:
      - "test"
`)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--rules", rulesFile, "--output", outDir, "scan", scanDir})
	if code != 0 {
		t.Fatalf("expected exit code 0 (no findings), got %d", code)
	}
}

func TestScan_CustomRulesInterspersedFlag(t *testing.T) {
	// Verify that --rules works when placed after "scan <path>" using the
	// interspersed flag extraction pattern. When the subcommand "scan" is
	// the first non-flag argument, string flags like --rules are correctly
	// hoisted to the top-level parser.
	scanDir := t.TempDir()
	writeFile(t, scanDir, "data.txt", "CUSTOM_SECRET_abcdef0123456789\n")

	rulesDir := t.TempDir()
	rulesFile := writeFile(t, rulesDir, "custom.yaml", customRuleYAML)

	outDir := filepath.Join(scanDir, "output")
	// Place --rules and --output after "scan <path>" so the interspersed
	// extraction hoists them to the front for the top-level parser.
	code := run([]string{"-q", "scan", scanDir, "--rules", rulesFile, "--output", outDir})
	if code != 1 {
		t.Fatalf("expected exit code 1 with interspersed --rules flag, got %d", code)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "findings.json"))
	if err != nil {
		t.Fatalf("reading findings.json: %v", err)
	}
	if !strings.Contains(string(data), "CUSTOM-001") {
		t.Fatal("expected CUSTOM-001 finding with interspersed --rules flag")
	}
}

func TestScan_CustomRuleInvalidRegex(t *testing.T) {
	// A rule with a pattern field that is not a valid regex should cause
	// a validation error at rule level (the engine silently skips invalid
	// patterns when compiling, but the rule itself should still load).
	// The rule engine gracefully handles invalid regex by returning no
	// matches, so the scan should succeed with no findings from this rule.
	scanDir := t.TempDir()
	writeFile(t, scanDir, "main.go", "package main\nfunc main() {}\n")

	rulesDir := t.TempDir()
	rulesFile := writeFile(t, rulesDir, "bad_regex.yaml", `rules:
  - id: "BADRE-001"
    version: "1.0"
    description: "Bad regex"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "[invalid"
    tags:
      - "test"
`)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--rules", rulesFile, "--output", outDir, "scan", scanDir})
	// The scan should succeed (bad regex is handled by the engine, returns no matches).
	if code != 0 {
		t.Fatalf("expected exit code 0 (invalid regex handled gracefully), got %d", code)
	}
}

func TestScan_CustomRuleMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "missing ID",
			yaml: `rules:
  - matcher_type: "regex"
    severity: "high"
    pattern: "test"
`,
		},
		{
			name: "missing matcher_type",
			yaml: `rules:
  - id: "BAD-001"
    severity: "high"
    pattern: "test"
`,
		},
		{
			name: "invalid severity",
			yaml: `rules:
  - id: "BAD-002"
    matcher_type: "regex"
    severity: "extreme"
    pattern: "test"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanDir := t.TempDir()
			writeFile(t, scanDir, "main.go", "package main\nfunc main() {}\n")

			rulesDir := t.TempDir()
			rulesFile := writeFile(t, rulesDir, "bad.yaml", tt.yaml)

			outDir := filepath.Join(scanDir, "output")
			code := run([]string{"--quiet", "--rules", rulesFile, "--output", outDir, "scan", scanDir})
			if code != 2 {
				t.Fatalf("expected exit code 2 (validation error), got %d", code)
			}
		})
	}
}

func TestScan_CustomRulesInSARIF(t *testing.T) {
	// Verify that custom rules appear in SARIF output alongside built-in
	// rules when --format sarif is used.
	scanDir := t.TempDir()
	writeFile(t, scanDir, "data.txt", "CUSTOM_SECRET_abcdef0123456789\n")

	rulesDir := t.TempDir()
	rulesFile := writeFile(t, rulesDir, "custom.yaml", customRuleYAML)

	outDir := filepath.Join(scanDir, "output")
	code := run([]string{"--quiet", "--format", "sarif", "--rules", rulesFile, "--output", outDir, "scan", scanDir})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "results.sarif"))
	if err != nil {
		t.Fatalf("reading results.sarif: %v", err)
	}

	// Parse SARIF to check for the custom rule.
	var sarif struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("parsing SARIF: %v", err)
	}

	if len(sarif.Runs) == 0 {
		t.Fatal("expected at least one SARIF run")
	}

	// Check that CUSTOM-001 appears in the SARIF rules.
	foundRule := false
	for _, r := range sarif.Runs[0].Tool.Driver.Rules {
		if r.ID == "CUSTOM-001" {
			foundRule = true
			break
		}
	}
	if !foundRule {
		t.Fatal("expected CUSTOM-001 in SARIF tool.driver.rules")
	}

	// Check that CUSTOM-001 appears in the SARIF results.
	foundResult := false
	for _, r := range sarif.Runs[0].Results {
		if r.RuleID == "CUSTOM-001" {
			foundResult = true
			break
		}
	}
	if !foundResult {
		t.Fatal("expected CUSTOM-001 in SARIF results")
	}
}
