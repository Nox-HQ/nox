package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// RunScan tests
// ---------------------------------------------------------------------------

func TestRunScan_EmptyDirectory(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Findings == nil {
		t.Fatal("expected non-nil findings set")
	}
	if result.Inventory == nil {
		t.Fatal("expected non-nil inventory")
	}
	if result.AIInventory == nil {
		t.Fatal("expected non-nil AI inventory")
	}
	if result.Rules == nil {
		t.Fatal("expected non-nil rules")
	}
}

func TestRunScan_DetectsSecrets(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with a known AWS Access Key pattern (SEC-001).
	testFile := filepath.Join(tmpDir, "config.go")
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	content := `package main

const apiKey = "` + awsKey + `"
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(result.Findings.Findings()) == 0 {
		t.Fatal("expected at least one finding, got none")
	}

	// Verify we got a SEC-001 finding.
	found := false
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			found = true
			if f.Location.FilePath != "config.go" {
				t.Errorf("expected file path config.go, got %s", f.Location.FilePath)
			}
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected SEC-001 finding for AWS Access Key")
	}
}

func TestRunScan_NonExistentDirectory(t *testing.T) {
	t.Parallel()

	_, err := RunScan("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for non-existent directory, got nil")
	}
}

func TestRunScan_ConfigExcludePatterns(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create .nox.yaml with exclude patterns.
	noxConfig := filepath.Join(tmpDir, ".nox.yaml")
	configContent := `scan:
  exclude:
    - "vendor/**"
    - "*.test.go"
`
	if err := os.WriteFile(noxConfig, []byte(configContent), 0o644); err != nil {
		t.Fatalf("failed to write .nox.yaml: %v", err)
	}

	// Create a file in vendor/ with a secret.
	vendorDir := filepath.Join(tmpDir, "vendor")
	if err := os.MkdirAll(vendorDir, 0o755); err != nil {
		t.Fatalf("failed to create vendor dir: %v", err)
	}
	vendorFile := filepath.Join(vendorDir, "dep.go")
	if err := os.WriteFile(vendorFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write vendor file: %v", err)
	}

	// Create a normal file with a secret.
	normalFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(normalFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write normal file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that findings only come from main.go, not vendor/.
	for _, f := range result.Findings.Findings() {
		if filepath.Base(f.Location.FilePath) == "dep.go" {
			t.Error("expected vendor/dep.go to be excluded, but found a finding")
		}
	}
}

func TestRunScan_ConfigDisableRule(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create .nox.yaml that disables SEC-001.
	noxConfig := filepath.Join(tmpDir, ".nox.yaml")
	configContent := `scan:
  rules:
    disable:
      - "SEC-001"
`
	if err := os.WriteFile(noxConfig, []byte(configContent), 0o644); err != nil {
		t.Fatalf("failed to write .nox.yaml: %v", err)
	}

	// Create a file with an AWS key.
	testFile := filepath.Join(tmpDir, "config.go")
	if err := os.WriteFile(testFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify SEC-001 findings are removed.
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			t.Error("expected SEC-001 to be disabled, but found a finding")
		}
	}
}

func TestRunScan_ConfigSeverityOverride(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create .nox.yaml that overrides SEC-001 severity.
	noxConfig := filepath.Join(tmpDir, ".nox.yaml")
	configContent := `scan:
  rules:
    severity_override:
      SEC-001: "low"
`
	if err := os.WriteFile(noxConfig, []byte(configContent), 0o644); err != nil {
		t.Fatalf("failed to write .nox.yaml: %v", err)
	}

	// Create a file with an AWS key.
	testFile := filepath.Join(tmpDir, "config.go")
	if err := os.WriteFile(testFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify SEC-001 severity is overridden to low.
	found := false
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			found = true
			if f.Severity != findings.SeverityLow {
				t.Errorf("expected severity low, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find SEC-001 finding")
	}
}

// ---------------------------------------------------------------------------
// RunScanWithOptions tests
// ---------------------------------------------------------------------------

func TestRunScanWithOptions_CustomRulesFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a custom rules file.
	customRulesFile := filepath.Join(tmpDir, "custom.yaml")
	customRulesContent := `rules:
  - id: "CUSTOM-001"
    version: "1.0"
    description: "Detect TODO comments"
    severity: "info"
    confidence: "high"
    matcher_type: "regex"
    pattern: "TODO"
    file_patterns:
      - "*.go"
`
	if err := os.WriteFile(customRulesFile, []byte(customRulesContent), 0o644); err != nil {
		t.Fatalf("failed to write custom rules file: %v", err)
	}

	// Create a file with TODO comment.
	testFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(testFile, []byte("// TODO: implement feature\n"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: customRulesFile,
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify CUSTOM-001 finding exists.
	found := false
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "CUSTOM-001" {
			found = true
			if f.Severity != findings.SeverityInfo {
				t.Errorf("expected severity info, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected CUSTOM-001 finding for TODO comment")
	}

	// Verify custom rule is in the rule set.
	_, ok := result.Rules.ByID("CUSTOM-001")
	if !ok {
		t.Error("expected CUSTOM-001 rule in result rule set")
	}
}

func TestRunScanWithOptions_CustomRulesDir(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a custom rules directory.
	customRulesDir := filepath.Join(tmpDir, "rules")
	if err := os.MkdirAll(customRulesDir, 0o755); err != nil {
		t.Fatalf("failed to create custom rules dir: %v", err)
	}

	customRulesFile := filepath.Join(customRulesDir, "custom1.yaml")
	customRulesContent := `rules:
  - id: "CUSTOM-002"
    version: "1.0"
    description: "Detect FIXME comments"
    severity: "low"
    confidence: "medium"
    matcher_type: "regex"
    pattern: "FIXME"
    file_patterns:
      - "*.go"
`
	if err := os.WriteFile(customRulesFile, []byte(customRulesContent), 0o644); err != nil {
		t.Fatalf("failed to write custom rules file: %v", err)
	}

	// Create a file with FIXME comment.
	testFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(testFile, []byte("// FIXME: bug here\n"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: customRulesDir,
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify CUSTOM-002 finding exists.
	found := false
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "CUSTOM-002" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CUSTOM-002 finding for FIXME comment")
	}
}

func TestRunScanWithOptions_CustomRulesConflictWithBuiltin(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a custom rules file with a conflicting rule ID.
	customRulesFile := filepath.Join(tmpDir, "custom.yaml")
	customRulesContent := `rules:
  - id: "SEC-001"
    version: "2.0"
    description: "Conflicting rule"
    severity: "critical"
    confidence: "high"
    matcher_type: "regex"
    pattern: "conflict"
    file_patterns:
      - "*.go"
`
	if err := os.WriteFile(customRulesFile, []byte(customRulesContent), 0o644); err != nil {
		t.Fatalf("failed to write custom rules file: %v", err)
	}

	_, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: customRulesFile,
	})
	if err == nil {
		t.Fatal("expected error for conflicting rule ID, got nil")
	}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestRunScanWithOptions_CustomRulesNonExistent(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	_, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: "/nonexistent/rules.yaml",
	})
	if err == nil {
		t.Fatal("expected error for non-existent custom rules path, got nil")
	}
}

func TestRunScanWithOptions_CustomRulesRelativePath(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a custom rules file in the scan target.
	customRulesFile := filepath.Join(tmpDir, "my-rules.yaml")
	customRulesContent := `rules:
  - id: "CUSTOM-003"
    version: "1.0"
    description: "Detect DEBUG logs"
    severity: "info"
    confidence: "low"
    matcher_type: "regex"
    pattern: "DEBUG"
    file_patterns:
      - "*.go"
`
	if err := os.WriteFile(customRulesFile, []byte(customRulesContent), 0o644); err != nil {
		t.Fatalf("failed to write custom rules file: %v", err)
	}

	// Create a file with DEBUG log.
	testFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(testFile, []byte("log.Println(\"DEBUG: test\")\n"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: "my-rules.yaml", // relative path
	})
	if err != nil {
		t.Fatalf("expected no error with relative path, got: %v", err)
	}

	// Verify CUSTOM-003 finding exists.
	found := false
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "CUSTOM-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CUSTOM-003 finding for DEBUG log")
	}
}

func TestRunScanWithOptions_ConfigRulesDirTakesPrecedence(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create .nox.yaml with rules_dir.
	noxConfig := filepath.Join(tmpDir, ".nox.yaml")
	configContent := `scan:
  rules_dir: "config-rules"
`
	if err := os.WriteFile(noxConfig, []byte(configContent), 0o644); err != nil {
		t.Fatalf("failed to write .nox.yaml: %v", err)
	}

	// Create config-rules directory.
	configRulesDir := filepath.Join(tmpDir, "config-rules")
	if err := os.MkdirAll(configRulesDir, 0o755); err != nil {
		t.Fatalf("failed to create config-rules dir: %v", err)
	}

	configRulesFile := filepath.Join(configRulesDir, "rules.yaml")
	configRulesContent := `rules:
  - id: "CONFIG-001"
    version: "1.0"
    description: "Config rule"
    severity: "medium"
    confidence: "high"
    matcher_type: "regex"
    pattern: "CONFIG"
    file_patterns:
      - "*.go"
`
	if err := os.WriteFile(configRulesFile, []byte(configRulesContent), 0o644); err != nil {
		t.Fatalf("failed to write config rules file: %v", err)
	}

	// Create cli-rules directory for CLI option.
	cliRulesDir := filepath.Join(tmpDir, "cli-rules")
	if err := os.MkdirAll(cliRulesDir, 0o755); err != nil {
		t.Fatalf("failed to create cli-rules dir: %v", err)
	}

	cliRulesFile := filepath.Join(cliRulesDir, "rules.yaml")
	cliRulesContent := `rules:
  - id: "CLI-001"
    version: "1.0"
    description: "CLI rule"
    severity: "high"
    confidence: "high"
    matcher_type: "regex"
    pattern: "CLI"
    file_patterns:
      - "*.go"
`
	if err := os.WriteFile(cliRulesFile, []byte(cliRulesContent), 0o644); err != nil {
		t.Fatalf("failed to write cli rules file: %v", err)
	}

	// Create a test file.
	testFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(testFile, []byte("// CONFIG and CLI\n"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: cliRulesDir,
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// CLI option should take precedence, so CLI-001 should be present.
	foundCLI := false
	foundConfig := false
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "CLI-001" {
			foundCLI = true
		}
		if f.RuleID == "CONFIG-001" {
			foundConfig = true
		}
	}

	if !foundCLI {
		t.Error("expected CLI-001 finding from CLI rules")
	}
	if foundConfig {
		t.Error("did not expect CONFIG-001 finding (CLI should override config)")
	}
}

// ---------------------------------------------------------------------------
// RunStagedScan tests
// ---------------------------------------------------------------------------

func TestRunStagedScan_NoGitRepo(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	_, err := RunStagedScan(tmpDir)
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
	}
}

func TestRunStagedScan_NoStagedFiles(t *testing.T) {
	t.Parallel()

	// This test needs a git repo, but we can't easily create one in tests.
	// For now, we test the error case above. A real integration test would
	// require git commands.
	t.Skip("requires git repository initialization")
}

// ---------------------------------------------------------------------------
// SeverityMeetsThreshold tests
// ---------------------------------------------------------------------------

func TestSeverityMeetsThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		severity  findings.Severity
		threshold findings.Severity
		want      bool
	}{
		{
			name:      "critical meets critical",
			severity:  findings.SeverityCritical,
			threshold: findings.SeverityCritical,
			want:      true,
		},
		{
			name:      "critical meets high",
			severity:  findings.SeverityCritical,
			threshold: findings.SeverityHigh,
			want:      true,
		},
		{
			name:      "critical meets medium",
			severity:  findings.SeverityCritical,
			threshold: findings.SeverityMedium,
			want:      true,
		},
		{
			name:      "critical meets low",
			severity:  findings.SeverityCritical,
			threshold: findings.SeverityLow,
			want:      true,
		},
		{
			name:      "critical meets info",
			severity:  findings.SeverityCritical,
			threshold: findings.SeverityInfo,
			want:      true,
		},
		{
			name:      "high meets critical",
			severity:  findings.SeverityHigh,
			threshold: findings.SeverityCritical,
			want:      false,
		},
		{
			name:      "high meets high",
			severity:  findings.SeverityHigh,
			threshold: findings.SeverityHigh,
			want:      true,
		},
		{
			name:      "high meets medium",
			severity:  findings.SeverityHigh,
			threshold: findings.SeverityMedium,
			want:      true,
		},
		{
			name:      "medium meets critical",
			severity:  findings.SeverityMedium,
			threshold: findings.SeverityCritical,
			want:      false,
		},
		{
			name:      "medium meets high",
			severity:  findings.SeverityMedium,
			threshold: findings.SeverityHigh,
			want:      false,
		},
		{
			name:      "medium meets medium",
			severity:  findings.SeverityMedium,
			threshold: findings.SeverityMedium,
			want:      true,
		},
		{
			name:      "medium meets low",
			severity:  findings.SeverityMedium,
			threshold: findings.SeverityLow,
			want:      true,
		},
		{
			name:      "low meets critical",
			severity:  findings.SeverityLow,
			threshold: findings.SeverityCritical,
			want:      false,
		},
		{
			name:      "low meets low",
			severity:  findings.SeverityLow,
			threshold: findings.SeverityLow,
			want:      true,
		},
		{
			name:      "low meets info",
			severity:  findings.SeverityLow,
			threshold: findings.SeverityInfo,
			want:      true,
		},
		{
			name:      "info meets critical",
			severity:  findings.SeverityInfo,
			threshold: findings.SeverityCritical,
			want:      false,
		},
		{
			name:      "info meets info",
			severity:  findings.SeverityInfo,
			threshold: findings.SeverityInfo,
			want:      true,
		},
		{
			name:      "invalid severity",
			severity:  findings.Severity("invalid"),
			threshold: findings.SeverityCritical,
			want:      false,
		},
		{
			name:      "invalid threshold",
			severity:  findings.SeverityCritical,
			threshold: findings.Severity("invalid"),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SeverityMeetsThreshold(tt.severity, tt.threshold)
			if got != tt.want {
				t.Errorf("SeverityMeetsThreshold(%q, %q) = %v, want %v",
					tt.severity, tt.threshold, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Suppression tests (via applySuppressions)
// ---------------------------------------------------------------------------

func TestRunScan_InlineSuppression(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with a secret and a nox:ignore comment.
	testFile := filepath.Join(tmpDir, "config.go")
	content := `package main

// nox:ignore SEC-001 -- false positive
const apiKey = "AKIAIOSFODNN7EXAMPLE"
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the finding is suppressed.
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			if f.Status != findings.StatusSuppressed {
				t.Errorf("expected status suppressed, got %s", f.Status)
			}
			return
		}
	}
	t.Error("expected SEC-001 finding to be present but suppressed")
}

func TestRunScan_InlineSuppressionMultipleRules(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create files with multiple suppressions on separate lines.
	testFile := filepath.Join(tmpDir, "config.go")
	content := `package main

// nox:ignore SEC-001 -- false positive
const apiKey = "AKIAIOSFODNN7EXAMPLE"
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	testFile2 := filepath.Join(tmpDir, "secret.go")
	content2 := `package main

// nox:ignore SEC-002 -- false positive
const secretKey = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
`
	if err := os.WriteFile(testFile2, []byte(content2), 0o644); err != nil {
		t.Fatalf("failed to write test file 2: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify both findings are suppressed.
	suppressedCount := 0
	totalCount := 0
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" || f.RuleID == "SEC-002" {
			totalCount++
			if f.Status == findings.StatusSuppressed {
				suppressedCount++
			} else {
				t.Logf("Finding %s not suppressed: status=%q, line=%d", f.RuleID, f.Status, f.Location.StartLine)
			}
		}
	}
	if totalCount < 2 {
		t.Fatalf("expected at least 2 findings (SEC-001 and SEC-002), got %d", totalCount)
	}
	if suppressedCount != 2 {
		t.Errorf("expected 2 suppressed findings, got %d out of %d total", suppressedCount, totalCount)
	}
}

func TestRunScan_InlineSuppressionExpired(t *testing.T) {
	// NOT parallel: this test mutates the package-level timeNow variable,
	// which would race with other tests calling RunScanWithOptions.

	// Override timeNow for testing expired suppressions.
	oldTimeNow := timeNow
	defer func() { timeNow = oldTimeNow }()

	// Set current time to after the expiration date.
	timeNow = func() time.Time {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	tmpDir := t.TempDir()

	// Create a file with an expired suppression.
	testFile := filepath.Join(tmpDir, "config.go")
	content := `package main

// nox:ignore SEC-001 -- temporary fix expires:2025-12-31
const apiKey = "AKIAIOSFODNN7EXAMPLE"
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the finding is NOT suppressed (expired).
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			if f.Status == findings.StatusSuppressed {
				t.Error("expected finding to not be suppressed (expired)")
			}
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Baseline tests (via applyBaseline)
// ---------------------------------------------------------------------------

func TestRunScan_BaselineMatching(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with a secret.
	testFile := filepath.Join(tmpDir, "config.go")
	content := `package main

const apiKey = "AKIAIOSFODNN7EXAMPLE"
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// First scan to get findings.
	result1, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(result1.Findings.Findings()) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Get the fingerprint of the first finding.
	fingerprint := result1.Findings.Findings()[0].Fingerprint

	// Create a baseline file in the correct location: .nox/baseline.json
	noxDir := filepath.Join(tmpDir, ".nox")
	if err := os.MkdirAll(noxDir, 0o755); err != nil {
		t.Fatalf("failed to create .nox directory: %v", err)
	}

	baselineFile := filepath.Join(noxDir, "baseline.json")
	baselineContent := `{
  "schema_version": "1.0.0",
  "entries": [
    {
      "fingerprint": "` + fingerprint + `",
      "rule_id": "SEC-001",
      "file_path": "config.go",
      "severity": "high",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}`
	if err := os.WriteFile(baselineFile, []byte(baselineContent), 0o644); err != nil {
		t.Fatalf("failed to write baseline file: %v", err)
	}

	// Second scan with baseline.
	result2, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the finding is baselined.
	for _, f := range result2.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			if f.Status != findings.StatusBaselined {
				t.Errorf("expected status baselined, got %s", f.Status)
			}
			return
		}
	}
	t.Error("expected SEC-001 finding to be baselined")
}

func TestRunScan_BaselineCustomPath(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with a secret first.
	testFile := filepath.Join(tmpDir, "config.go")
	content := `package main

const apiKey = "AKIAIOSFODNN7EXAMPLE"
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// First scan to get findings.
	result1, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(result1.Findings.Findings()) == 0 {
		t.Fatal("expected at least one finding")
	}

	fingerprint := result1.Findings.Findings()[0].Fingerprint

	// Create a custom baseline file.
	customBaselineFile := filepath.Join(tmpDir, "custom-baseline.json")
	baselineContent := `{
  "schema_version": "1.0.0",
  "entries": [
    {
      "fingerprint": "` + fingerprint + `",
      "rule_id": "SEC-001",
      "file_path": "config.go",
      "severity": "high",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}`
	if err := os.WriteFile(customBaselineFile, []byte(baselineContent), 0o644); err != nil {
		t.Fatalf("failed to write custom baseline file: %v", err)
	}

	// Create .nox.yaml with custom baseline path.
	noxConfig := filepath.Join(tmpDir, ".nox.yaml")
	configContent := `policy:
  baseline_path: "custom-baseline.json"
`
	if err := os.WriteFile(noxConfig, []byte(configContent), 0o644); err != nil {
		t.Fatalf("failed to write .nox.yaml: %v", err)
	}

	// Second scan with custom baseline.
	result2, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the finding is baselined.
	for _, f := range result2.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			if f.Status != findings.StatusBaselined {
				t.Errorf("expected status baselined, got %s", f.Status)
			}
			return
		}
	}
	t.Error("expected SEC-001 finding to be baselined")
}

// ---------------------------------------------------------------------------
// Policy evaluation tests
// ---------------------------------------------------------------------------

func TestRunScan_PolicyFailOn(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create .nox.yaml with fail_on policy.
	noxConfig := filepath.Join(tmpDir, ".nox.yaml")
	configContent := `policy:
  fail_on: "high"
`
	if err := os.WriteFile(noxConfig, []byte(configContent), 0o644); err != nil {
		t.Fatalf("failed to write .nox.yaml: %v", err)
	}

	// Create a file with a high-severity secret.
	testFile := filepath.Join(tmpDir, "config.go")
	if err := os.WriteFile(testFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.PolicyResult == nil {
		t.Fatal("expected policy result to be non-nil")
	}
}

func TestRunScan_Deduplication(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create two files with the same secret at the same location.
	testFile1 := filepath.Join(tmpDir, "file1.go")
	testFile2 := filepath.Join(tmpDir, "file2.go")
	content := `package main

const apiKey = "AKIAIOSFODNN7EXAMPLE"
`
	if err := os.WriteFile(testFile1, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file 1: %v", err)
	}
	if err := os.WriteFile(testFile2, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file 2: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Count SEC-001 findings.
	count := 0
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			count++
		}
	}

	// Should find 2 findings (one per file).
	if count != 2 {
		t.Errorf("expected 2 SEC-001 findings, got %d", count)
	}
}

func TestRunScan_DeterministicSorting(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create multiple files with secrets.
	files := []string{"z.go", "a.go", "m.go"}
	for _, name := range files {
		testFile := filepath.Join(tmpDir, name)
		if err := os.WriteFile(testFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
			t.Fatalf("failed to write test file %s: %v", name, err)
		}
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify findings are sorted by file path.
	prevFile := ""
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			if prevFile != "" && f.Location.FilePath < prevFile {
				t.Errorf("findings not sorted: %s came after %s", f.Location.FilePath, prevFile)
			}
			prevFile = f.Location.FilePath
		}
	}
}

// ---------------------------------------------------------------------------
// loadCustomRules tests (indirectly via RunScanWithOptions)
// ---------------------------------------------------------------------------

func TestLoadCustomRules_InvalidYAML(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create an invalid YAML file.
	customRulesFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(customRulesFile, []byte("invalid: yaml: content: ["), 0o644); err != nil {
		t.Fatalf("failed to write invalid YAML file: %v", err)
	}

	_, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: customRulesFile,
	})
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadCustomRules_InvalidRule(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a rules file with an invalid rule (missing ID).
	customRulesFile := filepath.Join(tmpDir, "invalid-rule.yaml")
	customRulesContent := `rules:
  - version: "1.0"
    description: "Missing ID"
    severity: "high"
    confidence: "medium"
    matcher_type: "regex"
    pattern: "test"
`
	if err := os.WriteFile(customRulesFile, []byte(customRulesContent), 0o644); err != nil {
		t.Fatalf("failed to write invalid rule file: %v", err)
	}

	_, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: customRulesFile,
	})
	if err == nil {
		t.Fatal("expected error for invalid rule, got nil")
	}
}

func TestLoadCustomRules_EmptyRulesArray(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a rules file with an empty rules array.
	customRulesFile := filepath.Join(tmpDir, "empty.yaml")
	customRulesContent := `rules: []`
	if err := os.WriteFile(customRulesFile, []byte(customRulesContent), 0o644); err != nil {
		t.Fatalf("failed to write empty rules file: %v", err)
	}

	result, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: customRulesFile,
	})
	if err != nil {
		t.Fatalf("expected no error for empty rules, got: %v", err)
	}

	// Should succeed with no custom rules.
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestRunScanWithOptions_CustomRulesFileReadError(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with a secret.
	testFile := filepath.Join(tmpDir, "config.go")
	if err := os.WriteFile(testFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Create a custom rules file.
	customRulesFile := filepath.Join(tmpDir, "custom.yaml")
	customRulesContent := `rules:
  - id: "CUSTOM-001"
    version: "1.0"
    description: "Test rule"
    severity: "info"
    confidence: "high"
    matcher_type: "regex"
    pattern: "test"
    file_patterns:
      - "*.txt"
`
	if err := os.WriteFile(customRulesFile, []byte(customRulesContent), 0o644); err != nil {
		t.Fatalf("failed to write custom rules file: %v", err)
	}

	// Make the file unreadable to trigger an error during artifact reading.
	if err := os.Chmod(testFile, 0o000); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}
	defer os.Chmod(testFile, 0o644)

	_, err := RunScanWithOptions(tmpDir, ScanOptions{
		CustomRulesPath: customRulesFile,
	})
	if err == nil {
		t.Fatal("expected error for unreadable file, got nil")
	}
}

func TestRunScan_SuppressionOnPreviousLine(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with suppression on previous line.
	testFile := filepath.Join(tmpDir, "config.go")
	content := `package main

// nox:ignore SEC-001 -- intentional for testing
const apiKey = "AKIAIOSFODNN7EXAMPLE"
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the finding is suppressed.
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			if f.Status != findings.StatusSuppressed {
				t.Errorf("expected status suppressed, got %s", f.Status)
			}
			return
		}
	}
	t.Error("expected SEC-001 finding to be present but suppressed")
}

func TestRunScan_BaselineNotFound(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with a secret.
	testFile := filepath.Join(tmpDir, "config.go")
	if err := os.WriteFile(testFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error when baseline not found, got: %v", err)
	}

	// All findings should be active (not baselined).
	for _, f := range result.Findings.Findings() {
		if f.Status == findings.StatusBaselined {
			t.Error("expected no findings to be baselined when baseline file doesn't exist")
		}
	}
}

func TestRunScan_MultipleSecrets(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with multiple different secrets.
	testFile := filepath.Join(tmpDir, "multi.go")
	content := `package main

const awsKey = "AKIAIOSFODNN7EXAMPLE"
const awsSecret = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Count different rule IDs.
	ruleIDs := make(map[string]int)
	for _, f := range result.Findings.Findings() {
		ruleIDs[f.RuleID]++
	}

	if len(ruleIDs) < 2 {
		t.Errorf("expected at least 2 different rule IDs, got %d", len(ruleIDs))
	}
}

func TestRunScan_EmptySuppressionFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with a secret but no suppression.
	testFile := filepath.Join(tmpDir, "config.go")
	if err := os.WriteFile(testFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify finding is not suppressed.
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SEC-001" && f.Status == findings.StatusSuppressed {
			t.Error("expected finding to not be suppressed")
		}
	}
}

func TestRunScan_BaselineSuppressedDoesNotApplyBaseline(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a file with a secret.
	testFile := filepath.Join(tmpDir, "config.go")
	content := `package main

// nox:ignore SEC-001 -- suppressed
const apiKey = "AKIAIOSFODNN7EXAMPLE"
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// First scan to get the fingerprint.
	result1, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(result1.Findings.Findings()) == 0 {
		t.Fatal("expected at least one finding")
	}

	fingerprint := result1.Findings.Findings()[0].Fingerprint

	// Create a baseline file.
	noxDir := filepath.Join(tmpDir, ".nox")
	if err := os.MkdirAll(noxDir, 0o755); err != nil {
		t.Fatalf("failed to create .nox directory: %v", err)
	}

	baselineFile := filepath.Join(noxDir, "baseline.json")
	baselineContent := `{
  "schema_version": "1.0.0",
  "entries": [
    {
      "fingerprint": "` + fingerprint + `",
      "rule_id": "SEC-001",
      "file_path": "config.go",
      "severity": "high",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}`
	if err := os.WriteFile(baselineFile, []byte(baselineContent), 0o644); err != nil {
		t.Fatalf("failed to write baseline file: %v", err)
	}

	// Second scan.
	result2, err := RunScan(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the finding is suppressed (not baselined, because suppression takes precedence).
	for _, f := range result2.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			if f.Status != findings.StatusSuppressed {
				t.Errorf("expected status suppressed (not baselined), got %s", f.Status)
			}
			return
		}
	}
}
