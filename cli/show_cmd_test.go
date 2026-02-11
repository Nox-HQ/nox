package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/findings"
)

func TestRunShow_NoFindings(t *testing.T) {
	dir := t.TempDir()

	// Create clean file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runShow([]string{dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no findings, got %d", code)
	}
}

func TestRunShow_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	// Create file with finding and scan it.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	scanCode := run([]string{"--quiet", "--output", outDir, "scan", dir})
	if scanCode != 1 {
		t.Fatalf("expected scan exit code 1, got %d", scanCode)
	}

	findingsPath := filepath.Join(outDir, "findings.json")

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runShow([]string{"--json", "--input", findingsPath})

	w.Close()
	os.Stdout = oldStdout

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Validate JSON output.
	var details []*detail.FindingDetail
	if err := json.Unmarshal([]byte(output), &details); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, output)
	}

	if len(details) == 0 {
		t.Fatal("expected JSON output to contain findings")
	}
}

func TestRunShow_SeverityFilter(t *testing.T) {
	dir := t.TempDir()

	// Create file with finding and scan it.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	scanCode := run([]string{"--quiet", "--output", outDir, "scan", dir})
	if scanCode != 1 {
		t.Fatalf("expected scan exit code 1, got %d", scanCode)
	}

	findingsPath := filepath.Join(outDir, "findings.json")

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runShow([]string{"--json", "--severity", "critical", "--input", findingsPath})

	w.Close()
	os.Stdout = oldStdout

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Validate JSON output.
	var details []*detail.FindingDetail
	if err := json.Unmarshal([]byte(output), &details); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, output)
	}

	// Verify all findings match severity filter (or empty if no critical findings).
	for _, d := range details {
		if d.Severity != "critical" {
			t.Fatalf("expected only critical findings, got %s", d.Severity)
		}
	}
}

func TestRunShow_RuleFilter(t *testing.T) {
	dir := t.TempDir()

	// Create file with finding and scan it.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	scanCode := run([]string{"--quiet", "--output", outDir, "scan", dir})
	if scanCode != 1 {
		t.Fatalf("expected scan exit code 1, got %d", scanCode)
	}

	findingsPath := filepath.Join(outDir, "findings.json")

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runShow([]string{"--json", "--rule", "SEC-*", "--input", findingsPath})

	w.Close()
	os.Stdout = oldStdout

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Validate JSON output.
	var details []*detail.FindingDetail
	if err := json.Unmarshal([]byte(output), &details); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, output)
	}

	// Verify all findings match rule pattern.
	for _, d := range details {
		if !strings.HasPrefix(d.RuleID, "SEC-") {
			t.Fatalf("expected only SEC-* rules, got %s", d.RuleID)
		}
	}
}

func TestRunShow_FileFilter(t *testing.T) {
	dir := t.TempDir()

	// Create files with findings and scan them.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	scanCode := run([]string{"--quiet", "--output", outDir, "scan", dir})
	if scanCode != 1 {
		t.Fatalf("expected scan exit code 1, got %d", scanCode)
	}

	findingsPath := filepath.Join(outDir, "findings.json")

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runShow([]string{"--json", "--file", "config.env", "--input", findingsPath})

	w.Close()
	os.Stdout = oldStdout

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Validate JSON output.
	var details []*detail.FindingDetail
	if err := json.Unmarshal([]byte(output), &details); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, output)
	}

	// Verify all findings match file pattern.
	for _, d := range details {
		if !strings.Contains(d.Location.FilePath, "config.env") {
			t.Fatalf("expected only config.env findings, got %s", d.Location.FilePath)
		}
	}
}

func TestRunShow_FromFile(t *testing.T) {
	dir := t.TempDir()

	// Create file with finding and scan it.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	scanCode := run([]string{"--quiet", "--output", outDir, "scan", dir})
	if scanCode != 1 {
		t.Fatalf("expected scan exit code 1, got %d", scanCode)
	}

	findingsPath := filepath.Join(outDir, "findings.json")

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runShow([]string{"--json", "--input", findingsPath})

	w.Close()
	os.Stdout = oldStdout

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Validate JSON output.
	var details []*detail.FindingDetail
	if err := json.Unmarshal([]byte(output), &details); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if len(details) == 0 {
		t.Fatal("expected findings from input file")
	}
}

func TestRunShow_InvalidInputFile(t *testing.T) {
	code := runShow([]string{"--json", "--input", "/nonexistent/findings.json"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid input, got %d", code)
	}
}

func TestRunShow_ContextLines(t *testing.T) {
	dir := t.TempDir()

	// Create file with finding and scan it.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	scanCode := run([]string{"--quiet", "--output", outDir, "scan", dir})
	if scanCode != 1 {
		t.Fatalf("expected scan exit code 1, got %d", scanCode)
	}

	findingsPath := filepath.Join(outDir, "findings.json")

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runShow([]string{"--json", "--context", "10", "--input", findingsPath})

	w.Close()
	os.Stdout = oldStdout

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Validate JSON output.
	var details []*detail.FindingDetail
	if err := json.Unmarshal([]byte(output), &details); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, output)
	}
}

func TestRunShow_MultipleSeverities(t *testing.T) {
	dir := t.TempDir()

	// Create file with finding and scan it.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	outDir := filepath.Join(dir, "output")
	scanCode := run([]string{"--quiet", "--output", outDir, "scan", dir})
	if scanCode != 1 {
		t.Fatalf("expected scan exit code 1, got %d", scanCode)
	}

	findingsPath := filepath.Join(outDir, "findings.json")

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runShow([]string{"--json", "--severity", "critical,high,medium", "--input", findingsPath})

	w.Close()
	os.Stdout = oldStdout

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Validate JSON output.
	var details []*detail.FindingDetail
	if err := json.Unmarshal([]byte(output), &details); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, output)
	}
}

func TestRunShow_ScanError(t *testing.T) {
	code := runShow([]string{"--json", "/nonexistent/path/xyz123"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for scan error, got %d", code)
	}
}

func TestRunShow_DefaultPath(t *testing.T) {
	dir := t.TempDir()

	// Create clean file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Change to temp dir and run show without path.
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	code := runShow([]string{"--json"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestToFindingSet_Empty(t *testing.T) {
	t.Parallel()

	result := toFindingSet(nil)
	if result == nil {
		t.Fatal("expected non-nil FindingSet")
	}
	if len(result.Findings()) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings()))
	}
}

func TestToFindingSet_WithFindings(t *testing.T) {
	t.Parallel()

	ff := []findings.Finding{
		{
			ID:       "1",
			RuleID:   "SEC-001",
			Severity: findings.SeverityHigh,
			Message:  "test finding 1",
			Location: findings.Location{FilePath: "test.go", StartLine: 1},
		},
		{
			ID:       "2",
			RuleID:   "SEC-002",
			Severity: findings.SeverityMedium,
			Message:  "test finding 2",
			Location: findings.Location{FilePath: "test.go", StartLine: 5},
		},
	}

	result := toFindingSet(ff)
	if result == nil {
		t.Fatal("expected non-nil FindingSet")
	}
	if len(result.Findings()) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings()))
	}
}

func TestRunShow_InterspersedFlags(t *testing.T) {
	dir := t.TempDir()

	// Create clean file.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Test flags before and after positional arg.
	code := runShow([]string{dir, "--json"})
	if code != 0 {
		t.Fatalf("expected exit code 0 with interspersed flags, got %d", code)
	}
}

func TestIsBoolFlag(t *testing.T) {
	tests := []struct {
		flag     string
		expected bool
	}{
		{"--json", true},
		{"-json", true},
		{"json", true},
		{"--severity", false},
		{"-severity", false},
		{"severity", false},
		{"--rule", false},
		{"--file", false},
		{"--input", false},
		{"--context", false},
	}

	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			result := isBoolFlag(tt.flag)
			if result != tt.expected {
				t.Fatalf("expected %v for %s, got %v", tt.expected, tt.flag, result)
			}
		})
	}
}
