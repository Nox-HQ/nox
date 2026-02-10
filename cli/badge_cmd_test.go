package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

func writeFindingsJSON(t *testing.T, dir string, ff []findings.Finding) string {
	t.Helper()
	rep := report.JSONReport{
		Meta: report.Meta{
			SchemaVersion: "1.0.0",
			GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
			ToolName:      "nox",
			ToolVersion:   "test",
		},
		Findings: ff,
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("marshalling findings: %v", err)
	}
	path := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing findings.json: %v", err)
	}
	return path
}

func TestBadge_CleanScan(t *testing.T) {
	dir := t.TempDir()
	input := writeFindingsJSON(t, dir, nil)
	output := filepath.Join(dir, "badge.svg")

	code := runBadge([]string{"--input", input, "--output", output})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("reading badge: %v", err)
	}
	svg := string(data)
	if !strings.Contains(svg, "clean") {
		t.Fatal("expected badge to contain 'clean'")
	}
	if !strings.Contains(svg, "#4c1") {
		t.Fatal("expected green color for clean badge")
	}
}

func TestBadge_CriticalFindings(t *testing.T) {
	dir := t.TempDir()
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityCritical, Message: "secret exposed"},
		{RuleID: "SEC-002", Severity: findings.SeverityHigh, Message: "another issue"},
	}
	input := writeFindingsJSON(t, dir, ff)
	output := filepath.Join(dir, "badge.svg")

	code := runBadge([]string{"--input", input, "--output", output})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("reading badge: %v", err)
	}
	svg := string(data)
	if !strings.Contains(svg, "#e05d44") {
		t.Fatal("expected red color for critical findings")
	}
	if !strings.Contains(svg, "1 critical") {
		t.Fatalf("expected '1 critical' in badge, got:\n%s", svg)
	}
}

func TestBadge_MediumOnly(t *testing.T) {
	dir := t.TempDir()
	ff := []findings.Finding{
		{RuleID: "IAC-001", Severity: findings.SeverityMedium, Message: "issue 1"},
		{RuleID: "IAC-002", Severity: findings.SeverityMedium, Message: "issue 2"},
	}
	input := writeFindingsJSON(t, dir, ff)
	output := filepath.Join(dir, "badge.svg")

	code := runBadge([]string{"--input", input, "--output", output})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("reading badge: %v", err)
	}
	svg := string(data)
	if !strings.Contains(svg, "#dfb317") {
		t.Fatal("expected yellow color for medium findings")
	}
	if !strings.Contains(svg, "2 medium") {
		t.Fatalf("expected '2 medium' in badge, got:\n%s", svg)
	}
}

func TestBadge_CustomLabel(t *testing.T) {
	dir := t.TempDir()
	input := writeFindingsJSON(t, dir, nil)
	output := filepath.Join(dir, "badge.svg")

	code := runBadge([]string{"--input", input, "--output", output, "--label", "security"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("reading badge: %v", err)
	}
	svg := string(data)
	if !strings.Contains(svg, "security") {
		t.Fatal("expected custom label 'security' in badge")
	}
}

func TestBadge_RunsScan(t *testing.T) {
	dir := t.TempDir()
	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	output := filepath.Join(dir, "badge.svg")
	code := runBadge([]string{dir, "--output", output})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	if _, err := os.Stat(output); os.IsNotExist(err) {
		t.Fatal("expected badge SVG to be created")
	}
}

func TestBadge_InvalidInput(t *testing.T) {
	code := runBadge([]string{"--input", "/nonexistent/findings.json"})
	if code != 2 {
		t.Fatalf("expected exit 2 for missing input, got %d", code)
	}
}

func TestBadgeValue(t *testing.T) {
	tests := []struct {
		name     string
		total    int
		maxSev   findings.Severity
		counts   map[findings.Severity]int
		expected string
	}{
		{"clean", 0, "", nil, "clean"},
		{"all critical", 3, findings.SeverityCritical, map[findings.Severity]int{findings.SeverityCritical: 3}, "3 critical"},
		{"mixed", 5, findings.SeverityHigh, map[findings.Severity]int{findings.SeverityHigh: 2, findings.SeverityMedium: 3}, "2 high · 5 total"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := badgeValue(tt.total, tt.maxSev, tt.counts)
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestBadgeColor(t *testing.T) {
	tests := []struct {
		name     string
		maxSev   findings.Severity
		total    int
		expected string
	}{
		{"clean", "", 0, "#4c1"},
		{"critical", findings.SeverityCritical, 1, "#e05d44"},
		{"high", findings.SeverityHigh, 2, "#fe7d37"},
		{"medium", findings.SeverityMedium, 1, "#dfb317"},
		{"low", findings.SeverityLow, 1, "#a3c51c"},
		{"info", findings.SeverityInfo, 1, "#9f9f9f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := badgeColor(tt.maxSev, tt.total)
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestGenerateBadgeSVG(t *testing.T) {
	svg := generateBadgeSVG("nox", "clean", "#4c1")
	if !strings.HasPrefix(svg, "<svg") {
		t.Fatal("expected SVG output")
	}
	if !strings.Contains(svg, "nox") {
		t.Fatal("expected label in SVG")
	}
	if !strings.Contains(svg, "clean") {
		t.Fatal("expected value in SVG")
	}
	if !strings.Contains(svg, "#4c1") {
		t.Fatal("expected color in SVG")
	}
	if !strings.Contains(svg, `aria-label="nox: clean"`) {
		t.Fatal("expected aria-label in SVG")
	}
}
