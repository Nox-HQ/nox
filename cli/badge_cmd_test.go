package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/badge"
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
	if !strings.Contains(svg, ">A<") {
		t.Fatal("expected badge to contain grade 'A'")
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
	// 1 critical (10) + 1 high (5) = 15 → grade D (orange)
	if !strings.Contains(svg, "#fe7d37") {
		t.Fatalf("expected orange color for grade D, got:\n%s", svg)
	}
	if !strings.Contains(svg, ">D<") {
		t.Fatalf("expected grade 'D' in badge, got:\n%s", svg)
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
	// 2 medium (2*2=4) → grade B (yellow-green)
	if !strings.Contains(svg, "#a3c51c") {
		t.Fatalf("expected yellow-green color for grade B, got:\n%s", svg)
	}
	if !strings.Contains(svg, ">B<") {
		t.Fatalf("expected grade 'B' in badge, got:\n%s", svg)
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

func TestBadge_HighFindings(t *testing.T) {
	dir := t.TempDir()
	ff := []findings.Finding{
		{RuleID: "IAC-001", Severity: findings.SeverityHigh, Message: "issue 1"},
		{RuleID: "IAC-002", Severity: findings.SeverityHigh, Message: "issue 2"},
		{RuleID: "IAC-003", Severity: findings.SeverityMedium, Message: "issue 3"},
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
	// 2 high (10) + 1 medium (2) = 12 → grade C (yellow)
	if !strings.Contains(svg, "#dfb317") {
		t.Fatalf("expected yellow color for grade C, got:\n%s", svg)
	}
	if !strings.Contains(svg, ">C<") {
		t.Fatalf("expected grade 'C' in badge, got:\n%s", svg)
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

func TestSecurityScore(t *testing.T) {
	tests := []struct {
		name   string
		counts map[findings.Severity]int
		want   int
	}{
		{"empty", nil, 0},
		{"1 critical", map[findings.Severity]int{findings.SeverityCritical: 1}, 10},
		{"2 high + 1 medium", map[findings.Severity]int{findings.SeverityHigh: 2, findings.SeverityMedium: 1}, 12},
		{"info only", map[findings.Severity]int{findings.SeverityInfo: 5}, 0},
		{"3 low", map[findings.Severity]int{findings.SeverityLow: 3}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := badge.SecurityScore(tt.counts)
			if got != tt.want {
				t.Fatalf("SecurityScore(%v) = %d, want %d", tt.counts, got, tt.want)
			}
		})
	}
}

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score  int
		letter string
		color  string
	}{
		{0, "A", "#4c1"},
		{1, "B", "#a3c51c"},
		{4, "B", "#a3c51c"},
		{5, "C", "#dfb317"},
		{14, "C", "#dfb317"},
		{15, "D", "#fe7d37"},
		{29, "D", "#fe7d37"},
		{30, "E", "#e05d44"},
		{49, "E", "#e05d44"},
		{50, "F", "#b60205"},
		{100, "F", "#b60205"},
	}
	for _, tt := range tests {
		t.Run(tt.letter, func(t *testing.T) {
			g := badge.GradeFromScore(tt.score)
			if g.Letter != tt.letter {
				t.Fatalf("GradeFromScore(%d).Letter = %q, want %q", tt.score, g.Letter, tt.letter)
			}
			if g.Color != tt.color {
				t.Fatalf("GradeFromScore(%d).Color = %q, want %q", tt.score, g.Color, tt.color)
			}
		})
	}
}

func TestBadgeValue(t *testing.T) {
	tests := []struct {
		name     string
		counts   map[findings.Severity]int
		expected string
	}{
		{"grade A", nil, "A"},
		{"grade B - low findings", map[findings.Severity]int{findings.SeverityLow: 3}, "B"},
		{"grade C - high findings", map[findings.Severity]int{findings.SeverityHigh: 1}, "C"},
		{"grade D - critical", map[findings.Severity]int{findings.SeverityCritical: 2}, "D"},
		{"grade F - many critical", map[findings.Severity]int{findings.SeverityCritical: 5, findings.SeverityHigh: 3}, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := badge.SecurityScore(tt.counts)
			got := badge.GradeFromScore(score).Letter
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestBadgeColor(t *testing.T) {
	tests := []struct {
		name     string
		counts   map[findings.Severity]int
		expected string
	}{
		{"A green", nil, "#4c1"},
		{"B yellow-green", map[findings.Severity]int{findings.SeverityLow: 2}, "#a3c51c"},
		{"C yellow", map[findings.Severity]int{findings.SeverityHigh: 1}, "#dfb317"},
		{"D orange", map[findings.Severity]int{findings.SeverityCritical: 2}, "#fe7d37"},
		{"F dark red", map[findings.Severity]int{findings.SeverityCritical: 10}, "#b60205"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := badge.SecurityScore(tt.counts)
			got := badge.GradeFromScore(score).Color
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestBadge_BySeverity(t *testing.T) {
	dir := t.TempDir()
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityCritical, Message: "critical"},
		{RuleID: "SEC-002", Severity: findings.SeverityHigh, Message: "high 1"},
		{RuleID: "SEC-003", Severity: findings.SeverityHigh, Message: "high 2"},
		{RuleID: "IAC-001", Severity: findings.SeverityMedium, Message: "medium"},
	}
	input := writeFindingsJSON(t, dir, ff)
	output := filepath.Join(dir, "nox-badge.svg")

	code := runBadge([]string{"--input", input, "--output", output, "--by-severity"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	// Main badge should exist.
	if _, err := os.Stat(output); os.IsNotExist(err) {
		t.Fatal("expected main badge to exist")
	}

	// Per-severity badges should exist.
	expected := map[string]struct {
		count string
		color string // non-zero color
	}{
		"nox-critical.svg": {"1", "#b60205"},
		"nox-high.svg":     {"2", "#e05d44"},
		"nox-medium.svg":   {"1", "#dfb317"},
		"nox-low.svg":      {"0", "#4c1"}, // zero → green
	}

	for file, want := range expected {
		path := filepath.Join(dir, file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		svg := string(data)
		if !strings.Contains(svg, ">"+want.count+"<") {
			t.Errorf("%s: expected count %s in SVG", file, want.count)
		}
		if !strings.Contains(svg, want.color) {
			t.Errorf("%s: expected color %s in SVG", file, want.color)
		}
	}
}

func TestBadge_BySeverity_Clean(t *testing.T) {
	dir := t.TempDir()
	input := writeFindingsJSON(t, dir, nil)
	output := filepath.Join(dir, "nox-badge.svg")

	code := runBadge([]string{"--input", input, "--output", output, "--by-severity"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	// All severity badges should show 0 with green color.
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		path := filepath.Join(dir, "nox-"+sev+".svg")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading nox-%s.svg: %v", sev, err)
		}
		svg := string(data)
		if !strings.Contains(svg, ">0<") {
			t.Errorf("nox-%s.svg: expected count 0", sev)
		}
		if !strings.Contains(svg, "#4c1") {
			t.Errorf("nox-%s.svg: expected green color for zero count", sev)
		}
	}
}

func TestGenerateBadgeSVG(t *testing.T) {
	svg := badge.GenerateSVG("nox", "A", "#4c1")
	if !strings.HasPrefix(svg, "<svg") {
		t.Fatal("expected SVG output")
	}
	if !strings.Contains(svg, "nox") {
		t.Fatal("expected label in SVG")
	}
	if !strings.Contains(svg, ">A<") {
		t.Fatal("expected grade in SVG")
	}
	if !strings.Contains(svg, "#4c1") {
		t.Fatal("expected color in SVG")
	}
	if !strings.Contains(svg, `aria-label="nox: A"`) {
		t.Fatal("expected aria-label in SVG")
	}
}
