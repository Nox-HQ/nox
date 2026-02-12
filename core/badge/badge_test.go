package badge

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestSecurityScore(t *testing.T) {
	tests := []struct {
		name   string
		counts map[findings.Severity]int
		want   int
	}{
		{"empty", map[findings.Severity]int{}, 0},
		{"one critical", map[findings.Severity]int{findings.SeverityCritical: 1}, 10},
		{"one high", map[findings.Severity]int{findings.SeverityHigh: 1}, 5},
		{"mixed", map[findings.Severity]int{
			findings.SeverityCritical: 1,
			findings.SeverityHigh:     2,
			findings.SeverityMedium:   3,
		}, 10 + 10 + 6},
		{"info only", map[findings.Severity]int{findings.SeverityInfo: 100}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SecurityScore(tt.counts)
			if got != tt.want {
				t.Errorf("SecurityScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score      int
		wantLetter string
	}{
		{0, "A"},
		{4, "B"},
		{14, "C"},
		{29, "D"},
		{49, "E"},
		{50, "F"},
		{100, "F"},
	}
	for _, tt := range tests {
		g := GradeFromScore(tt.score)
		if g.Letter != tt.wantLetter {
			t.Errorf("GradeFromScore(%d) = %s, want %s", tt.score, g.Letter, tt.wantLetter)
		}
	}
}

func TestGenerateFromFindings_Empty(t *testing.T) {
	result := GenerateFromFindings(nil, "nox")
	if result.Grade != "A" {
		t.Errorf("expected grade A for no findings, got %s", result.Grade)
	}
	if result.Score != 0 {
		t.Errorf("expected score 0, got %d", result.Score)
	}
}

func TestGenerateFromFindings_WithFindings(t *testing.T) {
	ff := []findings.Finding{
		{Severity: findings.SeverityCritical},
		{Severity: findings.SeverityHigh},
	}
	result := GenerateFromFindings(ff, "nox")
	if result.Score != 15 {
		t.Errorf("expected score 15, got %d", result.Score)
	}
	if result.Grade != "D" {
		t.Errorf("expected grade D, got %s", result.Grade)
	}
}

func TestGenerateSVG_Structure(t *testing.T) {
	svg := GenerateSVG("nox", "A", "#4c1")
	if !strings.HasPrefix(svg, "<svg") {
		t.Error("expected SVG to start with <svg")
	}
	if !strings.Contains(svg, "nox") {
		t.Error("expected SVG to contain label")
	}
	if !strings.Contains(svg, "#4c1") {
		t.Error("expected SVG to contain color")
	}
}

func TestSeverityBadges(t *testing.T) {
	ff := []findings.Finding{
		{Severity: findings.SeverityCritical},
		{Severity: findings.SeverityCritical},
		{Severity: findings.SeverityHigh},
	}
	badges := SeverityBadges(ff, "nox")
	if len(badges) != 4 {
		t.Fatalf("expected 4 severity badges, got %d", len(badges))
	}
	crit := badges[findings.SeverityCritical]
	if crit.Value != "2" {
		t.Errorf("expected critical count 2, got %s", crit.Value)
	}
	low := badges[findings.SeverityLow]
	if low.Value != "0" {
		t.Errorf("expected low count 0, got %s", low.Value)
	}
}

func TestCountBySeverity(t *testing.T) {
	ff := []findings.Finding{
		{Severity: findings.SeverityHigh},
		{Severity: findings.SeverityHigh},
		{Severity: findings.SeverityLow},
	}
	counts := CountBySeverity(ff)
	if counts[findings.SeverityHigh] != 2 {
		t.Errorf("expected 2 high, got %d", counts[findings.SeverityHigh])
	}
	if counts[findings.SeverityLow] != 1 {
		t.Errorf("expected 1 low, got %d", counts[findings.SeverityLow])
	}
}
