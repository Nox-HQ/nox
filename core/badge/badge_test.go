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

// ---------------------------------------------------------------------------
// Confidence-weighted scoring — issue #62
// ---------------------------------------------------------------------------

func TestWeightedSecurityScore_ConfidenceScalesContribution(t *testing.T) {
	// Five high-severity, low-confidence findings:
	//   5 * SeverityWeight[high]=5 * ConfidenceWeight[low]=0.2 = 5.0
	// Compare to unweighted baseline of 5*5=25 (would grade D).
	ff := make([]findings.Finding, 5)
	for i := range ff {
		ff[i] = findings.Finding{
			RuleID:     "FAKE-001",
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceLow,
		}
	}
	score, contribs := WeightedSecurityScore(ff)
	if score != 5 {
		t.Fatalf("expected weighted score 5, got %d", score)
	}
	if len(contribs) != 5 {
		t.Fatalf("expected 5 contributions, got %d", len(contribs))
	}
	for _, c := range contribs {
		if c.Points != 1.0 {
			t.Fatalf("expected 1.0 points per low-confidence finding, got %v", c.Points)
		}
	}
}

func TestWeightedSecurityScore_HighConfidenceDominates(t *testing.T) {
	// 1 critical/high-confidence + 5 low/low-confidence:
	//   10*1.0 + 5*1*0.2 = 11.0  → grade C
	ff := []findings.Finding{
		{Severity: findings.SeverityCritical, Confidence: findings.ConfidenceHigh},
		{Severity: findings.SeverityLow, Confidence: findings.ConfidenceLow},
		{Severity: findings.SeverityLow, Confidence: findings.ConfidenceLow},
		{Severity: findings.SeverityLow, Confidence: findings.ConfidenceLow},
		{Severity: findings.SeverityLow, Confidence: findings.ConfidenceLow},
		{Severity: findings.SeverityLow, Confidence: findings.ConfidenceLow},
	}
	score, contribs := WeightedSecurityScore(ff)
	if score != 11 {
		t.Fatalf("expected weighted score 11, got %d", score)
	}
	// Highest-points contribution should be the critical finding.
	if contribs[0].Severity != findings.SeverityCritical {
		t.Fatalf("expected critical to sort first, got %+v", contribs[0])
	}
}

func TestWeightedSecurityScore_MissingConfidenceDefaultsToFull(t *testing.T) {
	// A finding with no Confidence set should count fully (1.0) so we don't
	// silently shrink scores for older rules that haven't been annotated.
	ff := []findings.Finding{
		{Severity: findings.SeverityHigh}, // Confidence: ""
	}
	score, _ := WeightedSecurityScore(ff)
	if score != 5 {
		t.Fatalf("expected score 5 (full-weight default), got %d", score)
	}
}

func TestGenerateFromFindings_ConfidenceWeightedRegression62(t *testing.T) {
	// Mirror of the issue #62 reproduction: 14 false-positive findings, all
	// low/medium confidence. Old (unweighted) formula made this an E (49);
	// the weighted formula keeps it well below E.
	ff := make([]findings.Finding, 0, 14)
	for range 9 {
		ff = append(ff, findings.Finding{
			RuleID: "FAKE-MED", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
		})
	}
	for range 5 {
		ff = append(ff, findings.Finding{
			RuleID: "FAKE-LOW", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceLow,
		})
	}
	result := GenerateFromFindings(ff, "nox")
	// 9*5*0.5 + 5*5*0.2 = 22.5 + 5 = 27.5 → ceil 28 → grade D, not E.
	if result.Score != 28 {
		t.Fatalf("expected weighted score 28, got %d", result.Score)
	}
	if result.Grade == "E" {
		t.Fatalf("expected grade above E with confidence weighting, got %s", result.Grade)
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
