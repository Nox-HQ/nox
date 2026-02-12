package annotate

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestBuildReviewPayload_Empty(t *testing.T) {
	result := BuildReviewPayload(nil)
	if result != nil {
		t.Fatal("expected nil for empty findings")
	}
}

func TestBuildReviewPayload_SingleFinding(t *testing.T) {
	ff := []findings.Finding{
		{
			RuleID:   "SEC-001",
			Severity: findings.SeverityHigh,
			Message:  "secret detected",
			Location: findings.Location{
				FilePath:  "config.env",
				StartLine: 5,
			},
		},
	}

	payload := BuildReviewPayload(ff)
	if payload == nil {
		t.Fatal("expected non-nil payload")
	}
	if payload.Event != "COMMENT" {
		t.Errorf("expected COMMENT event, got %s", payload.Event)
	}
	if len(payload.Comments) != 1 {
		t.Fatalf("expected 1 comment, got %d", len(payload.Comments))
	}

	c := payload.Comments[0]
	if c.Path != "config.env" {
		t.Errorf("expected path config.env, got %s", c.Path)
	}
	if c.Line != 5 {
		t.Errorf("expected line 5, got %d", c.Line)
	}
	if c.Side != "RIGHT" {
		t.Errorf("expected side RIGHT, got %s", c.Side)
	}
}

func TestBuildReviewPayload_MultipleFindings(t *testing.T) {
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityHigh, Message: "one", Location: findings.Location{FilePath: "a.go", StartLine: 1}},
		{RuleID: "SEC-002", Severity: findings.SeverityCritical, Message: "two", Location: findings.Location{FilePath: "b.go", StartLine: 2}},
		{RuleID: "AI-001", Severity: findings.SeverityMedium, Message: "three", Location: findings.Location{FilePath: "c.py"}},
	}

	payload := BuildReviewPayload(ff)
	if payload == nil {
		t.Fatal("expected non-nil payload")
	}
	if len(payload.Comments) != 3 {
		t.Fatalf("expected 3 comments, got %d", len(payload.Comments))
	}

	// Third finding has no line number.
	if payload.Comments[2].Line != 0 {
		t.Errorf("expected line 0 for finding without line, got %d", payload.Comments[2].Line)
	}
}

func TestBuildReviewPayload_SeverityBadges(t *testing.T) {
	tests := []struct {
		severity  findings.Severity
		wantEmoji string
	}{
		{findings.SeverityCritical, ":red_circle:"},
		{findings.SeverityHigh, ":orange_circle:"},
		{findings.SeverityMedium, ":yellow_circle:"},
		{findings.SeverityLow, ":large_blue_circle:"},
		{findings.SeverityInfo, ":white_circle:"},
	}
	for _, tt := range tests {
		ff := []findings.Finding{{RuleID: "X", Severity: tt.severity, Message: "m", Location: findings.Location{FilePath: "f"}}}
		payload := BuildReviewPayload(ff)
		if payload == nil {
			t.Fatal("expected non-nil payload")
		}
		body := payload.Comments[0].Body
		if body == "" || len(body) < len(tt.wantEmoji) {
			t.Errorf("expected body with emoji for %s", tt.severity)
		}
	}
}
