package main

import (
	"strings"
	"testing"
)

func TestDemote(t *testing.T) {
	cases := map[string]string{
		"critical": "high",
		"high":     "medium",
		"medium":   "low",
		"low":      "info",
		"info":     "info",
		"":         "",
	}
	for in, want := range cases {
		if got := demote(in); got != want {
			t.Errorf("demote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPromote(t *testing.T) {
	cases := map[string]string{
		"info":     "low",
		"low":      "medium",
		"medium":   "high",
		"high":     "critical",
		"critical": "critical",
	}
	for in, want := range cases {
		if got := promote(in); got != want {
			t.Errorf("promote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderCalibrateYAML_Empty(t *testing.T) {
	got := renderCalibrateYAML(nil, 5)
	if !strings.Contains(got, "No recommendations") {
		t.Errorf("expected empty-state comment, got: %s", got)
	}
}

func TestRenderCalibrateYAML_WithRecs(t *testing.T) {
	recs := []recommendation{
		{ruleID: "SEC-073", current: "critical", recommended: "high", fireRate: 0.9, reason: "fires on 90% of corpus"},
	}
	got := renderCalibrateYAML(recs, 10)
	if !strings.Contains(got, "severity_override:") {
		t.Errorf("expected severity_override section: %s", got)
	}
	if !strings.Contains(got, "SEC-073: high") {
		t.Errorf("expected SEC-073 override line: %s", got)
	}
}
