package main

import (
	"strings"
	"testing"
)

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
