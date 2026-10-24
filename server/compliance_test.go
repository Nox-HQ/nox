package server

import (
	"context"
	"regexp"
	"testing"

	"github.com/nox-hq/nox/core/compliance/iso27001"
)

// TestAnAgentCanAskAboutISO27001 is the vision beat: "I'm preparing for ISO
// 27001. What can you help me with?" answered from the scan already held.
func TestAnAgentCanAskAboutISO27001(t *testing.T) {
	s := scanned(t)
	res, err := s.handleComplianceISO27001(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var out complianceISO27001Output
	decode(t, res, &out)

	if out.Summary == "" || len(out.Assessment.Controls) == 0 {
		t.Fatalf("empty answer: %s", payload(t, res))
	}
	if len(out.Assessment.Organizational) == 0 {
		t.Error("the answer omits the organizational evidence the user still needs")
	}
	if out.Assessment.Meta.Standard != iso27001.Standard {
		t.Errorf("standard = %q", out.Assessment.Meta.Standard)
	}
	// The agent must be told not to overclaim, and nothing it relays may.
	if out.Note == "" {
		t.Error("no instruction on what the agent may not say")
	}
	if regexp.MustCompile(`(?i)\b(met|compliant|passed|certified)\b`).MatchString(out.Summary) {
		t.Errorf("summary claims more than technical evidence:\n%s", out.Summary)
	}
	if len(out.Assessment.Provenance.Artifacts) == 0 {
		t.Error("no evidence files cited")
	}
}

func TestISO27001NeedsAScanFirst(t *testing.T) {
	s := New("test", nil)
	res, err := s.handleComplianceISO27001(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if got := payload(t, res); !regexp.MustCompile(`no scan results`).MatchString(got) {
		t.Errorf("expected a request to scan first, got %s", got)
	}
}
