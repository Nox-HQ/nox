package server

import (
	"context"
	"regexp"
	"testing"

	"github.com/nox-hq/nox/core/threatmodel"
)

// TestAnAgentCanAskForAThreatModel is the vision beat: "we need a threat model"
// answered from the scan already held, by the same core code the CLI uses.
func TestAnAgentCanAskForAThreatModel(t *testing.T) {
	s := scanned(t)
	res, err := s.handleThreatModel(context.Background(), threatModelInput{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var out threatModelOutput
	decode(t, res, &out)

	if out.Summary == "" || out.Model.Meta.Report != threatmodel.ReportKind {
		t.Fatalf("empty answer: %s", payload(t, res))
	}
	if len(out.Model.Limits) == 0 {
		t.Error("the answer omits what nox cannot see")
	}
	if out.Note == "" {
		t.Error("no instruction on what the agent may not say")
	}
	if regexp.MustCompile(`(?i)\b(secure|safe|mitigated|handled|compliant)\b`).MatchString(out.Summary) {
		t.Errorf("summary claims more than evidence:\n%s", out.Summary)
	}
	if len(out.Model.Provenance.Artifacts) == 0 {
		t.Error("no evidence files cited")
	}
	// The MCP model and the CLI model are one function of one input.
	in, err := s.getCache("").result.ThreatModelInput(s.version)
	if err != nil {
		t.Fatal(err)
	}
	again := threatmodel.Build(in)
	if again.Summary != out.Model.Summary {
		t.Errorf("summary differs between calls: %+v vs %+v", again.Summary, out.Model.Summary)
	}
}

func TestThreatModelNeedsAScanFirst(t *testing.T) {
	s := New("test", nil)
	res, err := s.handleThreatModel(context.Background(), threatModelInput{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if got := payload(t, res); !regexp.MustCompile(`no scan results`).MatchString(got) {
		t.Errorf("expected a request to scan first, got %s", got)
	}
}
