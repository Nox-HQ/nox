package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

func generate(t *testing.T, caps []report.CapabilityCoverage) Report {
	t.Helper()
	r := NewReporter("test", nil)
	r.Capabilities = caps
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{RuleID: "SEC-001", Message: "m", Severity: findings.SeverityHigh})
	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var doc Report
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc
}

func notifications(t *testing.T, doc Report) []Notification {
	t.Helper()
	if len(doc.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(doc.Runs))
	}
	if len(doc.Runs[0].Invocations) == 0 {
		return nil
	}
	return doc.Runs[0].Invocations[0].ToolExecutionNotifications
}

// SARIF has no slot for "this analysis was never able to run here", so a
// consumer reading results.sarif sees a green run whether nox looked and found
// nothing or never had the ability to look. These notifications are the whole
// difference.
func TestUnprovidedCapabilityIsNotified(t *testing.T) {
	doc := generate(t, []report.CapabilityCoverage{
		{Capability: "call_graph", Provided: false},
	})
	notes := notifications(t, doc)
	if len(notes) != 1 {
		t.Fatalf("got %d notifications, want 1", len(notes))
	}
	if notes[0].Descriptor == nil || notes[0].Descriptor.ID != "nox/capability/unsupported" {
		t.Errorf("descriptor = %+v, want nox/capability/unsupported", notes[0].Descriptor)
	}
	if !strings.Contains(notes[0].Message.Text, "not an all-clear") {
		t.Errorf("message does not warn against reading silence as safety: %q", notes[0].Message.Text)
	}
}

// A capability that answered everything it was asked is not a notification.
// Reporting the successes too would bury the two rows that matter in seven that
// do not, and a signal nobody reads is not a signal.
func TestFullyAnsweredCapabilitiesProduceNoNotification(t *testing.T) {
	doc := generate(t, []report.CapabilityCoverage{
		{Capability: "lexical_context", Provided: true, Answered: 12},
		{Capability: "taint", Provided: true, Answered: 3},
	})
	if notes := notifications(t, doc); len(notes) != 0 {
		t.Errorf("got %d notifications for a fully-answered matrix, want none: %+v", len(notes), notes)
	}
	if len(doc.Runs[0].Invocations) != 0 {
		t.Error("emitted an invocations block with nothing to report")
	}
}

// Provided-but-silent is the state this whole model exists for: the capability
// is installed, nothing asked it, and no error was raised. It must be reported
// distinctly from a capability that does not exist, because the operator's
// remedy differs — one is a gap they can close, the other a limit they cannot.
func TestProvidedButUnaskedIsReportedDistinctly(t *testing.T) {
	doc := generate(t, []report.CapabilityCoverage{
		{Capability: "reachability", Provided: true, Answered: 0},
		{Capability: "entry_point", Provided: false},
	})
	notes := notifications(t, doc)
	if len(notes) != 2 {
		t.Fatalf("got %d notifications, want 2", len(notes))
	}
	ids := []string{notes[0].Descriptor.ID, notes[1].Descriptor.ID}
	if ids[0] != "nox/capability/not-evaluated" || ids[1] != "nox/capability/unsupported" {
		t.Errorf("ids = %v, want a gap and a limit reported under different descriptors", ids)
	}
}

// A capability that ran and could not decide is neither answered nor absent.
func TestInconclusiveIsReportedEvenWhenSomeSubjectsAnswered(t *testing.T) {
	doc := generate(t, []report.CapabilityCoverage{
		{Capability: "reachability", Provided: true, Answered: 5, Inconclusive: 2},
	})
	notes := notifications(t, doc)
	if len(notes) != 1 {
		t.Fatalf("got %d notifications, want 1", len(notes))
	}
	if !strings.Contains(notes[0].Message.Text, "5") || !strings.Contains(notes[0].Message.Text, "2") {
		t.Errorf("message drops the counts: %q", notes[0].Message.Text)
	}
}

// Every notification is a note, never an error. A capability nobody implements
// is a permanent honest limit, and a run that reports it as a failure is one
// whose users learn to filter these out.
func TestNotificationsAreNotesNotFailures(t *testing.T) {
	doc := generate(t, []report.CapabilityCoverage{
		{Capability: "call_graph", Provided: false},
		{Capability: "reachability", Provided: true, Answered: 0},
	})
	if !doc.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("executionSuccessful is false — a missing capability is not a failed run")
	}
	for _, n := range notifications(t, doc) {
		if n.Level != "note" {
			t.Errorf("%s: level %q, want note", n.Descriptor.ID, n.Level)
		}
	}
}

// A reporter with no capability data emits no invocations block at all —
// absence, rather than an empty claim of full coverage.
func TestNoCapabilityDataEmitsNoInvocations(t *testing.T) {
	doc := generate(t, nil)
	if len(doc.Runs[0].Invocations) != 0 {
		t.Errorf("got %d invocations without capability data, want 0", len(doc.Runs[0].Invocations))
	}
}
