package core

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
)

// flowFinding builds a finding that describes one dataflow, anchored wherever
// the caller says.
func flowFinding(ruleID string, anchorLine int, sourceLine, sinkLine, sourceVar string) findings.Finding {
	return findings.Finding{
		RuleID:   ruleID,
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "app/handler.py", StartLine: anchorLine, StartColumn: 5},
		Metadata: map[string]string{
			"source_line": sourceLine,
			"sink_line":   sinkLine,
			"source_var":  sourceVar,
		},
	}
}

// TestTriage002IsOneFlowNotTwoVulnerabilities recreates the case Phase 5 names
// as its exit criterion, and resolves it through the model.
//
// The history: TRIAGE-002 reported "missing input validation" on the SOURCE
// line of a taint flow whose SINK was already reported one line below. All 12
// of its corpus findings were that shape; it scored 0 true positives and 12
// false positives, precision 0.000. It was not detecting anything — it was
// re-reporting, one line up, what the taint engine had already found.
//
// It was fixed by deleting the rule family. That worked and taught nothing: the
// next detector to re-report a flow from the other end would reproduce it
// exactly, because nothing in the model could say the two were one condition.
//
// Now something can. Both candidates resolve to the SAME flow subject — that is
// what FlowID being rule-independent buys — so "two findings" and "one
// vulnerability" are both representable and the relationship between them is
// recorded rather than inferred from a count going down.
func TestTriage002IsOneFlowNotTwoVulnerabilities(t *testing.T) {
	const (
		sourceLine = "41"
		sinkLine   = "42"
		sourceVar  = "user_input"
	)
	// The taint engine, anchored at the sink.
	sink := flowFinding("TAINT-002", 42, sourceLine, sinkLine, sourceVar)
	// A triage-style rule, anchored one line up at the source — the exact
	// TRIAGE-002 shape.
	source := flowFinding("TRIAGE-002", 41, sourceLine, sinkLine, sourceVar)

	sinkID, ok := findings.FlowID(&sink)
	if !ok {
		t.Fatal("the sink-anchored finding does not describe a flow")
	}
	sourceID, ok := findings.FlowID(&source)
	if !ok {
		t.Fatal("the source-anchored finding does not describe a flow")
	}

	if sinkID != sourceID {
		t.Fatalf("the two ends of one flow got different identities:\n  sink:   %s\n  source: %s\n"+
			"They must agree, or the model cannot say they are one condition and the "+
			"only remaining move is to delete one of them — which is how this was "+
			"resolved last time.", sinkID, sourceID)
	}

	// Recorded through the store, both candidates concern the one flow.
	store := reasoning.New()
	flow := reasoning.Flow(sinkID)
	for _, f := range []findings.Finding{sink, source} {
		var l evidence.Ledger
		l.Add(evidence.Claim{
			Kind: evidence.KindStatic, Subject: flow,
			Statement:  f.RuleID + " reports this flow",
			Provenance: evidence.Provenance{Source: "nox-scan", Tool: "taint"},
		})
		store.Relate(evidence.Relation{
			From: SubjectForFinding(f), Kind: evidence.RelConcerns, To: flow, Ledger: l,
		})
	}

	concerning := store.Concerning(flow, evidence.RelConcerns)
	if len(concerning) != 2 {
		t.Fatalf("%d candidate(s) recorded as concerning the flow, want 2", len(concerning))
	}
	// Two candidates, one flow. That is the sentence the model could not say
	// before, and the reason it matters is that the count of FINDINGS and the
	// count of VULNERABILITIES are now different numbers rather than the same
	// number reported twice.
	graph := store.Relations()
	flows := map[evidence.Subject]bool{}
	for _, r := range graph.Relations {
		flows[r.To] = true
	}
	if len(flows) != 1 {
		t.Errorf("%d distinct flows for one condition, want 1", len(flows))
	}

	if errs := graph.Validate(); len(errs) != 0 {
		t.Errorf("the relation graph does not validate: %v", errs)
	}
}

// TestFlowIdentityIgnoresTheRule pins the property the recreation depends on.
//
// flowKey — which DeduplicateFlows merges on — includes the rule ID, and must:
// it decides whether to DELETE a finding, and deleting across rules would lose
// a genuinely different report. FlowID must not, because it names the condition
// rather than the report, and a condition does not change identity because a
// second rule noticed it.
func TestFlowIdentityIgnoresTheRule(t *testing.T) {
	a := flowFinding("TAINT-002", 42, "41", "42", "user_input")
	b := flowFinding("VARIANT-005", 42, "41", "42", "user_input")

	idA, okA := findings.FlowID(&a)
	idB, okB := findings.FlowID(&b)
	if !okA || !okB {
		t.Fatal("a flow finding did not yield an identity")
	}
	if idA != idB {
		t.Errorf("two rules reporting one flow got different identities: %s vs %s", idA, idB)
	}

	// A genuinely different flow must not collide.
	other := flowFinding("TAINT-002", 42, "41", "42", "other_var")
	idOther, _ := findings.FlowID(&other)
	if idOther == idA {
		t.Error("two different tainted variables produced one flow identity")
	}
}

// TestAFindingThatIsNotAFlowHasNoFlowIdentity. Most findings are not flows, and
// inventing an identity for them would relate unrelated things.
func TestAFindingThatIsNotAFlowHasNoFlowIdentity(t *testing.T) {
	f := findings.Finding{
		RuleID:   "SEC-003",
		Location: findings.Location{FilePath: "app/creds.py", StartLine: 1},
	}
	if _, ok := findings.FlowID(&f); ok {
		t.Error("a secrets finding was given a flow identity")
	}
	f.Metadata = map[string]string{"source_line": "3"} // half the evidence
	if _, ok := findings.FlowID(&f); ok {
		t.Error("a finding naming a source line but no variable was given a flow identity")
	}
}
