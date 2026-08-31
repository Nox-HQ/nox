package attack

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
)

// Milestone D: the scan produces the hypothesis; the attack fills in the
// observation. Given a scan result, `nox attack` must be able to consume a
// hypothesis without rediscovering why nox considered it worth testing.
//
// Before this, it rediscovered it badly. The runner seeded its ledger with a
// single heuristic claim restating the rationale, while the scan had already
// gathered better evidence and thrown it away — the evidence is out-of-band and
// dies with the scan. `nox scan --evidence-out` keeps it, and the artifact
// built for replay turns out to be exactly this handoff.

func planFinding() findings.Finding {
	return findings.Finding{
		RuleID: "AI-PI-001", Severity: findings.SeverityHigh,
		Fingerprint: "abc123def456",
		Location:    findings.Location{FilePath: "app/agent.py", StartLine: 50},
		Message:     "untrusted input reaches the system prompt",
		Metadata: map[string]string{
			"source_var":           "user_input",
			"analysis_limitations": "reflection",
		},
	}
}

// TestAHypothesisCarriesWhatTheScanEstablished checks the fields the handoff
// exists to carry.
func TestAHypothesisCarriesWhatTheScanEstablished(t *testing.T) {
	f := planFinding()
	subject := evidence.Subject{Kind: evidence.SubjectCandidate, ID: "AI-PI-001@app/agent.py:50"}
	ledger := evidence.Ledger{Claims: []evidence.Claim{{
		Kind: evidence.KindStatic, Subject: subject,
		Statement: "the value is not a literal",
	}}}

	in := PlanInput{
		Root: ".", Findings: []findings.Finding{f}, Now: "2026-08-31T00:00:00Z",
		Evidence: func(findings.Finding) (evidence.Subject, evidence.Ledger) {
			return subject, ledger
		},
		Unknowns: func(evidence.Subject) []string {
			return []string{"call_graph: nothing could establish it"}
		},
	}
	var h Hypothesis
	attachEvidence(&h, f, in)

	if h.Subject != subject {
		t.Errorf("the hypothesis is not attributed: %v", h.Subject)
	}
	if len(h.Evidence.Claims) != 1 {
		t.Errorf("the scan's evidence was not carried: %d claims", len(h.Evidence.Claims))
	}
	if len(h.Unknowns) != 1 {
		t.Errorf("the open questions were not carried: %v", h.Unknowns)
	}
}

// TestAHypothesisWithoutEvidenceIsStillUsable. `attack plan` reads a findings
// file and works offline, so a caller with no artifact must get the behaviour
// it had before this existed rather than an error or an empty plan.
func TestAHypothesisWithoutEvidenceIsStillUsable(t *testing.T) {
	f := planFinding()
	var h Hypothesis
	attachEvidence(&h, f, PlanInput{Root: ".", Findings: []findings.Finding{f}})

	if !h.Subject.Zero() {
		t.Errorf("a hypothesis built without evidence invented a subject: %v", h.Subject)
	}
	if len(h.Evidence.Claims) != 0 || len(h.Unknowns) != 0 {
		t.Error("a hypothesis built without evidence carries claims or unknowns from nowhere")
	}
}

// TestAssumptionsNameWhatWasNotEstablished. Stating them is what lets a reader
// disagree with the hypothesis rather than only with its result, and every
// entry must be something nox did NOT establish.
func TestAssumptionsNameWhatWasNotEstablished(t *testing.T) {
	got := assumptionsOf(planFinding(), "POST /chat")
	joined := strings.Join(got, " | ")

	for _, want := range []string{
		"reachable by an attacker", // the entry point is assumed reachable
		"is the one that executes", // the static path is assumed to be the real one
		"reachable at runtime",     // no reach level was recorded on this finding
		"incomplete",               // the file carries an analysis limitation
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the assumptions do not mention %q:\n%s", want, joined)
		}
	}

	// A finding whose reachability WAS established should not carry the
	// assumption that it was not.
	established := planFinding()
	established.Metadata["reach_level"] = "symbol_referenced"
	if strings.Contains(strings.Join(assumptionsOf(established, "e"), " "), "reachable at runtime") {
		t.Error("a finding with a recorded reach level still assumes nothing established it")
	}
}

// TestTheRunnerUsesTheCarriedEvidence is the acceptance criterion at the
// consumer. A run that rebuilt its own thin ledger would pass every test above
// and still discard what it was handed.
func TestTheRunnerUsesTheCarriedEvidence(t *testing.T) {
	subject := evidence.Subject{Kind: evidence.SubjectFlow, ID: "flow-9"}
	h := Hypothesis{
		ID: "hyp-x", Rationale: "grounding",
		Evidence: evidence.Ledger{Claims: []evidence.Claim{{
			Kind: evidence.KindStatic, Subject: subject,
			Statement: "the scan established this",
		}}},
	}
	l := groundingLedger(h, "2026-08-31T00:00:00Z")

	var carried bool
	for _, c := range l.Claims {
		if c.Statement == "the scan established this" {
			carried = true
			if c.Subject != subject {
				t.Errorf("a carried claim was re-attributed from %v to %v. It is "+
					"evidence about that proposition, not about this hypothesis's "+
					"invariant, and re-attributing it is the promotion the "+
					"reproduction hierarchy exists to prevent", subject, c.Subject)
			}
		}
	}
	if !carried {
		t.Error("the runner rebuilt its ledger and discarded what the scan established")
	}
}
