package hypothesize_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/hypothesize"
)

// The whole passive-to-active chain, end to end: a scan produces a question, an
// attack consumes it, and both file their claims in one ledger.
//
// Milestones 10.1 through 10.3 in one assertion, because they are one property
// and testing them apart would let the seam between them rot. Nothing asserted
// that the artifact 8.1 writes is one `nox attack run --plan` can actually
// read — the two sides were built at different times against the same type, and
// "the same type" is exactly the assumption that stops being true quietly.
//
// The target is a SimTarget and the profile is safe: nothing is sent anywhere.
// That is 10.1 holding while 10.2 is exercised.
func TestAScanQuestionReachesAnAttackAndOneLedger(t *testing.T) {
	dir := t.TempDir()
	src := `import openai
from flask import request

def chat():
    client = openai.OpenAI()
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Answer this: {request.json['q']}"}],
    )
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	res, err := nox.RunScanWithOptions(dir, nox.ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	plan, err := hypothesize.From(res, dir, "2026-09-10T00:00:00Z")
	if err != nil {
		t.Fatalf("hypotheses: %v", err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Fatal("the scan raised no question; this test asserts nothing")
	}
	if len(plan.Hypotheses[0].Evidence.Claims) == 0 {
		t.Fatal("the hypothesis carries no evidence, so nothing can be shown to survive")
	}

	out, err := attack.Run(context.Background(), plan, attack.NewSimTarget(), attack.RunConfig{
		Profile: attack.ProfileSafe, Now: "2026-09-10T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("attack.Run refused a scan-emitted plan: %v", err)
	}
	if len(out.Traces) == 0 {
		t.Fatal("the attack produced no trace from a plan with hypotheses")
	}

	// 10.1: the safe profile executed nothing, so no state above PLAUSIBLE is
	// reachable however the plan was built.
	for _, tr := range out.Traces {
		if tr.Exploitability == evidence.Confirmed || tr.Exploitability == evidence.Prevented {
			t.Errorf("%s reached %s under the safe profile, which sends nothing",
				tr.ID, tr.Exploitability)
		}
	}

	// 10.3: one ledger. The scan's claims are carried, not rebuilt, and the
	// attack's own claim sits beside them under a DIFFERENT subject — a
	// reproduction confirms the invariant it tested and nothing above it.
	var fromScan, fromAttack int
	for _, c := range out.Traces[0].Ledger.Claims {
		switch c.Subject.Kind {
		case evidence.SubjectCandidate:
			fromScan++
		case evidence.SubjectInvariantViolation:
			fromAttack++
		}
	}
	if fromScan == 0 {
		t.Error("the trace's ledger holds nothing the scan established. The attack would " +
			"be rediscovering why nox thought this worth testing — badly, because it " +
			"cannot see the evidence the scan gathered.")
	}
	if fromAttack == 0 {
		t.Error("the attack filed no claim of its own, so there is nothing to distinguish " +
			"from the scan's")
	}
	// The distinction is the point: if these collapsed onto one subject, a
	// deterministic scan claim would satisfy the CONFIRMED precondition for a
	// proposition nobody validated.
	if fromScan > 0 && fromAttack > 0 {
		t.Logf("one ledger: %d claim(s) carried from the scan, %d from the attack, "+
			"under distinct subjects", fromScan, fromAttack)
	}
}
