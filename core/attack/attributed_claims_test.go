package attack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// Every verdict in this package is derived ABOUT a named subject.
//
// TestAnAttackConfirmsTheInvariantItTestedAndNothingAbove records why: before
// it landed, core/attack set no Subject on any claim, so every claim shared the
// zero subject and the cheapest deterministic claim satisfied the precondition
// for the most expensive. That was fixed in the run path and only there.
// Replay, regress and the MCP path kept building unattributed claims and
// deriving through the subject-blind form.
//
// Those three were not wrong. Each builds a fresh single-purpose ledger whose
// claims all share the zero subject, so the blind form asked the right question
// by accident of construction — and it is worth being exact about that, because
// "latent" and "broken" are different words and only one of them was true.
//
// They were one merge away from wrong, and the merge is scheduled: Phase 10.3
// puts verification evidence into the same ledger the scan wrote, which is
// precisely a multi-subject ledger reaching a derivation that cannot tell the
// subjects apart. groundingLedger already builds one, and its own comment says
// the claims "are evidence about those propositions and not about this
// hypothesis's invariant".
//
// So the guard is on the call, not on the outcome: a new derivation added to
// this package must name what it is deciding.
func TestEveryVerdictNamesItsSubject(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package: %v", err)
	}
	var checked int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		checked++
		for i, line := range strings.Split(string(raw), "\n") {
			// DeriveExploitabilityAbout contains DeriveExploitability as a
			// prefix, so match the open paren that only the blind form has.
			if !strings.Contains(line, "DeriveExploitability(") {
				continue
			}
			t.Errorf("%s:%d derives a verdict through the subject-blind form. "+
				"A deterministic claim about any subject in the ledger then satisfies the "+
				"CONFIRMED precondition for whatever is being decided — which is how a "+
				"reproduced trigger becomes a reported exploit. Use "+
				"DeriveExploitabilityAbout with the subject this verdict is about.",
				name, i+1)
		}
	}
	if checked == 0 {
		t.Fatal("no source files were checked; the guard is vacuous")
	}
}

// The promotion the attributed form prevents, demonstrated rather than asserted
// — and the opposite failure, which is the one that would have been silent.
//
// The subject-blind form does NOT mean "match any subject". It asks about the
// ZERO subject, which is what every unattributed claim carries. So the two
// failure modes are the two halves of one inconsistency:
//
//   - claims unattributed + blind derivation — everything is about the zero
//     subject, so everything matches everything, and the cheapest deterministic
//     claim confirms the most expensive proposition. Loud and wrong.
//   - claims attributed + blind derivation — nothing carries the zero subject,
//     so HasDeterministicAbout finds nothing and CONFIRMED becomes unreachable.
//     Silent and wrong, and worse: `nox attack regress` would stop registering
//     regressions and report a suite of held cases.
//
// The migration in this change had to move both halves together for exactly
// that reason, and the tests that prove CONFIRMED still fires — replay's
// TestReplayReproducesConfirmed, regress's TestLiveExploitStillRegresses, the
// MCP path's TestRunMCPConfirmsPoisonedDescriptions — are what rule out the
// second mode.
func TestUnattributedClaimsPromoteAcrossPropositions(t *testing.T) {
	h := Hypothesis{ID: "hyp-42", Rationale: "a prompt boundary is splice-able"}
	invariant := InvariantSubject(h)
	outcome := evidence.RunOutcome{
		Executed: true, Violated: true, Reproduced: true, ControlSound: true,
	}

	// The pre-migration shape: a scan's static claim about a line of code,
	// carried into an attack ledger with no subject on it.
	unattributed := &evidence.Ledger{}
	unattributed.Add(evidence.Claim{
		Kind:      evidence.KindStatic,
		Statement: "a prompt template interpolates an untrusted value",
	})
	unattributed.Add(evidence.Claim{
		Kind:      evidence.KindSemantic,
		Statement: "a model judged the guardrail bypassed",
	})

	// Blind: the static claim about a source line satisfies the deterministic
	// precondition, and the run is CONFIRMED on evidence that says nothing
	// about the invariant it tested.
	if got := evidence.DeriveExploitability(outcome, unattributed); got != evidence.Confirmed {
		t.Fatalf("the promotion this guard exists for did not occur (got %s); if the kernel "+
			"changed, TestEveryVerdictNamesItsSubject may now be protecting nothing", got)
	}
	// Attributed: the same evidence decides nothing about the invariant.
	if got := evidence.DeriveExploitabilityAbout(outcome, unattributed, invariant); got == evidence.Confirmed {
		t.Error("a claim about no particular proposition confirmed an attack invariant")
	}
}

// The other half, at the producer: a claim attributed to the invariant, decided
// about that invariant, still reaches CONFIRMED. Without this, "no promotion" is
// satisfiable by never confirming anything.
func TestAttributionDoesNotMakeConfirmedUnreachable(t *testing.T) {
	h := Hypothesis{ID: "hyp-42"}
	invariant := InvariantSubject(h)
	ledger := &evidence.Ledger{}
	ledger.Add(evidence.Claim{
		Kind:      evidence.KindDynamicExploit,
		Subject:   invariant,
		Statement: "a deterministic oracle observed the invariant violated and it reproduced",
	})
	outcome := evidence.RunOutcome{
		Executed: true, Violated: true, Reproduced: true, ControlSound: true,
	}
	if got := evidence.DeriveExploitabilityAbout(outcome, ledger, invariant); got != evidence.Confirmed {
		t.Errorf("a reproduced deterministic violation of this very invariant = %s, want "+
			"CONFIRMED. Attribution must not cost the verdict it exists to protect.", got)
	}
}
