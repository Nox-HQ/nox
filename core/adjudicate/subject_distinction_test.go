package adjudicate_test

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// allSubjectKinds is the kernel's closed set, written out so a kind added
// upstream fails TestEveryKnownKindIsAudited rather than slipping past this
// audit unexamined.
var allSubjectKinds = []evidence.SubjectKind{
	evidence.SubjectPackage,
	evidence.SubjectSymbol,
	evidence.SubjectFlow,
	evidence.SubjectCallPath,
	evidence.SubjectInput,
	evidence.SubjectControl,
	evidence.SubjectHypothesis,
	evidence.SubjectCandidate,
	evidence.SubjectTriggerCondition,
	evidence.SubjectInvariantViolation,
	evidence.SubjectCrash,
	evidence.SubjectSecurityEffect,
	evidence.SubjectExploit,
}

// Gate C, audited across every subject kind rather than the two the
// reproduction hierarchy made obvious.
//
// The rule is one sentence — evidence about one proposition establishes that
// proposition and no other — and it is easy to believe it holds because the
// cases anyone thinks to write are the cases where the two propositions are
// obviously different. The pairs that matter are the ones that look alike: a
// package and a candidate found in that package, a flow and the call path it
// runs along, a crash and the security effect somebody infers from it.
//
// So this asserts the whole matrix. Deterministic, reproduced evidence about
// each kind confirms that kind and refuses all twelve others.
func TestDeterministicEvidenceConfirmsOnlyItsOwnSubject(t *testing.T) {
	outcome := evidence.RunOutcome{
		Executed: true, Violated: true, Reproduced: true, ControlSound: true,
	}
	for _, about := range allSubjectKinds {
		t.Run(string(about), func(t *testing.T) {
			// The ID is deliberately identical across kinds. Two subjects that
			// differ only by kind are the hardest case and the one a
			// string-keyed implementation would get wrong.
			subject := evidence.Subject{Kind: about, ID: "shared-id"}
			ledger := &evidence.Ledger{}
			ledger.Add(evidence.Claim{
				Kind:      evidence.KindDynamicExploit,
				Subject:   subject,
				Statement: "a deterministic oracle observed this and it reproduced",
			})

			if got := evidence.DeriveExploitabilityAbout(outcome, ledger, subject); got != evidence.Confirmed {
				t.Fatalf("evidence about %s did not confirm %s (got %s); the audit cannot "+
					"distinguish kinds if it confirms none of them", about, about, got)
			}
			for _, other := range allSubjectKinds {
				if other == about {
					continue
				}
				neighbour := evidence.Subject{Kind: other, ID: "shared-id"}
				if got := evidence.DeriveExploitabilityAbout(outcome, ledger, neighbour); got == evidence.Confirmed {
					t.Errorf("evidence about %s confirmed %s — two propositions sharing an "+
						"ID are not the same proposition", about, other)
				}
			}
		})
	}
}

// The same distinction for the aggregate confidence, which is the other half a
// caller reads and the half nox's own reports surface.
func TestConfidenceDoesNotCrossSubjects(t *testing.T) {
	pkg := evidence.Subject{Kind: evidence.SubjectPackage, ID: "golang.org/x/text"}
	cand := evidence.Subject{Kind: evidence.SubjectCandidate, ID: "golang.org/x/text"}

	ledger := &evidence.Ledger{}
	// The strongest thing a scanner ever holds about a package: somebody else
	// published an advisory. It says nothing about whether this repository's
	// code is exploitable.
	ledger.Add(evidence.Claim{
		Kind:      evidence.KindPublicAdvisory,
		Subject:   pkg,
		Statement: "an advisory affects this module",
	})

	strong := ledger.ConfidenceAbout(pkg)
	weak := ledger.ConfidenceAbout(cand)
	if strong == weak {
		t.Fatalf("an advisory about a package produced the same confidence about a "+
			"candidate (%s); the exit criterion for milestone 3.2 is exactly that it "+
			"must not", strong)
	}
	if weak != evidence.ConfidenceLow {
		t.Errorf("confidence about a candidate with no evidence = %s, want LOW", weak)
	}
}

// A kind added to the kernel must be audited, not inherited.
//
// The list above is hand-written, which is the only way to state "these are the
// kinds we have examined". The cost is that it can fall behind, and this is
// what makes falling behind loud: a new kind is a new proposition, and an
// unexamined proposition is one nothing has checked cannot be confused with its
// neighbours.
func TestEveryKnownKindIsAudited(t *testing.T) {
	seen := make(map[evidence.SubjectKind]bool, len(allSubjectKinds))
	for _, k := range allSubjectKinds {
		if seen[k] {
			t.Errorf("%s is listed twice", k)
		}
		seen[k] = true
		if !k.Valid() {
			t.Errorf("%s is not a kind the kernel recognises; the audit list has drifted", k)
		}
	}
	// The kernel exposes no enumeration, so the count is the pin. If this
	// fails, read subject.go and add the new kind above rather than raising the
	// number.
	if len(allSubjectKinds) != 13 {
		t.Errorf("the audit covers %d kinds; nox-core defined 13 when this was written. "+
			"A new kind needs a distinguishing case here before anything files claims "+
			"against it.", len(allSubjectKinds))
	}
}
