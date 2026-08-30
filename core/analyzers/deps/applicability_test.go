package deps

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/applicability"
	"github.com/nox-hq/nox/core/capability"
)

// goAdvisory builds an OSV record scoping to the given import paths of module.
func goAdvisory(module string, imports ...string) *osvVuln {
	aff := osvAffected{Package: osvPackage{Name: module}}
	for _, im := range imports {
		aff.EcosystemSpecific.Imports = append(aff.EcosystemSpecific.Imports, osvImport{Path: im})
	}
	return &osvVuln{Affected: []osvAffected{aff}}
}

// TestApplicabilityClimbsAsFarAsTheEvidenceGoes covers every branch a
// dependency finding can take, and asserts the reason as well as the outcome.
//
// The reason is half the value. "Stopped at call_reachable" is not actionable;
// "stopped because no call-graph analysis is available" tells an operator what
// to install — and it distinguishes a limit of this installation from a limit
// of the evidence, which look identical in a finding that says neither.
func TestApplicabilityClimbsAsFarAsTheEvidenceGoes(t *testing.T) {
	const module = "golang.org/x/crypto"
	linked := map[string]struct{}{"golang.org/x/crypto/openpgp": {}}

	for _, tc := range []struct {
		name        string
		pkg         Package
		adv         *osvVuln
		linked      map[string]struct{}
		linkedKnown bool
		wantOutcome applicability.Outcome
		wantReached applicability.Rung
		wantStopped applicability.Rung
		wantBecause capability.State
	}{
		{
			name:   "affected package is linked — climbs to symbol_used, then hits a wall nox has not built",
			pkg:    Package{Name: module, Ecosystem: "go"},
			adv:    goAdvisory(module, "golang.org/x/crypto/openpgp"),
			linked: linked, linkedKnown: true,
			wantOutcome: applicability.Undetermined,
			wantReached: applicability.SymbolUsed,
			wantStopped: applicability.CallReachable,
			wantBecause: capability.Unsupported,
		},
		{
			name:   "affected package is not linked — the only NotImpacting case",
			pkg:    Package{Name: module, Ecosystem: "go"},
			adv:    goAdvisory(module, "golang.org/x/crypto/ssh"),
			linked: linked, linkedKnown: true,
			wantOutcome: applicability.NotImpacting,
			wantReached: applicability.AffectedVersion,
			wantStopped: applicability.SymbolUsed,
			wantBecause: capability.Negative,
		},
		{
			name:   "advisory names no import paths — nothing established",
			pkg:    Package{Name: module, Ecosystem: "go"},
			adv:    goAdvisory(module),
			linked: linked, linkedKnown: true,
			wantOutcome: applicability.Undetermined,
			wantReached: applicability.AffectedVersion,
			wantStopped: applicability.SymbolUsed,
			wantBecause: capability.Unknown,
		},
		{
			name:   "linked set unknown — an unavailable answer, not an empty one",
			pkg:    Package{Name: module, Ecosystem: "go"},
			adv:    goAdvisory(module, "golang.org/x/crypto/ssh"),
			linked: nil, linkedKnown: false,
			wantOutcome: applicability.Undetermined,
			wantReached: applicability.AffectedVersion,
			wantStopped: applicability.SymbolUsed,
			wantBecause: capability.Unknown,
		},
		{
			name:   "npm — unexamined, not unreachable",
			pkg:    Package{Name: "left-pad", Ecosystem: "npm"},
			adv:    goAdvisory("left-pad"),
			linked: nil, linkedKnown: false,
			wantOutcome: applicability.Undetermined,
			wantReached: applicability.AffectedVersion,
			wantStopped: applicability.SymbolUsed,
			wantBecause: capability.Unsupported,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := applicabilityFor(tc.pkg, tc.adv, tc.linked, tc.linkedKnown)
			if v.Outcome != tc.wantOutcome {
				t.Errorf("outcome = %q, want %q", v.Outcome, tc.wantOutcome)
			}
			if v.Reached != tc.wantReached {
				t.Errorf("reached = %q, want %q", v.Reached, tc.wantReached)
			}
			if v.StoppedAt != tc.wantStopped {
				t.Errorf("stoppedAt = %q, want %q", v.StoppedAt, tc.wantStopped)
			}
			if v.Because != tc.wantBecause {
				t.Errorf("because = %q, want %q — an unsupported analysis and an "+
					"undetermined one are different answers", v.Because, tc.wantBecause)
			}
			if d := v.Describe(); d == "" {
				t.Error("the verdict describes itself as nothing")
			}
		})
	}
}

// TestOnlyTheUnlinkedCaseIsNotImpacting is Gate B at the analyzer level. Four of
// the five branches above are absences of knowledge; exactly one is a finding.
func TestOnlyTheUnlinkedCaseIsNotImpacting(t *testing.T) {
	const module = "golang.org/x/crypto"
	linked := map[string]struct{}{"golang.org/x/crypto/openpgp": {}}

	notImpacting := 0
	for _, tc := range []struct {
		adv         *osvVuln
		linked      map[string]struct{}
		linkedKnown bool
		eco         string
	}{
		{goAdvisory(module, "golang.org/x/crypto/openpgp"), linked, true, "go"},
		{goAdvisory(module, "golang.org/x/crypto/ssh"), linked, true, "go"},
		{goAdvisory(module), linked, true, "go"},
		{goAdvisory(module, "golang.org/x/crypto/ssh"), nil, false, "go"},
		{goAdvisory("left-pad"), nil, false, "npm"},
	} {
		v := applicabilityFor(Package{Name: module, Ecosystem: tc.eco}, tc.adv, tc.linked, tc.linkedKnown)
		if v.Outcome == applicability.NotImpacting {
			notImpacting++
		}
	}
	if notImpacting != 1 {
		t.Errorf("%d branches produced NotImpacting, want exactly 1 — every other "+
			"branch is an absence of knowledge, and an absence that de-emphasises a "+
			"finding is a blind spot reported as an all-clear", notImpacting)
	}
}

// TestTheMessageSaysWhatWasEstablished. The old message said only "not
// reachable", which invites the reader to supply the more comfortable reading.
func TestTheMessageSaysWhatWasEstablished(t *testing.T) {
	const module = "golang.org/x/crypto"
	linked := map[string]struct{}{"golang.org/x/crypto/openpgp": {}}

	unlinked := applicabilityFor(Package{Name: module, Ecosystem: "go"},
		goAdvisory(module, "golang.org/x/crypto/ssh"), linked, true)
	got := unlinked.Describe()
	if !strings.Contains(got, "not currently impacting") {
		t.Errorf("%q does not state the conclusion in a developer's terms", got)
	}
	if !strings.Contains(got, "not linked by this build") {
		t.Errorf("%q does not give the reason", got)
	}

	stalled := applicabilityFor(Package{Name: module, Ecosystem: "go"},
		goAdvisory(module, "golang.org/x/crypto/openpgp"), linked, true)
	got = stalled.Describe()
	if strings.Contains(got, "not currently impacting") {
		t.Errorf("%q claims non-impact for a linked package", got)
	}
	if !strings.Contains(got, "not established") {
		t.Errorf("%q does not say that the climb stopped short", got)
	}
}
