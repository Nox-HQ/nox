package intel_test

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/intel"
)

func servedRecord(claims ...evidence.Claim) vulnsource.Record {
	return vulnsource.Record{
		ID: "NOX-CAND-2026-0001",
		Affected: []vulnsource.Affected{{
			Package: vulnsource.Package{Name: "golang.org/x/crypto", Ecosystem: "Go"},
			EcosystemSpecific: vulnsource.EcosystemSpecific{
				Imports: []vulnsource.Import{{Path: "golang.org/x/crypto/ssh"}},
			},
		}},
		Intelligence: &vulnsource.Intelligence{
			Corroboration: 3,
			Evidence:      &evidence.Ledger{Claims: claims},
		},
	}
}

// TestAServedRecordBecomesALocalQuestion is the receiving end of Milestone M.
//
// The service says a package is affected and how strongly its own evidence
// supports that; local nox turns it into what THIS build still has to establish.
// The adapter must carry the affected symbol across, because that is what the
// local applicability test needs — "does this build reference it?" cannot be
// asked without the "it".
func TestAServedRecordBecomesALocalQuestion(t *testing.T) {
	p := intel.FromRecord(servedRecord(evidence.Claim{
		Kind: evidence.KindIndependentObservation, Statement: "a distinct installation reported it",
		Provenance: evidence.Provenance{Source: "nox-intel"},
	}))

	if p.Package != "golang.org/x/crypto" || p.Ecosystem != "Go" {
		t.Errorf("the package was not carried: %s/%s", p.Ecosystem, p.Package)
	}
	if len(p.AffectedSymbols) != 1 || p.AffectedSymbols[0] != "golang.org/x/crypto/ssh" {
		t.Errorf("the affected symbol was not carried: %v", p.AffectedSymbols)
	}
	if p.ReporterCount != 3 {
		t.Errorf("the corroboration count was not carried: %d", p.ReporterCount)
	}

	// And the questions it hands to local analysis reference that symbol.
	var asksSymbol bool
	for _, q := range p.AppliesLocally() {
		if q == "does this build reference golang.org/x/crypto/ssh?" {
			asksSymbol = true
		}
	}
	if !asksSymbol {
		t.Errorf("the local questions do not test the affected symbol: %v", p.AppliesLocally())
	}
}

// TestMaturityComesFromTheStrongestLiveClaim. A ledger is as mature as its
// best-supported evidence, and a retracted claim is not part of that — the same
// rule the kernel applies to confidence.
func TestMaturityComesFromTheStrongestLiveClaim(t *testing.T) {
	p := intel.FromRecord(servedRecord(
		evidence.Claim{Kind: evidence.KindIndependentObservation, Statement: "reported"},
		evidence.Claim{Kind: evidence.KindStatic, Statement: "static analysis established it"},
	))
	if p.Maturity != intel.MaturityStatic {
		t.Errorf("maturity = %q, want static (the strongest live claim)", p.Maturity)
	}

	// A retracted reproduction must not lift the maturity above what still
	// stands. The kernel weighs a retracted claim at nothing; so does this.
	retracted := intel.FromRecord(servedRecord(
		evidence.Claim{Kind: evidence.KindIndependentObservation, Statement: "reported"},
		evidence.Claim{
			Kind: evidence.KindControlledReproduction, Statement: "reproduced, then withdrawn",
			Status: evidence.StatusRetracted,
		},
	))
	if retracted.Maturity == intel.MaturityReproduced {
		t.Error("a retracted reproduction lifted the maturity to reproduced; a " +
			"withdrawn claim must weigh nothing here as it does in the kernel")
	}
}

// TestRefutationsCrossTheWire. A disputed proposition must arrive disputed. The
// service records refuting claims in the ledger; the adapter must carry them,
// or a source that forwarded only support would look uncontested.
func TestRefutationsCrossTheWire(t *testing.T) {
	p := intel.FromRecord(servedRecord(
		evidence.Claim{Kind: evidence.KindStatic, Statement: "affected"},
		evidence.Claim{
			Kind: evidence.KindStatic, Polarity: evidence.PolarityRefutes,
			Statement: "the maintainer says the sink is unreachable",
		},
	))
	if len(p.Refutations) != 1 {
		t.Errorf("a refuting claim did not cross the wire: %v", p.Refutations)
	}
}

// TestARecordWithNoEvidenceIsAHypothesisNotNothing. The weakest a served record
// can be is a hypothesis, never an absence — a package the service names at all
// is at least a lead, and dropping it to no maturity would lose it.
func TestARecordWithNoEvidenceIsAHypothesis(t *testing.T) {
	p := intel.FromRecord(vulnsource.Record{
		ID:       "NOX-CAND-2026-0002",
		Affected: []vulnsource.Affected{{Package: vulnsource.Package{Name: "left-pad", Ecosystem: "npm"}}},
	})
	if p.Maturity != intel.MaturityHypothesis {
		t.Errorf("a record with no evidence has maturity %q, want hypothesis", p.Maturity)
	}
	// And a proposition from it still produces its claims about the PACKAGE, not
	// about any local candidate — the M invariant survives the adapter.
	for _, c := range p.Claims("nox-intel", "t") {
		if c.Subject.Kind != evidence.SubjectPackage {
			t.Errorf("an adapted proposition filed a claim against %q", c.Subject.Kind)
		}
	}
}
