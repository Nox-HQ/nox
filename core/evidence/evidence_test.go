package evidence

import "testing"

func TestKindStrengthOrdering(t *testing.T) {
	// The ordering is the whole point of the package: if a semantic judgment
	// ever outranks a deterministic claim, every verdict built on it is wrong.
	ordered := []Kind{
		KindHeuristic,
		KindSemantic,
		KindStatic,
		KindIndependentObservation,
		KindResearchHypothesis,
		KindSourceConfirmed,
		KindControlledReproduction,
		KindDynamicExploit,
	}
	for i := 1; i < len(ordered); i++ {
		prev, cur := ordered[i-1], ordered[i]
		if cur.Strength() <= prev.Strength() {
			t.Errorf("%s (%d) must be stronger than %s (%d)",
				cur, cur.Strength(), prev, prev.Strength())
		}
	}
	if KindPublicAdvisory.Strength() != 100 {
		t.Errorf("public advisory strength = %d, want 100", KindPublicAdvisory.Strength())
	}
}

func TestSemanticIsNeverDeterministic(t *testing.T) {
	if KindSemantic.Deterministic() {
		t.Fatal("semantic evidence must never be classified deterministic")
	}
	if !KindSemantic.Semantic() {
		t.Fatal("KindSemantic must report Semantic() == true")
	}
	for _, k := range []Kind{KindStatic, KindSourceConfirmed, KindControlledReproduction,
		KindDynamicExploit, KindMaintainerConfirmed, KindPublicAdvisory} {
		if !k.Deterministic() {
			t.Errorf("%s should be deterministic", k)
		}
		if k.Semantic() {
			t.Errorf("%s must not be semantic", k)
		}
	}
}

func TestUnknownKindCarriesNoWeight(t *testing.T) {
	var k Kind = "made-up"
	if k.Valid() {
		t.Fatal("unknown kind must not validate")
	}
	if k.Strength() != 0 {
		t.Fatalf("unknown kind strength = %d, want 0", k.Strength())
	}
	// An unrecognised claim is kept for the audit trail but must not lift the
	// verdict off the floor.
	l := &Ledger{}
	l.Add(Claim{Kind: k, Statement: "trust me"})
	if got := l.Confidence(); got != ConfidenceLow {
		t.Fatalf("confidence from unknown kind = %s, want LOW", got)
	}
	if l.Len() != 1 {
		t.Fatal("unknown claims must still be retained in the ledger")
	}
}

func TestConfidenceEmptyLedgerIsLow(t *testing.T) {
	l := &Ledger{}
	if got := l.Confidence(); got != ConfidenceLow {
		t.Fatalf("empty ledger = %s, want LOW", got)
	}
}

func TestOnlyDeterministicReproductionReachesConfirmed(t *testing.T) {
	tests := []struct {
		name  string
		kinds []Kind
		want  Confidence
	}{
		{"heuristic alone", []Kind{KindHeuristic}, ConfidenceLow},
		{"static alone", []Kind{KindStatic}, ConfidenceMedium},
		{"source confirmed", []Kind{KindSourceConfirmed}, ConfidenceHigh},
		{"controlled reproduction", []Kind{KindControlledReproduction}, ConfidenceConfirmed},
		{"dynamic exploit", []Kind{KindDynamicExploit}, ConfidenceConfirmed},
		{"maintainer", []Kind{KindMaintainerConfirmed}, ConfidenceConfirmed},
		{"public advisory", []Kind{KindPublicAdvisory}, ConfidenceConfirmed},
		{"a pile of heuristics is still low", []Kind{
			KindHeuristic, KindHeuristic, KindHeuristic, KindHeuristic,
		}, ConfidenceLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Ledger{}
			for _, k := range tt.kinds {
				l.Add(Claim{Kind: k, Statement: string(k)})
			}
			if got := l.Confidence(); got != tt.want {
				t.Errorf("Confidence() = %s, want %s", got, tt.want)
			}
		})
	}
}

// A stack of LLM judgments is still a stack of opinions. §24 forbids any single
// agent conclusion elevating a candidate to CONFIRMED; restating one many times
// must not do it either.
func TestSemanticOnlyLedgerIsCappedAtMedium(t *testing.T) {
	l := &Ledger{}
	for i := 0; i < 10; i++ {
		l.Add(Claim{
			Kind:       KindSemantic,
			Statement:  "the model thinks this is exploitable",
			Provenance: Provenance{Source: "judge", SourceID: string(rune('a' + i))},
		})
	}
	if got := l.Confidence(); got != ConfidenceMedium {
		t.Fatalf("ten independent semantic judgments = %s, want MEDIUM", got)
	}
	if !l.HasSemantic() {
		t.Error("HasSemantic() should be true")
	}
	if l.HasDeterministic() {
		t.Error("HasDeterministic() must be false for a semantic-only ledger")
	}
}

// The §11 failure mode: volume is not corroboration.
func TestOneSourceScanningRepeatedlyIsOneIndependentSource(t *testing.T) {
	l := &Ledger{}
	for i := 0; i < 100; i++ {
		l.Add(Claim{
			Kind:       KindHeuristic,
			Statement:  "saw the pattern again",
			Provenance: Provenance{Source: "nox-scan", SourceID: "sensor-1"},
		})
	}
	if got := l.IndependentSources(); got != 1 {
		t.Fatalf("IndependentSources() = %d, want 1 for 100 scans from one sensor", got)
	}
	if got := l.Confidence(); got != ConfidenceLow {
		t.Fatalf("100 self-scans = %s, want LOW", got)
	}
}

func TestUnattributedClaimsAreNeverIndependent(t *testing.T) {
	l := &Ledger{}
	for i := 0; i < 5; i++ {
		l.Add(Claim{Kind: KindHeuristic, Provenance: Provenance{Source: "nox-scan"}})
	}
	if got := l.IndependentSources(); got != 0 {
		t.Fatalf("IndependentSources() = %d, want 0 when no SourceID is set", got)
	}
}

func TestIndependentCorroborationPromotesButNeverConfirms(t *testing.T) {
	l := &Ledger{}
	// Two genuinely distinct sensors reporting the same static finding.
	l.Add(Claim{Kind: KindStatic, Provenance: Provenance{SourceID: "sensor-1"}})
	l.Add(Claim{Kind: KindStatic, Provenance: Provenance{SourceID: "sensor-2"}})
	if got := l.IndependentSources(); got != 2 {
		t.Fatalf("IndependentSources() = %d, want 2", got)
	}
	if got := l.Confidence(); got != ConfidenceHigh {
		t.Fatalf("two independent static claims = %s, want HIGH (promoted from MEDIUM)", got)
	}

	// Adding a third source must not push past HIGH: corroboration is not proof.
	l.Add(Claim{Kind: KindStatic, Provenance: Provenance{SourceID: "sensor-3"}})
	if got := l.Confidence(); got != ConfidenceHigh {
		t.Fatalf("three independent static claims = %s, want HIGH (capped)", got)
	}
}

func TestStrongestPicksHighestAndIsStable(t *testing.T) {
	l := &Ledger{}
	if _, ok := l.Strongest(); ok {
		t.Fatal("empty ledger must report no strongest claim")
	}
	l.Add(Claim{Kind: KindHeuristic, Statement: "first"})
	l.Add(Claim{Kind: KindDynamicExploit, Statement: "exploit"})
	l.Add(Claim{Kind: KindMaintainerConfirmed, Statement: "maintainer"})
	got, ok := l.Strongest()
	if !ok {
		t.Fatal("expected a strongest claim")
	}
	// Dynamic exploit and maintainer confirmation tie at 95; the earlier claim
	// wins so repeated evaluation is stable.
	if got.Statement != "exploit" {
		t.Fatalf("Strongest() = %q, want the earlier of the tied claims (%q)", got.Statement, "exploit")
	}
}

func TestKindsAreSortedForDeterminism(t *testing.T) {
	l := &Ledger{}
	l.Add(Claim{Kind: KindStatic})
	l.Add(Claim{Kind: KindHeuristic})
	l.Add(Claim{Kind: KindStatic})
	got := l.Kinds()
	if len(got) != 2 || got[0] != KindHeuristic || got[1] != KindStatic {
		t.Fatalf("Kinds() = %v, want [heuristic static]", got)
	}
}

func TestExploitabilityLadder(t *testing.T) {
	if !Confirmed.AtLeast(Prevented) || !Prevented.AtLeast(Inconclusive) ||
		!Inconclusive.AtLeast(Plausible) || !Plausible.AtLeast(Potential) {
		t.Fatal("exploitability ladder is mis-ordered")
	}
	if Potential.AtLeast(Confirmed) {
		t.Fatal("POTENTIAL must not outrank CONFIRMED")
	}
	for _, e := range []Exploitability{Potential, Plausible, Prevented, Inconclusive, Confirmed} {
		if !e.Valid() {
			t.Errorf("%s should be valid", e)
		}
	}
	if Exploitability("EXPLOITED").Valid() {
		t.Error("undefined state must not validate")
	}
}
