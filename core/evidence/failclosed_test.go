package evidence

import (
	"strings"
	"testing"
)

// This file pins the evidence spine's FAIL-CLOSED contract.
//
// evidence.go and verdict.go already encode these rules; nothing here is a new
// requirement. What is new is the SHAPE of the check: each guard sweeps the
// entire input space and derives its expectation from the stated rule, so a
// future edit that widens a branch by one condition fails here rather than
// shipping. The failure being defended against is the one that makes a security
// verdict worthless — a weak claim wearing a strong claim's label, or a run
// that was cut short reading as a defense that held.

// failClosedKinds is every defined evidence kind. Keeping the list here means
// adding a Kind without weighing it lands as a test failure: an unweighed kind
// is a claim of unknown strength, and the rules below have to place it.
var failClosedKinds = []Kind{
	KindHeuristic,
	KindSemantic,
	KindStatic,
	KindIndependentObservation,
	KindResearchHypothesis,
	KindSourceConfirmed,
	KindControlledReproduction,
	KindDynamicExploit,
	KindMaintainerConfirmed,
	KindPublicAdvisory,
}

// failClosedUndefinedKinds are values that are not evidence kinds: the zero
// value, a plausible-looking invention, a case variant. None may carry weight.
var failClosedUndefinedKinds = []Kind{
	"",
	"Dynamic_Exploit",
	"DYNAMIC_EXPLOIT",
	"dynamic exploit",
	"llm_said_so",
	"unknown",
}

// failClosedExploitabilityStates is every defined lifecycle state.
var failClosedExploitabilityStates = []Exploitability{
	Potential, Plausible, Prevented, Inconclusive, Confirmed,
}

// failClosedClaim builds a claim of a kind attributed to a named reporter.
// An empty source deliberately produces an unattributed claim.
func failClosedClaim(k Kind, sourceID string) Claim {
	return Claim{
		Kind:      k,
		Statement: "fail-closed fixture",
		Provenance: Provenance{
			Source:   "nox-test",
			SourceID: sourceID,
			// ObservedAt stays empty: the package never reads a clock and
			// neither does this file, so every verdict here is reproducible.
		},
	}
}

// failClosedLedgerOf builds a ledger from kinds, all unattributed so the
// independence promotion never quietly enters a case that is about strength.
func failClosedLedgerOf(kinds ...Kind) *Ledger {
	l := &Ledger{}
	for _, k := range kinds {
		l.Add(failClosedClaim(k, ""))
	}
	return l
}

// TestFailClosed_ConfirmedOnlyFromTheExactIntendedCombination walks the FULL
// cross product of RunOutcome's booleans, both TargetErrors cases, and four
// ledger shapes — every input DeriveExploitability can see — and asserts
// CONFIRMED appears in exactly one combination and nowhere else.
//
// CONFIRMED is the only word nox says that means "this is real". Every other
// state is hedged. So the guard is mechanical rather than illustrative: the
// intended combination is restated once, from the doc comment on
// DeriveExploitability, and every one of the remaining hundreds of
// combinations must not reach it. A new branch that confirms on one extra
// condition — a semantic ledger, an unsound control, a single non-reproduced
// hit — fails here.
//
// Note what is deliberately NOT in the condition: BudgetExhausted and
// TargetErrors. A reproduced, deterministically-oracled violation is a real
// observation whether or not other attempts ran out of budget or failed to
// reach the target. Running short of budget cannot un-observe what was
// observed. It can, however, stop a run from claiming a defense held — which is
// the next test.
func TestFailClosed_ConfirmedOnlyFromTheExactIntendedCombination(t *testing.T) {
	t.Parallel()

	ledgers := []struct {
		name          string
		ledger        *Ledger
		deterministic bool
	}{
		{"nil", nil, false},
		{"empty", &Ledger{}, false},
		{"semantic-only", failClosedLedgerOf(KindSemantic, KindSemantic), false},
		{"heuristic+semantic", failClosedLedgerOf(KindHeuristic, KindSemantic), false},
		{"deterministic", failClosedLedgerOf(KindSemantic, KindDynamicExploit), true},
	}

	var confirmedSeen int
	for _, lc := range ledgers {
		// bits enumerates the seven independent booleans of a RunOutcome.
		for bits := 0; bits < 1<<7; bits++ {
			for _, targetErrors := range []int{0, 1} {
				o := RunOutcome{
					HypothesisConstructed: bits&1 != 0,
					Executed:              bits&2 != 0,
					Violated:              bits&4 != 0,
					Reproduced:            bits&8 != 0,
					DefenseObserved:       bits&16 != 0,
					BudgetExhausted:       bits&32 != 0,
					ControlSound:          bits&64 != 0,
					TargetErrors:          targetErrors,
				}

				// The rule, restated from DeriveExploitability's contract.
				want := o.Executed && o.Violated && o.Reproduced && o.ControlSound && lc.deterministic

				got := DeriveExploitability(o, lc.ledger)
				if (got == Confirmed) != want {
					t.Errorf("DeriveExploitability(%+v, %s ledger) = %s, Confirmed=%v want Confirmed=%v",
						o, lc.name, got, got == Confirmed, want)
				}
				if want {
					confirmedSeen++
				}
			}
		}
	}

	// A guard that never observes the positive case is a guard that passes
	// because it tests nothing.
	if confirmedSeen == 0 {
		t.Fatal("no combination reached Confirmed — the guard proves nothing")
	}
}

// TestFailClosed_PreventedNeverFromAShortenedRun sweeps the same space and
// asserts the necessary conditions for PREVENTED from the other direction:
// wherever the answer is PREVENTED, every one of them must hold.
//
// This is the "we stopped early" failure. A run that exhausted its budget, or
// that never reached the target, observed nothing — and "we did not exploit it"
// must never be rendered as "a defense held". That is the same false all-clear
// as a git hook exiting 0 because the scan crashed.
func TestFailClosed_PreventedNeverFromAShortenedRun(t *testing.T) {
	t.Parallel()

	ledgers := []*Ledger{nil, {}, failClosedLedgerOf(KindSemantic), failClosedLedgerOf(KindDynamicExploit)}

	var preventedSeen int
	for _, l := range ledgers {
		for bits := 0; bits < 1<<7; bits++ {
			for _, targetErrors := range []int{0, 1, 7} {
				o := RunOutcome{
					HypothesisConstructed: bits&1 != 0,
					Executed:              bits&2 != 0,
					Violated:              bits&4 != 0,
					Reproduced:            bits&8 != 0,
					DefenseObserved:       bits&16 != 0,
					BudgetExhausted:       bits&32 != 0,
					ControlSound:          bits&64 != 0,
					TargetErrors:          targetErrors,
				}

				got := DeriveExploitability(o, l)
				if got != Prevented {
					continue
				}
				preventedSeen++

				switch {
				case o.BudgetExhausted:
					t.Errorf("PREVENTED from a run cut short by its budget: %+v — stopping early is not a defense", o)
				case o.TargetErrors > 0:
					t.Errorf("PREVENTED from a run with %d unreachable attempts: %+v — never arriving is not being blocked", o.TargetErrors, o)
				case !o.Executed:
					t.Errorf("PREVENTED without executing anything: %+v", o)
				case o.Violated:
					t.Errorf("PREVENTED despite an observed violation: %+v", o)
				case !o.DefenseObserved:
					t.Errorf("PREVENTED without observing a defense: %+v — silence is not prevention", o)
				case !o.ControlSound:
					t.Errorf("PREVENTED from an unsound control environment: %+v", o)
				}
			}
		}
	}

	if preventedSeen == 0 {
		t.Fatal("no combination reached Prevented — the guard proves nothing")
	}
}

// TestFailClosed_EveryDerivedStateIsDefined sweeps the space once more for the
// dullest possible property: the derivation always names a state. A future
// branch falling through to the zero Exploitability would produce a finding
// whose lifecycle field is empty, which downstream renders as neither a warning
// nor a verdict — a finding that quietly says nothing at all.
func TestFailClosed_EveryDerivedStateIsDefined(t *testing.T) {
	t.Parallel()

	for _, l := range []*Ledger{nil, {}, failClosedLedgerOf(KindDynamicExploit)} {
		for bits := 0; bits < 1<<7; bits++ {
			for _, targetErrors := range []int{0, 1} {
				o := RunOutcome{
					HypothesisConstructed: bits&1 != 0,
					Executed:              bits&2 != 0,
					Violated:              bits&4 != 0,
					Reproduced:            bits&8 != 0,
					DefenseObserved:       bits&16 != 0,
					BudgetExhausted:       bits&32 != 0,
					ControlSound:          bits&64 != 0,
					TargetErrors:          targetErrors,
				}
				if got := DeriveExploitability(o, l); !got.Valid() {
					t.Fatalf("DeriveExploitability(%+v) = %q, which is not a defined state", o, got)
				}
			}
		}
	}
}

// TestFailClosed_ConfidenceConfirmedOnlyFromDeterministicReproduction iterates
// every evidence kind — defined and undefined — and asserts a ledger reaches
// ConfidenceConfirmed only for the kinds that are BOTH machine-checkable and at
// least reproduction strength.
//
// §24 of the intelligence PRD: no single agent conclusion may independently
// elevate a candidate to CONFIRMED. The mechanical form of that rule is this
// iteration — a kind added to the strengths table without thought about whether
// it is deterministic cannot silently join the confirming set.
func TestFailClosed_ConfidenceConfirmedOnlyFromDeterministicReproduction(t *testing.T) {
	t.Parallel()

	reproductionStrength := KindControlledReproduction.Strength()
	all := append(append([]Kind{}, failClosedKinds...), failClosedUndefinedKinds...)

	var confirming int
	for _, k := range all {
		want := k.Deterministic() && k.Strength() >= reproductionStrength
		if want {
			confirming++
		}

		// One claim on its own.
		if got := failClosedLedgerOf(k).Confidence(); (got == ConfidenceConfirmed) != want {
			t.Errorf("ledger of one %q claim: Confidence = %s, want CONFIRMED=%v", k, got, want)
		}

		// Repetition is not evidence: the same reporter saying it five times
		// must not change the answer either way.
		repeated := failClosedLedgerOf(k, k, k, k, k)
		if got := repeated.Confidence(); (got == ConfidenceConfirmed) != want {
			t.Errorf("ledger of five identical %q claims: Confidence = %s, want CONFIRMED=%v", k, got, want)
		}

		// Nor is corroboration a substitute for proof: five INDEPENDENT
		// reporters lift the level at most to HIGH.
		independent := &Ledger{}
		for i := 0; i < 5; i++ {
			independent.Add(failClosedClaim(k, string(rune('a'+i))))
		}
		if got := independent.Confidence(); (got == ConfidenceConfirmed) != want {
			t.Errorf("ledger of five independently-sourced %q claims: Confidence = %s, want CONFIRMED=%v", k, got, want)
		}
	}

	if confirming == 0 {
		t.Fatal("no kind reaches CONFIRMED — the guard proves nothing")
	}

	// Stated plainly for the kinds most likely to be re-weighed: a source read
	// by a human is strong, but it is not a reproduction.
	for _, k := range []Kind{KindHeuristic, KindSemantic, KindStatic, KindIndependentObservation,
		KindResearchHypothesis, KindSourceConfirmed} {
		if failClosedLedgerOf(k).Confidence() == ConfidenceConfirmed {
			t.Errorf("%q alone reached CONFIRMED", k)
		}
	}

	// A pile of everything short of reproduction still does not confirm.
	pile := &Ledger{}
	for i, k := range []Kind{KindHeuristic, KindSemantic, KindStatic, KindIndependentObservation,
		KindResearchHypothesis, KindSourceConfirmed} {
		pile.Add(failClosedClaim(k, string(rune('a'+i))))
	}
	if got := pile.Confidence(); got == ConfidenceConfirmed {
		t.Errorf("six independent sub-reproduction claims reached CONFIRMED: %s", got)
	}
}

// TestFailClosed_UndefinedKindWeighsNothingAndLiftsNothing pins the treatment of
// a value that is not an evidence kind.
//
// Add keeps such a claim so the audit trail stays complete, but it must
// contribute zero: no strength, not deterministic, not semantic, and — the part
// that matters — appending it to any ledger must leave that ledger's confidence
// exactly where it was. An unrecognised claim that could nudge a level is the
// evidence-side version of the empty string mapping to a permissive default.
func TestFailClosed_UndefinedKindWeighsNothingAndLiftsNothing(t *testing.T) {
	t.Parallel()

	for _, k := range failClosedUndefinedKinds {
		if k.Valid() {
			t.Errorf("%q reports itself as a defined kind", k)
		}
		if s := k.Strength(); s != 0 {
			t.Errorf("%q.Strength() = %d, want 0", k, s)
		}
		if k.Deterministic() {
			t.Errorf("%q reports itself as deterministic", k)
		}
		if k.Semantic() {
			t.Errorf("%q reports itself as semantic", k)
		}
	}

	// Appending undefined claims to a ledger of every defined kind changes
	// nothing. The added claims are unattributed, so the independence promotion
	// is not what is being measured here.
	for _, base := range failClosedKinds {
		l := failClosedLedgerOf(base)
		before := l.Confidence()
		for _, junk := range failClosedUndefinedKinds {
			l.Add(failClosedClaim(junk, ""))
		}
		if after := l.Confidence(); after != before {
			t.Errorf("adding %d undefined claims to a %q ledger moved confidence %s -> %s",
				len(failClosedUndefinedKinds), base, before, after)
		}
		// Nothing was dropped from the audit trail either.
		if want := 1 + len(failClosedUndefinedKinds); l.Len() != want {
			t.Errorf("ledger dropped claims: Len = %d, want %d", l.Len(), want)
		}
	}

	// A ledger made only of undefined claims, however many and however widely
	// sourced, stays at the bottom of the scale and never confirms.
	junkOnly := &Ledger{}
	for i := 0; i < 20; i++ {
		junkOnly.Add(failClosedClaim(failClosedUndefinedKinds[i%len(failClosedUndefinedKinds)], string(rune('a'+i))))
	}
	if got := junkOnly.Confidence(); got.AtLeast(ConfidenceHigh) {
		t.Errorf("20 undefined claims from 20 sources reached %s — an unrecognised claim must never carry a verdict", got)
	}
	if junkOnly.HasDeterministic() {
		t.Error("a ledger of undefined claims reports deterministic evidence")
	}
	if _, ok := junkOnly.Strongest(); !ok {
		t.Error("Strongest reported no claim on a non-empty ledger")
	}
}

// TestFailClosed_DescribeNeverAssertsSafety checks the wording every surface
// shows a user.
//
// §25 is explicit: nox reports "attack not reproduced" or "prevented under the
// strategies tested", never "safe". Nox does not have the evidence to assert
// safety and must not sound like it does — a reader who takes PREVENTED as
// "secure" has been handed a false all-clear by the phrasing alone. The check
// covers undefined states too, since the default branch is exactly where a
// careless "looks secure" would be written.
func TestFailClosed_DescribeNeverAssertsSafety(t *testing.T) {
	t.Parallel()

	banned := []string{"safe", "secure"}
	states := append(append([]Exploitability{}, failClosedExploitabilityStates...),
		Exploitability(""), Exploitability("CLEAN"), Exploitability("whatever"))

	for _, e := range states {
		d := Describe(e)
		if d == "" {
			t.Errorf("Describe(%q) returned an empty string — a state with no reading is a state a user cannot act on", e)
		}
		lower := strings.ToLower(d)
		for _, word := range banned {
			if strings.Contains(lower, word) {
				t.Errorf("Describe(%q) = %q, which claims %q — nox never asserts safety", e, d, word)
			}
		}
	}

	// PREVENTED is the state most easily misread as an all-clear, so its
	// wording must stay explicitly conditional on what was actually tried.
	if p := strings.ToLower(Describe(Prevented)); !strings.Contains(p, "tested") {
		t.Errorf("Describe(Prevented) = %q, which must qualify the claim by what was tested", Describe(Prevented))
	}
}

// TestFailClosed_ExploitabilityLadderPlacesUndefinedStatesAtTheBottom guards the
// comparison operator. AtLeast is how a caller asks "has this been established
// at least this far?"; an undefined state answering yes to anything would let a
// junk value satisfy a threshold, which is the same fail-open as an
// unclassified risk class passing a ceiling.
func TestFailClosed_ExploitabilityLadderPlacesUndefinedStatesAtTheBottom(t *testing.T) {
	t.Parallel()

	undefined := []Exploitability{"", "CLEAN", "confirmed" /* wrong case */, "EXPLOITED"}

	for _, u := range undefined {
		if u.Valid() {
			t.Errorf("%q reports itself as a defined state", u)
		}
		for _, defined := range failClosedExploitabilityStates {
			if u.AtLeast(defined) {
				t.Errorf("undefined state %q claims to be at least %s", u, defined)
			}
			if !defined.AtLeast(u) {
				t.Errorf("defined state %s does not outrank undefined %q", defined, u)
			}
		}
	}

	// Confirmed tops the ladder and Potential sits at its foot, so a threshold
	// expressed against either behaves the way a reader expects.
	for _, e := range failClosedExploitabilityStates {
		if !Confirmed.AtLeast(e) {
			t.Errorf("Confirmed does not outrank %s", e)
		}
		if !e.AtLeast(Potential) {
			t.Errorf("%s ranks below Potential", e)
		}
	}
}
