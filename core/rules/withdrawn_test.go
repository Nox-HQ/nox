package rules

import (
	"strings"
	"testing"
)

// A withdrawn rule is a retraction, not a rename. These guard the two things
// that make the tombstone worth having: it must never match anything, and it
// must say enough for an operator to act on.

func TestAWithdrawnRuleIsNotInTheRuleSet(t *testing.T) {
	t.Parallel()

	// The registry is a record of absence. A withdrawn ID that is ALSO a live
	// rule would mean the scanner both reports the condition and tells
	// operators it retracted it.
	live := map[string]bool{}
	for _, id := range WithdrawnIDs() {
		live[id] = true
	}
	if len(live) == 0 {
		t.Fatal("no withdrawn rules registered; this test would pass vacuously")
	}
}

func TestAWithdrawnRuleCarriesAnActionableReason(t *testing.T) {
	t.Parallel()

	for _, id := range WithdrawnIDs() {
		w, ok := Withdrawn(id)
		if !ok {
			t.Fatalf("%s is listed but does not resolve", id)
		}
		if w.ID != id {
			t.Errorf("%s resolves to a tombstone for %s", id, w.ID)
		}
		if !strings.HasPrefix(w.Version, "v") {
			t.Errorf("%s: version %q should name the release that withdrew it, e.g. v1.36.0", id, w.Version)
		}
		// "Removed" is not a reason. The bar is a sentence an operator can
		// argue with, which in practice means it says what the rule CLAIMED
		// and why the claim does not hold.
		if len(w.Reason) < 80 {
			t.Errorf("%s: reason is %d characters; state what the rule claimed and why it does not hold",
				id, len(w.Reason))
		}
	}
}

func TestAnUnknownIDHasNoTombstone(t *testing.T) {
	t.Parallel()

	if _, ok := Withdrawn("SEC-000-does-not-exist"); ok {
		t.Error("an unregistered ID resolved to a tombstone")
	}
	// A rule that is merely RETIRED must not be tombstoned: retirement keeps
	// the condition reported under a survivor, and telling an operator it was
	// withdrawn would be false.
	for _, id := range []string{"SEC-454", "SEC-455", "SEC-692"} {
		if _, ok := Withdrawn(id); ok {
			t.Errorf("%s is retired into a survivor, not withdrawn; a tombstone would misreport it", id)
		}
	}
}
