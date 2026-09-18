package core

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// An operator who waived a rule nox has since RETRACTED used to be told the
// finding "may have been fixed" and to "check the rule ID". Both are wrong: the
// finding was not fixed, and the ID is not a typo. The advice sends them
// looking for something that cannot exist.
//
// withdrawnWaiverNote is what turns that into a sentence they can act on.

func TestAWaiverOnAWithdrawnRuleExplainsItself(t *testing.T) {
	t.Parallel()

	ids := rules.WithdrawnIDs()
	if len(ids) == 0 {
		t.Fatal("no withdrawn rules registered; this test would pass vacuously")
	}
	id := ids[0]
	w, _ := rules.Withdrawn(id)

	note := withdrawnWaiverNote([]string{id})
	if note == "" {
		t.Fatalf("a waiver naming the withdrawn rule %s produced no explanation", id)
	}
	for _, want := range []string{id, w.Version, "withdrawn"} {
		if !strings.Contains(note, want) {
			t.Errorf("the explanation for %s omits %q:\n%s", id, want, note)
		}
	}
	// It has to say what to DO, or it is just a longer silence.
	if !strings.Contains(note, "can be deleted") {
		t.Errorf("the explanation for %s does not say what to do with the waiver:\n%s", id, note)
	}
}

func TestAWaiverOnALiveRuleGetsTheOrdinaryAdvice(t *testing.T) {
	t.Parallel()

	// A live or merely-retired rule must fall through to the generic
	// unused-waiver message: claiming it was withdrawn would be false, and
	// retirement keeps the condition reported under a survivor.
	for _, id := range []string{"SEC-001", "SEC-454", "IAC-013"} {
		if note := withdrawnWaiverNote([]string{id}); note != "" {
			t.Errorf("%s is not withdrawn but got a withdrawal note: %s", id, note)
		}
	}
}
