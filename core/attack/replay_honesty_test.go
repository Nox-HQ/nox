package attack

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// Milestone H: nox must never claim execution reproducibility where it can only
// guarantee adjudication reproducibility.
//
// Two commands are called replay and they answer different questions.
// `nox replay` re-derives verdicts from a stored ledger and touches nothing —
// deterministic, because the ledger is the whole input. `nox attack replay`
// re-runs the winning probe against a live target — best-effort, because nox
// does not control the target's state, so a failed replay may mean the bug was
// fixed, the data changed, or the service moved.
//
// The artifact used to blur that. Every trace carried a ReplayCommand,
// including hypotheses that never executed, and attack.Replay answers such a
// trace with "carries no reproducible evidence". An artifact advertising a
// reproduction it cannot perform is the criterion violated in its most literal
// form.

// TestOnlyAReplayableTraceAdvertisesAReplay checks that the artifact promises a
// re-run only where one is possible.
func TestOnlyAReplayableTraceAdvertisesAReplay(t *testing.T) {
	notRun := notRunTrace(Hypothesis{ID: "h1"}, RunConfig{}, "scenario above profile")
	if notRun.ReplayCommand != "" {
		t.Errorf("a hypothesis that never executed advertises %q; attack.Replay "+
			"refuses it, so the artifact promises something the tool declines",
			notRun.ReplayCommand)
	}
	if notRun.ReplayNote == "" {
		t.Error("a trace that cannot be re-run says nothing about why. Silence there " +
			"reads as an oversight rather than as a limit")
	}
	if notRun.Evidence != nil {
		t.Fatal("fixture: a not-run trace should carry no evidence")
	}
}

// TestTheReplayNoteDistinguishesTheTwoKinds. A reader holding a trace with no
// replay command should learn that the OTHER replay still applies — the verdict
// can be re-derived from its evidence even though the probe cannot be re-fired.
// Those are different guarantees and the note is where the difference is
// visible to someone reading an artifact rather than the source.
func TestTheReplayNoteDistinguishesTheTwoKinds(t *testing.T) {
	notRun := notRunTrace(Hypothesis{ID: "h2"}, RunConfig{}, "nothing ran")
	if strings.Contains(notRun.ReplayNote, "nox attack replay") {
		t.Errorf("the note points back at the command that will refuse it: %q", notRun.ReplayNote)
	}
	// A trace whose run produced no reproduction is the common case, and it is
	// the one where the distinction matters most: no probe to re-fire, but the
	// verdict is still re-derivable.
	r := &runner{cfg: RunConfig{}.withDefaults()}
	tr := r.finalize(Trace{ID: "trace-h3"}, evidence.RunOutcome{HypothesisConstructed: true, ControlSound: true}, Hypothesis{ID: "h3"}, nil, OracleVerdict{}, true)
	if tr.ReplayCommand != "" {
		t.Errorf("a trace with no reproduced violation advertises %q", tr.ReplayCommand)
	}
	if !strings.Contains(tr.ReplayNote, "nox replay") {
		t.Errorf("the note does not tell the reader that the verdict is still "+
			"re-derivable from its evidence: %q", tr.ReplayNote)
	}
}
