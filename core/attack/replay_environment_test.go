package attack

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// Milestone 11.2: an execution replay is best-effort, and it must SAY what it
// took for granted.
//
// `nox replay` re-derives a verdict from a stored ledger: the ledger is the
// whole input, so the answer is deterministic. `nox attack replay` re-fires a
// recorded probe at a live target nox does not control, so "it did not
// reproduce" has at least four readings — the bug was fixed, the target moved,
// the target's state changed, or no probe ever reached the code. A replay that
// does not distinguish them has issued a clean bill of health it did not earn.
//
// These tests pin the assumptions to the artifact rather than to the prose.

// replayedAgainst runs the standard confirmed fixture and replays its first
// confirmed trace against a target in the given mode, with cfg applied.
func replayedAgainst(t *testing.T, mode fakeMode, mutate func(*RunConfig)) *Trace {
	t.Helper()
	res, cfg, cs := confirmedRun(t)
	id := firstConfirmedTraceID(res)
	if id == "" {
		t.Fatal("setup: no confirmed trace")
	}
	if mutate != nil {
		mutate(&cfg)
	}
	tr, err := Replay(context.Background(), res, id, newFakeTarget(mode, cs), cfg)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return tr
}

// TestARunRecordsTheSeedItsCanariesWereMintedFrom. The seed is the one piece of
// the replay environment nox cannot recover from anything else, and the flag
// help already tells the operator it "must match the original run" — a rule
// nothing could check, because the run never wrote it down.
func TestARunRecordsTheSeedItsCanariesWereMintedFrom(t *testing.T) {
	res, cfg, _ := confirmedRun(t)
	if res.Seed != cfg.Seed {
		t.Errorf("result records seed %q, run used %q; a replay cannot verify an "+
			"assumption the run never wrote down", res.Seed, cfg.Seed)
	}
}

// TestAReplayStatesTheEnvironmentItAssumed checks that a replayed trace carries
// the conditions its verdict was produced under, rather than leaving a reader to
// assume they matched the recorded run.
func TestAReplayStatesTheEnvironmentItAssumed(t *testing.T) {
	tr := replayedAgainst(t, modeVulnerable, nil)
	env := tr.ReplayEnvironment
	if env == nil {
		t.Fatal("a replayed trace carries no environment; the reader cannot tell " +
			"what the result was conditional on")
	}
	if env.Recorded.Seed == "" || env.Actual.Seed == "" {
		t.Errorf("environment does not state both seeds: recorded=%q actual=%q",
			env.Recorded.Seed, env.Actual.Seed)
	}
	if env.Recorded.Target == "" || env.Actual.Target == "" {
		t.Errorf("environment does not state both targets: recorded=%q actual=%q",
			env.Recorded.Target, env.Actual.Target)
	}
	if env.Actual.Route == "" {
		t.Error("environment does not state the route the replay probed")
	}
	if len(env.Assumptions) == 0 {
		t.Fatal("a replay that assumes nothing is a replay that checked everything, " +
			"and this one checked neither the target's planted canary nor its state")
	}
	// The benign control is the specific assumption that is invisible without
	// being stated: a replay fires none, so its control soundness is inherited.
	if !strings.Contains(strings.ToLower(strings.Join(env.Assumptions, " ")), "control") {
		t.Errorf("the assumptions do not mention control soundness, which a replay "+
			"carries from the original run rather than re-measuring: %v", env.Assumptions)
	}
}

// TestAReplayUnderADifferentSeedIsRefusedRatherThanReported. Canary values are
// minted from the seed. The recorded payload carries the ORIGINAL seed's
// transform word, and a replay mints its own set to score the answer against,
// so under a different seed no target behaviour whatsoever can reproduce the
// signal. Reporting that as "did not reproduce" is a fix that was never tested.
func TestAReplayUnderADifferentSeedIsRefusedRatherThanReported(t *testing.T) {
	res, cfg, cs := confirmedRun(t)
	id := firstConfirmedTraceID(res)
	cfg.Seed = "some-other-seed"
	tr, err := Replay(context.Background(), res, id, newFakeTarget(modeVulnerable, cs), cfg)
	if err == nil {
		t.Fatalf("a replay whose seed cannot reproduce the recorded signal returned "+
			"a verdict (%s) instead of refusing", tr.Exploitability)
	}
	if !strings.Contains(err.Error(), "seed") {
		t.Errorf("the refusal does not name the seed: %v", err)
	}
	if !strings.Contains(err.Error(), cfg.Seed) || !strings.Contains(err.Error(), res.Seed) {
		t.Errorf("the refusal names neither the seed used nor the seed recorded: %v", err)
	}
}

// TestAnUnrecordedSeedIsStatedAsUnverifiable. A trace file written before the
// seed was recorded cannot have the assumption checked. That is a limit, and
// silence about it reads as a clearance.
func TestAnUnrecordedSeedIsStatedAsUnverifiable(t *testing.T) {
	res, cfg, cs := confirmedRun(t)
	id := firstConfirmedTraceID(res)
	res.Seed = "" // an older attack.trace.json
	tr, err := Replay(context.Background(), res, id, newFakeTarget(modeVulnerable, cs), cfg)
	if err != nil {
		t.Fatalf("an unrecorded seed must not block the replay: %v", err)
	}
	joined := strings.Join(tr.ReplayEnvironment.Unverifiable, " ")
	if !strings.Contains(joined, "seed") {
		t.Errorf("the replay does not state that the seed assumption could not be "+
			"checked: %v", tr.ReplayEnvironment.Unverifiable)
	}
}

// TestAReplayNamesADivergentEnvironment. Route, target, profile and the
// determinism gate can all differ from the recorded run, and each changes what
// a non-reproduction means.
func TestAReplayNamesADivergentEnvironment(t *testing.T) {
	tr := replayedAgainst(t, modeFixed, func(c *RunConfig) {
		c.Route = "/v2/chat"
		c.Samples = 5
		c.MinHits = 5
	})
	joined := strings.Join(tr.ReplayEnvironment.Divergences, "\n")
	for _, want := range []string{"/v2/chat", "route"} {
		if !strings.Contains(joined, want) {
			t.Errorf("divergences do not mention %q: %v", want, tr.ReplayEnvironment.Divergences)
		}
	}
	if !strings.Contains(joined, "fake-fixed") {
		t.Errorf("the replay hit a different target than the run recorded and did not "+
			"say so: %v", tr.ReplayEnvironment.Divergences)
	}
	if !strings.Contains(strings.ToLower(joined), "determinism") && !strings.Contains(joined, "5") {
		t.Errorf("the determinism gate moved from 2/2 to 5/5 unremarked: %v",
			tr.ReplayEnvironment.Divergences)
	}
}

// TestAnUnreachableTargetIsNotAFixThatHeld. Every probe erroring means the
// recorded exploit was never tested. `nox attack regress` already refuses to
// call that a pass; replay reported "did not reproduce", which is the same
// false all-clear one command over.
func TestAnUnreachableTargetIsNotAFixThatHeld(t *testing.T) {
	tr := replayedAgainst(t, modeErroring, nil)
	if tr.Outcome.TargetErrors != tr.ReproductionSamples {
		t.Errorf("TargetErrors=%d of %d samples; a probe that never reached the "+
			"target must be counted, or the verdict is derived from a run that did "+
			"not happen", tr.Outcome.TargetErrors, tr.ReproductionSamples)
	}
	if tr.Exploitability == evidence.Prevented {
		t.Error("a replay whose every probe failed reports PREVENTED")
	}
	if !tr.ReplayUnexercised() {
		t.Error("the trace does not report itself unexercised, so a caller gating " +
			"CI on it cannot tell nothing was proven")
	}
	low := strings.ToLower(tr.Note)
	if !strings.Contains(low, "could not be exercised") {
		t.Errorf("the note reads as a result rather than as a failure to test: %q", tr.Note)
	}
}

// TestAReplayReMeasuresDefenceRatherThanInheritingIt. A trace may record
// DefenseObserved from a probe that was refused while another one won. Carrying
// that flag into a replay lets an unreachable target derive PREVENTED — "a
// defense was observed" — from a connection refused.
func TestAReplayReMeasuresDefenceRatherThanInheritingIt(t *testing.T) {
	res, cfg, cs := confirmedRun(t)
	id := firstConfirmedTraceID(res)
	for i := range res.Traces {
		if res.Traces[i].ID == id {
			res.Traces[i].Outcome.DefenseObserved = true
		}
	}
	tr, err := Replay(context.Background(), res, id, newFakeTarget(modeErroring, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Outcome.DefenseObserved {
		t.Error("the replay carried the original run's DefenseObserved forward; " +
			"no defense was observed here, every probe failed to connect")
	}
	if tr.Exploitability == evidence.Prevented {
		t.Errorf("connection refused derived PREVENTED (%s): the worst reading of "+
			"a broken replay is the reassuring one", evidence.Describe(tr.Exploitability))
	}
}

// TestAReplayThatRefusedIsToldApartFromOneThatFailed. A target that answers and
// declines the payload is a different fact from one that never answered, and
// the two must not share a note.
func TestAReplayThatRefusedIsToldApartFromOneThatFailed(t *testing.T) {
	tr := replayedAgainst(t, modeRefusing, nil)
	if tr.Outcome.TargetErrors != 0 {
		t.Errorf("a refusal was counted as a target error: %d", tr.Outcome.TargetErrors)
	}
	if !tr.Outcome.DefenseObserved {
		t.Error("the target refused the recorded payload and the replay did not observe it")
	}
	if !strings.Contains(strings.ToLower(tr.Note), "refus") {
		t.Errorf("the note does not distinguish a refusal from silence: %q", tr.Note)
	}
}

// TestANonReproducingReplayStopsAdvertisingTheOriginalsClaims. Milestone H said
// a trace must not advertise a reproduction it cannot perform. Replay built its
// result by copying the original trace, so a replay that reproduced nothing
// carried the original's replay command AND its CONFIRMED-grade severity.
func TestANonReproducingReplayStopsAdvertisingTheOriginalsClaims(t *testing.T) {
	res, cfg, cs := confirmedRun(t)
	id := firstConfirmedTraceID(res)
	orig, _ := res.TraceByID(id)
	if orig.ReplayCommand == "" || orig.Classification.Severity == "" {
		t.Fatal("fixture: the original trace should advertise both a replay and a severity")
	}
	tr, err := Replay(context.Background(), res, id, newFakeTarget(modeFixed, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Evidence != nil {
		t.Fatal("fixture: this replay should not reproduce")
	}
	if tr.ReplayCommand != "" {
		t.Errorf("a replay with no reproduced violation advertises %q", tr.ReplayCommand)
	}
	if tr.ReplayNote == "" {
		t.Error("and says nothing about why it cannot be re-run")
	}
	if tr.Classification.Severity == orig.Classification.Severity &&
		tr.Exploitability != orig.Exploitability {
		t.Errorf("the replay dropped to %s but kept the original's %s severity: a "+
			"trace that demonstrated nothing is scored as if it had",
			tr.Exploitability, tr.Classification.Severity)
	}
}

// TestARegressionSuiteCarriesTheSeedItWasRecordedUnder. The suite is the CI
// gate, and the seed hazard is worse there than in a one-off replay: a suite
// whose canary values do not match the target's reports every case HELD, exits
// 0, and nobody reads a passing build.
func TestARegressionSuiteCarriesTheSeedItWasRecordedUnder(t *testing.T) {
	res, cfg, cs := confirmedRun(t)
	suite := SuiteFromResult(res, testNow)
	if len(suite.Cases) == 0 {
		t.Fatal("setup: expected at least one recorded case")
	}
	if suite.Seed != cfg.Seed {
		t.Errorf("suite records seed %q, run used %q", suite.Seed, cfg.Seed)
	}

	wrong := cfg
	wrong.Seed = "some-other-seed"
	sr, err := RunSuite(context.Background(), suite, newFakeTarget(modeVulnerable, cs), wrong)
	if err == nil {
		t.Fatalf("a suite run under the wrong seed returned %d regression(s) instead of "+
			"refusing; a green gate that tested nothing", sr.Regressions)
	}
	if !strings.Contains(err.Error(), "seed") {
		t.Errorf("the refusal does not name the seed: %v", err)
	}

	// The recorded seed still runs, and still catches the regression.
	sr, err = RunSuite(context.Background(), suite, newFakeTarget(modeVulnerable, cs), cfg)
	if err != nil {
		t.Fatalf("the recorded seed must still run: %v", err)
	}
	if sr.Regressions == 0 {
		t.Error("the suite no longer detects the exploit it recorded")
	}
}
