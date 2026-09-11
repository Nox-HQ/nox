package attack

import (
	"fmt"
	"strings"
)

// ReplayWorld is the set of conditions an execution replay depends on: where
// traffic went, under what profile, through which entry point and field, with
// which canary seed, and against what determinism gate. Two replays of the same
// trace agree only to the extent that these agree.
type ReplayWorld struct {
	// Target is the target's reported name.
	Target string `json:"target,omitempty"`
	// Profile is the safety profile in force.
	Profile string `json:"profile,omitempty"`
	// Route is the entry point probed.
	Route string `json:"route,omitempty"`
	// Fields are the request fields the probe filled.
	Fields []string `json:"fields,omitempty"`
	// Seed is the canary seed. Canary VALUES are minted from it, so a probe
	// recorded under one seed is scored against another seed's values — which
	// is why a mismatch is structural rather than merely suspicious.
	Seed string `json:"seed,omitempty"`
	// Samples and MinHits are the determinism gate.
	Samples int `json:"samples,omitempty"`
	MinHits int `json:"min_hits,omitempty"`
}

// ReplayEnvironment states the world an execution replay ran in, beside the
// world the original run recorded, and names every place the two differ.
//
// Two commands are called replay and they carry different guarantees. `nox
// replay` re-derives a verdict from a stored ledger: the ledger is the whole
// input, so the answer is deterministic. `nox attack replay` re-fires a
// recorded probe at a live target nox neither owns nor controls, so "it did not
// reproduce" has at least four readings — the bug was fixed, the target moved,
// the target's state changed, or no probe ever reached the code under test.
//
// Best-effort is an acceptable guarantee. Best-effort reported as if it were
// deterministic is not, and the difference is entirely in whether the
// conditions are written down. This type is where they are written down.
type ReplayEnvironment struct {
	// Recorded is the world the original run reported. Fields the run did not
	// record are empty — an older trace file, not a zero value with meaning.
	Recorded ReplayWorld `json:"recorded"`
	// Actual is the world this replay ran in.
	Actual ReplayWorld `json:"actual"`
	// Assumptions are what the replay takes as true without checking. They hold
	// even when nothing diverged: a replay cannot read the target's planted
	// canary, restore its state, or re-fire the original's benign control.
	Assumptions []string `json:"assumptions,omitempty"`
	// Divergences name each way the replay world differed from the recorded
	// one. A divergence is not an error — an operator overriding the route
	// after a fix moved the endpoint is doing the right thing — but it changes
	// what a non-reproduction means, so it is reported rather than absorbed.
	Divergences []string `json:"divergences,omitempty"`
	// Unverifiable names assumptions that could not be checked at all, because
	// the recorded run did not write down what to check them against. Silence
	// here would read as a clearance.
	Unverifiable []string `json:"unverifiable,omitempty"`
}

// seedIsIncompatible reports whether the recorded seed is known and differs
// from the one this replay minted its canaries from. When it does, no target
// behaviour can reproduce the recorded signal: the recorded payload carries the
// original seed's transform word and the replay scores the answer against a
// different seed's canary values. It is the one divergence that makes the
// replay meaningless rather than merely conditional.
func (e *ReplayEnvironment) seedIsIncompatible() bool {
	return e.Recorded.Seed != "" && e.Recorded.Seed != e.Actual.Seed
}

// describeReplayEnvironment compares the world a replay is about to run in with
// the one the result recorded.
func describeReplayEnvironment(r *Result, t Target, cfg RunConfig, route string, fields []string) *ReplayEnvironment {
	recorded := ReplayWorld{
		Target:  r.Target,
		Profile: r.Profile,
		Route:   r.Route,
		Fields:  sortedCopy(r.Fields),
		Seed:    r.Seed,
	}
	actual := ReplayWorld{
		Target:  t.Name(),
		Profile: string(cfg.Profile),
		Route:   route,
		Fields:  sortedCopy(fields),
		Seed:    cfg.Seed,
		Samples: cfg.Samples,
		MinHits: cfg.MinHits,
	}
	env := &ReplayEnvironment{Recorded: recorded, Actual: actual}

	// Assumptions hold whether or not anything diverged. They are the parts of
	// the environment nox cannot inspect at all, and they are the reason this
	// command is best-effort in the first place.
	env.Assumptions = append(env.Assumptions,
		fmt.Sprintf("the canary planted in the target is the one seed %q mints; nox reads the target's responses, never its planted value", actual.Seed),
		"the target state the original run depended on — session, corpus, retrieved documents — is unchanged; nox neither records nor restores it",
		"the benign control the original run fired is still sound; a replay fires no control of its own, so control soundness is carried from the recorded run rather than re-measured",
		fmt.Sprintf("%q names the same application the run attacked; nox compares names, not identity", actual.Target),
	)

	if recorded.Seed == "" {
		env.Unverifiable = append(env.Unverifiable,
			fmt.Sprintf("the recorded run did not write down its canary seed, so nox cannot check that %q matches it. "+
				"A replay under the wrong seed cannot reproduce the recorded signal whatever the target does", actual.Seed))
	}
	if recorded.Target == "" {
		env.Unverifiable = append(env.Unverifiable,
			"the recorded run did not name its target, so nox cannot tell whether this replay hit the same application")
	}

	if recorded.Target != "" && recorded.Target != actual.Target {
		env.Divergences = append(env.Divergences,
			fmt.Sprintf("target: recorded %q, replayed against %q", recorded.Target, actual.Target))
	}
	if recorded.Profile != "" && recorded.Profile != actual.Profile {
		env.Divergences = append(env.Divergences,
			fmt.Sprintf("profile: recorded %q, replayed under %q", recorded.Profile, actual.Profile))
	}
	if recorded.Route != "" && recorded.Route != actual.Route {
		env.Divergences = append(env.Divergences,
			fmt.Sprintf("route: recorded %q, replayed against %q", recorded.Route, actual.Route))
	}
	if recorded.Fields != nil && strings.Join(recorded.Fields, ",") != strings.Join(actual.Fields, ",") {
		env.Divergences = append(env.Divergences,
			fmt.Sprintf("fields: recorded [%s], replayed with [%s]",
				strings.Join(recorded.Fields, " "), strings.Join(actual.Fields, " ")))
	}
	if env.seedIsIncompatible() {
		env.Divergences = append(env.Divergences,
			fmt.Sprintf("seed: recorded %q, replayed with %q — the canary values differ, so the recorded signal cannot recur",
				recorded.Seed, actual.Seed))
	}
	return env
}

// noteDeterminismGate records a determinism gate that differs from the one the
// original trace was judged under. It is recorded per trace rather than per
// result because the gate lives on the trace's reproduction tally.
func (e *ReplayEnvironment) noteDeterminismGate(recordedHits, recordedSamples int) {
	e.Recorded.Samples = recordedSamples
	e.Recorded.MinHits = recordedHits
	if recordedSamples > 0 && recordedSamples != e.Actual.Samples {
		e.Divergences = append(e.Divergences,
			fmt.Sprintf("determinism gate: the trace was confirmed at %d/%d, this replay requires %d/%d",
				recordedHits, recordedSamples, e.Actual.MinHits, e.Actual.Samples))
	}
}
