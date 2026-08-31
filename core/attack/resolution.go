package attack

import (
	"sort"

	"github.com/nox-hq/nox-core/evidence"
)

// Resolution is what one hypothesis's verification achieved, and what it cost.
//
// Milestone J's metric is hypotheses resolved per unit of verification effort,
// not generic coverage. A fuzzer that fired a million probes and confirmed
// nothing has done worse than one that fired three and confirmed one, and a
// coverage number cannot tell them apart. This can.
//
// "Resolved" is deliberately three-valued. A hypothesis is confirmed, refuted,
// or left inconclusive, and the third is not a failure of the harness — it is
// the honest state of a thing that was tested and did not decide, which is most
// of them. Counting only confirmations would make the harness look worse the
// more careful it was.
type Resolution struct {
	HypothesisID string           `json:"hypothesis_id"`
	Subject      evidence.Subject `json:"subject"`
	// Outcome is where the hypothesis ended: confirmed, refuted, inconclusive,
	// or not-run.
	Outcome ResolutionOutcome `json:"outcome"`
	// Attempts is how many probes this hypothesis cost — the denominator of the
	// metric. A hypothesis resolved in three attempts is cheaper than the same
	// resolution in three hundred.
	Attempts int `json:"attempts"`
	// Exploitability is the lifecycle state the run derived.
	Exploitability evidence.Exploitability `json:"exploitability"`
	// Note carries the trace's own explanation.
	Note string `json:"note,omitempty"`
}

// ResolutionOutcome is the three-plus-one states a hypothesis can end in.
type ResolutionOutcome string

const (
	// ResolvedConfirmed — a reproduced violation under a sound control.
	ResolvedConfirmed ResolutionOutcome = "confirmed"
	// ResolvedRefuted — the attack ran and the objective was not achievable.
	// Distinct from inconclusive: something was established, in the negative.
	ResolvedRefuted ResolutionOutcome = "refuted"
	// ResolvedInconclusive — the attack ran and did not decide. The honest
	// majority, not a harness failure.
	ResolvedInconclusive ResolutionOutcome = "inconclusive"
	// ResolvedNotRun — the hypothesis never executed (profile too low, budget
	// exhausted before its turn). It cost nothing and resolved nothing.
	ResolvedNotRun ResolutionOutcome = "not_run"
)

// Resolutions builds the per-hypothesis accounting from a completed result.
func (r *Result) Resolutions() []Resolution {
	out := make([]Resolution, 0, len(r.Traces))
	for i := range r.Traces {
		t := &r.Traces[i]
		out = append(out, Resolution{
			HypothesisID:   t.HypothesisID,
			Subject:        InvariantSubject(Hypothesis{ID: t.HypothesisID}),
			Outcome:        resolutionOf(t),
			Attempts:       len(t.Attempts),
			Exploitability: t.Exploitability,
			Note:           t.Note,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].HypothesisID < out[j].HypothesisID })
	return out
}

// resolutionOf reads a trace's outcome into the three-plus-one states.
//
// The mapping is deliberately conservative in the direction that matters. Only
// CONFIRMED is confirmed. A run that executed and reached neither a reproduced
// violation nor a clean refutation is inconclusive, never "probably fine" —
// PREVENTED is the kernel's word for an observed defense and is treated as a
// refutation of THIS hypothesis, because the objective was not reachable, while
// staying carefully short of "the target is secure".
func resolutionOf(t *Trace) ResolutionOutcome {
	switch t.Exploitability {
	case evidence.Confirmed:
		return ResolvedConfirmed
	case evidence.Prevented:
		return ResolvedRefuted
	case evidence.Potential, evidence.Plausible:
		// Never executed, or executed without an attempt reaching a verdict.
		if !t.Outcome.Executed {
			return ResolvedNotRun
		}
		return ResolvedInconclusive
	default:
		// INCONCLUSIVE and anything unrecognised: the run did not decide.
		return ResolvedInconclusive
	}
}

// Efficiency is the metric J asks for: what the verification effort bought.
type Efficiency struct {
	Hypotheses   int `json:"hypotheses"`
	Confirmed    int `json:"confirmed"`
	Refuted      int `json:"refuted"`
	Inconclusive int `json:"inconclusive"`
	NotRun       int `json:"not_run"`
	// Attempts is the total verification effort, the denominator.
	Attempts int `json:"attempts"`
	// Resolved is confirmed + refuted: the hypotheses the run actually decided.
	Resolved int `json:"resolved"`
}

// AttemptsPerResolution is the headline number, or zero when nothing resolved.
//
// Reported as a ratio rather than a rate because the useful comparison is
// between runs: a lower number is a harness that decides more per probe. When
// nothing resolved, the answer is not "infinity" or "zero" but "this run
// decided nothing", which callers must read from Resolved rather than from a
// divided value.
func (e Efficiency) AttemptsPerResolution() float64 {
	if e.Resolved == 0 {
		return 0
	}
	return float64(e.Attempts) / float64(e.Resolved)
}

// Efficiency summarises a result against J's metric.
func (r *Result) Efficiency() Efficiency {
	var e Efficiency
	for _, res := range r.Resolutions() {
		e.Hypotheses++
		e.Attempts += res.Attempts
		switch res.Outcome {
		case ResolvedConfirmed:
			e.Confirmed++
			e.Resolved++
		case ResolvedRefuted:
			e.Refuted++
			e.Resolved++
		case ResolvedInconclusive:
			e.Inconclusive++
		case ResolvedNotRun:
			e.NotRun++
		}
	}
	return e
}
