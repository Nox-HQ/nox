package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nox-hq/nox-core/evidence"
)

// resultSchemaVersion identifies the attack-result document format.
const resultSchemaVersion = "attack-result/1"

// RunConfig controls a run. Seed and Now make the run reproducible; Profile and
// Authorized gate whether it may send traffic at all.
type RunConfig struct {
	// Profile is the safety envelope.
	Profile Profile
	// Authorized is the caller's explicit authorization to send traffic. It is
	// required by every profile except safe.
	Authorized bool
	// Budget caps resource consumption; a zero-value field means unbounded for
	// that dimension. Use DefaultBudget for a sensible default.
	Budget Budget
	// Samples is the total number of times a candidate exploit is fired for the
	// determinism gate (the initial hit plus re-runs). Defaults to 2.
	Samples int
	// MinHits is the minimum number of samples that must reproduce the signal to
	// CONFIRM. Defaults to Samples (require every sample).
	MinHits int
	// Seed deterministically mints the canary set.
	Seed string
	// Now is an RFC3339 timestamp stamped onto the result and evidence.
	Now string
	// Route overrides each hypothesis's entry point when set.
	Route string
	// Fields are the request fields to probe; defaults to ["message"].
	Fields []string
	// Clock, when set, makes Budget.Duration real. The engine is otherwise
	// pure — it reads no clock, so a run is reproducible from its inputs — and
	// a wall-clock budget cannot be enforced without one.
	//
	// It is an injected dependency rather than a call to time.Now for exactly
	// that reason: tests keep a deterministic engine, and the CLI supplies a
	// real clock so --max-duration is not a flag that silently does nothing on
	// an ACTIVE capability.
	Clock func() time.Time
}

// withDefaults returns cfg with defaults applied.
func (c RunConfig) withDefaults() RunConfig {
	if c.Samples <= 0 {
		c.Samples = 2
	}
	if c.MinHits <= 0 || c.MinHits > c.Samples {
		c.MinHits = c.Samples
	}
	if c.Budget == (Budget{}) {
		c.Budget = DefaultBudget()
	}
	return c
}

// Attempt records one probe and what the target returned for it.
type Attempt struct {
	// HypothesisID is the hypothesis this attempt belongs to.
	HypothesisID string `json:"hypothesis_id"`
	// Field is the request field the payload entered through.
	Field string `json:"field"`
	// Category is the payload category.
	Category string `json:"category"`
	// PayloadID identifies the payload.
	PayloadID string `json:"payload_id"`
	// Payload is the exact text sent.
	Payload string `json:"payload"`
	// Status is the target's status code.
	Status int `json:"status"`
	// Reply is the extracted reply.
	Reply string `json:"reply"`
	// Signal is the reflection-immune signal detected, or "" if none.
	Signal string `json:"signal,omitempty"`
	// Err is a transport-level error, or "".
	Err string `json:"err,omitempty"`
}

// ExploitEvidence is the concrete proof behind a CONFIRMED trace: the exact
// winning probe, the oracle that scored it, and the determinism outcome.
type ExploitEvidence struct {
	// OracleKind classifies the winning oracle.
	OracleKind OracleKind `json:"oracle_kind"`
	// OracleName identifies the winning oracle.
	OracleName string `json:"oracle_name"`
	// Signal is the signal that tripped.
	Signal string `json:"signal"`
	// Field is the field the payload entered through.
	Field string `json:"field"`
	// PayloadID identifies the winning payload.
	PayloadID string `json:"payload_id"`
	// Payload is the exact winning text.
	Payload string `json:"payload"`
	// Response is the reply that carried the signal.
	Response string `json:"response"`
	// Reproduced reports whether the determinism gate passed.
	Reproduced bool `json:"reproduced"`
	// Hits and Samples are the determinism-gate tally.
	Hits    int `json:"hits"`
	Samples int `json:"samples"`
}

// Trace is the full record of attacking one hypothesis: the attempts, the derived
// verdict and its evidence ledger, the reproduction tally, and the command to
// replay it. Exploitability and Confidence are always produced by the evidence
// package, never by this package inventing a state.
type Trace struct {
	// ID is a stable, deterministic identifier.
	ID string `json:"id"`
	// HypothesisID links to the plan hypothesis.
	HypothesisID string `json:"hypothesis_id"`
	// ScenarioID links to the scenario.
	ScenarioID string `json:"scenario_id"`
	// Objective restates the attack goal.
	Objective string `json:"objective"`
	// Path is the attack path.
	Path []PathStep `json:"path"`
	// Attempts are every probe fired for this hypothesis.
	Attempts []Attempt `json:"attempts"`
	// Outcome is the raw run outcome fed to the evidence derivation.
	Outcome evidence.RunOutcome `json:"outcome"`
	// Exploitability is the derived lifecycle state.
	Exploitability evidence.Exploitability `json:"exploitability"`
	// Confidence is the derived aggregate confidence.
	Confidence evidence.Confidence `json:"confidence"`
	// Classification maps this trace to security standards and scores it by what
	// was actually demonstrated, not by what the rule asserts.
	Classification Classification `json:"classification"`
	// Ledger is the evidence backing the verdict.
	Ledger evidence.Ledger `json:"ledger"`
	// Evidence is the concrete proof, present only for a reproduced violation.
	Evidence *ExploitEvidence `json:"evidence,omitempty"`
	// ReproductionHits and ReproductionSamples are the determinism-gate tally.
	ReproductionHits    int `json:"reproduction_hits"`
	ReproductionSamples int `json:"reproduction_samples"`
	// Note is a human-readable explanation of the outcome.
	Note string `json:"note,omitempty"`
	// ReplayCommand is the literal command to re-run this trace against a
	// target, and it is EMPTY when there is nothing to re-run.
	//
	// It used to be set on every trace, including hypotheses that never
	// executed — so an artifact advertised a reproduction it could not perform,
	// and attack.Replay answered "carries no reproducible evidence". That is
	// nox claiming execution reproducibility it does not have, which is the one
	// thing this artifact must not do.
	//
	// Note what KIND of reproducibility this is. Re-running against a target is
	// best-effort: nox does not control the target's state, so a replay that
	// fails may mean the bug was fixed, the data changed, or the service moved.
	// That is a different guarantee from `nox replay`, which re-derives verdicts
	// from a stored ledger and is deterministic. Two commands named replay,
	// answering different questions — see ReplayNote.
	ReplayCommand string `json:"replay_command,omitempty"`
	// ReplayNote says why this trace cannot be re-run, when it cannot.
	ReplayNote string `json:"replay_note,omitempty"`
	// FindingFingerprints links the trace back to the static findings its
	// hypothesis was grounded in. This is an additive field beyond the original
	// contract; it lets Correlate merge static and dynamic claims without needing
	// the plan. It is omitted from JSON when empty.
	FindingFingerprints []string `json:"finding_fingerprints,omitempty"`
}

// Result is the top-level attack-result document.
type Result struct {
	// SchemaVersion identifies the document format.
	SchemaVersion string `json:"schema_version"`
	// GeneratedAt is the caller-supplied timestamp.
	GeneratedAt string `json:"generated_at"`
	// Target identifies what was attacked.
	Target string `json:"target"`
	// Profile is the safety profile used.
	Profile string `json:"profile"`
	// PlanRoot is the workspace root of the plan.
	PlanRoot string `json:"plan_root"`
	// Route and Fields record the entry point that was probed, so a replay or a
	// regression suite can re-reach the same code rather than guessing.
	Route  string   `json:"route,omitempty"`
	Fields []string `json:"fields,omitempty"`
	// Traces is one trace per hypothesis.
	Traces []Trace `json:"traces"`
	// Spend is the resources consumed.
	Spend Spend `json:"spend"`
	// BudgetStop names the budget limit that stopped the run, or "".
	BudgetStop string `json:"budget_stop,omitempty"`
	// ControlSound is false if any benign control tripped a signal, meaning
	// nothing may be confirmed from this run.
	ControlSound bool `json:"control_sound"`
}

// runner holds the mutable state of one run: the spend tally and the budget stop.
type runner struct {
	ctx        context.Context
	t          Target
	cs         *CanarySet
	cfg        RunConfig
	simulated  bool
	spend      Spend
	budget     Budget
	budgetStop string
	stopped    bool
	// startedAt is the zero Time unless cfg.Clock was supplied.
	startedAt time.Time
}

// elapsed returns the wall-clock time consumed so far, or zero when no clock
// was injected (the pure engine).
func (r *runner) elapsed() time.Duration {
	if r.cfg.Clock == nil {
		return 0
	}
	return r.cfg.Clock().Sub(r.startedAt)
}

// fire sends one probe, first checking the budget. It returns ok=false and marks
// the run stopped if the budget is exhausted, so a caller can break out. A
// simulated target consumes an attempt but no network/model budget, since it
// sends nothing.
func (r *runner) fire(p Probe) (Observation, bool) {
	if r.stopped {
		return Observation{}, false
	}
	// Refresh elapsed before the check so a long-running target trips the
	// wall-clock budget rather than sailing past it.
	r.spend.Elapsed = r.elapsed()
	if exhausted, which := r.budget.Exhausted(r.spend); exhausted {
		r.stopped = true
		r.budgetStop = which
		return Observation{}, false
	}
	r.spend.Attempts++
	if !r.simulated {
		r.spend.NetworkRequests++
		r.spend.ModelCalls++
	}
	obs, err := r.t.Send(r.ctx, p)
	if err != nil && obs.Err == "" {
		obs.Err = err.Error()
	}
	r.spend.ToolInvocations += len(obs.ToolCalls)
	r.spend.Elapsed = r.elapsed()
	return obs, true
}

// Run executes the plan against the target under cfg. It enforces the safety
// gates structurally before any traffic, asserts reflection immunity over the
// whole corpus, then attacks each hypothesis and derives a verdict via the
// evidence package. It never confirms from an unsound control or an
// unreproducible violation.
func Run(ctx context.Context, p *Plan, t Target, cfg RunConfig) (*Result, error) {
	if p == nil {
		return nil, fmt.Errorf("attack: nil plan")
	}
	if t == nil {
		return nil, fmt.Errorf("attack: nil target")
	}
	cfg = cfg.withDefaults()

	// SAFETY GATES — structural, before any byte leaves the process.
	if !cfg.Profile.AllowsNetwork() {
		if !isSimTarget(t) {
			return nil, fmt.Errorf("attack: profile %q forbids network traffic; only SimTarget may be used", cfg.Profile)
		}
	}
	if cfg.Profile.RequiresAuthorization() && !cfg.Authorized {
		return nil, fmt.Errorf("attack: profile %q requires explicit authorization", cfg.Profile)
	}

	cs := MintCanaries(cfg.Seed)
	// Fail closed if any payload could be mistaken for a signal.
	if err := cs.AssertReflectionImmune(PayloadCorpus(cs)); err != nil {
		return nil, fmt.Errorf("attack: refusing to run: %w", err)
	}

	r := &runner{
		ctx:       ctx,
		t:         t,
		cs:        cs,
		cfg:       cfg,
		simulated: isSimTarget(t),
		budget:    cfg.Budget,
	}
	if cfg.Clock != nil {
		r.startedAt = cfg.Clock()
	}
	res := &Result{
		SchemaVersion: resultSchemaVersion,
		GeneratedAt:   cfg.Now,
		Target:        t.Name(),
		Profile:       string(cfg.Profile),
		PlanRoot:      p.Root,
		Route:         cfg.Route,
		Fields:        sortedCopy(cfg.Fields),
		ControlSound:  true,
	}

	for i := range p.Hypotheses {
		h := p.Hypotheses[i]
		var trace Trace
		if r.stopped {
			trace = notRunTrace(h, cfg, "budget exhausted before this hypothesis")
		} else {
			trace = r.attackHypothesis(h)
		}
		if !trace.Outcome.ControlSound {
			res.ControlSound = false
		}
		res.Traces = append(res.Traces, trace)
	}
	res.Spend = r.spend
	res.BudgetStop = r.budgetStop
	return res, nil
}

// notRunTrace builds a trace for a hypothesis that never executed.
func notRunTrace(h Hypothesis, cfg RunConfig, note string) Trace {
	outcome := evidence.RunOutcome{HypothesisConstructed: true, ControlSound: true, BudgetExhausted: true}
	ledger := groundingLedger(h, cfg.Now)
	return classified(Trace{
		ID:                  "trace-" + h.ID,
		HypothesisID:        h.ID,
		ScenarioID:          h.ScenarioID,
		Objective:           h.Objective,
		Path:                h.Path,
		Outcome:             outcome,
		Exploitability:      evidence.DeriveExploitability(outcome, ledger),
		Confidence:          ledger.Confidence(),
		Ledger:              *ledger,
		ReproductionSamples: cfg.Samples,
		Note:                note,
		ReplayNote:          "nothing ran, so there is nothing to re-run",
		FindingFingerprints: h.FindingFingerprints,
	})
}

// InvariantSubject is the proposition an attack run can establish: that this
// hypothesis's security invariant was violated.
//
// It is invariant_violation rather than exploit on purpose. A run that saw a
// guardrail bypassed has established that the guardrail was bypassed; what an
// attacker could then do is a later proposition needing its own evidence, and
// promoting across that gap is how a scanner reports an RCE it never saw.
func InvariantSubject(h Hypothesis) evidence.Subject {
	return evidence.Subject{Kind: evidence.SubjectInvariantViolation, ID: h.ID}
}

// groundingLedger returns a ledger seeded with the hypothesis's grounding as a
// heuristic claim. It is deliberately NON-deterministic in the evidence sense,
// so it can never on its own carry a trace to CONFIRMED — only a reproduced
// deterministic oracle can add that.
func groundingLedger(h Hypothesis, now string) *evidence.Ledger {
	l := &evidence.Ledger{}
	// What the SCAN established, carried on the hypothesis rather than
	// rediscovered. Milestone D: the scan produces the hypothesis, the attack
	// fills in the observation, and a run that rebuilt a one-claim ledger from
	// the rationale was discarding the better record it had been handed.
	//
	// Claims arrive with their own subjects — a candidate, a flow — and keep
	// them. They are evidence about those propositions and not about this
	// hypothesis's invariant, so re-attributing them would be exactly the
	// promotion the reproduction hierarchy exists to prevent.
	for _, c := range h.Evidence.Claims {
		l.Add(c)
	}
	l.Add(evidence.Claim{
		Kind:      evidence.KindHeuristic,
		Subject:   InvariantSubject(h),
		Statement: h.Rationale,
		Provenance: evidence.Provenance{
			Source:     "nox-attack",
			ObservedAt: now,
			Reference:  "trace-" + h.ID,
		},
	})
	return l
}

// attackHypothesis runs the full attack loop for one hypothesis and derives its
// verdict.
func (r *runner) attackHypothesis(h Hypothesis) Trace {
	scen, _ := ScenarioByID(h.ScenarioID)
	trace := Trace{
		ID:                  "trace-" + h.ID,
		HypothesisID:        h.ID,
		ScenarioID:          h.ScenarioID,
		Objective:           h.Objective,
		Path:                h.Path,
		ReproductionSamples: r.cfg.Samples,
		FindingFingerprints: h.FindingFingerprints,
	}
	outcome := evidence.RunOutcome{HypothesisConstructed: true, ControlSound: true}

	// Profile gate: a scenario below the run's profile is not executed.
	if profileRank(r.cfg.Profile) < profileRank(scen.MinProfile) {
		trace.Note = fmt.Sprintf("profile %q is below scenario minimum %q; not executed", r.cfg.Profile, scen.MinProfile)
		ledger := groundingLedger(h, r.cfg.Now)
		trace.Outcome = outcome
		trace.Ledger = *ledger
		trace.Exploitability = evidence.DeriveExploitability(outcome, ledger)
		trace.Confidence = ledger.Confidence()
		return classified(trace)
	}

	// A simulated target sends nothing, so the run is never "executed".
	outcome.Executed = !r.simulated

	route := r.cfg.Route
	if route == "" {
		route = h.EntryPoint
	}
	fields := sortedCopy(r.cfg.Fields)
	if len(fields) == 0 {
		fields = sortedCopy(defaultFields)
	}

	specs := scenarioPayloads(h.ScenarioID, r.cs)
	violationOracles := []Oracle{CanaryOracle(r.cs), ToolTraceOracle(scenarioForbiddenTools(h.ScenarioID))}
	defenseOracle := RefusalOracle()

	// Benign controls first: any signal here means the environment is unsound.
	controlSound := true
	for si := range specs {
		if !specs[si].control {
			continue
		}
		for _, f := range fields {
			obs, ok := r.fire(makeProbe(route, fields, f, specs[si]))
			if !ok {
				outcome.BudgetExhausted = true
				return r.finalize(trace, outcome, h, nil, OracleVerdict{}, controlSound)
			}
			att := makeAttempt(h.ID, f, specs[si], obs)
			if v, hit := firstViolation(violationOracles, obs); hit {
				att.Signal = v.Signal
				controlSound = false
			}
			trace.Attempts = append(trace.Attempts, att)
		}
	}
	outcome.ControlSound = controlSound

	// Attacks: find the first winning attempt in deterministic order.
	var winner *Attempt
	var winnerSpec payloadSpec
	var winnerVerdict OracleVerdict
	var winnerObs Observation
	targetErrors := 0
	defenseSeen := false

attackLoop:
	for _, f := range fields {
		for si := range specs {
			if specs[si].control {
				continue
			}
			obs, ok := r.fire(makeProbe(route, fields, f, specs[si]))
			if !ok {
				outcome.BudgetExhausted = true
				break attackLoop
			}
			att := makeAttempt(h.ID, f, specs[si], obs)
			if obs.Err != "" {
				targetErrors++
			}
			if v, hit := firstViolation(violationOracles, obs); hit {
				att.Signal = v.Signal
				if winner == nil {
					a := att
					winner = &a
					winnerSpec = specs[si]
					winnerVerdict = v
					winnerObs = obs
				}
			} else if defenseOracle.Evaluate(obs).Violated {
				defenseSeen = true
			}
			trace.Attempts = append(trace.Attempts, att)
		}
	}
	outcome.TargetErrors = targetErrors
	outcome.DefenseObserved = defenseSeen

	// Determinism gate: a violation only counts if it reproduces, and only in a
	// sound environment.
	switch {
	case winner != nil && controlSound:
		outcome.Violated = true
		hits, samples := r.determinism(route, fields, *winner, winnerSpec, winnerVerdict.Signal, violationOracles)
		trace.ReproductionHits = hits
		trace.ReproductionSamples = samples
		outcome.Reproduced = hits >= r.cfg.MinHits
		if outcome.Reproduced {
			trace.Evidence = &ExploitEvidence{
				OracleKind: winnerVerdict.Kind,
				OracleName: winnerVerdict.OracleName,
				Signal:     winnerVerdict.Signal,
				Field:      winner.Field,
				PayloadID:  winner.PayloadID,
				Payload:    winner.Payload,
				Response:   winnerObs.Reply,
				Reproduced: true,
				Hits:       hits,
				Samples:    samples,
			}
		} else {
			trace.Note = fmt.Sprintf("winning payload did not reproduce (%d/%d < %d); refusing to confirm", hits, samples, r.cfg.MinHits)
		}
	case winner != nil && !controlSound:
		trace.Note = "benign control tripped a signal; environment unsound, refusing to confirm"
	case !controlSound:
		trace.Note = "benign control tripped a signal; environment unsound"
	}

	return r.finalize(trace, outcome, h, winner, winnerVerdict, controlSound)
}

// finalize builds the evidence ledger, derives the verdict, and returns the
// completed trace. The dynamic-exploit claim is added ONLY for a reproduced
// violation observed by a machine-checkable oracle in a sound environment — this
// is the single gate that lets a trace reach CONFIRMED, and it is enforced here
// rather than trusted to the caller.
//
// Every claim is attributed to a SUBJECT, and the subject says which
// proposition the evidence is about. Until Milestone G this file set none, so
// every claim shared the zero subject and landed in one bag where the cheapest
// deterministic claim satisfied the precondition for the most expensive.
// Reproducing an invariant violation is not reproducing an exploit, and the
// subject is what keeps those apart — the kernel aggregates per subject, so the
// distinction is only real if somebody makes it here.
func (r *runner) finalize(trace Trace, outcome evidence.RunOutcome, h Hypothesis, winner *Attempt, verdict OracleVerdict, controlSound bool) Trace {
	ledger := groundingLedger(h, r.cfg.Now)
	// What a reproduced oracle hit actually establishes: the security invariant
	// this scenario names was violated, and it recurred. That is
	// invariant_violation on the reproduction hierarchy. It is deliberately NOT
	// filed against the exploit — nothing here demonstrated an end-to-end
	// exploit, and an oracle that saw a control bypassed has not thereby shown
	// what an attacker could do with it.
	violated := InvariantSubject(h)
	if outcome.Violated && outcome.Reproduced && controlSound && winner != nil {
		ledger.Add(evidence.Claim{
			Kind:      oracleEvidenceKind(verdict.Kind),
			Subject:   violated,
			Statement: fmt.Sprintf("a %s oracle observed the invariant violated and it reproduced (%d/%d)", verdict.Kind, trace.ReproductionHits, trace.ReproductionSamples),
			Provenance: evidence.Provenance{
				Source:     "nox-attack",
				SourceID:   "nox-attack",
				ObservedAt: r.cfg.Now,
				Reference:  trace.ID,
			},
			Attributes: map[string]string{"oracle": verdict.OracleName, "signal": verdict.Signal},
		})
	}
	// Advertise a re-run only where there is something to re-run. Replay
	// reconstructs the winning probe from trace.Evidence, so a trace without it
	// cannot be replayed and must not say it can.
	if trace.Evidence != nil {
		trace.ReplayCommand = "nox attack replay " + trace.ID
	} else {
		trace.ReplayNote = "no reproduced violation was recorded, so there is no " +
			"winning probe to re-run; `nox replay` still re-derives this verdict " +
			"from its evidence"
	}
	trace.Outcome = outcome
	trace.Ledger = *ledger
	trace.Exploitability = evidence.DeriveExploitabilityAbout(outcome, ledger, violated)
	trace.Confidence = ledger.Confidence()
	return classified(trace)
}

// determinism re-fires the winning probe until Samples total samples are taken,
// counting how many reproduce the same signal. The first hit counts as sample 1.
func (r *runner) determinism(route string, fields []string, winner Attempt, spec payloadSpec, signal string, oracles []Oracle) (hits, samples int) {
	hits, samples = 1, 1
	for i := 1; i < r.cfg.Samples; i++ {
		obs, ok := r.fire(makeProbe(route, fields, winner.Field, spec))
		if !ok {
			break
		}
		samples++
		if v, hit := firstViolation(oracles, obs); hit && v.Signal == signal {
			hits++
		}
	}
	return hits, samples
}

// oracleEvidenceKind maps an oracle kind to an evidence kind. Deterministic,
// trace, and state oracles are machine-checkable and map to a dynamic-exploit
// claim; a semantic oracle maps to a semantic claim, which can never on its own
// confirm.
func oracleEvidenceKind(k OracleKind) evidence.Kind {
	if k == OracleSemantic {
		return evidence.KindSemantic
	}
	return evidence.KindDynamicExploit
}

// makeAttempt builds an Attempt from a probe spec and its observation.
func makeAttempt(hypothesisID, field string, spec payloadSpec, obs Observation) Attempt {
	return Attempt{
		HypothesisID: hypothesisID,
		Field:        field,
		Category:     spec.category,
		PayloadID:    spec.id,
		Payload:      spec.text,
		Status:       obs.Status,
		Reply:        obs.Reply,
		Err:          obs.Err,
	}
}

// AnyConfirmed reports whether at least one trace reached CONFIRMED.
func (r *Result) AnyConfirmed() bool {
	for i := range r.Traces {
		if r.Traces[i].Exploitability == evidence.Confirmed {
			return true
		}
	}
	return false
}

// ExitCode returns 1 if any trace is CONFIRMED, else 0, for CI gating.
func (r *Result) ExitCode() int {
	if r.AnyConfirmed() {
		return 1
	}
	return 0
}

// JSON returns the result as pretty-printed JSON.
func (r *Result) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// LoadResult parses a result from JSON.
func LoadResult(raw []byte) (*Result, error) {
	var res Result
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("attack: parsing result: %w", err)
	}
	return &res, nil
}

// TraceByID returns the trace with the given ID, or false if none matches.
func (r *Result) TraceByID(id string) (*Trace, bool) {
	for i := range r.Traces {
		if r.Traces[i].ID == id {
			return &r.Traces[i], true
		}
	}
	return nil, false
}
