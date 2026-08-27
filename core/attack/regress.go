package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/nox-hq/nox-core/evidence"
)

// suiteSchemaVersion identifies the regression-suite document format.
const suiteSchemaVersion = "attack-suite/1"

// suiteResultSchemaVersion identifies the regression-run document format.
const suiteResultSchemaVersion = "attack-suite-result/1"

// Case is one recorded exploit a regression suite guards. It captures the exact
// winning probe and the signal to look for, so a later run can re-detect it
// deterministically and tell whether a fix held.
type Case struct {
	// ID is a stable identifier (the originating trace ID).
	ID string `json:"id"`
	// HypothesisID and ScenarioID link the case to its origin.
	HypothesisID string `json:"hypothesis_id"`
	ScenarioID   string `json:"scenario_id"`
	// Objective restates the attack goal.
	Objective string `json:"objective"`
	// Route is the endpoint the exploit was recorded against. Without it a
	// regression run cannot re-reach the same code, and every probe 404s.
	Route string `json:"route,omitempty"`
	// Field, PayloadID, and Payload are the winning probe.
	Field     string `json:"field"`
	PayloadID string `json:"payload_id"`
	Payload   string `json:"payload"`
	// ExpectSignal is the signal that constitutes reproduction.
	ExpectSignal string `json:"expect_signal"`
	// MinHits and Samples are the determinism gate for the re-check.
	MinHits int `json:"min_hits"`
	Samples int `json:"samples"`
	// RecordedExploitability is the state at the time the case was recorded.
	RecordedExploitability evidence.Exploitability `json:"recorded_exploitability"`
}

// Suite is a set of regression cases derived from a result.
type Suite struct {
	// SchemaVersion identifies the document format.
	SchemaVersion string `json:"schema_version"`
	// GeneratedAt is the caller-supplied timestamp.
	GeneratedAt string `json:"generated_at"`
	// Cases are the recorded exploits, sorted by ID.
	Cases []Case `json:"cases"`
}

// SuiteFromResult builds a regression suite from the CONFIRMED traces of a
// result. Only confirmed, reproduced exploits become cases: a suite exists to
// prove those exact exploits stay fixed, so anything that was never confirmed has
// nothing to regress against.
func SuiteFromResult(r *Result, now string) *Suite {
	s := &Suite{SchemaVersion: suiteSchemaVersion, GeneratedAt: now}
	if r == nil {
		return s
	}
	for i := range r.Traces {
		tr := r.Traces[i]
		if tr.Evidence == nil || tr.Exploitability != evidence.Confirmed {
			continue
		}
		samples := tr.ReproductionSamples
		if samples < 1 {
			samples = 1
		}
		s.Cases = append(s.Cases, Case{
			ID:                     tr.ID,
			HypothesisID:           tr.HypothesisID,
			ScenarioID:             tr.ScenarioID,
			Objective:              tr.Objective,
			Route:                  r.Route,
			Field:                  tr.Evidence.Field,
			PayloadID:              tr.Evidence.PayloadID,
			Payload:                tr.Evidence.Payload,
			ExpectSignal:           tr.Evidence.Signal,
			MinHits:                1,
			Samples:                samples,
			RecordedExploitability: tr.Exploitability,
		})
	}
	sort.Slice(s.Cases, func(i, j int) bool { return s.Cases[i].ID < s.Cases[j].ID })
	return s
}

// JSON returns the suite as pretty-printed JSON.
func (s *Suite) JSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// LoadSuite parses a suite from JSON.
func LoadSuite(raw []byte) (*Suite, error) {
	var s Suite
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("attack: parsing suite: %w", err)
	}
	return &s, nil
}

// CaseOutcome is the regression-test verdict for one case: did the recorded
// exploit reproduce? It is deliberately separate from Exploitability.
//
// The two answer different questions, and conflating them makes one of them
// wrong. "The recorded payload no longer reproduces" is a perfectly good test
// result to gate CI on; it is NOT a claim that the target is secure. nox
// already draws this line elsewhere: OpenVEX lets you assert `not_affected`
// only with a justification, and falls back to `under_investigation` without
// one. CaseOutcome is the pass/fail; Exploitability is the justified claim.
type CaseOutcome string

// Case outcomes.
const (
	// CaseHeld — the recorded exploit did not reproduce. The regression test
	// passes. This is not a statement about the target's security.
	CaseHeld CaseOutcome = "HELD"
	// CaseRegressed — the recorded exploit reproduced. The fix has regressed.
	CaseRegressed CaseOutcome = "REGRESSED"
	// CaseUnexercised — no probe reached the code under test, so the case
	// demonstrated nothing either way.
	CaseUnexercised CaseOutcome = "UNEXERCISED"
)

// CaseResult is the outcome of re-checking one regression case.
type CaseResult struct {
	// Case is the case that was re-checked.
	Case Case `json:"case"`
	// Outcome is the regression-test verdict: HELD, REGRESSED, or UNEXERCISED.
	// This is what CI gates on.
	Outcome CaseOutcome `json:"outcome"`
	// Exploitability is the evidence claim about the target right now. A case
	// that HELD is PREVENTED only when a defense was actually observed;
	// otherwise it is INCONCLUSIVE, because nothing was demonstrated.
	Exploitability evidence.Exploitability `json:"exploitability"`
	// Hits and Samples are the re-check determinism tally.
	Hits    int `json:"hits"`
	Samples int `json:"samples"`
	// Errors counts probes that never reached the code under test (a transport
	// failure or an HTTP error status). A case whose probes all errored proves
	// nothing, and must never be reported as a fix holding.
	Errors int `json:"errors,omitempty"`
	// Regressed is true if the exploit reproduces again — a fix has regressed.
	Regressed bool `json:"regressed"`
	// Note is a human-readable explanation.
	Note string `json:"note,omitempty"`
}

// SuiteResult is the outcome of running a whole suite.
type SuiteResult struct {
	// SchemaVersion identifies the document format.
	SchemaVersion string `json:"schema_version"`
	// GeneratedAt is the caller-supplied timestamp.
	GeneratedAt string `json:"generated_at"`
	// Results is one entry per case.
	Results []CaseResult `json:"results"`
	// Regressions is the count of cases that reproduced again.
	Regressions int `json:"regressions"`
	// Unexercised counts cases whose every probe failed to reach the target.
	// A suite that is entirely unexercised has proven nothing, and callers must
	// not read its zero regressions as a pass.
	Unexercised int `json:"unexercised,omitempty"`
}

// RunSuite re-checks every case against the current target. A case that
// reproduces its recorded signal is a REGRESSION: the exploit that was supposed
// to be fixed works again. The same safety gates as Run apply.
func RunSuite(ctx context.Context, s *Suite, t Target, cfg RunConfig) (*SuiteResult, error) {
	if s == nil {
		return nil, fmt.Errorf("attack: nil suite")
	}
	if t == nil {
		return nil, fmt.Errorf("attack: nil target")
	}
	cfg = cfg.withDefaults()

	if !cfg.Profile.AllowsNetwork() {
		if !isSimTarget(t) {
			return nil, fmt.Errorf("attack: profile %q forbids network traffic; only SimTarget may be used", cfg.Profile)
		}
	}
	if cfg.Profile.RequiresAuthorization() && !cfg.Authorized {
		return nil, fmt.Errorf("attack: profile %q requires explicit authorization", cfg.Profile)
	}

	cs := MintCanaries(cfg.Seed)
	route := cfg.Route
	fields := sortedCopy(cfg.Fields)
	if len(fields) == 0 {
		fields = sortedCopy(defaultFields)
	}

	out := &SuiteResult{SchemaVersion: suiteResultSchemaVersion, GeneratedAt: cfg.Now}
	for i := range s.Cases {
		c := s.Cases[i]
		out.Results = append(out.Results, runCase(ctx, c, t, cs, route, fields))
	}
	for i := range out.Results {
		if out.Results[i].Regressed {
			out.Regressions++
		}
		if r := out.Results[i]; r.Samples > 0 && r.Errors == r.Samples {
			out.Unexercised++
		}
	}
	return out, nil
}

// runCase re-fires one case's probe and decides whether it regressed.
//
// The verdict goes through evidence.DeriveExploitability like every other
// verdict nox produces. An earlier version decided the state inline and mapped
// "did not reproduce" straight to PREVENTED, which meant a suite pointed at the
// wrong route — every probe answering 404 — printed "fix holds" and exited 0.
// That is the false all-clear this whole package exists to prevent, and it is
// exactly why the state machine is not allowed to be reimplemented locally.
func runCase(ctx context.Context, c Case, t Target, cs *CanarySet, route string, fields []string) CaseResult {
	spec := payloadSpec{id: c.PayloadID, text: c.Payload}
	oracles := []Oracle{CanaryOracle(cs), ToolTraceOracle(scenarioForbiddenTools(c.ScenarioID))}
	refusal := RefusalOracle()
	minHits := c.MinHits
	if minHits <= 0 {
		minHits = 1
	}
	samplesWant := c.Samples
	if samplesWant < 1 {
		samplesWant = 1
	}
	// Precedence: an explicitly supplied route wins, because the operator is
	// telling nox where the code lives now — typically after a fix moved it.
	// The route recorded on the case is the fallback, so a suite replays
	// correctly when no route is given at all.
	if route == "" {
		route = c.Route
	}

	hits, samples, errs, refusals := 0, 0, 0, 0
	for i := 0; i < samplesWant; i++ {
		obs, err := t.Send(ctx, makeProbe(route, fields, c.Field, spec))
		if err != nil && obs.Err == "" {
			obs.Err = err.Error()
		}
		samples++
		// A transport failure and an HTTP error status both mean the recorded
		// probe never reached the code under test. Neither is evidence that a
		// fix holds.
		if obs.Err != "" || (obs.Status != 0 && obs.Status >= 400) {
			errs++
			continue
		}
		if v, hit := firstViolation(oracles, obs); hit && v.Signal == c.ExpectSignal {
			hits++
			continue
		}
		if refusal.Evaluate(obs).Violated {
			refusals++
		}
	}

	res := CaseResult{Case: c, Hits: hits, Samples: samples, Errors: errs}
	reproduced := hits >= minHits

	ledger := &evidence.Ledger{}
	if reproduced {
		ledger.Add(evidence.Claim{
			Kind:      evidence.KindDynamicExploit,
			Statement: fmt.Sprintf("recorded exploit %s reproduced (%d/%d)", c.ID, hits, samples),
			Provenance: evidence.Provenance{
				Source:     "nox-attack",
				SourceID:   "nox-attack",
				Reference:  c.ID,
				ObservedAt: "",
			},
		})
	}

	outcome := evidence.RunOutcome{
		HypothesisConstructed: true,
		Executed:              samples > 0 && !isSimTarget(t),
		Violated:              hits > 0,
		Reproduced:            reproduced,
		DefenseObserved:       refusals > 0,
		ControlSound:          true,
		TargetErrors:          errs,
	}
	res.Exploitability = evidence.DeriveExploitability(outcome, ledger)
	res.Regressed = res.Exploitability == evidence.Confirmed
	switch {
	case res.Regressed:
		res.Outcome = CaseRegressed
	case errs == samples:
		res.Outcome = CaseUnexercised
	default:
		res.Outcome = CaseHeld
	}

	switch {
	case res.Regressed:
		res.Note = fmt.Sprintf("recorded exploit reproduced (%d/%d); regression", hits, samples)
	case errs == samples:
		res.Note = fmt.Sprintf("the target could not be exercised: %d/%d probe(s) failed or returned an error status. "+
			"This proves nothing about the fix — check --route and --target", errs, samples)
	case errs > 0:
		res.Note = fmt.Sprintf("recorded exploit did not reproduce (%d/%d), but %d probe(s) failed to reach the target; "+
			"treat this as inconclusive", hits, samples, errs)
	case refusals > 0:
		res.Note = fmt.Sprintf("recorded exploit did not reproduce (%d/%d); the target refused it", hits, samples)
	default:
		res.Note = fmt.Sprintf("recorded exploit did not reproduce (%d/%d) under the recorded payload; "+
			"this is not proof the target is secure", hits, samples)
	}
	return res
}

// ExitCode gates CI: 1 if any case regressed, 2 if no case could be exercised
// at all, else 0.
//
// The 2 matters. A suite whose every probe failed has zero regressions, and
// returning 0 for it would turn a misconfigured target into a green build —
// the same failure mode as a skipped gate. Nothing proven is an error, not a
// pass.
func (sr *SuiteResult) ExitCode() int {
	if sr.Regressions > 0 {
		return 1
	}
	if len(sr.Results) > 0 && sr.Unexercised == len(sr.Results) {
		return 2
	}
	return 0
}
