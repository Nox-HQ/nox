package attack

import (
	"context"
	"fmt"

	"github.com/nox-hq/nox-core/evidence"
)

// Replay reconstructs the exact winning probe from a persisted trace and re-runs
// it against a target, reporting whether the exploit reproduces. It is how a
// CONFIRMED verdict is independently checked and how a remediation is verified:
// replaying a fixed target does NOT reproduce, and the returned trace derives to
// something below CONFIRMED. The same safety gates as Run apply.
func Replay(ctx context.Context, r *Result, traceID string, t Target, cfg RunConfig) (*Trace, error) {
	if r == nil {
		return nil, fmt.Errorf("attack: nil result")
	}
	if t == nil {
		return nil, fmt.Errorf("attack: nil target")
	}
	orig, ok := r.TraceByID(traceID)
	if !ok {
		return nil, fmt.Errorf("attack: no trace %q in result", traceID)
	}
	if orig.Evidence == nil {
		return nil, fmt.Errorf("attack: trace %q carries no reproducible evidence", traceID)
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

	spec := payloadSpec{
		category: categoryForPayload(orig),
		id:       orig.Evidence.PayloadID,
		text:     orig.Evidence.Payload,
	}
	oracles := []Oracle{CanaryOracle(cs), ToolTraceOracle(scenarioForbiddenTools(orig.ScenarioID))}

	// Re-fire the winning probe Samples times, requiring the SAME signal.
	hits, samples := 0, 0
	var lastReply string
	for i := 0; i < cfg.Samples; i++ {
		obs, err := t.Send(ctx, makeProbe(route, fields, orig.Evidence.Field, spec))
		if err != nil && obs.Err == "" {
			obs.Err = err.Error()
		}
		samples++
		lastReply = obs.Reply
		if v, hit := firstViolation(oracles, obs); hit && v.Signal == orig.Evidence.Signal {
			hits++
		}
	}

	reproduced := hits >= cfg.MinHits
	outcome := orig.Outcome
	outcome.Executed = !isSimTarget(t)
	outcome.Violated = hits > 0
	outcome.Reproduced = reproduced

	newTrace := *orig
	newTrace.ReproductionHits = hits
	newTrace.ReproductionSamples = samples
	newTrace.Outcome = outcome

	ledger := &evidence.Ledger{}
	ledger.Add(evidence.Claim{
		Kind:      evidence.KindHeuristic,
		Statement: "replay of " + orig.ID,
		Provenance: evidence.Provenance{
			Source:     "nox-attack",
			ObservedAt: cfg.Now,
			Reference:  orig.ID,
		},
	})
	if reproduced && outcome.Violated && outcome.ControlSound {
		ledger.Add(evidence.Claim{
			Kind:      oracleEvidenceKind(orig.Evidence.OracleKind),
			Statement: fmt.Sprintf("replay reproduced the exploit (%d/%d)", hits, samples),
			Provenance: evidence.Provenance{
				Source:     "nox-attack",
				SourceID:   "nox-attack",
				ObservedAt: cfg.Now,
				Reference:  orig.ID,
			},
		})
	}
	newTrace.Ledger = *ledger
	newTrace.Exploitability = evidence.DeriveExploitability(outcome, ledger)
	newTrace.Confidence = ledger.Confidence()

	if reproduced {
		ev := *orig.Evidence
		ev.Reproduced = true
		ev.Hits = hits
		ev.Samples = samples
		ev.Response = lastReply
		newTrace.Evidence = &ev
		newTrace.Note = fmt.Sprintf("replay reproduced the exploit (%d/%d)", hits, samples)
	} else {
		newTrace.Evidence = nil
		newTrace.Note = fmt.Sprintf("replay did not reproduce (%d/%d < %d)", hits, samples, cfg.MinHits)
	}
	return &newTrace, nil
}

// categoryForPayload recovers the payload category for a replayed trace from its
// scenario's corpus, so the reconstructed probe carries the same category label.
func categoryForPayload(tr *Trace) string {
	for i := range tr.Attempts {
		if tr.Evidence != nil && tr.Attempts[i].PayloadID == tr.Evidence.PayloadID {
			return tr.Attempts[i].Category
		}
	}
	return ""
}
