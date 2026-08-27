package attack

import (
	"context"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

func confirmedRun(t *testing.T) (*Result, RunConfig, *CanarySet) {
	t.Helper()
	plan := piPlan(t)
	cfg := sandboxCfg()
	cs := MintCanaries(cfg.Seed)
	res, err := Run(context.Background(), plan, newFakeTarget(modeVulnerable, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnyConfirmed() {
		t.Fatal("setup: expected a confirmed run")
	}
	return res, cfg, cs
}

func firstConfirmedTraceID(r *Result) string {
	for i := range r.Traces {
		if r.Traces[i].Exploitability == evidence.Confirmed {
			return r.Traces[i].ID
		}
	}
	return ""
}

func TestReplayReproducesConfirmed(t *testing.T) {
	res, cfg, cs := confirmedRun(t)
	id := firstConfirmedTraceID(res)
	if id == "" {
		t.Fatal("no confirmed trace")
	}
	tr, err := Replay(context.Background(), res, id, newFakeTarget(modeVulnerable, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Exploitability != evidence.Confirmed {
		t.Errorf("replay against vulnerable = %s, want CONFIRMED", tr.Exploitability)
	}
	if tr.Evidence == nil || !tr.Evidence.Reproduced {
		t.Error("replay must report reproduction with evidence")
	}
}

func TestReplayAgainstFixedDoesNotReproduce(t *testing.T) {
	res, cfg, cs := confirmedRun(t)
	id := firstConfirmedTraceID(res)
	tr, err := Replay(context.Background(), res, id, newFakeTarget(modeFixed, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Exploitability == evidence.Confirmed {
		t.Error("replay against a fixed target must not confirm")
	}
	if tr.Evidence != nil {
		t.Error("a non-reproducing replay must carry no evidence")
	}
}

func TestReplayCommandFormat(t *testing.T) {
	res, _, _ := confirmedRun(t)
	id := firstConfirmedTraceID(res)
	tr, _ := res.TraceByID(id)
	want := "nox attack replay " + id
	if tr.ReplayCommand != want {
		t.Errorf("ReplayCommand=%q want %q", tr.ReplayCommand, want)
	}
}

func TestReplayUnknownTrace(t *testing.T) {
	res, cfg, cs := confirmedRun(t)
	if _, err := Replay(context.Background(), res, "trace-does-not-exist", newFakeTarget(modeVulnerable, cs), cfg); err == nil {
		t.Error("Replay must error on an unknown trace ID")
	}
}
