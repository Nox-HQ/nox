package attack

import (
	"bytes"
	"context"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
)

const testNow = "2026-08-23T00:00:00Z"

// piPlan returns a plan with the two prompt-injection hypotheses grounded in a
// single injection finding.
func piPlan(t *testing.T) *Plan {
	t.Helper()
	plan, err := BuildPlan(PlanInput{
		Root:     "/repo",
		Findings: []findings.Finding{injectionFinding("fp-pi")},
		Now:      testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// sandboxCfg is the standard authorized sandbox run config.
func sandboxCfg() RunConfig {
	return RunConfig{
		Profile:    ProfileSandbox,
		Authorized: true,
		Seed:       "test-seed",
		Now:        testNow,
		Route:      "/chat",
		Fields:     []string{"message"},
		Samples:    2,
		MinHits:    2,
	}
}

func TestRunRefusesHTTPTargetUnderSafeProfile(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cfg.Profile = ProfileSafe
	cfg.Authorized = false
	ht := NewHTTPTarget("http://localhost:9999", "reply", 0)
	_, err := Run(context.Background(), plan, ht, cfg)
	if err == nil {
		t.Fatal("Run must refuse an HTTPTarget under the safe profile")
	}
}

func TestRunRefusesUnauthorizedAndSendsNothing(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cfg.Authorized = false // network-requiring profile, but no authorization
	rec := &recordingTarget{}
	_, err := Run(context.Background(), plan, rec, cfg)
	if err == nil {
		t.Fatal("Run must refuse a network-requiring profile without authorization")
	}
	if rec.sends != 0 {
		t.Errorf("a refused run must send nothing; got %d sends", rec.sends)
	}
}

func TestRunSafeProfileSimTargetIsPlausible(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cfg.Profile = ProfileSafe
	cfg.Authorized = false
	res, err := Run(context.Background(), plan, NewSimTarget(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range res.Traces {
		if tr.Exploitability != evidence.Plausible {
			t.Errorf("safe-profile sim trace %s = %s, want PLAUSIBLE", tr.ID, tr.Exploitability)
		}
	}
	if res.AnyConfirmed() {
		t.Error("a safe simulation must never confirm")
	}
}

// TestDiscrimination is the single most important test: the SAME corpus must
// CONFIRM against the vulnerable target and NOT confirm against the fixed one.
func TestDiscrimination(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cs := MintCanaries(cfg.Seed)

	vuln := newFakeTarget(modeVulnerable, cs)
	vres, err := Run(context.Background(), plan, vuln, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !vres.AnyConfirmed() {
		t.Fatal("vulnerable target must produce at least one CONFIRMED trace")
	}
	if vres.ExitCode() != 1 {
		t.Errorf("vulnerable ExitCode()=%d want 1", vres.ExitCode())
	}
	// The confirmed trace must carry deterministic evidence.
	var confirmed *Trace
	for i := range vres.Traces {
		if vres.Traces[i].Exploitability == evidence.Confirmed {
			confirmed = &vres.Traces[i]
			break
		}
	}
	if confirmed == nil || confirmed.Evidence == nil {
		t.Fatal("confirmed trace must carry evidence")
	}
	if confirmed.Confidence != evidence.ConfidenceConfirmed {
		t.Errorf("confirmed trace confidence=%s want CONFIRMED", confirmed.Confidence)
	}
	if !confirmed.Ledger.HasDeterministic() {
		t.Error("confirmed trace ledger must have a deterministic claim")
	}

	fixed := newFakeTarget(modeFixed, cs)
	fres, err := Run(context.Background(), plan, fixed, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if fres.AnyConfirmed() {
		t.Fatal("fixed target must NOT confirm — same corpus, safe construction")
	}
	if fres.ExitCode() != 0 {
		t.Errorf("fixed ExitCode()=%d want 0", fres.ExitCode())
	}
}

func TestEchoTargetNeverConfirms(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cs := MintCanaries(cfg.Seed)
	res, err := Run(context.Background(), plan, newFakeTarget(modeEcho, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.AnyConfirmed() {
		t.Error("an echoing target must never be scored a hijack")
	}
}

func TestRefusingTargetIsPrevented(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cs := MintCanaries(cfg.Seed)
	res, err := Run(context.Background(), plan, newFakeTarget(modeRefusing, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.AnyConfirmed() {
		t.Fatal("a refusing target must not confirm")
	}
	for _, tr := range res.Traces {
		if tr.Exploitability != evidence.Prevented {
			t.Errorf("refusing trace %s = %s, want PREVENTED", tr.ID, tr.Exploitability)
		}
	}
}

func TestErroringTargetIsInconclusive(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cs := MintCanaries(cfg.Seed)
	res, err := Run(context.Background(), plan, newFakeTarget(modeErroring, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range res.Traces {
		if tr.Exploitability != evidence.Inconclusive {
			t.Errorf("erroring trace %s = %s, want INCONCLUSIVE", tr.ID, tr.Exploitability)
		}
	}
}

func TestUnsoundControlPreventsConfirmation(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cs := MintCanaries(cfg.Seed)
	res, err := Run(context.Background(), plan, newFakeTarget(modeNoisy, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.ControlSound {
		t.Error("a target that leaks on the benign control must mark the run unsound")
	}
	if res.AnyConfirmed() {
		t.Error("nothing may be confirmed from an unsound environment")
	}
}

// TestBudgetExhaustionIsInconclusive proves a run cut short by a budget derives
// to INCONCLUSIVE, never PREVENTED.
func TestBudgetExhaustionIsInconclusive(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cfg.Budget = Budget{Attempts: 1} // trips after the first probe
	cs := MintCanaries(cfg.Seed)
	res, err := Run(context.Background(), plan, newFakeTarget(modeVulnerable, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.BudgetStop != "attempts" {
		t.Errorf("BudgetStop=%q want %q", res.BudgetStop, "attempts")
	}
	if res.AnyConfirmed() {
		t.Error("a budget-exhausted run must not confirm")
	}
	// The first (cut-short) trace must be INCONCLUSIVE, not PREVENTED.
	first := res.Traces[0]
	if first.Exploitability != evidence.Inconclusive {
		t.Errorf("cut-short trace = %s, want INCONCLUSIVE", first.Exploitability)
	}
	if first.Exploitability == evidence.Prevented {
		t.Error("a cut-short run must never read as PREVENTED")
	}
}

func TestResultRoundTrip(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cs := MintCanaries(cfg.Seed)
	res, err := Run(context.Background(), plan, newFakeTarget(modeVulnerable, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := res.JSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	re, _ := got.JSON()
	if !bytes.Equal(raw, re) {
		t.Error("result did not survive a JSON round-trip byte-identically")
	}
}

func TestRunDeterministic(t *testing.T) {
	plan := piPlan(t)
	cfg := sandboxCfg()
	cs := MintCanaries(cfg.Seed)
	r1, err := Run(context.Background(), plan, newFakeTarget(modeVulnerable, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Run(context.Background(), plan, newFakeTarget(modeVulnerable, cs), cfg)
	if err != nil {
		t.Fatal(err)
	}
	j1, _ := r1.JSON()
	j2, _ := r2.JSON()
	if !bytes.Equal(j1, j2) {
		t.Error("Run is not deterministic: result JSON differs between two runs")
	}
}
