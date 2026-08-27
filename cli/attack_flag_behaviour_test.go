package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

// Behavioural flag guards for `nox attack`. TestAttackFlagInventoryMatchesTheHelpText
// proves these flags are REGISTERED and DOCUMENTED; nothing there proves any of
// them CHANGES AN OUTCOME. That gap is where a false all-clear lives: a
// --reply-field that never reaches the oracle makes every target look silent, a
// --seed that never reaches the canary makes every replay look prevented, and a
// --route that never reaches the request probes the wrong code and calls it
// clean. Each test below drives the real entry point against a local target and
// reads the artifact the CLI wrote.

// transformCanary returns the reflection-immune transform canary minted from
// seed, plus the lowercase word a payload asks the target to upper-case.
func transformCanary(t *testing.T, seed string) (value, seedWord string) {
	t.Helper()
	cs := attack.MintCanaries(seed)
	for _, c := range cs.Canaries() {
		if c.Kind == attack.CanaryTransform {
			return c.Value, cs.TransformSeed()
		}
	}
	t.Fatalf("seed %q minted no transform canary", seed)
	return "", ""
}

// obedientTarget serves a target that actually performs the attacker-ordered
// transform — it emits the canary only when the request carries the transform
// seed, so the benign control stays clean and a CONFIRMED verdict is honest.
// obeyLimit caps how many times it obeys, which is what makes a flaky target.
func obedientTarget(t *testing.T, seed, route string, obeyLimit int64) (srv *httptest.Server, reset func()) {
	t.Helper()
	canary, seedWord := transformCanary(t, seed)
	var obeyed int64
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if route != "" && r.URL.Path != route {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(strings.ToLower(string(body)), seedWord) &&
			(obeyLimit < 0 || atomic.AddInt64(&obeyed, 1) <= obeyLimit) {
			_, _ = w.Write([]byte(`{"reply":"sure: ` + canary + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"reply":"hello"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() { atomic.StoreInt64(&obeyed, 0) }
}

// attackRun drives the real `nox attack run` and returns the traces it wrote.
func attackRun(t *testing.T, out string, args ...string) *attack.Result {
	t.Helper()
	code, printed := captureCLI(t, func() int { return runAttackRun(args) })
	if code == 2 {
		t.Fatalf("attack run failed (%d): %s", code, printed)
	}
	raw, err := os.ReadFile(out) //nolint:gosec // path built by this test
	if err != nil {
		t.Fatalf("--output %s was not written: %v", out, err)
	}
	res, err := attack.LoadResult(raw)
	if err != nil {
		t.Fatalf("parsing traces: %v", err)
	}
	if len(res.Traces) == 0 {
		t.Fatal("the run produced no traces; every assertion below would be vacuous")
	}
	return res
}

// runArgs assembles the common `attack run` argument list.
func runArgs(planPath, targetURL, out string, extra ...string) []string {
	return append([]string{
		"--plan", planPath, "--target", targetURL, "--profile", "sandbox",
		"--authorize", "--output", out,
	}, extra...)
}

// TestAttackRunReplyFieldDecidesWhatNoxCanSee pins --reply-field to the oracle.
// The refusal oracle reads Observation.Reply and nothing else, so the flag
// decides whether nox can see a defense at all. Both directions are asserted,
// and the safe one matters most: pointed at the wrong key, nox must fall to
// INCONCLUSIVE rather than read its own blindness as prevention.
func TestAttackRunReplyFieldDecidesWhatNoxCanSee(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The refusal lives under "answer", not the default "reply".
		_, _ = w.Write([]byte(`{"answer":"I cannot help with that."}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	plan := attackPlanFile(t, dir)

	blind := attackRun(t, filepath.Join(dir, "blind.json"),
		runArgs(plan, srv.URL, filepath.Join(dir, "blind.json"), "--route", "/chat", "--samples", "1")...)
	seeing := attackRun(t, filepath.Join(dir, "seeing.json"),
		runArgs(plan, srv.URL, filepath.Join(dir, "seeing.json"), "--route", "/chat", "--samples", "1",
			"--reply-field", "answer")...)

	if got := seeing.Traces[0].Exploitability; got != evidence.Prevented {
		t.Errorf("--reply-field answer read %q, want PREVENTED — the flag never reached the reply extraction", got)
	}
	if got := blind.Traces[0].Exploitability; got == evidence.Prevented {
		t.Error("with the default --reply-field the reply was never extracted, yet nox reported PREVENTED — " +
			"it read its own blindness as a defense")
	}
	// And the mechanism, not just the verdict: the extracted reply itself must
	// differ, or the two verdicts diverged for some unrelated reason.
	if replyOf(blind) != "" {
		t.Errorf("default --reply-field extracted %q from a body with no \"reply\" key", replyOf(blind))
	}
	if !strings.Contains(replyOf(seeing), "cannot help") {
		t.Errorf("--reply-field answer extracted %q, want the refusal text", replyOf(seeing))
	}
}

// replyOf returns the first attempt's extracted reply.
func replyOf(res *attack.Result) string {
	for _, tr := range res.Traces {
		if len(tr.Attempts) > 0 {
			return tr.Attempts[0].Reply
		}
	}
	return ""
}

// TestAttackRunSeedDeterminesTheCanary pins --seed to canary minting. The whole
// replay and regression story rests on "the same seed replays identically": if
// the flag never reached MintCanaries, a replay would hunt for a canary the run
// never used and come back clean every time.
func TestAttackRunSeedDeterminesTheCanary(t *testing.T) {
	srv, _ := obedientTarget(t, "seed-a", "/chat", -1)
	dir := t.TempDir()
	plan := attackPlanFile(t, dir)

	payloads := func(name, seed string) []string {
		out := filepath.Join(dir, name+".json")
		res := attackRun(t, out, runArgs(plan, srv.URL, out, "--route", "/chat", "--samples", "1", "--seed", seed)...)
		var ps []string
		for _, tr := range res.Traces {
			for _, a := range tr.Attempts {
				ps = append(ps, a.Payload)
			}
		}
		if len(ps) == 0 {
			t.Fatalf("run %q fired no payloads", name)
		}
		return ps
	}

	a1 := payloads("a1", "seed-a")
	a2 := payloads("a2", "seed-a")
	b := payloads("b", "seed-b")

	if strings.Join(a1, "\n") != strings.Join(a2, "\n") {
		t.Error("the same --seed produced different payloads; a replay cannot reproduce a run whose canaries move")
	}
	if strings.Join(a1, "\n") == strings.Join(b, "\n") {
		t.Error("--seed seed-a and --seed seed-b produced identical payloads — the seed never reached the canary set")
	}
}

// TestAttackRunMinHitsGatesConfirmation pins --min-hits to the determinism gate.
// Against a target that obeys only twice, the default gate (all samples must
// reproduce) must refuse to confirm, and --min-hits 1 must confirm. A --min-hits
// that never reached the gate would make one of those two wrong — and the
// dangerous direction, confirming an exploit that did not reproduce, is exactly
// what this flag controls.
func TestAttackRunMinHitsGatesConfirmation(t *testing.T) {
	srv, reset := obedientTarget(t, "nox", "/chat", 2)
	dir := t.TempDir()
	plan := attackPlanFile(t, dir)

	reset()
	strict := attackRun(t, filepath.Join(dir, "strict.json"),
		runArgs(plan, srv.URL, filepath.Join(dir, "strict.json"), "--route", "/chat", "--seed", "nox", "--samples", "3")...)
	reset()
	loose := attackRun(t, filepath.Join(dir, "loose.json"),
		runArgs(plan, srv.URL, filepath.Join(dir, "loose.json"), "--route", "/chat", "--seed", "nox",
			"--samples", "3", "--min-hits", "1")...)

	st, lt := strict.Traces[0], loose.Traces[0]
	if st.ReproductionSamples != 3 || lt.ReproductionSamples != 3 {
		t.Fatalf("--samples 3 recorded %d/%d samples; the tally does not follow the flag",
			st.ReproductionSamples, lt.ReproductionSamples)
	}
	if st.ReproductionHits == 0 || st.ReproductionHits >= st.ReproductionSamples {
		t.Fatalf("the flaky target reproduced %d/%d times; the guard needs a partial tally to discriminate",
			st.ReproductionHits, st.ReproductionSamples)
	}
	if st.Exploitability == evidence.Confirmed {
		t.Errorf("a %d/%d reproduction was CONFIRMED under the default gate — --min-hits defaults to samples, "+
			"so this must not confirm", st.ReproductionHits, st.ReproductionSamples)
	}
	if lt.Exploitability != evidence.Confirmed {
		t.Errorf("--min-hits 1 with %d/%d reproductions read %q, want CONFIRMED — the flag never reached the gate",
			lt.ReproductionHits, lt.ReproductionSamples, lt.Exploitability)
	}
}

// TestAttackRunRouteDecidesWhatIsProbed pins --route to the request. A route
// that never reached the target probes the wrong path, and a target that was
// never actually reached must never come back as anything but INCONCLUSIVE.
func TestAttackRunRouteDecidesWhatIsProbed(t *testing.T) {
	srv, _ := obedientTarget(t, "nox", "/chat", -1)
	dir := t.TempDir()
	plan := attackPlanFile(t, dir)

	right := attackRun(t, filepath.Join(dir, "right.json"),
		runArgs(plan, srv.URL, filepath.Join(dir, "right.json"), "--route", "/chat", "--seed", "nox", "--samples", "1")...)
	wrong := attackRun(t, filepath.Join(dir, "wrong.json"),
		runArgs(plan, srv.URL, filepath.Join(dir, "wrong.json"), "--route", "/nowhere", "--seed", "nox", "--samples", "1")...)

	if right.Route != "/chat" || wrong.Route != "/nowhere" {
		t.Errorf("the traces recorded routes %q and %q; --route is not being recorded as probed",
			right.Route, wrong.Route)
	}
	if right.Traces[0].Exploitability != evidence.Confirmed {
		t.Errorf("--route /chat reached an obedient target but read %q, want CONFIRMED",
			right.Traces[0].Exploitability)
	}
	switch got := wrong.Traces[0].Exploitability; got {
	case evidence.Confirmed:
		t.Error("--route /nowhere CONFIRMED an exploit against a 404")
	case evidence.Prevented:
		t.Error("--route /nowhere read a 404 as PREVENTED — never reaching the code is not a defense")
	}
}

// TestAttackPlanFindingsAndOutputAreRead pins the three flags of `attack plan`.
// --findings decides what the plan is built from, --output decides where it
// lands, and --json decides the shape of what is printed. A plan silently built
// from the wrong findings file is the quietest failure in the whole command:
// it produces a valid, empty, entirely reassuring plan.
func TestAttackPlanFindingsAndOutputAreRead(t *testing.T) {
	dir := t.TempDir()
	hijackable := writeFindingsFile(t, dir, "hits.json", []findings.Finding{{
		RuleID:      "AGENTFLOW-001",
		Fingerprint: "fp-plan-flag",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceHigh,
		Location:    findings.Location{FilePath: "app/handlers.py", StartLine: 42},
		Message:     "untrusted input reaches an LLM prompt",
		Metadata:    map[string]string{"function": "chat", "route": "/chat"},
	}})
	empty := writeFindingsFile(t, dir, "empty.json", nil)
	// A real (if empty) inventory keeps the "no inventory" warning off stderr,
	// which captureCLI folds into the same stream the --json assertion reads.
	inventory := filepath.Join(dir, "ai.inventory.json")
	if err := os.WriteFile(inventory, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("writing inventory: %v", err)
	}

	planFrom := func(name, findingsPath string, extra ...string) (*attack.Plan, string) {
		t.Helper()
		out := filepath.Join(dir, name+".plan.json")
		args := append([]string{"--findings", findingsPath, "--inventory", inventory,
			"--output", out}, extra...)
		code, printed := captureCLI(t, func() int { return runAttackPlan(append(args, dir)) })
		if code == 2 {
			t.Fatalf("attack plan failed: %s", printed)
		}
		raw, err := os.ReadFile(out) //nolint:gosec // path built by this test
		if err != nil {
			t.Fatalf("--output %s was not written: %v", out, err)
		}
		p, err := attack.LoadPlan(raw)
		if err != nil {
			t.Fatalf("parsing plan: %v", err)
		}
		return p, printed
	}

	full, summary := planFrom("full", hijackable)
	if len(full.Hypotheses) == 0 {
		t.Fatal("--findings with a hijackable finding produced no hypotheses; the flag is not being read")
	}
	blank, _ := planFrom("blank", empty)
	if len(blank.Hypotheses) != 0 {
		t.Errorf("--findings with an empty findings file still produced %d hypotheses — the plan is not built "+
			"from the file the flag names", len(blank.Hypotheses))
	}
	if _, err := os.Stat(defaultPlanPath); err == nil {
		t.Errorf("--output was given, yet a plan was also written to the default %s", defaultPlanPath)
	}

	// --json changes what is printed, not merely whether a flag parses.
	_, asJSON := planFrom("json", hijackable, "--json")
	if json.Valid([]byte(strings.TrimSpace(asJSON))) == json.Valid([]byte(strings.TrimSpace(summary))) {
		t.Errorf("--json and the summary printed the same shape of output; the flag selects nothing\n"+
			"summary: %.80s\njson:    %.80s", summary, asJSON)
	}
	if !json.Valid([]byte(strings.TrimSpace(asJSON))) {
		t.Errorf("--json printed something that is not JSON: %.120s", asJSON)
	}
}

// writeFindingsFile writes a findings.json the CLI's own loader can read.
func writeFindingsFile(t *testing.T, dir, name string, ff []findings.Finding) string {
	t.Helper()
	raw, err := json.Marshal(report.JSONReport{Findings: ff})
	if err != nil {
		t.Fatalf("marshalling findings: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing findings: %v", err)
	}
	return path
}

// TestAttackRegressRecordDerivesASuiteWithoutTouchingTheTarget pins --record.
// It is the flag that separates "write the suite" from "attack the target", so
// if it were ignored, `nox attack regress --record` would send live attack
// traffic at whatever --target happened to be set to.
func TestAttackRegressRecordDerivesASuiteWithoutTouchingTheTarget(t *testing.T) {
	// The run must CONFIRM something, or the derived suite is empty and "--record
	// sent no requests" would hold no matter what --record did.
	canary, seedWord := transformCanary(t, "nox")
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(strings.ToLower(string(body)), seedWord) {
			_, _ = w.Write([]byte(`{"reply":"sure: ` + canary + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"reply":"hello"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	plan := attackPlanFile(t, dir)
	tracePath := filepath.Join(dir, "traces.json")
	res := attackRun(t, tracePath, runArgs(plan, srv.URL, tracePath,
		"--route", "/chat", "--seed", "nox", "--samples", "1")...)
	if res.Traces[0].Exploitability != evidence.Confirmed {
		t.Fatalf("the recorded run read %q, want CONFIRMED — a suite derived from it would be empty "+
			"and the guard below would pass vacuously", res.Traces[0].Exploitability)
	}
	atomic.StoreInt64(&hits, 0)

	suitePath := filepath.Join(dir, "suite.json")
	code, printed := captureCLI(t, func() int {
		return runAttackRegress([]string{"--record", "--trace", tracePath, "--suite", suitePath,
			"--target", srv.URL, "--authorize"})
	})
	if code == 2 {
		t.Fatalf("attack regress --record failed: %s", printed)
	}
	raw, err := os.ReadFile(suitePath) //nolint:gosec // path built by this test
	if err != nil {
		t.Fatalf("--record wrote no suite to --suite %s: %v", suitePath, err)
	}
	suite, err := attack.LoadSuite(raw)
	if err != nil {
		t.Fatalf("--record wrote a suite that does not parse: %v", err)
	}
	if len(suite.Cases) == 0 {
		t.Fatal("--record derived an empty suite from a CONFIRMED trace; the request assertion would be vacuous")
	}
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Errorf("attack regress --record sent %d request(s) to --target; --record must derive the suite and exit", n)
	}
}
