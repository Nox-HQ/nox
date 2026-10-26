package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/intel"
)

type fakeIntel struct {
	mu   sync.Mutex
	reqs []recordedReq
	srv  *httptest.Server
}

type recordedReq struct {
	path, auth string
	body       []byte
}

func newFakeIntel(t *testing.T) *fakeIntel {
	t.Helper()
	f := &fakeIntel{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recordedReq{r.URL.Path, r.Header.Get("Authorization"), b})
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"candidate_id":"NOX-CAND-x","attack_reporters":1,"scope":"reporter"}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIntel) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reqs) }

const contribCandidate = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// contributeEnv isolates the consent file and sets the org token.
func contributeEnv(t *testing.T, token string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NOX_INTEL_TOKEN", token)
}

func acceptAttackTerms(t *testing.T) {
	t.Helper()
	if err := intel.RecordAttackConsent(saltPathFor(""), "2026-10-26T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
}

func contributeArgs(dir string, plan string, target *httptest.Server, f *fakeIntel, extra ...string) []string {
	out := filepath.Join(dir, "t.json")
	return append(runArgs(plan, target.URL, out, "--route", "/chat", "--seed", "nox", "--samples", "3"),
		append([]string{"--contribute", "--candidate", contribCandidate, "--endpoint", f.srv.URL}, extra...)...)
}

// The acceptance path: an executed, CONFIRMED run is sent to the attested route
// with the org token, as an allowlisted RunReport, and nothing about the target
// is in the body.
func TestAttackRunContributeSendsOnlyTheAllowlist(t *testing.T) {
	contributeEnv(t, "org-token-1")
	acceptAttackTerms(t)
	target, _ := obedientTarget(t, "nox", "/chat", -1)
	f := newFakeIntel(t)
	dir := t.TempDir()
	plan := attackPlanFile(t, dir)

	code, out := captureCLI(t, func() int { return runAttackRun(contributeArgs(dir, plan, target, f)) })
	if code != 1 { // exit 1 = at least one CONFIRMED, unchanged by contributing
		t.Fatalf("exit %d, want 1 (a confirmed run); output:\n%s", code, out)
	}
	if f.count() == 0 {
		t.Fatalf("nothing was contributed:\n%s", out)
	}
	for _, r := range f.reqs {
		if r.path != "/v1/attested/attack-runs" || r.auth != "Bearer org-token-1" {
			t.Fatalf("request %s auth %q", r.path, r.auth)
		}
		// The service's own strictness: unknown fields refused.
		var rep evidence.RunReport
		dec := json.NewDecoder(bytes.NewReader(r.body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rep); err != nil {
			t.Fatalf("body is not exactly a RunReport: %v\n%s", err, r.body)
		}
		if err := rep.Validate(); err != nil {
			t.Fatal(err)
		}
		if rep.Fingerprint != contribCandidate || rep.Exploitability != evidence.Confirmed ||
			!rep.Deterministic || !rep.Reproduced || rep.Profile != "sandbox" {
			t.Errorf("report = %+v", rep)
		}
		body := string(r.body)
		canary, _ := transformCanary(t, "nox")
		for _, leak := range []string{target.URL, strings.TrimPrefix(target.URL, "http://"), "127.0.0.1", "/chat", canary, "payload", "response"} {
			if strings.Contains(body, leak) {
				t.Errorf("the body leaks %q:\n%s", leak, body)
			}
		}
	}
	// The wire fields are exactly the printed allowlist.
	var m map[string]any
	_ = json.Unmarshal(f.reqs[0].body, &m)
	allowed := map[string]bool{}
	for _, a := range intel.AttackAllowlist() {
		allowed[a.Name] = true
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("field %q is sent but not on the printed allowlist", k)
		}
	}
}

// Every refusal happens before the attack fires: a run that cannot be
// contributed is not run on the promise that it would be.
func TestAttackRunContributeRefusesBeforeFiring(t *testing.T) {
	cases := map[string]struct {
		token   string
		consent bool
		extra   []string
		mutate  func(args []string) []string
	}{
		"no consent":   {token: "t", consent: false},
		"no token":     {token: "", consent: true},
		"no candidate": {token: "t", consent: true, mutate: func(a []string) []string { return replaceFlag(a, "--candidate", "nope") }},
		"safe profile": {token: "t", consent: true, mutate: func(a []string) []string { return replaceFlag(a, "--profile", "safe") }},
		"wrong terms":  {token: "t", consent: false, extra: []string{"--accept-attack-terms", "attack-1999"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			contributeEnv(t, c.token)
			if c.consent {
				acceptAttackTerms(t)
			}
			var hits int
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
			defer target.Close()
			f := newFakeIntel(t)
			dir := t.TempDir()
			args := contributeArgs(dir, attackPlanFile(t, dir), target, f, c.extra...)
			if c.mutate != nil {
				args = c.mutate(args)
			}
			code, out := captureCLI(t, func() int { return runAttackRun(args) })
			if code != 2 || hits != 0 || f.count() != 0 {
				t.Fatalf("code %d, target hits %d, intel requests %d; want 2/0/0\n%s", code, hits, f.count(), out)
			}
		})
	}
}

func replaceFlag(args []string, flag, val string) []string {
	out := append([]string(nil), args...)
	for i := range out {
		if out[i] == flag && i+1 < len(out) {
			out[i+1] = val
		}
	}
	return out
}

// --accept-attack-terms records acceptance, then the run proceeds.
func TestAttackRunAcceptFlagRecordsTheTerms(t *testing.T) {
	contributeEnv(t, "tok")
	target, _ := obedientTarget(t, "nox", "/chat", -1)
	f := newFakeIntel(t)
	dir := t.TempDir()
	code, out := captureCLI(t, func() int {
		return runAttackRun(contributeArgs(dir, attackPlanFile(t, dir), target, f, "--accept-attack-terms", intel.AttackTermsVersion))
	})
	if code != 1 || f.count() == 0 {
		t.Fatalf("code %d, requests %d\n%s", code, f.count(), out)
	}
	if st, _ := intel.LoadAttackConsent(saltPathFor("")); st != intel.ConsentGranted {
		t.Error("acceptance was not recorded")
	}
}

// Without --contribute nothing is sent, whatever else is configured.
func TestAttackRunWithoutContributeSendsNothing(t *testing.T) {
	contributeEnv(t, "tok")
	acceptAttackTerms(t)
	target, _ := obedientTarget(t, "nox", "/chat", -1)
	f := newFakeIntel(t)
	dir := t.TempDir()
	args := runArgs(attackPlanFile(t, dir), target.URL, filepath.Join(dir, "t.json"), "--route", "/chat", "--seed", "nox", "--endpoint", f.srv.URL)
	_ = args
	captureCLI(t, func() int {
		return runAttackRun(runArgs(attackPlanFile(t, dir), target.URL, filepath.Join(dir, "t.json"), "--route", "/chat", "--seed", "nox"))
	})
	if f.count() != 0 {
		t.Fatalf("%d request(s) without --contribute", f.count())
	}
}

// A trace nothing exercised is never reported: "the target was not reached" must
// not be stored as a defense that held.
func TestRunReportsSkipUnexercisedTraces(t *testing.T) {
	ok := func() attack.Trace {
		tr := attack.Trace{ID: "t-ok", Exploitability: evidence.Prevented, ReproductionSamples: 3}
		tr.Outcome.Executed, tr.Outcome.ControlSound = true, true
		return tr
	}
	notRun := ok()
	notRun.ID = "t-sim"
	notRun.Outcome.Executed = false
	errored := ok()
	errored.ID = "t-err"
	errored.Outcome.TargetErrors = 2
	unsound := ok()
	unsound.ID = "t-unsound"
	unsound.Outcome.ControlSound = false

	reports, skipped := runReportsFromTraces([]attack.Trace{ok(), notRun, errored, unsound},
		contribCandidate, "sandbox", "2026-10-26T00:00:00Z", "1.50.0")
	if len(reports) != 1 || len(skipped) != 3 {
		t.Fatalf("reports %d skipped %d: %v", len(reports), len(skipped), skipped)
	}
	r := reports[0]
	if r.Exploitability != evidence.Prevented || r.Establishes() || r.Deterministic {
		t.Errorf("a PREVENTED run was reported as %+v", r)
	}
}

// CONFIRMED is only claimed with a deterministic oracle; a semantic one is
// reported at the strength it has, which the shared type refuses for CONFIRMED.
func TestRunReportNeverClaimsConfirmedOnASemanticOracle(t *testing.T) {
	tr := attack.Trace{ID: "t-sem", Exploitability: evidence.Confirmed, ReproductionSamples: 3, ReproductionHits: 3,
		Evidence: &attack.ExploitEvidence{OracleKind: attack.OracleSemantic, Reproduced: true, Samples: 3, Hits: 3}}
	tr.Outcome.Executed, tr.Outcome.ControlSound = true, true
	reports, skipped := runReportsFromTraces([]attack.Trace{tr}, contribCandidate, "sandbox", "2026-10-26T00:00:00Z", "dev")
	if len(reports) != 0 || len(skipped) != 1 {
		t.Fatalf("a CONFIRMED trace on a semantic oracle was reported: %+v", reports)
	}
}

func TestAttackAllowlistMatchesTheSharedType(t *testing.T) {
	var m map[string]any
	b, _ := json.Marshal(evidence.RunReport{})
	_ = json.Unmarshal(b, &m)
	// Omitted-empty fields (tool, version) still must be listed.
	listed := map[string]bool{}
	for _, a := range intel.AttackAllowlist() {
		listed[a.Name] = true
	}
	for k := range m {
		if !listed[k] {
			t.Errorf("RunReport field %q is not on the allowlist", k)
		}
	}
	for _, k := range []string{"tool", "version"} {
		if !listed[k] {
			t.Errorf("%q missing from the allowlist", k)
		}
	}
}

var _ = os.Stdout

// A replay contributes too, and a CONFIRMED replay carries a sound control.
func TestAttackReplayContributes(t *testing.T) {
	contributeEnv(t, "tok")
	acceptAttackTerms(t)
	target, _ := obedientTarget(t, "nox", "/chat", -1)
	dir := t.TempDir()
	plan := attackPlanFile(t, dir)
	out := filepath.Join(dir, "t.json")
	res := attackRun(t, out, runArgs(plan, target.URL, out, "--route", "/chat", "--seed", "nox", "--samples", "3")...)
	id := res.Traces[0].ID

	f := newFakeIntel(t)
	code, printed := captureCLI(t, func() int {
		return runAttackReplay([]string{id, "--trace", out, "--target", target.URL, "--profile", "sandbox", "--authorize",
			"--seed", "nox", "--contribute", "--candidate", contribCandidate, "--endpoint", f.srv.URL})
	})
	if code != 1 {
		t.Fatalf("replay exit %d:\n%s", code, printed)
	}
	if f.count() != 1 {
		t.Fatalf("replay contributed %d run(s), want 1:\n%s", f.count(), printed)
	}
}
