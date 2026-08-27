package attack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox-core/evidence"
)

// End-to-end tests over a REAL http.Server, driven through the REAL HTTPTarget.
//
// The in-package fakeTarget covers the oracle and verdict logic, but three of
// the bugs this package shipped lived BELOW it, in the wiring: the route was
// never recorded so a replay could not reach the endpoint, the payload was
// dropped before it was sent, and a suite pointed at a 404 route reported "fix
// holds". A fake target cannot surface any of those, because it never uses the
// route, never serialises a request, and always answers.
//
// So these drive the actual transport, and — the point of the file — they cover
// the NEGATIVE SPACE: the cases where the attack cannot possibly work. In every
// one, the requirement is the same and it is the requirement a security tool
// exists to meet: when nox could not evaluate, it must not report success.

// e2eApp is an in-process target whose two routes differ ONLY in where the
// untrusted field lands, which is the distinction the whole corpus is built to
// detect.
func e2eApp(t *testing.T, cs *CanarySet) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// /vuln splices the untrusted persona into the authoritative (system) role,
	// so an injected instruction is obeyed.
	mux.HandleFunc("/vuln", func(w http.ResponseWriter, r *http.Request) {
		body := decodeFields(w, r)
		if body == nil {
			return
		}
		system := "You are a support agent. Confidential token: " + cs.secret.Value + "\n" + body["persona"]
		writeReply(w, e2eModel(system, cs))
	})

	// /fixed confines the untrusted persona to the user role, where the model
	// treats it as inert data.
	mux.HandleFunc("/fixed", func(w http.ResponseWriter, r *http.Request) {
		body := decodeFields(w, r)
		if body == nil {
			return
		}
		system := "You are a support agent. Confidential token: " + cs.secret.Value
		_ = body["persona"] // present, but never authoritative
		writeReply(w, e2eModel(system, cs))
	})

	// /boom always fails, standing in for a target that errors under attack.
	mux.HandleFunc("/boom", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// e2eModel is a deterministic stand-in for an LLM that obeys instructions in its
// authoritative context. It performs the attacker-ordered transform by
// UPPERCASING the seed — it never echoes a canary value, so reflection immunity
// is preserved end to end.
func e2eModel(systemRole string, cs *CanarySet) string {
	low := strings.ToLower(systemRole)
	if i := strings.Index(low, "uppercase form of the word "); i >= 0 {
		rest := systemRole[i+len("uppercase form of the word "):]
		word := strings.FieldsFunc(rest, func(r rune) bool {
			return r == ' ' || r == '.' || r == '\n' || r == ',' || r == '"'
		})
		if len(word) > 0 {
			return strings.ToUpper(word[0])
		}
	}
	if strings.Contains(low, "system prompt") || strings.Contains(low, "secret token") {
		return "My system prompt is: token=" + cs.secret.Value
	}
	return "Our support hours are 9-5."
}

func decodeFields(w http.ResponseWriter, r *http.Request) map[string]string {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil
	}
	return body
}

func writeReply(w http.ResponseWriter, reply string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"reply": reply})
}

// e2eCfg is an authorized sandbox config pointed at a route and field.
func e2eCfg(route string) RunConfig {
	cfg := sandboxCfg()
	cfg.Route = route
	cfg.Fields = []string{"persona", "message"}
	cfg.Samples = 2
	cfg.MinHits = 2
	return cfg
}

func e2eTarget(base string) Target {
	return NewHTTPTarget(base, "reply", 5*time.Second)
}

// The discrimination proof over the real transport: the same corpus must confirm
// against the vulnerable route and not against the fixed one. If this ever
// passes for both, or fails for both, the tool is not discriminating and every
// verdict it emits is noise.
func TestE2EDiscriminationOverHTTP(t *testing.T) {
	cfg := e2eCfg("/vuln")
	cs := MintCanaries(cfg.Seed)
	srv := e2eApp(t, cs)

	vuln, err := Run(context.Background(), piPlan(t), e2eTarget(srv.URL), cfg)
	if err != nil {
		t.Fatalf("run against /vuln: %v", err)
	}
	if !vuln.AnyConfirmed() {
		t.Fatal("the vulnerable route must produce a CONFIRMED exploit over real HTTP")
	}
	if vuln.ExitCode() != 1 {
		t.Errorf("ExitCode = %d, want 1 when something is confirmed", vuln.ExitCode())
	}

	fixedCfg := e2eCfg("/fixed")
	fixed, err := Run(context.Background(), piPlan(t), e2eTarget(srv.URL), fixedCfg)
	if err != nil {
		t.Fatalf("run against /fixed: %v", err)
	}
	if fixed.AnyConfirmed() {
		t.Fatal("the fixed route must NOT confirm — the same corpus must discriminate")
	}
}

// A route that does not exist answers 404 to every probe. nox never reached the
// code under test, so it must not report a defense or a clean result. This is
// the shape of the bug where a regression suite printed "fix holds" for a target
// it never touched.
func TestE2EWrongRouteIsNeverPreventedOrConfirmed(t *testing.T) {
	cfg := e2eCfg("/does-not-exist")
	cs := MintCanaries(cfg.Seed)
	srv := e2eApp(t, cs)

	res, err := Run(context.Background(), piPlan(t), e2eTarget(srv.URL), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for i := range res.Traces {
		tr := res.Traces[i]
		if tr.Exploitability == evidence.Confirmed {
			t.Errorf("%s CONFIRMED against a 404 route — nothing was demonstrated", tr.ID)
		}
		if tr.Exploitability == evidence.Prevented {
			t.Errorf("%s reported PREVENTED against a 404 route; a target we never reached "+
				"did not defend anything", tr.ID)
		}
	}
	if res.ExitCode() != 0 {
		t.Errorf("ExitCode = %d, want 0 (nothing confirmed)", res.ExitCode())
	}
}

// A target that errors on every probe is the same class of non-evidence.
func TestE2EErroringTargetIsNeverPrevented(t *testing.T) {
	cfg := e2eCfg("/boom")
	cs := MintCanaries(cfg.Seed)
	srv := e2eApp(t, cs)

	res, err := Run(context.Background(), piPlan(t), e2eTarget(srv.URL), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for i := range res.Traces {
		if got := res.Traces[i].Exploitability; got == evidence.Prevented || got == evidence.Confirmed {
			t.Errorf("%s = %s against a 500-ing target; want an inconclusive reading",
				res.Traces[i].ID, got)
		}
	}
}

// A target that is not listening at all must not crash the run, and must not
// yield a clean bill of health.
func TestE2EUnreachableTargetIsNeverClean(t *testing.T) {
	cfg := e2eCfg("/vuln")
	// A closed port: httptest hands us a URL, then we shut it down.
	srv := e2eApp(t, MintCanaries(cfg.Seed))
	dead := srv.URL
	srv.Close()

	res, err := Run(context.Background(), piPlan(t), e2eTarget(dead), cfg)
	if err != nil {
		t.Fatalf("an unreachable target must degrade, not error the run: %v", err)
	}
	for i := range res.Traces {
		if got := res.Traces[i].Exploitability; got == evidence.Prevented || got == evidence.Confirmed {
			t.Errorf("%s = %s against an unreachable target", res.Traces[i].ID, got)
		}
	}
}

// The end-to-end false-all-clear guard: a regression suite recorded against the
// vulnerable route, then run against a route that does not exist, must NOT
// report the fixes holding. It must say it proved nothing, and exit non-zero so
// a CI gate cannot go green on it.
func TestE2ERegressAgainstWrongRouteDoesNotGoGreen(t *testing.T) {
	cfg := e2eCfg("/vuln")
	cs := MintCanaries(cfg.Seed)
	srv := e2eApp(t, cs)

	res, err := Run(context.Background(), piPlan(t), e2eTarget(srv.URL), cfg)
	if err != nil || !res.AnyConfirmed() {
		t.Fatalf("setup: expected a confirmed run, err=%v", err)
	}
	suite := SuiteFromResult(res, testNow)
	if len(suite.Cases) == 0 {
		t.Fatal("setup: expected recorded cases")
	}

	// Point the suite at a route that does not exist.
	wrong := e2eCfg("/does-not-exist")
	sr, err := RunSuite(context.Background(), suite, e2eTarget(srv.URL), wrong)
	if err != nil {
		t.Fatalf("suite run: %v", err)
	}
	for _, r := range sr.Results {
		if r.Regressed {
			t.Errorf("case %s reported a regression against a 404 route", r.Case.ID)
		}
		if strings.Contains(r.Note, "fix holds") {
			t.Errorf("case %s claimed the fix holds for a target it never reached: %q", r.Case.ID, r.Note)
		}
	}
	if sr.ExitCode() == 0 {
		t.Error("a suite that could not exercise the target must not exit 0 — " +
			"a green build here is a security gate that silently did nothing")
	}
}
