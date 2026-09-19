package main

import (
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
)

const testCandidate = "46f3edf20f27caba7f34aa15ed44f03b8019297434bd7fea4b2cefc4ce5bf772"

func attackResult() *attack.Result {
	return &attack.Result{
		GeneratedAt: "2026-09-19T12:00:00Z",
		Traces: []attack.Trace{
			{ID: "trace-hyp-a", Objective: "exfiltrate", Exploitability: evidence.Confirmed,
				Evidence: &attack.ExploitEvidence{OracleKind: attack.OracleDeterministic, Reproduced: true}},
			{ID: "trace-hyp-b", Objective: "judged", Exploitability: evidence.Confirmed,
				Evidence: &attack.ExploitEvidence{OracleKind: attack.OracleSemantic, Reproduced: true}},
			{ID: "trace-hyp-c", Objective: "held", Exploitability: evidence.Prevented},
		},
	}
}

func TestEvidenceFromResult(t *testing.T) {
	evs, _, err := evidenceFromResult(attackResult(), testCandidate, "checkout:npm:lodash@4.17.20", nil)
	if err != nil {
		t.Fatal(err)
	}
	// By default only runs that observed a violation: the prevented one raises
	// no reach and is left out.
	if len(evs) != 2 {
		t.Fatalf("evidence %+v, want the two violations", evs)
	}
	for _, ev := range evs {
		if ev.Fingerprint != testCandidate || ev.ComponentID == "" || ev.ObservedAt != "2026-09-19T12:00:00Z" {
			t.Errorf("binding not carried: %+v", ev)
		}
		switch ev.TraceID {
		case "trace-hyp-a":
			if !ev.Deterministic || !ev.Reproduced {
				t.Errorf("a deterministic, reproduced run: %+v", ev)
			}
		case "trace-hyp-b":
			// A model's judgment is never deterministic, so the service cannot
			// reach CONFIRMED from it.
			if ev.Deterministic {
				t.Errorf("a semantic oracle was sent as deterministic: %+v", ev)
			}
		}
	}

	named, _, err := evidenceFromResult(attackResult(), testCandidate, "", []string{"trace-hyp-c"})
	if err != nil || len(named) != 1 || named[0].Exploitability != "PREVENTED" {
		t.Errorf("a named prevented trace: %+v %v", named, err)
	}
	if _, _, err := evidenceFromResult(attackResult(), testCandidate, "", []string{"trace-missing"}); err == nil {
		t.Error("a trace id not in the result was accepted")
	}
	undated := attackResult()
	undated.GeneratedAt = ""
	if _, _, err := evidenceFromResult(undated, testCandidate, "", nil); err == nil {
		t.Error("a result with no timestamp was accepted")
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stderr = orig
	return <-done
}

type recorded struct {
	method, path, auth string
	body               []byte
}

func stubIntel(t *testing.T, status int, reply string) (*httptest.Server, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	var got []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recorded{r.Method, r.URL.EscapedPath(), r.Header.Get("Authorization"), b})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestIntelEvidenceUpload(t *testing.T) {
	srv, got := stubIntel(t, http.StatusAccepted, `{}`)
	file := filepath.Join(t.TempDir(), "attack.json")
	raw, _ := json.Marshal(attackResult())
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOX_INTEL_TOKEN", "noxi_test")

	var code int
	captureStdout(t, func() {
		code = runIntelEvidence([]string{file, "--candidate", testCandidate, "--upload", "--endpoint", srv.URL})
	})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(*got) != 2 {
		t.Fatalf("sent %d requests, want 2", len(*got))
	}
	for _, r := range *got {
		if r.method != http.MethodPost || r.path != "/v1/org/exploit-evidence" || r.auth != "Bearer noxi_test" {
			t.Errorf("request %s %s auth=%q", r.method, r.path, r.auth)
		}
	}
}

// Without --upload nothing leaves, and without a token nothing can.
func TestIntelEvidenceSendsNothingUnlessAsked(t *testing.T) {
	srv, got := stubIntel(t, http.StatusAccepted, `{}`)
	file := filepath.Join(t.TempDir(), "attack.json")
	raw, _ := json.Marshal(attackResult())
	_ = os.WriteFile(file, raw, 0o600)
	t.Setenv("NOX_INTEL_TOKEN", "")

	captureStdout(t, func() {
		if code := runIntelEvidence([]string{file, "--candidate", testCandidate, "--endpoint", srv.URL}); code != 0 {
			t.Errorf("print-only run exited %d", code)
		}
		if code := runIntelEvidence([]string{file, "--candidate", testCandidate, "--upload", "--endpoint", srv.URL}); code != 2 {
			t.Errorf("upload without NOX_INTEL_TOKEN exited %d, want 2", code)
		}
		if code := runIntelEvidence([]string{file, "--candidate", "NOX-CAND-46f3edf20f27"}); code != 2 {
			t.Errorf("a candidate id instead of a fingerprint exited %d, want 2", code)
		}
	})
	if len(*got) != 0 {
		t.Errorf("%d request(s) sent without --upload and a token", len(*got))
	}
}

func TestIntelComponentsUploadsOneService(t *testing.T) {
	srv, got := stubIntel(t, http.StatusOK, `{"components":1}`)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"name":"x","lockfileVersion":3,"packages":{
 "":{"name":"x","dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}}}`), 0o600)
	t.Setenv("NOX_INTEL_TOKEN", "noxi_test")
	t.Setenv("NOX_HOME", t.TempDir())

	var code int
	captureStdout(t, func() {
		code = runIntelComponents([]string{dir, "--service", "checkout", "--no-such-flag", "--upload", "--endpoint", srv.URL})
	})
	if code != 2 {
		// An unknown flag must be refused before anything is scanned or sent.
		t.Fatalf("unknown flag exited %d, want 2", code)
	}
	if len(*got) != 0 {
		t.Fatal("a refused invocation sent a request")
	}

	out := captureStdout(t, func() {
		code = runIntelComponents([]string{dir, "--service", "checkout", "--upload", "--endpoint", srv.URL})
	})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(*got) != 1 {
		t.Fatalf("sent %d requests, want 1", len(*got))
	}
	r := (*got)[0]
	if r.method != http.MethodPut || r.path != "/v1/org/services/checkout/components" || r.auth != "Bearer noxi_test" {
		t.Errorf("request %s %s auth=%q", r.method, r.path, r.auth)
	}
	var body struct {
		Components []struct {
			ID      string `json:"id"`
			Service string `json:"service"`
		} `json:"components"`
	}
	if err := json.Unmarshal(r.body, &body); err != nil || len(body.Components) != 1 ||
		body.Components[0].Service != "checkout" || !strings.HasPrefix(body.Components[0].ID, "checkout:npm:lodash") {
		t.Errorf("body %s (%v)", r.body, err)
	}
	if !strings.Contains(out, `"service": "checkout"`) || !strings.Contains(out, `"components"`) {
		t.Errorf("stdout did not show the inventory that was sent: %s", out)
	}
}

func TestIntelComponentsExplainsAMissingPlan(t *testing.T) {
	srv, _ := stubIntel(t, http.StatusForbidden, `{"error":"this capability is not included in your plan","capability":"blast_radius"}`)
	dir := t.TempDir()
	t.Setenv("NOX_INTEL_TOKEN", "noxi_test")
	t.Setenv("NOX_HOME", t.TempDir())
	var code int
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			code = runIntelComponents([]string{dir, "--service", "checkout", "--upload", "--endpoint", srv.URL})
		})
	})
	if code != 1 || !strings.Contains(stderr, "Security or above") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}
