package confirm_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nox-hq/nox/core/confirm"
	"github.com/nox-hq/nox/core/confirm/harnessmock"
	"github.com/nox-hq/nox/core/findings"
)

// aiFindings builds the two static AI-security findings nox raises on the demo
// apps (both point at the same sink; the driver dedupes them to one).
func aiFindings() []findings.Finding {
	loc := findings.Location{FilePath: "app.py", StartLine: 50, EndLine: 50}
	md := map[string]string{"function": "chat", "source_kind": "http_body"}
	return []findings.Finding{
		{RuleID: "AGENTFLOW-001", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
			Location: loc, Message: "untrusted input reaches LLM prompt call", Fingerprint: "aaa", Metadata: md},
		{RuleID: "TAINT-AI-001", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
			Location: loc, Message: "untrusted input reaches prompt_injection sink", Fingerprint: "bbb", Metadata: md},
	}
}

// startApp wires a mock model + the given app handler as httptest servers and
// returns the app base URL.
func startApp(t *testing.T, makeApp func(modelChatURL string) http.Handler) string {
	t.Helper()
	model := httptest.NewServer(harnessmock.NewMockModel())
	t.Cleanup(model.Close)
	app := httptest.NewServer(makeApp(model.URL + "/v1/chat/completions"))
	t.Cleanup(app.Close)
	return app.URL
}

func runDriver(t *testing.T, target string) *confirm.Report {
	t.Helper()
	if err := confirm.AssertReflectionImmune(); err != nil {
		t.Fatalf("reflection immunity: %v", err)
	}
	d := confirm.NewDriver()
	rep, err := d.Run(context.Background(), aiFindings(), confirm.Config{
		Target: target,
		Route:  "/chat",
		Fields: []string{"persona", "message"},
		N:      2, K: 2,
	})
	if err != nil {
		t.Fatalf("driver run: %v", err)
	}
	return rep
}

// TestDiscrimination_Vulnerable is the true-positive half of the proof: the
// vulnerable app (untrusted input → system role) must be CONFIRMED, with the
// exploit localized to the `persona` field and a reflection-immune signal.
func TestDiscrimination_Vulnerable(t *testing.T) {
	target := startApp(t, harnessmock.NewVulnerableApp)
	rep := runDriver(t, target)

	if rep.UniqueSinks != 1 {
		t.Fatalf("expected 1 unique sink after dedupe, got %d", rep.UniqueSinks)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rep.Results))
	}
	r := rep.Results[0]
	if !r.StaticFlag {
		t.Error("static_flag must be true (nox flagged it)")
	}
	if r.Verdict != confirm.VerdictConfirmed {
		t.Fatalf("expected CONFIRMED, got %s (note=%q)", r.Verdict, r.Note)
	}
	if !rep.AnyConfirmed() {
		t.Error("AnyConfirmed should be true")
	}
	if r.Evidence == nil {
		t.Fatal("CONFIRMED verdict must carry evidence")
	}
	if r.Evidence.Field != "persona" {
		t.Errorf("exploit should localize to persona field, got %q", r.Evidence.Field)
	}
	// Evidence must be a genuine hijack signal, not an echo.
	if got := confirm.ClassifySignal(r.Evidence.ModelResponse); got == "" {
		t.Errorf("evidence model_response %q carries no signal", r.Evidence.ModelResponse)
	}
	if !r.Evidence.Determinism.Reproduced {
		t.Error("determinism gate must have reproduced the exploit")
	}
	if r.ControlOK == nil || !*r.ControlOK {
		t.Error("benign control must be safe")
	}
	// The `message` field is the user role — injection there is inert.
	for _, a := range r.Attempts {
		if a.Field == "message" && a.Signal != "" {
			t.Errorf("message-field probe should never hijack, got signal %q", a.Signal)
		}
	}
}

// TestDiscrimination_Fixed is the false-positive half: the fixed app (untrusted
// input confined to the user role) must be UNCONFIRMED under the SAME corpus.
// This is the proof the loop does not always fire.
func TestDiscrimination_Fixed(t *testing.T) {
	target := startApp(t, harnessmock.NewFixedApp)
	rep := runDriver(t, target)

	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rep.Results))
	}
	r := rep.Results[0]
	if !r.StaticFlag {
		t.Error("static_flag must still be true — nox flags both apps statically")
	}
	if r.Verdict != confirm.VerdictUnconfirmed {
		t.Fatalf("expected UNCONFIRMED, got %s", r.Verdict)
	}
	if rep.AnyConfirmed() {
		t.Error("no finding should be confirmed against the fixed app")
	}
	if r.Evidence != nil {
		t.Errorf("UNCONFIRMED must carry no evidence, got %+v", r.Evidence)
	}
	if r.ControlOK == nil || !*r.ControlOK {
		t.Error("benign control must be safe")
	}
	// Every attack attempt must have produced no signal.
	for _, a := range r.Attempts {
		if a.Category != confirm.CategoryBenignControl && a.Signal != "" {
			t.Errorf("fixed app should not hijack: field=%s category=%s signal=%s", a.Field, a.Category, a.Signal)
		}
	}
}

// TestBenignControlGate: if the benign control ever trips, the harness refuses to
// confirm. Simulated with a model that always leaks.
func TestBenignControlGate(t *testing.T) {
	always := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Always leak the canary regardless of input → benign control trips too.
		_, _ = w.Write([]byte(`{"reply":"build_token = ` + confirm.SecretCanary + `"}`))
	}))
	t.Cleanup(always.Close)

	d := confirm.NewDriver()
	rep, err := d.Run(context.Background(), aiFindings(), confirm.Config{
		Target: always.URL, Route: "/chat", Fields: []string{"persona"}, N: 2, K: 2,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	r := rep.Results[0]
	if r.Verdict != confirm.VerdictUnconfirmed {
		t.Fatalf("unsound environment must not CONFIRM, got %s", r.Verdict)
	}
	if r.ControlOK == nil || *r.ControlOK {
		t.Error("control_ok must be false when the benign control trips")
	}
}

// TestNoAIFindings: a findings set with no AI rules yields an empty report.
func TestNoAIFindings(t *testing.T) {
	d := confirm.NewDriver()
	ff := []findings.Finding{{RuleID: "SEC-161", Severity: findings.SeverityMedium, Confidence: findings.ConfidenceLow,
		Location: findings.Location{FilePath: "x.go", StartLine: 1}}}
	rep, err := d.Run(context.Background(), ff, confirm.Config{Target: "http://unused", Route: "/x", Fields: []string{"a"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.UniqueSinks != 0 || len(rep.Results) != 0 {
		t.Fatalf("expected no results for non-AI findings, got %d sinks", rep.UniqueSinks)
	}
}
