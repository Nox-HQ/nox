package attack

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/report"
)

func invoiceLead() report.Lead {
	return report.Lead{
		Category: "authorization", RuleID: "AUTHZ-001", Route: "GET /invoices/:id",
		FilePath: "src/server.js", Line: 24, IDSource: "path",
		Statement: "loads a record by a caller-supplied id with no visible ownership check",
		Test:      "Test it with two user accounts: request user A's record while signed in as user B.",
	}
}

func authzPlan(t *testing.T, leads ...report.Lead) *Plan {
	t.Helper()
	plan, err := BuildPlan(PlanInput{Root: "/repo", Leads: leads, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestAuthzLeadBecomesBOLAHypothesis(t *testing.T) {
	plan := authzPlan(t, invoiceLead())
	if len(plan.Hypotheses) != 1 {
		t.Fatalf("hypotheses = %d, want 1", len(plan.Hypotheses))
	}
	h := plan.Hypotheses[0]
	if h.ScenarioID != ScenarioAuthzBOLA || h.EntryPoint != "GET /invoices/:id" {
		t.Fatalf("got scenario %q entry %q", h.ScenarioID, h.EntryPoint)
	}
	p := h.TestProcedure
	if p == nil {
		t.Fatal("no test procedure")
	}
	if p.ObjectParameter != "id" || p.ObjectParameterLocation != "path" {
		t.Errorf("object parameter = %q in %q, want id in path", p.ObjectParameter, p.ObjectParameterLocation)
	}
	if p.Executable {
		t.Error("procedure claims to be executable, but nothing runs it")
	}
	for _, want := range []string{"user A", "user B", "403", "200"} {
		all := strings.Join(p.Steps, " ") + p.SecureResponse + p.VulnerableResponse
		if !strings.Contains(all, want) {
			t.Errorf("procedure never mentions %q", want)
		}
	}
	if !strings.Contains(h.Rationale, "ownership") {
		t.Errorf("rationale lacks the missing-ownership reasoning: %q", h.Rationale)
	}
	if len(plan.Assets) != 1 || len(plan.Scenarios) != 1 {
		t.Errorf("assets=%d scenarios=%d, want 1 and 1", len(plan.Assets), len(plan.Scenarios))
	}
}

func TestAuthzIgnoresOtherLeads(t *testing.T) {
	l := invoiceLead()
	l.Category, l.RuleID = "authentication", "AUTHN-001"
	if got := authzPlan(t, l).Hypotheses; len(got) != 0 {
		t.Errorf("an authentication lead produced %d BOLA hypotheses", len(got))
	}
}

func TestObjectParameter(t *testing.T) {
	cases := []struct{ path, src, name, loc string }{
		{"/invoices/:id", "path", "id", "path"},
		{"/orgs/:orgId/invoices/:invoiceId", "path", "invoiceId", "path"},
		{"/invoices/{invoice_id}", "path", "invoice_id", "path"},
		{"/invoices/<int:pk>", "path", "pk", "path"},
		{"/invoices/<slug>", "path", "slug", "path"},
		{"/invoices/[id]", "path", "id", "path"},
		{"/invoices", "query", "", "query"},
		{"/invoices", "body", "", "body"},
		{"/invoices", "", "", ""},
	}
	for _, c := range cases {
		name, loc := objectParameter(authzTarget{path: c.path, idSource: c.src})
		if name != c.name || loc != c.loc {
			t.Errorf("%s (%s) = %q,%q want %q,%q", c.path, c.src, name, loc, c.name, c.loc)
		}
	}
}

func TestAuthzPlanIsDeterministic(t *testing.T) {
	a, _ := authzPlan(t, invoiceLead()).JSON()
	b, _ := authzPlan(t, invoiceLead()).JSON()
	if !bytes.Equal(a, b) {
		t.Error("two plans from the same lead differ")
	}
}

// The dangerous failure for an active capability is "we never exercised it"
// reported as "it is fixed". A BOLA hypothesis has no executor, so a run must
// say it did not run, send nothing, and never score it PREVENTED or CONFIRMED.
func TestRunDoesNotScoreUnexecutedAuthzAsPrevented(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), authzPlan(t, invoiceLead()), NewHTTPTarget(srv.URL, "reply", 0), sandboxCfg())
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Errorf("run sent %d requests for a hypothesis it cannot execute", hits.Load())
	}
	if len(res.Traces) != 1 {
		t.Fatalf("traces = %d, want 1", len(res.Traces))
	}
	tr := res.Traces[0]
	if tr.Exploitability == evidence.Prevented || tr.Exploitability == evidence.Confirmed {
		t.Errorf("unexecuted BOLA scored %s", tr.Exploitability)
	}
	if tr.Outcome.Executed {
		t.Error("trace claims execution")
	}
	if !strings.Contains(tr.Note, "not executed") {
		t.Errorf("trace note does not say it was not executed: %q", tr.Note)
	}
}

func TestAuthzScenarioIsPlanOnlyAndCWETagged(t *testing.T) {
	s, ok := ScenarioByID(ScenarioAuthzBOLA)
	if !ok || !s.PlanOnly || s.PlanOnlyReason == "" || s.CWE != "CWE-639" {
		t.Errorf("scenario = %+v", s)
	}
}
