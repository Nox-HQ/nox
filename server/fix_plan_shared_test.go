package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox/core/remediate"
)

// The MCP tool and `nox fix plan` show one plan: the Text an agent passes on to
// a person is exactly what the CLI prints for the same findings.
func TestHandleFixPlan_CarriesTheSharedClassifiedPlan(t *testing.T) {
	s := New("0.1.0", nil)
	res := depScanResult("golang.org/x/crypto", "0.51.0", "0.54.0")
	res.AdvisoryLookupSkipped = true // plans from the findings alone, as the CLI's Build below does
	s.setCache("", res)

	out, err := s.handleFixPlan(context.Background(), fixPlanInput{})
	if err != nil {
		t.Fatalf("fix_plan failed: %v", err)
	}
	var resp fixPlanResponse
	if err := json.Unmarshal([]byte(textOf(out)), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Plan.Items) != 1 || resp.Plan.Items[0].Class != remediate.ClassSafe {
		t.Fatalf("plan = %+v", resp.Plan)
	}

	want := remediate.Build(remediate.Input{Findings: res.Findings.ActiveFindings(), Rules: res.Rules})
	var wantText strings.Builder
	if err := remediate.RenderPlan(&wantText, want); err != nil {
		t.Fatal(err)
	}
	if resp.Text != wantText.String() {
		t.Fatalf("MCP text differs from the CLI's rendering:\n%s\n---\n%s", resp.Text, wantText.String())
	}
	if !strings.Contains(resp.Note, "never changes the workspace") {
		t.Errorf("note does not say the tool is read-only: %q", resp.Note)
	}
}

// An offline scan's fix_plan must not reach the advisory database, and must
// say its targets were not verified. The control proves the counting server is
// reachable: an online scan's plan does ask it.
func TestHandleFixPlan_OfflineScanMakesNoAdvisoryRequests(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"results":[{}]}`))
	}))
	defer srv.Close()
	t.Setenv("NOX_OSV_BASE_URL", srv.URL)

	plan := func(skipped bool) fixPlanResponse {
		s := New("0.1.0", nil)
		res := depScanResult("golang.org/x/crypto", "0.51.0", "0.54.0")
		res.AdvisoryLookupSkipped = skipped
		s.setCache("", res)
		out, err := s.handleFixPlan(context.Background(), fixPlanInput{})
		if err != nil {
			t.Fatal(err)
		}
		var resp fixPlanResponse
		if err := json.Unmarshal([]byte(textOf(out)), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := plan(true)
	if n := hits.Load(); n != 0 {
		t.Fatalf("offline fix_plan made %d advisory requests", n)
	}
	if !strings.Contains(resp.Note, "not verified against all advisories") {
		t.Errorf("offline plan should say targets are unverified: %q", resp.Note)
	}
	if len(resp.Actions) != 1 || resp.Actions[0].To != "0.54.0" {
		t.Errorf("offline plan should keep today's behaviour: %+v", resp.Actions)
	}

	plan(false)
	if hits.Load() == 0 {
		t.Error("control: an online scan's plan should have asked the advisory source")
	}
}
