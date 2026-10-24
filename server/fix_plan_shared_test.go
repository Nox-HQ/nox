package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/remediate"
)

// The MCP tool and `nox fix plan` show one plan: the Text an agent passes on to
// a person is exactly what the CLI prints for the same findings.
func TestHandleFixPlan_CarriesTheSharedClassifiedPlan(t *testing.T) {
	s := New("0.1.0", nil)
	res := depScanResult("golang.org/x/crypto", "0.51.0", "0.54.0")
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
