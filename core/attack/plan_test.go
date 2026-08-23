package attack

import (
	"bytes"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
)

func injectionFinding(fp string) findings.Finding {
	return findings.Finding{
		RuleID:      "AGENTFLOW-001",
		Fingerprint: fp,
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceHigh,
		Location:    findings.Location{FilePath: "app/handlers.py", StartLine: 42},
		Message:     "untrusted input reaches an LLM prompt",
		Metadata:    map[string]string{"function": "chat", "route": "/chat"},
	}
}

func TestBuildPlanGroundsInjectionFindings(t *testing.T) {
	in := PlanInput{
		Root:     "/repo",
		Findings: []findings.Finding{injectionFinding("fp-abc")},
		Now:      "2026-08-23T00:00:00Z",
	}
	plan, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Hypotheses) != 2 {
		t.Fatalf("expected 2 injection hypotheses (direct+indirect), got %d", len(plan.Hypotheses))
	}
	for _, h := range plan.Hypotheses {
		if len(h.FindingFingerprints) == 0 || h.FindingFingerprints[0] != "fp-abc" {
			t.Errorf("hypothesis %s not grounded in the finding: %+v", h.ID, h.FindingFingerprints)
		}
		if h.Rationale == "" {
			t.Errorf("hypothesis %s has no rationale", h.ID)
		}
	}
	if len(plan.Skipped) != 0 {
		t.Errorf("expected no skipped findings, got %d", len(plan.Skipped))
	}
}

func TestBuildPlanSkipsUnmappedFindings(t *testing.T) {
	unmapped := findings.Finding{
		RuleID:      "SEC-999",
		Fingerprint: "fp-unmapped",
		Severity:    findings.SeverityLow,
		Confidence:  findings.ConfidenceLow,
		Location:    findings.Location{FilePath: "x.go", StartLine: 1},
	}
	plan, err := BuildPlan(PlanInput{Findings: []findings.Finding{unmapped}, Now: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Hypotheses) != 0 {
		t.Fatalf("expected no hypotheses, got %d", len(plan.Hypotheses))
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].Fingerprint != "fp-unmapped" {
		t.Fatalf("expected the unmapped finding to be skipped, got %+v", plan.Skipped)
	}
	if plan.Skipped[0].Reason == "" {
		t.Error("skip note must carry a reason")
	}
}

func TestBuildPlanToolMatrixHypotheses(t *testing.T) {
	inv := ai.NewInventory()
	inv.ToolMatrix = []ai.ToolPermissionSet{
		{
			Agent: "support-agent",
			Path:  "agents/support.py",
			Tools: []string{"read_file", "http_post"},
			Capabilities: map[string][]string{
				"read_file": {"file_read"},
				"http_post": {"http_request"},
			},
		},
	}
	plan, err := BuildPlan(PlanInput{Inventory: inv, Now: "t"})
	if err != nil {
		t.Fatal(err)
	}
	var sawExfil bool
	for _, h := range plan.Hypotheses {
		if h.ScenarioID == ScenarioExfilFSNet {
			sawExfil = true
		}
	}
	if !sawExfil {
		t.Errorf("expected an EXFIL-FS-NET hypothesis from a file+network tool set; got %d hypotheses", len(plan.Hypotheses))
	}
}

// TestBuildPlanDeterministic proves BuildPlan is byte-identical on repeat.
func TestBuildPlanDeterministic(t *testing.T) {
	inv := ai.NewInventory()
	inv.ToolMatrix = []ai.ToolPermissionSet{
		{Agent: "b-agent", Path: "b.py", Tools: []string{"shell_exec"}},
		{Agent: "a-agent", Path: "a.py", Tools: []string{"read_file", "http_fetch"}},
	}
	in := PlanInput{
		Root:      "/repo",
		Findings:  []findings.Finding{injectionFinding("fp-2"), injectionFinding("fp-1")},
		Inventory: inv,
		Now:       "2026-08-23T00:00:00Z",
	}
	// Note: two injection findings at the same file/line/function dedupe to one
	// sink but ground both fingerprints.
	p1, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	j1, _ := p1.JSON()
	j2, _ := p2.JSON()
	if !bytes.Equal(j1, j2) {
		t.Error("BuildPlan is not deterministic: JSON differs between two runs")
	}
}

func TestPlanRoundTrip(t *testing.T) {
	in := PlanInput{
		Root:     "/repo",
		Findings: []findings.Finding{injectionFinding("fp-abc")},
		Now:      "2026-08-23T00:00:00Z",
	}
	plan, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := plan.JSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadPlan(raw)
	if err != nil {
		t.Fatal(err)
	}
	re, _ := got.JSON()
	if !bytes.Equal(raw, re) {
		t.Error("plan did not survive a JSON round-trip byte-identically")
	}
}
