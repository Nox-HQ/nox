package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

type mockClient struct {
	reply string
	err   error
	seen  []string
}

func (m *mockClient) Complete(_ context.Context, prompt string) (string, error) {
	m.seen = append(m.seen, prompt)
	return m.reply, m.err
}

func finding(rule string, sev pluginv1.Severity, fp, file string, line int, msg string) *pluginv1.Finding {
	return &pluginv1.Finding{
		RuleId:      rule,
		Severity:    sev,
		Fingerprint: fp,
		Message:     msg,
		Location:    &pluginv1.Location{FilePath: file, StartLine: int32(line)},
	}
}

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		in   string
		disp Disposition
	}{
		{"TRUE_POSITIVE\nThis reaches a shell.", DispTruePositive},
		{"FALSE_POSITIVE\nThe input is a constant.", DispFalsePositive},
		{"UNCERTAIN\nNeed more context.", DispUncertain},
		{"true positive - definitely exploitable", DispTruePositive},
		{"gibberish with no verdict", DispUncertain},
	}
	for _, c := range cases {
		disp, rationale := parseVerdict(c.in)
		if disp != c.disp {
			t.Errorf("parseVerdict(%q) disposition = %q, want %q", c.in, disp, c.disp)
		}
		if c.disp != DispUncertain && rationale == "" && strings.Contains(c.in, "\n") {
			t.Errorf("expected a rationale for %q", c.in)
		}
	}
}

func TestTriageEmitsVerdictPerFinding(t *testing.T) {
	client := &mockClient{reply: "FALSE_POSITIVE\nThe value is a hard-coded test constant."}
	findings := []*pluginv1.Finding{
		finding("SEC-001", pluginv1.Severity_SEVERITY_HIGH, "fp1", "a.py", 3, "hardcoded secret"),
		finding("AI-001", pluginv1.Severity_SEVERITY_MEDIUM, "fp2", "b.py", 5, "prompt injection"),
	}
	got, err := triageFindings(context.Background(), client, nil, findings, TriageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 verdicts, got %d", len(got))
	}
	for _, v := range got {
		if v.Disposition != DispFalsePositive {
			t.Errorf("expected false_positive, got %q", v.Disposition)
		}
		if v.Rationale == "" {
			t.Error("expected a rationale")
		}
	}
}

func TestTriageMinSeverityGate(t *testing.T) {
	client := &mockClient{reply: "TRUE_POSITIVE\nreal"}
	findings := []*pluginv1.Finding{
		finding("SEC-001", pluginv1.Severity_SEVERITY_LOW, "fp1", "a.py", 1, "low"),
		finding("SEC-002", pluginv1.Severity_SEVERITY_CRITICAL, "fp2", "a.py", 2, "crit"),
	}
	got, err := triageFindings(context.Background(), client, nil, findings, TriageOptions{MinSeverity: SevHigh})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Fingerprint != "fp2" {
		t.Fatalf("min-severity gate should keep only the critical finding, got %+v", got)
	}
}

func TestTriageMaxFindings(t *testing.T) {
	client := &mockClient{reply: "TRUE_POSITIVE\nx"}
	var findings []*pluginv1.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, finding("SEC-001", pluginv1.Severity_SEVERITY_HIGH, "fp", "a.py", i+1, "x"))
	}
	got, _ := triageFindings(context.Background(), client, nil, findings, TriageOptions{MaxFindings: 2})
	if len(got) != 2 {
		t.Fatalf("expected 2 judged (cap), got %d", len(got))
	}
}

func TestTriageLLMErrorIsUncertain(t *testing.T) {
	client := &mockClient{err: errors.New("boom")}
	findings := []*pluginv1.Finding{finding("SEC-001", pluginv1.Severity_SEVERITY_HIGH, "fp1", "a.py", 1, "x")}
	got, err := triageFindings(context.Background(), client, nil, findings, TriageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Disposition != DispUncertain {
		t.Fatalf("LLM error should yield an uncertain verdict, got %+v", got)
	}
}

func TestBuildPromptIncludesSnippet(t *testing.T) {
	f := finding("SEC-001", pluginv1.Severity_SEVERITY_HIGH, "fp", "a.py", 3, "hardcoded secret")
	p := buildPrompt(f, "api_key = \"AKIA...\"")
	for _, want := range []string{"SEC-001", "hardcoded secret", "a.py:3", "AKIA", "TRUE_POSITIVE"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q:\n%s", want, p)
		}
	}
}
