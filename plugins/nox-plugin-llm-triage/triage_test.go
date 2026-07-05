package main

import (
	"context"
	"errors"
	"fmt"
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

// findingC is finding with an explicit confidence, for routing tests.
func findingC(rule string, sev pluginv1.Severity, conf pluginv1.Confidence, fp string) *pluginv1.Finding {
	f := finding(rule, sev, fp, "a.py", 1, "msg")
	f.Confidence = conf
	return f
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
		// Distinct fingerprints so the pre-dedup step keeps all five; the cap,
		// not dedup, is what limits the run here.
		fp := fmt.Sprintf("fp-%d", i)
		findings = append(findings, finding("SEC-001", pluginv1.Severity_SEVERITY_HIGH, fp, "a.py", i+1, "x"))
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

// TestBuildPromptStatesGroundingContract proves the prompt explicitly forbids
// the model from reporting new findings or locations.
func TestBuildPromptStatesGroundingContract(t *testing.T) {
	f := finding("SEC-001", pluginv1.Severity_SEVERITY_HIGH, "fp", "a.py", 3, "hardcoded secret")
	p := buildPrompt(f, "api_key = \"AKIA...\"")
	for _, want := range []string{"Do NOT report new findings", "Do NOT propose a different location"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing grounding instruction %q:\n%s", want, p)
		}
	}
}

// TestHallucinatedLocationCannotCreateFinding is the core grounding guarantee:
// a mock LLM that invents a completely different file and line in its reply
// still only produces a verdict anchored to the ORIGINAL finding's fingerprint
// and location. No new finding location is ever emitted from model output.
func TestHallucinatedLocationCannotCreateFinding(t *testing.T) {
	// The model "hallucinates" a verdict about a different file/line than the
	// one it was asked about, and even claims a second issue.
	client := &mockClient{reply: "TRUE_POSITIVE\nActually the real bug is in /etc/shadow:999 and also secrets.env:1 leaks a key."}
	orig := finding("SECRET-ENTROPY", pluginv1.Severity_SEVERITY_HIGH, "fp-orig", "src/app.py", 42, "high-entropy string")

	got, err := triageFindings(context.Background(), client, nil, []*pluginv1.Finding{orig}, TriageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one verdict, for the one input finding — the hallucinated extra
	// location did not spawn a second verdict.
	if len(got) != 1 {
		t.Fatalf("hallucinated locations must not create findings: want 1 verdict, got %d: %+v", len(got), got)
	}
	v := got[0]
	// The verdict is anchored to the original fingerprint and rule, taken from
	// the input finding, never from the model reply.
	if v.Fingerprint != "fp-orig" {
		t.Errorf("verdict fingerprint = %q, want the original %q", v.Fingerprint, "fp-orig")
	}
	if v.RuleID != "SECRET-ENTROPY" {
		t.Errorf("verdict rule = %q, want the original %q", v.RuleID, "SECRET-ENTROPY")
	}
	// The hallucinated paths can only ever surface as inert free-text rationale;
	// they must never appear as a fingerprint or become a new finding key.
	if v.Fingerprint == "/etc/shadow:999" || v.Fingerprint == "secrets.env:1" {
		t.Errorf("hallucinated location leaked into fingerprint: %q", v.Fingerprint)
	}
}

func TestShouldTriageRouting(t *testing.T) {
	const (
		hi  = pluginv1.Severity_SEVERITY_HIGH
		med = pluginv1.Severity_SEVERITY_MEDIUM
		low = pluginv1.Severity_SEVERITY_LOW
	)
	const (
		cHigh = pluginv1.Confidence_CONFIDENCE_HIGH
		cMed  = pluginv1.Confidence_CONFIDENCE_MEDIUM
		cLow  = pluginv1.Confidence_CONFIDENCE_LOW
		cUnk  = pluginv1.Confidence_CONFIDENCE_UNSPECIFIED
	)
	cases := []struct {
		name string
		f    *pluginv1.Finding
		opts TriageOptions
		want bool
	}{
		{"below min severity is skipped", findingC("SEC-1", low, cLow, "a"), TriageOptions{MinSeverity: SevHigh}, false},
		{"high confidence skipped when gated", findingC("SEC-1", hi, cHigh, "a"), TriageOptions{SkipHighConfidence: true}, false},
		{"medium confidence is residual", findingC("SEC-1", hi, cMed, "a"), TriageOptions{SkipHighConfidence: true}, true},
		{"low confidence is residual", findingC("SEC-1", hi, cLow, "a"), TriageOptions{SkipHighConfidence: true}, true},
		{"unspecified confidence is residual", findingC("SEC-1", hi, cUnk, "a"), TriageOptions{SkipHighConfidence: true}, true},
		{"high confidence judged when gate off", findingC("SEC-1", hi, cHigh, "a"), TriageOptions{}, true},
		{"only_rules prefix match kept", findingC("SECRET-ENTROPY", hi, cLow, "a"), TriageOptions{OnlyRules: []string{"SECRET-*"}}, true},
		{"only_rules non-match dropped", findingC("SEC-1", hi, cLow, "a"), TriageOptions{OnlyRules: []string{"SECRET-*"}}, false},
		{"skip_rules exact match dropped", findingC("SEC-1", hi, cLow, "a"), TriageOptions{SkipRules: []string{"SEC-1"}}, false},
		{"skip_rules wins over only_rules", findingC("SECRET-X", hi, cLow, "a"), TriageOptions{OnlyRules: []string{"SECRET-*"}, SkipRules: []string{"SECRET-X"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldTriage(c.f, c.opts); got != c.want {
				t.Errorf("shouldTriage = %v, want %v", got, c.want)
			}
		})
	}
}

// TestTriageRoutingSendsOnlySubset proves that, end-to-end, only the intended
// subset ever reaches the (mock) client — the LLM never sees a filtered-out
// finding.
func TestTriageRoutingSendsOnlySubset(t *testing.T) {
	client := &mockClient{reply: "UNCERTAIN\nx"}
	findings := []*pluginv1.Finding{
		findingC("SECRET-ENTROPY", pluginv1.Severity_SEVERITY_HIGH, pluginv1.Confidence_CONFIDENCE_LOW, "fp-secret"),
		findingC("SECRET-KNOWN", pluginv1.Severity_SEVERITY_HIGH, pluginv1.Confidence_CONFIDENCE_HIGH, "fp-known"),
		findingC("SQLI-001", pluginv1.Severity_SEVERITY_HIGH, pluginv1.Confidence_CONFIDENCE_LOW, "fp-sqli"),
	}
	got, err := triageFindings(context.Background(), client, nil, findings, TriageOptions{
		SkipHighConfidence: true,
		OnlyRules:          []string{"SECRET-*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Only the low-confidence SECRET-* finding qualifies: SECRET-KNOWN is
	// high-confidence (gated out), SQLI-001 is not a SECRET rule.
	if len(got) != 1 || got[0].Fingerprint != "fp-secret" {
		t.Fatalf("routing should judge only fp-secret, got %+v", got)
	}
	if len(client.seen) != 1 {
		t.Fatalf("LLM should be called exactly once, got %d calls", len(client.seen))
	}
	if !strings.Contains(client.seen[0], "SECRET-ENTROPY") {
		t.Errorf("the one LLM call should be about SECRET-ENTROPY, got:\n%s", client.seen[0])
	}
}

func TestDedupeFindings(t *testing.T) {
	t.Run("dedupes by fingerprint", func(t *testing.T) {
		in := []*pluginv1.Finding{
			finding("SEC-1", pluginv1.Severity_SEVERITY_HIGH, "same", "a.py", 1, "x"),
			finding("SEC-1", pluginv1.Severity_SEVERITY_HIGH, "same", "a.py", 1, "x"),
			finding("SEC-2", pluginv1.Severity_SEVERITY_HIGH, "other", "b.py", 2, "y"),
		}
		got := dedupeFindings(in)
		if len(got) != 2 {
			t.Fatalf("want 2 unique findings, got %d", len(got))
		}
		if got[0].GetFingerprint() != "same" || got[1].GetFingerprint() != "other" {
			t.Errorf("dedup must preserve first-seen order, got %q,%q", got[0].GetFingerprint(), got[1].GetFingerprint())
		}
	})
	t.Run("dedupes by rule+location when fingerprint absent", func(t *testing.T) {
		in := []*pluginv1.Finding{
			finding("SEC-1", pluginv1.Severity_SEVERITY_HIGH, "", "a.py", 1, "x"),
			finding("SEC-1", pluginv1.Severity_SEVERITY_HIGH, "", "a.py", 1, "x"),
			finding("SEC-1", pluginv1.Severity_SEVERITY_HIGH, "", "a.py", 2, "x"),
		}
		got := dedupeFindings(in)
		if len(got) != 2 {
			t.Fatalf("want 2 (same loc collapsed, different line kept), got %d", len(got))
		}
	})
}

// TestTriageDedupsBeforeLLM proves the LLM is not asked the same question twice.
func TestTriageDedupsBeforeLLM(t *testing.T) {
	client := &mockClient{reply: "TRUE_POSITIVE\nx"}
	dup := finding("SEC-1", pluginv1.Severity_SEVERITY_HIGH, "same", "a.py", 1, "x")
	findings := []*pluginv1.Finding{dup, dup, dup}
	got, err := triageFindings(context.Background(), client, nil, findings, TriageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 verdict after dedup, got %d", len(got))
	}
	if len(client.seen) != 1 {
		t.Fatalf("LLM must be called once for duplicates, got %d calls", len(client.seen))
	}
}
