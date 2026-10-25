package assess

import (
	"bytes"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/findings"
)

// The definition of "needs attention" is the headline's contract: critical and
// high always, medium only when the analyzer is highly confident, nothing else.
func TestNeedsAttentionDefinition(t *testing.T) {
	cases := []struct {
		sev  findings.Severity
		conf findings.Confidence
		want bool
	}{
		{findings.SeverityCritical, findings.ConfidenceLow, true},
		{findings.SeverityHigh, findings.ConfidenceMedium, true},
		{findings.SeverityMedium, findings.ConfidenceHigh, true},
		{findings.SeverityMedium, findings.ConfidenceMedium, false},
		{findings.SeverityMedium, findings.ConfidenceLow, false},
		{findings.SeverityLow, findings.ConfidenceHigh, false},
		{findings.SeverityInfo, findings.ConfidenceHigh, false},
		{"", findings.ConfidenceHigh, false},
	}
	for _, c := range cases {
		if got := NeedsAttention(c.sev, c.conf); got != c.want {
			t.Errorf("NeedsAttention(%q,%q) = %v, want %v", c.sev, c.conf, got, c.want)
		}
	}
}

func hygiene(rule, sev, conf, fp string) findings.Finding {
	return findings.Finding{
		RuleID: rule, Severity: findings.Severity(sev), Confidence: findings.Confidence(conf),
		Location: findings.Location{FilePath: "deploy/k8s.yaml", StartLine: 2}, Message: rule + " hygiene",
		Fingerprint: fp,
	}
}

// Two real problems and many low-confidence hygiene items: the headline counts
// the two, the rest is a separate line, and no finding leaves the report.
func TestHeadlineCountsWhatNeedsAttention(t *testing.T) {
	ff := []findings.Finding{
		hygiene("IAC-007", "critical", "high", "a"),
		hygiene("IAC-040", "critical", "high", "b"),
		hygiene("IAC-139", "medium", "low", "c"),
		hygiene("IAC-140", "medium", "low", "d"),
		hygiene("IAC-124", "low", "low", "e"),
	}
	r := Build(Input{Findings: ff, Scope: nox.FullScope()})
	if r.AttentionIssues != 2 || r.AttentionFindings != 2 {
		t.Fatalf("attention = %d issues / %d findings, want 2 / 2", r.AttentionIssues, r.AttentionFindings)
	}
	if len(r.Issues) != 5 || r.FindingCount != 5 {
		t.Fatalf("an observation was dropped: %d issues, %d findings", len(r.Issues), r.FindingCount)
	}
	for i, is := range r.Issues {
		if is.Attention != (i < 2) {
			t.Errorf("issue %d (%s) attention=%v: attention issues must come first", i, is.RuleID, is.Attention)
		}
	}
	var out bytes.Buffer
	if err := Render(&out, r, RenderOptions{Limit: DefaultLimit}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"2 issues need attention (2 findings).", "Plus 3 lower-priority observations (3 findings)"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "IAC-124") {
		t.Errorf("observations are listed only under --verbose:\n%s", text)
	}
	out.Reset()
	if err := Render(&out, r, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "IAC-124") || !strings.Contains(out.String(), "3 lower-priority observations (3 findings)") {
		t.Errorf("--verbose must list every observation:\n%s", out.String())
	}
}

// Only observations: the headline says nothing needs attention rather than
// claiming the repository is clean.
func TestOnlyObservations(t *testing.T) {
	r := Build(Input{Findings: []findings.Finding{hygiene("IAC-124", "low", "low", "e")}, Scope: nox.FullScope()})
	var out bytes.Buffer
	if err := Render(&out, r, RenderOptions{Limit: DefaultLimit}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No issues need attention.") || !strings.Contains(out.String(), "1 lower-priority observation") {
		t.Errorf("got:\n%s", out.String())
	}
}
