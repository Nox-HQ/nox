package ai

import (
	"strings"
	"testing"
)

// Two rules in this family reported the opposite of what they claimed.
//
// AI-029 says "LLM repetition penalties disabled" and matched
// `presence_penalty\s*[:=]\s*0` with nothing after the zero — so
// `presence_penalty=0.1` matched too, and the rule reported "disabled" on code
// that had explicitly enabled them. 446 findings on the pinned corpus, the two
// most common being `frequency_penalty=0.1` (116) and `presence_penalty=0.1`
// (116): the remediation it recommends, reported as the defect.
//
// AI-041 says "high temperature/top_p settings" and its remediation says
// "High temperature (>0.9)", but `0\.9[0-9]*` matched exactly 0.9 as well.
// `top_p=0.9` is an ordinary nucleus-sampling value and was 317 of that rule's
// 391 findings.

func aiFired(t *testing.T, rule, body string) bool {
	t.Helper()
	a := NewAnalyzer()
	got, err := a.ScanFile("agent.py", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func TestAI029ReportsOnlyADisabledPenalty(t *testing.T) {
	for _, line := range []string{
		`presence_penalty=0,`,
		`frequency_penalty = 0`,
		`"presence_penalty": 0.0,`,
		`frequency_penalty=0.00,`,
	} {
		if !aiFired(t, "AI-029", line+"\n") {
			t.Errorf("AI-029 stopped reporting a genuinely disabled penalty: %s", line)
		}
	}
}

func TestAI029IgnoresAnEnabledPenalty(t *testing.T) {
	for _, line := range []string{
		`frequency_penalty=0.1,`,
		`presence_penalty=0.1,   # Encourage topic diversity`,
		`frequency_penalty=0.5,`,
		`presence_penalty = 0.05`,
	} {
		if aiFired(t, "AI-029", line+"\n") {
			t.Errorf("AI-029 reported %q as a DISABLED penalty — it is enabled, and this "+
				"is the remediation the rule recommends", line)
		}
	}
}

func TestAI041ReportsOnlyAboveThreshold(t *testing.T) {
	for _, line := range []string{
		`temperature=0.95,`,
		`top_p=0.99,`,
		`temperature = 1.0`,
		`top_p=1.00,`,
	} {
		if !aiFired(t, "AI-041", line+"\n") {
			t.Errorf("AI-041 stopped reporting a value above 0.9: %s", line)
		}
	}
}

func TestAI041IgnoresExactlyPointNine(t *testing.T) {
	for _, line := range []string{
		`top_p=0.9,`,
		`top_p=0.9,   # Nucleus sampling parameter`,
		`temperature=0.9`,
		`temperature=0.90`,
	} {
		if aiFired(t, "AI-041", line+"\n") {
			t.Errorf("AI-041 reported %q — the rule and its remediation both say >0.9, "+
				"and 0.9 is an ordinary nucleus-sampling value", line)
		}
	}
}

// TestAI041StillCatchesLongerDecimals guards the boundary from the other side:
// 0.900001 is above 0.9 and must still report.
func TestAI041StillCatchesLongerDecimals(t *testing.T) {
	if !aiFired(t, "AI-041", "temperature=0.9000001\n") {
		t.Error("AI-041 missed 0.9000001, which is greater than 0.9")
	}
	if aiFired(t, "AI-041", "temperature=0."+strings.Repeat("9", 1)+"0\n") {
		t.Error("AI-041 reported 0.90, which equals 0.9")
	}
}
