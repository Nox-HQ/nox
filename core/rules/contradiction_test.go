package rules

import (
	"regexp"
	"strings"
	"testing"
)

// retiredAI029 and retiredAI041 are the two rules withdrawn in v1.36.0, kept
// here verbatim as the retrospective corpus for this analysis.
//
// The question this file answers is not "does the code run" but "would it have
// said anything useful at the time". A candidate-surfacing signal that cannot
// re-derive the one case we already investigated by hand is not evidence; it
// is a tautology waiting to be discovered later.
var (
	retiredAI029 = &Rule{
		ID:          "AI-029",
		Pattern:     `(?im)(?:presence_penalty|frequency_penalty)["']?\s*[:=]\s*0(?:\.0+)?(?:[\s,)\]}]|$)`,
		Description: "LLM repetition penalties disabled",
		Remediation: "Set presence_penalty (-2 to 0) and frequency_penalty (-2 to 0) to reduce repetitive token generation. Default values of 0 may allow excessive repetition.",
	}
	retiredAI041 = &Rule{
		ID:          "AI-041",
		Pattern:     `(?i)(temperature|top_p)\s*[:=]\s*(?:0\.9[0-9]*[1-9]|1\.0+)`,
		Description: "AI model uses high temperature/top_p settings",
		Remediation: "High temperature (>0.9) increases randomness and reduces consistency. Use 0.1-0.3 for deterministic outputs.",
	}
)

// TestTheWithdrawnRuleIsRederived is the acceptance test for this signal.
func TestTheWithdrawnRuleIsRederived(t *testing.T) {
	got, ok := retiredAI029.RemediationContradiction()
	if !ok {
		t.Fatal("AI-029 not surfaced; the one case this signal exists to catch")
	}
	if got.Param != "presence_penalty" || got.Flagged != "0" {
		t.Errorf("read the wrong assignment: param=%q flagged=%q", got.Param, got.Flagged)
	}
	if got.Low != -2 || got.High != 0 {
		t.Errorf("read the wrong endorsed range: [%v,%v], want [-2,0]", got.Low, got.High)
	}
	if !strings.Contains(got.Endorsement, "-2 to 0") {
		t.Errorf("endorsement text %q does not quote the range it read", got.Endorsement)
	}
}

// TestTheOtherWithdrawnRuleIsNotSurfacedHere keeps this signal honest about
// its reach.
//
// AI-041 was withdrawn in the same release and for the same underlying reason
// — "different from the vendor's recommendation" is not a security
// proposition — but its remediation does NOT contradict its trigger: it flags
// temperature above 0.9 and recommends 0.1-0.3, which is consistent advice.
//
// Making this signal report AI-041 too would mean loosening it until it
// reported the thing we already knew the answer to, which is how a signal
// becomes a mirror. AI-041 is a case for the prevalence collapse signal, and
// it is correct for this one to stay silent.
func TestTheOtherWithdrawnRuleIsNotSurfacedHere(t *testing.T) {
	if c, ok := retiredAI041.RemediationContradiction(); ok {
		t.Fatalf("AI-041 surfaced as a contradiction it does not have: %+v", c)
	}
}

// TestSelfMatchIsNotTheSignal records the definition that was measured and
// rejected, so it is not proposed again.
//
// "The rule's pattern matches its own remediation" reports rules whose
// remediation quotes the defect in order to say remove it. Those are correct
// remediations. The property below is what makes the wider definition wrong,
// and it is asserted rather than described so it stays true.
func TestSelfMatchIsNotTheSignal(t *testing.T) {
	quotesDefectToRejectIt := &Rule{
		ID:          "IAC-203",
		Pattern:     `validate_certs\s*[:=]\s*false`,
		Remediation: "Enable certificate validation by removing validate_certs: false or setting it to true.",
	}
	re := regexp.MustCompile(quotesDefectToRejectIt.Pattern)
	if !re.MatchString(quotesDefectToRejectIt.Remediation) {
		t.Fatal("fixture no longer demonstrates self-match; pick another")
	}
	if c, ok := quotesDefectToRejectIt.RemediationContradiction(); ok {
		t.Fatalf("a remediation that quotes the defect to reject it was read as endorsing it: %+v", c)
	}
}

func TestAssignmentIsReadOutOfRegexSource(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		params  []string
		value   string
		ok      bool
	}{
		{"class operator", `(?i)(temperature|top_p)\s*[:=]\s*0`, []string{"temperature", "top_p"}, "0", true},
		{"non-capturing alternation", `(?im)(?:presence_penalty|frequency_penalty)["']?\s*[:=]\s*0(?:\.0+)?`, []string{"presence_penalty", "frequency_penalty"}, "0", true},
		{"bare identifier", `runAsNonRoot:\s*false`, []string{"runAsNonRoot"}, "false", true},
		{"flag argument", `--chmod[= ]777`, []string{"--chmod"}, "777", true},
		// A group colon is regex syntax. Reading it as an assignment is what
		// made the first draft extract nothing from AI-029.
		{"group colon is not an assignment", `(?:alpha|beta)`, nil, "", false},
		// A character class is not an identifier and its contents are not a
		// parameter name.
		{"character class is not a parameter", `[A-Za-z0-9]{32}=[A-Za-z0-9]{8}`, nil, "", false},
		// A pattern pinning a RANGE has no literal to compare against.
		{"alternation value is not a literal", `(?i)(temperature|top_p)\s*[:=]\s*(?:0\.9[0-9]*[1-9]|1\.0+)`, nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, value, ok := flaggedAssignment(tc.pattern)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v (params=%v value=%q)", ok, tc.ok, params, value)
			}
			if !tc.ok {
				return
			}
			if strings.Join(params, ",") != strings.Join(tc.params, ",") {
				t.Errorf("params=%v want %v", params, tc.params)
			}
			if value != tc.value {
				t.Errorf("value=%q want %q", value, tc.value)
			}
		})
	}
}

func TestEndorsementReadsTheClauseNotTheSentence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		remediation string
		param       string
		want        bool
	}{
		{"endorsed range", "Set presence_penalty (-2 to 0) to reduce repetition.", "presence_penalty", true},
		{"between spelling", "Configure top_p between 0.1 and 0.4.", "top_p", true},
		{"rejected range", "Avoid presence_penalty values of -2 to 0.", "presence_penalty", false},
		{"no verb at all", "presence_penalty -2 to 0.", "presence_penalty", false},
		// A rejection in an earlier sentence must not mute a later
		// recommendation, or a two-sentence remediation would go unread.
		{"rejection in a previous sentence", "Never disable this. Set presence_penalty 0.1 to 0.5.", "presence_penalty", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := len(endorsedRanges(tc.remediation, tc.param)) > 0
			if got != tc.want {
				t.Errorf("endorsed=%v want %v", got, tc.want)
			}
		})
	}
}
