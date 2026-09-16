package ai

import (
	"strings"
	"testing"
)

// AI-029 and AI-041 were retired. They were tuning guidance wearing a CWE.
//
// Both were first repaired rather than retired: AI-029 ("LLM repetition
// penalties disabled") had matched `presence_penalty=0.1` as well as `=0`, and
// AI-041 ("high temperature/top_p settings") had matched exactly 0.9 while its
// own remediation said ">0.9". Fixing the matchers cut them from 446 and 385
// findings to 78 and 0 on crewAI. That is what made the real question visible:
// once the matcher was right, what was left?
//
// Normalising crewAI's findings back to authored occurrences -- its docs tree
// carries one page in ~14 versions and ~8 locales, so a single authored line
// is counted up to 48 times -- answered it:
//
//	AI-041  385 raw ->  35 authored -> 0 after the fix. Every occurrence had
//	        been `top_p=0.9`, an ordinary nucleus-sampling value. Nothing
//	        remained for the rule to say.
//	AI-029  446 raw ->  26 authored -> 12 after the fix, and all 12 are two
//	        lines of a documentation code sample:
//	            frequency_penalty=0.0,
//	            presence_penalty=0.0,
//
// 0.0 is the OpenAI API's own default for both parameters. The rule flagged a
// value for being the vendor default, and its remediation then advised setting
// them "(-2 to 0)" -- a range containing the value it had just reported. A rule
// cannot both flag 0 and recommend a range including 0.
//
// Neither carries a security proposition. Repetitive output and non-determinism
// are output-quality properties: no confidentiality, integrity or availability
// claim follows from either, and the CWEs attached (CWE-754, CWE-20) describe
// neither. "Different from a vendor default or recommendation" is not a
// security finding, and AI-029 was not even that -- it flagged the default.
//
// Retired rather than downgraded to info: nox emits SARIF to security gates,
// and an informational security finding is still a security finding for
// everything downstream of it. If a defensible proposition is found later --
// "temperature 1.0 on a model whose output is executed", say -- that is a new
// rule with its own evidence, not these two with a lower severity.

// TestRetiredTuningRulesStayRetired stops either coming back by the back door.
// Both fired only on configuration values; reintroducing them would restore
// findings that no security claim supports.
func TestRetiredTuningRulesStayRetired(t *testing.T) {
	t.Parallel()

	retired := map[string]string{
		"AI-029": "repetition penalties: flagged the vendor default, remediation included the flagged value",
		"AI-041": "temperature/top_p: output-determinism guidance, no security claim",
	}
	for _, r := range builtinAIRules() {
		if why, ok := retired[r.ID]; ok {
			t.Errorf("%s is back in the rule set (%s). If it has a security proposition now, "+
				"write it as a new rule with evidence and tests rather than restoring this one.",
				r.ID, why)
		}
	}
}

// TestTuningValuesAreNotReportedAsSecurityFindings is the behavioural half: the
// exact lines that produced 831 findings between them on crewAI must produce
// none. Asserting on the rule IDs alone would pass if another rule in this
// family picked the same lines up.
func TestTuningValuesAreNotReportedAsSecurityFindings(t *testing.T) {
	t.Parallel()

	// The crewAI documentation sample, verbatim.
	body := strings.Join([]string{
		"llm = LLM(",
		`    model="gpt-4o",`,
		"    temperature=0.7,",
		"    max_tokens=4000,",
		"    top_p=0.9,",
		"    frequency_penalty=0.0,",
		"    presence_penalty=0.0,",
		")",
	}, "\n")

	got, err := NewAnalyzer().ScanFile("llms.mdx", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		t.Errorf("%s reported ordinary LLM tuning values as a security finding: %s",
			got[i].RuleID, got[i].Message)
	}
}
