package explain_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/explain"
	"github.com/nox-hq/nox/core/findings"
)

func subject() evidence.Subject {
	return evidence.Subject{Kind: evidence.SubjectCandidate, ID: "SEC-003@app/config.py:9"}
}

func baseInputs() explain.Inputs {
	return explain.Inputs{
		Finding: findings.Finding{
			RuleID: "SEC-003", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Location:    findings.Location{FilePath: "app/config.py", StartLine: 9},
			Message:     "GitHub Personal Access Token detected",
			Fingerprint: "abc123",
			Metadata:    map[string]string{"cwe": "CWE-798"},
		},
		Subject: subject(),
		Ledger: evidence.Ledger{Claims: []evidence.Claim{{
			Kind: evidence.KindStatic, Statement: "the embedded checksum verifies",
			Subject: subject(), Provenance: evidence.Provenance{Source: "nox-scan"},
		}}},
		Coverage: capability.NewCoverage(capability.DefaultRegistry()),
		Rule:     catalog.RuleMeta{ID: "SEC-003", Remediation: "Revoke the token"},
	}
}

// TestEveryQuestionIsAnswered. Milestone 9.3 lists eight questions, and an
// explanation that silently omits one is worse than no explanation: the reader
// assumes it was considered and had nothing to say.
//
// Checked by reflection so a field added later must be answered too, rather
// than quietly shipping empty.
func TestEveryQuestionIsAnswered(t *testing.T) {
	e := explain.Explain(baseInputs())
	v := reflect.ValueOf(e)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		switch f := v.Field(i); f.Kind() {
		case reflect.String:
			if strings.TrimSpace(f.String()) == "" {
				t.Errorf("%s is empty; an unanswered question reads as a considered silence", name)
			}
		case reflect.Slice:
			if f.Len() == 0 {
				t.Errorf("%s is empty; say that nothing was found rather than saying nothing", name)
			}
		}
	}
}

// TestNoAnswerAssertsSafety is the wording discipline every surface in this
// codebase shares, applied where a developer is most likely to want
// reassurance and least likely to get it honestly.
//
// "prevented" is banned alongside the obvious words: it is the kernel's term
// for a defense observed after execution, and a static scan executes nothing.
func TestNoAnswerAssertsSafety(t *testing.T) {
	banned := []string{"safe", "secure", "no risk", "not vulnerable", "prevented", "clean", "harmless"}

	inputs := []explain.Inputs{baseInputs(), {}, {
		Finding: findings.Finding{
			RuleID: "VULN-001", Severity: findings.SeverityCritical,
			Location: findings.Location{FilePath: "go.mod"},
			Message:  "vulnerable dependency",
			Metadata: map[string]string{
				"applicability":            "not_impacting",
				"applicability_reached":    "affected_version",
				"applicability_stopped_at": "symbol_used",
				"applicability_because":    "the build links no package under crypto/md5",
			},
		},
		Coverage: capability.NewCoverage(capability.DefaultRegistry()),
	}}

	for i, in := range inputs {
		e := explain.Explain(in)
		v := reflect.ValueOf(e)
		for f := 0; f < v.NumField(); f++ {
			var texts []string
			switch field := v.Field(f); field.Kind() {
			case reflect.String:
				texts = []string{field.String()}
			case reflect.Slice:
				for j := 0; j < field.Len(); j++ {
					texts = append(texts, field.Index(j).String())
				}
			}
			for _, text := range texts {
				low := strings.ToLower(text)
				for _, w := range banned {
					if strings.Contains(low, w) {
						t.Errorf("input %d, field %s says %q, which contains %q",
							i, v.Type().Field(f).Name, text, w)
					}
				}
			}
		}
	}
}

// TestNotImpactingIsAboutThePathNotTheApplication. A dependency whose
// vulnerable symbol is not linked is not impacting THROUGH THAT PATH, and the
// answer must say which path and stop there.
func TestNotImpactingIsAboutThePathNotTheApplication(t *testing.T) {
	in := baseInputs()
	in.Finding.Metadata = map[string]string{
		"applicability":            "not_impacting",
		"applicability_reached":    "affected_version",
		"applicability_stopped_at": "symbol_used",
		"applicability_because":    "the build links no package under crypto/md5",
	}
	got := explain.Explain(in).AffectsThisApplication
	if !strings.Contains(got, "crypto/md5") {
		t.Errorf("%q does not say WHY it does not impact", got)
	}
	if !strings.Contains(strings.ToLower(got), "another path") {
		t.Errorf("%q reads as a clearance for the application rather than for one path", got)
	}
}

// TestUndeterminedIsNotNo is the sentence this whole programme exists for.
func TestUndeterminedIsNotNo(t *testing.T) {
	in := baseInputs()
	in.Finding.Metadata = map[string]string{
		"applicability":            "undetermined",
		"applicability_reached":    "affected_version",
		"applicability_stopped_at": "call_reachable",
		"applicability_because":    "unsupported",
	}
	got := explain.Explain(in).AffectsThisApplication
	if !strings.Contains(strings.ToLower(got), "unknown") {
		t.Errorf("%q does not say the answer is unknown", got)
	}
	if !strings.Contains(strings.ToLower(got), "not the same as no") {
		t.Errorf("%q leaves an undetermined result to be read as a negative", got)
	}
}

// TestWhatWasNotEvaluatedSeparatesALimitFromAGap. "Nobody built the thing that
// would look" and "the thing that looks did not run here" send a reader to
// different places, and collapsing them wastes the answer.
func TestWhatWasNotEvaluatedSeparatesALimitFromAGap(t *testing.T) {
	in := baseInputs()
	in.Coverage.Record(subject(), capability.Taint, capability.Unknown)
	lines := strings.Join(explain.Explain(in).NotEvaluated, "\n")

	if !strings.Contains(lines, "no analysis on this installation can establish it") {
		t.Errorf("a capability nothing implements is not reported as a limit:\n%s", lines)
	}
	if !strings.Contains(lines, "could not determine anything") {
		t.Errorf("a capability that ran and could not tell is not distinguished:\n%s", lines)
	}
	if !strings.Contains(lines, "nothing asked this question here") {
		t.Errorf("a capability nothing asked is not distinguished:\n%s", lines)
	}
}

// TestSilenceIsNotAgreement. An empty "against" list must say that nothing was
// recorded against the finding AND that this is not the same as nothing having
// been looked for.
func TestSilenceIsNotAgreement(t *testing.T) {
	got := strings.Join(explain.Explain(baseInputs()).Against, " ")
	if !strings.Contains(got, "not the same as") {
		t.Errorf("%q lets an empty refutation list read as agreement", got)
	}
}

// TestARetractedClaimIsShownAsWithdrawn. A claim that weighs nothing still
// belongs in the explanation — it is why nox once thought otherwise — but a
// reader must not count it.
func TestARetractedClaimIsShownAsWithdrawn(t *testing.T) {
	in := baseInputs()
	in.Ledger.Claims[0].Status = evidence.StatusRetracted
	got := strings.Join(explain.Explain(in).Supports, " ")
	if !strings.Contains(got, "withdrawn") {
		t.Errorf("a retracted claim is listed as live support: %q", got)
	}
}

// TestTheExplanationIsDeterministic. The point of this package existing
// alongside the model-written one is that the same inputs always produce the
// same answers.
func TestTheExplanationIsDeterministic(t *testing.T) {
	in := baseInputs()
	in.Coverage.Record(subject(), capability.Taint, capability.Unknown)
	first := explain.Explain(in)
	for i := 0; i < 5; i++ {
		if got := explain.Explain(in); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs from the first; map iteration order is reaching the output", i)
		}
	}
}

// TestTheMatchedValueIsNeverPrinted. Metadata["match"] holds the raw matched
// value — for a secrets finding, the credential. This output goes to terminals
// and CI logs.
func TestTheMatchedValueIsNeverPrinted(t *testing.T) {
	const secret = "ghp_thisWouldBeALiveCredential000000000"
	in := baseInputs()
	in.Finding.Metadata["match"] = secret

	e := explain.Explain(in)
	v := reflect.ValueOf(e)
	for i := 0; i < v.NumField(); i++ {
		switch f := v.Field(i); f.Kind() {
		case reflect.String:
			if strings.Contains(f.String(), secret) {
				t.Errorf("%s printed the matched value; on a secrets finding that is the "+
					"credential, and this lands in CI logs", v.Type().Field(i).Name)
			}
		case reflect.Slice:
			for j := 0; j < f.Len(); j++ {
				if strings.Contains(f.Index(j).String(), secret) {
					t.Errorf("%s printed the matched value", v.Type().Field(i).Name)
				}
			}
		}
	}
}
