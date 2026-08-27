package attack

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
)

func TestCorrelateMergesStaticAndDynamic(t *testing.T) {
	res, _, _ := confirmedRun(t)
	fs := []findings.Finding{injectionFinding("fp-pi")}
	cors := Correlate(fs, res)
	if len(cors) != 1 {
		t.Fatalf("expected one correlation per finding, got %d", len(cors))
	}
	c := cors[0]
	if !c.StaticFlag {
		t.Error("StaticFlag must remain a separate, always-true claim")
	}
	if c.Fingerprint != "fp-pi" {
		t.Errorf("fingerprint=%q want fp-pi", c.Fingerprint)
	}
	if c.Exploitability != evidence.Confirmed {
		t.Errorf("expected the dynamic verdict to merge in (CONFIRMED), got %s", c.Exploitability)
	}
	if c.TraceID == "" || c.AttackPath == "" {
		t.Error("a merged correlation must link the trace and render its path")
	}
}

func TestCorrelateUnexercisedFindingStaysPotential(t *testing.T) {
	res, _, _ := confirmedRun(t)
	fs := []findings.Finding{
		injectionFinding("fp-pi"),                  // exercised
		{RuleID: "SEC-1", Fingerprint: "fp-other"}, // never exercised
	}
	cors := Correlate(fs, res)
	if len(cors) != 2 {
		t.Fatalf("expected two correlations (no duplication), got %d", len(cors))
	}
	byFP := map[string]Correlation{}
	for _, c := range cors {
		byFP[c.Fingerprint] = c
	}
	if byFP["fp-other"].Exploitability != evidence.Potential {
		t.Errorf("unexercised finding = %s, want POTENTIAL", byFP["fp-other"].Exploitability)
	}
	if !byFP["fp-other"].StaticFlag {
		t.Error("an unexercised finding is still statically flagged")
	}
}

func TestCorrelateNilResult(t *testing.T) {
	fs := []findings.Finding{injectionFinding("fp-pi")}
	cors := Correlate(fs, nil)
	if len(cors) != 1 || cors[0].Exploitability != evidence.Potential {
		t.Errorf("with no result every finding is POTENTIAL, got %+v", cors)
	}
}
