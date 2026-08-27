package attack

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
)

// allExploitability is every state Classify must handle, plus one unrecognised
// value: a classifier that panics or scores wildly on an unknown state is a
// classifier that breaks the day the evidence ladder grows a rung.
var allExploitability = []evidence.Exploitability{
	evidence.Confirmed,
	evidence.Prevented,
	evidence.Inconclusive,
	evidence.Plausible,
	evidence.Potential,
	evidence.Exploitability("SOMETHING-NEW"),
}

// TestClassifyScenarioLibraryIsFullyMapped fails when a scenario is added
// without its standards mapping. An unclassified scenario silently produces
// traces with no ASI, no CWE, and an unknown impact weight, which is the exact
// gap this package exists to close.
func TestClassifyScenarioLibraryIsFullyMapped(t *testing.T) {
	for _, s := range Scenarios() {
		t.Run(s.ID, func(t *testing.T) {
			if s.OWASPASI == "" {
				t.Error("no OWASP ASI category")
			}
			if s.OWASPLLM == "" {
				t.Error("no OWASP LLM Top 10 category")
			}
			if s.CWE == "" {
				t.Error("no CWE")
			}
			if s.CVSSVector == "" {
				t.Error("no CVSS vector")
			}
			if !strings.HasPrefix(s.OWASPASI, "ASI") {
				t.Errorf("OWASPASI = %q, want an ASINN identifier", s.OWASPASI)
			}
			if !strings.HasPrefix(s.OWASPLLM, "LLM") {
				t.Errorf("OWASPLLM = %q, want an LLMNN identifier", s.OWASPLLM)
			}
			if !strings.HasPrefix(s.CWE, "CWE-") {
				t.Errorf("CWE = %q, want a CWE-NNN identifier", s.CWE)
			}
		})
	}
}

// TestClassifyScenarioVectorsParseAndWeigh checks every library vector is a
// well-formed CVSS v4.0 base vector that nox can weigh. A typo'd vector that
// fell through to the unknown weight would attach a plausible-looking number to
// a metric nobody wrote.
func TestClassifyScenarioVectorsParseAndWeigh(t *testing.T) {
	for _, s := range Scenarios() {
		t.Run(s.ID, func(t *testing.T) {
			if _, ok := parseCVSSv4Base(s.CVSSVector); !ok {
				t.Fatalf("vector %q is not a valid CVSS v4.0 base vector", s.CVSSVector)
			}
			w, ok := ImpactWeight(s.CVSSVector)
			if !ok {
				t.Fatalf("vector %q could not be weighed", s.CVSSVector)
			}
			if w <= 0 || w > 10 {
				t.Errorf("impact weight = %v, want 0 < w <= 10", w)
			}
			c := Classify(s, evidence.Confirmed, 2, 2)
			if c.ImpactWeight != w {
				t.Errorf("Classification.ImpactWeight = %v, want %v", c.ImpactWeight, w)
			}
		})
	}
}

// nox must never present its own number as a CVSS score. The vector is
// published so a reader can score it with a real v4.0 calculator; the number
// beside it is nox's own, and the field names have to keep those apart.
func TestClassificationNeverLabelsItsScoreAsCVSS(t *testing.T) {
	raw, err := json.Marshal(Classify(Scenarios()[0], evidence.Confirmed, 2, 2))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range fields {
		if strings.Contains(strings.ToLower(k), "cvss") && k != "cvss_vector" {
			t.Errorf("field %q carries the CVSS name on a number nox did not compute with the CVSS algorithm", k)
		}
	}
	if _, ok := fields["cvss_vector"]; !ok {
		t.Error("the vector must be published: it is the checkable artifact")
	}
}

// The impact weight has to be a real function of the vector, not a constant.
// A weaker vector must weigh less than a stronger one, or the number carries no
// information at all.
func TestImpactWeightDiscriminates(t *testing.T) {
	const full = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	tests := []struct {
		name   string
		vector string
	}{
		{"attack requirement present", "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"privileges required", "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"local only", "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"confidentiality only", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
		{"no impact at all", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"},
	}
	base, ok := ImpactWeight(full)
	if !ok {
		t.Fatalf("the canonical full-impact vector must weigh")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, ok := ImpactWeight(tt.vector)
			if !ok {
				t.Fatalf("vector %q did not weigh", tt.vector)
			}
			if w >= base {
				t.Errorf("weight %v should be below the full-impact weight %v", w, base)
			}
		})
	}
}

func TestParseCVSSv4Base(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   bool
	}{
		{"full base vector", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", true},
		{"with threat metric appended", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", true},
		{"missing SA", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N", false},
		{"illegal metric value", "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", false},
		{"duplicate metric", "CVSS:4.0/AV:N/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", false},
		{"v3.1 vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", false},
		{"empty", "", false},
		{"prefix only", "CVSS:4.0/", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := parseCVSSv4Base(tt.vector); ok != tt.want {
				t.Errorf("parseCVSSv4Base(%q) ok = %v, want %v", tt.vector, ok, tt.want)
			}
		})
	}
}

// TestClassifyDemonstrationOrdering pins the ordering rather than the
// magnitudes: the factors are tunable, but the claim that a demonstrated
// exploit outranks a hypothesis is not.
func TestClassifyDemonstrationOrdering(t *testing.T) {
	for _, s := range Scenarios() {
		t.Run(s.ID, func(t *testing.T) {
			confirmed := Classify(s, evidence.Confirmed, 2, 2).Score
			inconclusive := Classify(s, evidence.Inconclusive, 0, 2).Score
			plausible := Classify(s, evidence.Plausible, 0, 0).Score
			prevented := Classify(s, evidence.Prevented, 0, 2).Score
			potential := Classify(s, evidence.Potential, 0, 0).Score

			if !(confirmed >= inconclusive) {
				t.Errorf("CONFIRMED (%v) scored below INCONCLUSIVE (%v)", confirmed, inconclusive)
			}
			if !(inconclusive >= plausible) {
				t.Errorf("INCONCLUSIVE (%v) scored below PLAUSIBLE (%v)", inconclusive, plausible)
			}
			if !(confirmed > prevented) {
				t.Errorf("CONFIRMED (%v) did not outscore PREVENTED (%v)", confirmed, prevented)
			}
			if !(prevented > potential) {
				t.Errorf("PREVENTED (%v) did not outscore POTENTIAL (%v)", prevented, potential)
			}
			if confirmed != s.cvssBaseForTest(t) {
				t.Errorf("CONFIRMED score = %v, want the full base score %v", confirmed, s.cvssBaseForTest(t))
			}
		})
	}
}

// cvssBaseForTest returns the scenario's impact weight, failing the test if it
// has none.
func (s Scenario) cvssBaseForTest(t *testing.T) float64 {
	t.Helper()
	w, ok := ImpactWeight(s.CVSSVector)
	if !ok {
		t.Fatalf("scenario %s has no weighable vector", s.ID)
	}
	return w
}

// TestClassifyPreventedIsNeverZeroAndNeverClaimsSafety guards the subtlest
// failure mode in the whole scoring model: PREVENTED means "a defense held
// against the strategies tested", not "fixed". Zeroing the score, or wording
// the rationale as an assurance, turns an observation into a promise nox cannot
// keep.
func TestClassifyPreventedIsNeverZeroAndNeverClaimsSafety(t *testing.T) {
	for _, s := range Scenarios() {
		t.Run(s.ID, func(t *testing.T) {
			c := Classify(s, evidence.Prevented, 0, 2)
			if c.Score <= 0 {
				t.Errorf("PREVENTED scored %v; the weakness is still present, only defended", c.Score)
			}
			if c.Severity == string(findings.SeverityInfo) {
				t.Errorf("PREVENTED banded as %q; a defended weakness is not informational", c.Severity)
			}
			if !strings.Contains(c.Rationale, "defen") {
				t.Errorf("PREVENTED rationale does not mention the observed defense: %q", c.Rationale)
			}
		})
	}
}

// TestClassifyPartialReproductionScoresNoHigher checks a flaky exploit never
// outscores one that fired every time, while staying close to it — it is still
// a demonstrated exploit.
func TestClassifyPartialReproductionScoresNoHigher(t *testing.T) {
	for _, s := range Scenarios() {
		t.Run(s.ID, func(t *testing.T) {
			full := Classify(s, evidence.Confirmed, 3, 3)
			partial := Classify(s, evidence.Confirmed, 1, 3)
			if partial.Score > full.Score {
				t.Errorf("partial reproduction (%v) outscored full reproduction (%v)", partial.Score, full.Score)
			}
			if partial.Score < full.Score*0.8 {
				t.Errorf("partial reproduction (%v) fell far below full reproduction (%v); a flaky exploit is still an exploit", partial.Score, full.Score)
			}
			if !strings.Contains(partial.Rationale, "1 of 3") {
				t.Errorf("partial rationale does not report the tally: %q", partial.Rationale)
			}
		})
	}
}

// TestClassifyRationaleNeverAssertsSafety runs the full cross-product of
// scenarios and states. nox reports what it observed; it never tells a reader
// that something is safe or secure, because it has no way to establish that.
func TestClassifyRationaleNeverAssertsSafety(t *testing.T) {
	banned := []string{"safe", "secure"}
	for _, s := range Scenarios() {
		for _, e := range allExploitability {
			t.Run(s.ID+"/"+string(e), func(t *testing.T) {
				c := Classify(s, e, 1, 2)
				if strings.TrimSpace(c.Rationale) == "" {
					t.Fatal("empty rationale: a score that moved without saying why is a score nobody can check")
				}
				lower := strings.ToLower(c.Rationale)
				for _, w := range banned {
					if strings.Contains(lower, w) {
						t.Errorf("rationale asserts %q: %q", w, c.Rationale)
					}
				}
				if !findings.Severity(c.Severity).IsValid() {
					t.Errorf("severity %q is not a nox severity band", c.Severity)
				}
			})
		}
	}
}

// TestSeverityForScoreBands pins the qualitative bands at their boundaries.
// They are the standard CVSS scale, the same one core/analyzers/deps applies to
// dependency advisories, so a score means the same thing wherever it is shown.
func TestSeverityForScoreBands(t *testing.T) {
	tests := []struct {
		score float64
		want  findings.Severity
	}{
		{10.0, findings.SeverityCritical},
		{9.0, findings.SeverityCritical},
		{8.9, findings.SeverityHigh},
		{7.0, findings.SeverityHigh},
		{6.9, findings.SeverityMedium},
		{4.0, findings.SeverityMedium},
		{3.9, findings.SeverityLow},
		{0.1, findings.SeverityLow},
		{0.0, findings.SeverityInfo},
	}
	for _, tt := range tests {
		if got := severityForScore(tt.score); got != tt.want {
			t.Errorf("severityForScore(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// TestClassifyUnknownScenarioUsesUnknownBase checks a scenario with no vector
// lands mid-scale rather than at zero. A zero would read as "harmless", which
// is the one meaning nox has no evidence for.
func TestClassifyUnknownScenarioUsesUnknownBase(t *testing.T) {
	c := Classify(Scenario{ID: "UNMAPPED"}, evidence.Confirmed, 2, 2)
	if c.ImpactWeight != unknownImpactWeight {
		t.Errorf("ImpactWeight = %v, want the unknown weight %v", c.ImpactWeight, unknownImpactWeight)
	}
	if c.Score <= 0 {
		t.Errorf("Score = %v, want a non-zero unknown score", c.Score)
	}
	if !strings.Contains(c.Rationale, "unknown impact weight") {
		t.Errorf("rationale does not disclose the unknown impact weight: %q", c.Rationale)
	}
}

// TestClassifyIsDeterministic guards the package's core promise: the same
// inputs produce the same classification, every time.
func TestClassifyIsDeterministic(t *testing.T) {
	for _, s := range Scenarios() {
		for _, e := range allExploitability {
			first := Classify(s, e, 1, 2)
			for i := 0; i < 5; i++ {
				if got := Classify(s, e, 1, 2); got != first {
					t.Fatalf("Classify(%s, %s) drifted: %+v != %+v", s.ID, e, got, first)
				}
			}
		}
	}
}

// TestClassifyCarriesScenarioMapping checks the standards fields survive the
// hop from scenario to classification — the mapping is the whole point.
func TestClassifyCarriesScenarioMapping(t *testing.T) {
	for _, s := range Scenarios() {
		c := Classify(s, evidence.Plausible, 0, 0)
		if c.OWASPASI != s.OWASPASI || c.OWASPLLM != s.OWASPLLM || c.CWE != s.CWE || c.CVSSVector != s.CVSSVector {
			t.Errorf("%s: classification mapping %+v does not match scenario", s.ID, c)
		}
	}
}

// TestClassifiedTraceFillsClassification checks the trace-level helper resolves
// the scenario by ID, so a finalised trace always carries its mapping.
func TestClassifiedTraceFillsClassification(t *testing.T) {
	got := classified(Trace{
		ScenarioID:          ScenarioToolUnauth,
		Exploitability:      evidence.Confirmed,
		ReproductionHits:    2,
		ReproductionSamples: 2,
	})
	want, _ := ScenarioByID(ScenarioToolUnauth)
	if got.Classification.OWASPASI != want.OWASPASI {
		t.Errorf("OWASPASI = %q, want %q", got.Classification.OWASPASI, want.OWASPASI)
	}
	if got.Classification.Severity != string(findings.SeverityCritical) {
		t.Errorf("severity = %q, want critical for a fully reproduced %s", got.Classification.Severity, ScenarioToolUnauth)
	}
}
