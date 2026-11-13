package deps

import (
	"context"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
)

// NOX Intelligence's nox_priority travels from the source's answer onto the
// finding, through the analyzer's own path; an answer without one adds
// nothing.
func TestPriorityReachesTheFinding(t *testing.T) {
	epss, pct := 0.42, 0.98
	src := &stubSource{
		name: "stub",
		records: map[string][]vulnsource.Record{
			"lodash": {
				{ID: "STUB-HOT", Summary: "hot", Priority: &vulnsource.Priority{
					Score: 1.42, Band: "epss", Rule: "epss-first-severity-cwe/v1",
					Why: "EPSS 42.0%", EPSS: &epss, EPSSPercentile: &pct,
				}},
				{ID: "STUB-PLAIN", Summary: "plain"},
			},
		},
	}
	_, artifacts := npmLockfile(t, "lodash", "4.17.20")
	_, fs, err := NewAnalyzer(WithSource(src), WithOSVBaseURL("http://127.0.0.1:1")).ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]string{}
	for _, f := range fs.Findings() {
		got[f.Metadata["vuln_id"]] = f.Metadata
	}
	hot := got["STUB-HOT"]
	want := map[string]string{
		"priority_score": "1.42", "priority_rule": "epss-first-severity-cwe/v1", "priority_band": "epss",
		"priority_why": "EPSS 42.0%", "priority_epss": "0.42", "priority_epss_percentile": "0.98",
	}
	for k, v := range want {
		if hot[k] != v {
			t.Errorf("STUB-HOT %s = %q, want %q", k, hot[k], v)
		}
	}
	for k := range want {
		if _, ok := got["STUB-PLAIN"][k]; ok {
			t.Errorf("STUB-PLAIN carries %s without a priority", k)
		}
	}
}

// A score without the rule that produced it cannot be compared or re-derived,
// so it is not recorded.
func TestPriorityWithoutARuleIsNotRecorded(t *testing.T) {
	meta := map[string]string{}
	addPriorityMetadata(meta, &vulnsource.Record{Priority: &vulnsource.Priority{Score: 1.2, Band: "epss"}})
	if len(meta) != 0 {
		t.Errorf("recorded %v from a priority with no rule", meta)
	}
}
