package core

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/report"
)

// incompleteIntel is NOX Intelligence v0.19.1 answering a query it could only
// partly check: no advisories, and nox_coverage saying so. The shape is the
// one recorded in nox-intelligence#56. An empty list here is "not fully
// checked", never "no vulnerabilities".
func incompleteIntel(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Nox-Intel-Incomplete", "1")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[],"nox_coverage":{"status":"incomplete","reason":"pagination stopped at 50 pages"}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The CLI used to decode only {"vulns": [...]}, so an answer the service had
// marked incomplete produced no degradation and no advisory_lookup — a report
// indistinguishable from a package with no advisories.
func TestScan_IncompleteIntelligenceAnswerIsNeverClean(t *testing.T) {
	intel := incompleteIntel(t)
	ref, _ := advisoryProbe(t) // the reference answers "none" for everything
	t.Setenv(IntelligenceEndpointEnv, intel.URL)

	dir := lockfileProject(t, "scan:\n  osv:\n    base_url: "+ref.URL+"\n    cache_disabled: true\n")
	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var found *degrade.Degradation
	for i, d := range res.Degradations {
		if d.Kind == degrade.IntelIncomplete {
			found = &res.Degradations[i]
		}
	}
	if found == nil {
		t.Fatalf("an incomplete answer produced no degradation: %+v", res.Degradations)
	}
	if !found.Blocks() {
		t.Error("the degradation does not block, so a gate counting them passes a partial answer")
	}
	if !strings.Contains(found.Detail, "npm/lodash@4.17.15") {
		t.Errorf("the affected package is not named: %q", found.Detail)
	}

	rep := res.JSONReporter("test")
	out, err := rep.Generate(res.Findings)
	if err != nil {
		t.Fatal(err)
	}
	buf := string(out)
	if !strings.Contains(buf, `"advisory_lookup": "`+report.AdvisoryLookupIncomplete+`"`) {
		t.Errorf("findings.json meta.advisory_lookup does not say the lookup was incomplete:\n%s", buf)
	}
}
