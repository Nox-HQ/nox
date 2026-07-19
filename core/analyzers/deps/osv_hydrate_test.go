package deps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// OSV's /v1/querybatch returns only {id, modified} — no severity, summary or
// affected ranges. Without a follow-up fetch every dependency finding gets the
// conservative SeverityMedium default and an empty summary, which means a
// critical dependency CVE can never trip a high/critical CI gate.
func TestHydrateVulnDetails_FillsSeverityAndSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vulns/GO-2026-9999" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{
			"id": "GO-2026-9999",
			"summary": "Remote code execution in example",
			"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"affected": [{
				"package": {"name": "example.com/mod", "ecosystem": "Go"},
				"ecosystem_specific": {"imports": [{"path": "example.com/mod/vulnerable"}]}
			}]
		}`))
	}))
	defer srv.Close()

	vulns := []osvVuln{{ID: "GO-2026-9999"}}
	hydrateVulnDetails(context.Background(), srv.Client(), srv.URL, vulns)

	got := vulns[0]
	if got.Summary != "Remote code execution in example" {
		t.Errorf("summary not hydrated: %q", got.Summary)
	}
	if sev := mapOSVSeverity(got.Severity, osvDatabaseSpecific{}); sev != findings.SeverityCritical {
		t.Errorf("severity = %v, want critical (CVSS 9.8)", sev)
	}
	if len(got.Affected) != 1 {
		t.Fatalf("affected not hydrated: %+v", got.Affected)
	}
	imps := got.Affected[0].EcosystemSpecific.Imports
	if len(imps) != 1 || imps[0].Path != "example.com/mod/vulnerable" {
		t.Errorf("import paths not hydrated: %+v", imps)
	}
}

// Each distinct advisory is fetched once, however many packages reference it.
func TestHydrateVulnDetails_CachesByID(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"id":"GO-1","summary":"s"}`))
	}))
	defer srv.Close()

	vulns := []osvVuln{{ID: "GO-1"}, {ID: "GO-1"}, {ID: "GO-1"}}
	hydrateVulnDetails(context.Background(), srv.Client(), srv.URL, vulns)

	if n := calls.Load(); n != 1 {
		t.Errorf("expected 1 request for 3 copies of the same ID, got %d", n)
	}
	for i, v := range vulns {
		if v.Summary != "s" {
			t.Errorf("vuln %d not hydrated: %+v", i, v)
		}
	}
}

// Hydration is best-effort: a failing detail lookup must leave the finding
// intact rather than dropping it. Under-reporting severity is bad; losing the
// finding entirely is worse.
func TestHydrateVulnDetails_FailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	vulns := []osvVuln{{ID: "GO-1", Summary: "original"}}
	hydrateVulnDetails(context.Background(), srv.Client(), srv.URL, vulns)

	if vulns[0].ID != "GO-1" || vulns[0].Summary != "original" {
		t.Errorf("failed lookup must not clobber the finding: %+v", vulns[0])
	}
}
