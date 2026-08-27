package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox/core/vulnsource"
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

	vulns := []vulnsource.Record{{ID: "GO-2026-9999"}}
	HydrateDetails(context.Background(), srv.Client(), srv.URL, vulns)

	got := vulns[0]
	if got.Summary != "Remote code execution in example" {
		t.Errorf("summary not hydrated: %q", got.Summary)
	}
	// Assert the vector arrived, not what it maps to: severity mapping is the
	// analyzer's job, and this layer's contract is only that the field the
	// mapping depends on is populated. That a CVSS 9.8 vector reaches a
	// critical finding end to end is covered in the deps package's wire tests.
	if len(got.Severity) != 1 || got.Severity[0].Score != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("severity not hydrated: %+v", got.Severity)
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

	vulns := []vulnsource.Record{{ID: "GO-1"}, {ID: "GO-1"}, {ID: "GO-1"}}
	HydrateDetails(context.Background(), srv.Client(), srv.URL, vulns)

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

	vulns := []vulnsource.Record{{ID: "GO-1", Summary: "original"}}
	HydrateDetails(context.Background(), srv.Client(), srv.URL, vulns)

	if vulns[0].ID != "GO-1" || vulns[0].Summary != "original" {
		t.Errorf("failed lookup must not clobber the finding: %+v", vulns[0])
	}
}

// TestApplyVulnDetails_CopiesEveryField is the structural guard for the bug
// that shipped twice in this file.
//
// /v1/querybatch returns only {id, modified}, so every other field of an
// advisory reaches nox exclusively through hydration. applyVulnDetails copies
// field by field, which means a field it forgets is silently empty in
// production while every unit test — which builds vulnsource.Record structs by hand —
// keeps passing. That is precisely how database_specific came to be dropped
// after summary and severity were already being copied.
//
// Reflection rather than a hand-written checklist: a checklist in a test fails
// the same way the implementation does, because the same author forgets in both
// places.
func TestApplyVulnDetails_CopiesEveryField(t *testing.T) {
	t.Parallel()

	detail := vulnsource.Record{
		ID:               "GHSA-x",
		Summary:          "a summary",
		Severity:         []vulnsource.Severity{{Type: "CVSS_V3", Score: "9.8"}},
		Aliases:          []string{"CVE-2024-0001"},
		Details:          "long form",
		Affected:         []vulnsource.Affected{{Package: vulnsource.Package{Name: "p", Ecosystem: "npm"}}},
		DatabaseSpecific: vulnsource.DatabaseSpecific{Severity: "CRITICAL"},
	}

	// Guard the guard: every field of vulnsource.Record must be set in the fixture, or
	// the completeness check below passes vacuously.
	dv := reflect.ValueOf(detail)
	for i := range dv.NumField() {
		if dv.Field(i).IsZero() {
			t.Fatalf("this test's fixture leaves vulnsource.Record.%s unset; populate it, then "+
				"make sure applyVulnDetails copies it",
				dv.Type().Field(i).Name)
		}
	}

	// A stub as querybatch actually returns it: ID and nothing else.
	vulns := []vulnsource.Record{{ID: "GHSA-x"}}
	applyVulnDetails(vulns, map[string]vulnsource.Record{"GHSA-x": detail})

	got := reflect.ValueOf(vulns[0])
	for i := range got.NumField() {
		if got.Field(i).IsZero() {
			t.Errorf("vulnsource.Record.%s was present in the hydrated advisory and is empty after "+
				"applyVulnDetails; it will be empty for every scan in production",
				got.Type().Field(i).Name)
		}
	}
}
