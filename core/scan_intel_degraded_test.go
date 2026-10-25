package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/findings"
)

// v0.20.0 of NOX Intelligence during an OSV outage (nox-intelligence#61): with
// X-Nox-Accept-Degraded: mirror it answers from its mirror, marks the query
// degraded, and carries provenance and nox_same_as on each record. Without the
// header it answers 503, so a client that does not send it fails over to
// nothing.
const mirrorOutageWire = `{"results":[{"vulns":[
 {"id":"GHSA-35jh-r3h4-6jhm","modified":"2026-05-01T00:00:00Z","aliases":["CVE-2021-23337"],
  "nox_provenance":[{"source":"osv.dev","via":"mirror","retrieved_at":"2026-10-25T04:00:00Z","modified":"2026-05-01T00:00:00Z"}],
  "nox_same_as":["GO-2021-9999"]},
 {"id":"GO-2021-9999","modified":"2026-05-01T00:00:00Z","aliases":["GHSA-35jh-r3h4-6jhm"],
  "nox_provenance":[{"source":"osv.dev","via":"mirror","retrieved_at":"2026-10-25T04:00:00Z","modified":"2026-05-01T00:00:00Z"}],
  "nox_same_as":["GHSA-35jh-r3h4-6jhm"]}],
 "nox_coverage":{"status":"degraded","reason":"upstream is unreachable; served from the local mirror corpus.","missing":["osv_live"],"source":"mirror","mirror_synced_at":"2026-10-25T04:00:00Z"}}]}`

func mirrorOnlyIntel(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Nox-Accept-Degraded") != "mirror" {
			http.Error(w, `{"error":"upstream unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Nox-Intel-Source", "mirror")
		w.Header().Set("X-Nox-Intel-Incomplete", "1")
		_, _ = w.Write([]byte(mirrorOutageWire))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func osvDown(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The opt-in is for NOX Intelligence only; OSV.dev must never see it.
		if r.Header.Get("X-Nox-Accept-Degraded") != "" {
			t.Errorf("the reference source was sent X-Nox-Accept-Degraded")
		}
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func scanMirrorOutage(t *testing.T) *ScanResult {
	t.Helper()
	t.Setenv(IntelligenceEndpointEnv, mirrorOnlyIntel(t).URL)
	dir := lockfileProject(t, "scan:\n  osv:\n    base_url: "+osvDown(t).URL+"\n    cache_disabled: true\n")
	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	return res
}

func vulnFindings(res *ScanResult) []findings.Finding {
	var out []findings.Finding
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "VULN-001" {
			out = append(out, f)
		}
	}
	return out
}

// During an OSV outage the scan still finds the vulnerability, says it came
// from the mirror, and is not a clean report.
func TestScan_OSVOutageIsAnsweredFromTheMirrorAndSaysSo(t *testing.T) {
	res := scanMirrorOutage(t)

	vs := vulnFindings(res)
	if len(vs) != 1 {
		t.Fatalf("got %d VULN-001 findings, want 1 (two ids, one vulnerability): %+v", len(vs), vs)
	}
	m := vs[0].Metadata
	if m["advisory_via"] != "mirror" || m["advisory_source"] != "osv.dev" {
		t.Errorf("provenance metadata = via %q source %q", m["advisory_via"], m["advisory_source"])
	}
	if m["advisory_mirror_synced_at"] != "2026-10-25T04:00:00Z" {
		t.Errorf("advisory_mirror_synced_at = %q", m["advisory_mirror_synced_at"])
	}
	if _, ok := m["advisory_retrieved_at"]; ok {
		t.Error("a live retrieval time is the wall clock; it must not be written into findings")
	}

	var incomplete *degrade.Degradation
	for i, d := range res.Degradations {
		if d.Kind == degrade.IntelIncomplete {
			incomplete = &res.Degradations[i]
		}
	}
	if incomplete == nil || !incomplete.Blocks() {
		t.Fatalf("a mirror-only answer must be a blocking intel_incomplete degradation: %+v", res.Degradations)
	}
}

// One vulnerability under two ids is one finding, and neither id is lost: a
// waiver written against either still matches.
func TestScan_SameAsIdsCollapseToOneFindingKeepingBothIds(t *testing.T) {
	vs := vulnFindings(scanMirrorOutage(t))
	if len(vs) != 1 {
		t.Fatalf("got %d findings, want 1", len(vs))
	}
	m := vs[0].Metadata
	ids := m["vuln_id"] + "," + m["aliases"]
	for _, want := range []string{"GHSA-35jh-r3h4-6jhm", "GO-2021-9999", "CVE-2021-23337"} {
		if !strings.Contains(ids, want) {
			t.Errorf("%s is no longer reachable from the finding: vuln_id=%q aliases=%q", want, m["vuln_id"], m["aliases"])
		}
	}
	if m["vuln_id"] != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("vuln_id = %q, want the smallest id when severities tie", m["vuln_id"])
	}
}

// The findings JSON for the same answer is byte-identical across runs.
func TestScan_MirrorProvenanceIsDeterministic(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	render := func() string {
		res := scanMirrorOutage(t)
		b, err := res.JSONReporter("test").Generate(res.Findings)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// The endpoints differ per run (random ports) only in the degradation
	// detail's source name, which does not include them.
	if a, b := render(), render(); a != b {
		t.Errorf("findings.json differs between identical runs")
	}
}
