package deps

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// These tests exercise the OSV WIRE PATH end to end: lockfile in, finding
// severity out, across a server that behaves the way api.osv.dev actually
// behaves.
//
// They exist because two severity bugs have now shipped with full unit-test
// coverage of the functions involved. Both times the defect was at a call site
// — data fetched from the network and then dropped before it reached the
// mapping function — while every test handed that function a struct built by
// hand. Asserting on mapOSVSeverity cannot catch that class of bug by
// construction. Asserting on the severity of the emitted finding can.

// fakeOSV serves the real two-endpoint OSV contract.
//
// The fidelity that matters: /v1/querybatch returns ONLY {id, modified}. Every
// other field — summary, severity, aliases, affected, database_specific —
// exists solely on the /v1/vulns/{id} response. A mock that returns full
// records from querybatch tests an API that does not exist, and will report
// success while the hydration path is broken.
func fakeOSV(t *testing.T, vulnsFor map[string][]string, advisories map[string]string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); ok {
			body, found := advisories[id]
			if !found {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}

		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding batch request: %v", err)
			return
		}

		results := make([]osvBatchResult, len(req.Queries))
		for i, q := range req.Queries {
			for _, id := range vulnsFor[q.Package.Name] {
				// ID and nothing else, exactly as the real endpoint answers.
				results[i].Vulns = append(results[i].Vulns, osvVuln{ID: id})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(osvBatchResponse{Results: results}); err != nil {
			t.Errorf("encoding batch response: %v", err)
		}
	}))
}

// scanOneNPMPackage runs the analyzer over a lockfile declaring a single npm
// package and returns the findings, so tests can assert on what an operator
// would actually see.
func scanOneNPMPackage(t *testing.T, srv *httptest.Server, name, version string) []findings.Finding {
	t.Helper()

	dir := t.TempDir()
	lock := fmt.Sprintf(`{"packages":{"node_modules/%s":{"version":%q}}}`, name, version)
	lockPath := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	analyzer := NewAnalyzer(WithOSVBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	_, fs, err := analyzer.ScanArtifacts(context.Background(), []discovery.Artifact{{
		Path:    "package-lock.json",
		AbsPath: lockPath,
		Type:    discovery.Lockfile,
		Size:    int64(len(lock)),
	}})
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	return fs.Findings()
}

func vulnSeverity(t *testing.T, items []findings.Finding) findings.Severity {
	t.Helper()

	for i := range items {
		if items[i].RuleID == "VULN-001" {
			return items[i].Severity
		}
	}
	t.Fatal("no VULN-001 finding was emitted")
	return ""
}

// TestOSVWire_CVSSv4OnlyAdvisoryKeepsItsSeverity is the regression test for the
// bug this release fixes: applyVulnDetails hydrated summary and severity but
// dropped database_specific, so the label fallback added for CVSS v4 advisories
// never received data and every such advisory reported medium.
func TestOSVWire_CVSSv4OnlyAdvisoryKeepsItsSeverity(t *testing.T) {
	t.Parallel()

	srv := fakeOSV(t,
		map[string][]string{"leftpad": {"GHSA-v4-only"}},
		map[string]string{
			"GHSA-v4-only": `{
				"id": "GHSA-v4-only",
				"summary": "Remote code execution",
				"severity": [{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
				"database_specific": {"severity": "CRITICAL"}
			}`,
		})
	defer srv.Close()

	got := vulnSeverity(t, scanOneNPMPackage(t, srv, "leftpad", "1.0.0"))
	if got != findings.SeverityCritical {
		t.Errorf("a CRITICAL advisory was reported as %s; a critical/high gate would not fire on it", got)
	}
}

// TestOSVWire_UnparseableCVSSFallsBackToLabel covers the second half of the
// bug. mapOSVSeverity returned on the first CVSS_V2/V3 entry it saw, so an
// advisory carrying a v2 vector (which the scorer cannot parse) collapsed to
// medium even when the source database stated the severity plainly.
func TestOSVWire_UnparseableCVSSFallsBackToLabel(t *testing.T) {
	t.Parallel()

	srv := fakeOSV(t,
		map[string][]string{"leftpad": {"GHSA-v2-vector"}},
		map[string]string{
			"GHSA-v2-vector": `{
				"id": "GHSA-v2-vector",
				"summary": "Authentication bypass",
				"severity": [{"type":"CVSS_V2","score":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
				"database_specific": {"severity": "HIGH"}
			}`,
		})
	defer srv.Close()

	got := vulnSeverity(t, scanOneNPMPackage(t, srv, "leftpad", "1.0.0"))
	if got != findings.SeverityHigh {
		t.Errorf("expected the HIGH label to be honoured when the CVSS vector is unparseable, got %s", got)
	}
}

// TestOSVWire_ParsableVectorBeatsLabel guards the other direction: the coarse
// label is a fallback, not an override. A computable CVSS score is more precise
// and must win.
func TestOSVWire_ParsableVectorBeatsLabel(t *testing.T) {
	t.Parallel()

	srv := fakeOSV(t,
		map[string][]string{"leftpad": {"GHSA-v3-vector"}},
		map[string]string{
			"GHSA-v3-vector": `{
				"id": "GHSA-v3-vector",
				"summary": "Remote code execution",
				"severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
				"database_specific": {"severity": "LOW"}
			}`,
		})
	defer srv.Close()

	got := vulnSeverity(t, scanOneNPMPackage(t, srv, "leftpad", "1.0.0"))
	if got != findings.SeverityCritical {
		t.Errorf("expected the computed 9.8 vector to win over the LOW label, got %s", got)
	}
}

// TestOSVWire_HydratesEveryOperatorFacingField pins the full set of fields that
// must survive hydration. Each has already been shipped broken once: the batch
// endpoint supplies none of them, so any field omitted from applyVulnDetails is
// silently empty in production while unit tests that build the struct by hand
// keep passing.
func TestOSVWire_HydratesEveryOperatorFacingField(t *testing.T) {
	t.Parallel()

	srv := fakeOSV(t,
		map[string][]string{"leftpad": {"GHSA-complete"}},
		map[string]string{
			"GHSA-complete": `{
				"id": "GHSA-complete",
				"summary": "Prototype pollution",
				"details": "Long form description.",
				"aliases": ["CVE-2024-0001"],
				"severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
				"database_specific": {"severity": "CRITICAL"},
				"affected": [{
					"package": {"name":"leftpad","ecosystem":"npm"},
					"ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]
				}]
			}`,
		})
	defer srv.Close()

	items := scanOneNPMPackage(t, srv, "leftpad", "1.0.0")

	var f *findings.Finding
	for i := range items {
		if items[i].RuleID == "VULN-001" {
			f = &items[i]
			break
		}
	}
	if f == nil {
		t.Fatal("no VULN-001 finding was emitted")
	}

	if !strings.Contains(f.Message, "Prototype pollution") {
		t.Errorf("summary did not survive hydration: %q", f.Message)
	}
	if !strings.Contains(f.Metadata["aliases"], "CVE-2024-0001") {
		t.Errorf("aliases did not survive hydration: %q — VEX waivers keyed on CVE IDs will not match",
			f.Metadata["aliases"])
	}
	if f.Metadata["fixed_in"] != "1.2.3" {
		t.Errorf("fixed_in did not survive hydration: %q — nox fix has nothing to act on",
			f.Metadata["fixed_in"])
	}
	if f.Severity != findings.SeverityCritical {
		t.Errorf("severity did not survive hydration: %s", f.Severity)
	}
}

// TestOSVWire_MultiRangeAdvisoryRemediatesForwards checks the whole path, not
// just the selection: the installed version has to reach fixedVersion from the
// call site, and the remediation command has to carry the version that was
// selected.
//
// Shaped after GHSA-47m2-4cr7-mhcw, where reporting the first range's fix told
// operators running 0.54.0 to move to 0.49.1.
func TestOSVWire_MultiRangeAdvisoryRemediatesForwards(t *testing.T) {
	t.Parallel()

	srv := fakeOSV(t,
		map[string][]string{"leftpad": {"GHSA-branches"}},
		map[string]string{
			"GHSA-branches": `{
				"id": "GHSA-branches",
				"summary": "Panic on undecryptable packets",
				"affected": [
					{
						"package": {"name":"leftpad","ecosystem":"npm"},
						"ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.49.1"}]}]
					},
					{
						"package": {"name":"leftpad","ecosystem":"npm"},
						"ranges": [{"type":"SEMVER","events":[{"introduced":"0.50.0"},{"fixed":"0.54.1"}]}]
					}
				]
			}`,
		})
	defer srv.Close()

	items := scanOneNPMPackage(t, srv, "leftpad", "0.54.0")

	var f *findings.Finding
	for i := range items {
		if items[i].RuleID == "VULN-001" {
			f = &items[i]
			break
		}
	}
	if f == nil {
		t.Fatal("no VULN-001 finding was emitted")
	}
	if got := f.Metadata["fixed_in"]; got != "0.54.1" {
		t.Errorf("fixed_in = %q, want 0.54.1 — 0.49.1 is below the installed 0.54.0 and following it downgrades", got)
	}
	if got := f.Metadata["remediation_command"]; !strings.Contains(got, "0.54.1") {
		t.Errorf("remediation_command = %q, want it to name 0.54.1", got)
	}
}
