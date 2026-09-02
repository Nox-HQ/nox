package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
)

// advisoryProbe is an OSV-compatible endpoint that answers every batch query
// with "no advisories" and counts how many it was asked.
func advisoryProbe(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var batches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			batches.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &batches
}

// lockfileProject is a directory with one npm dependency and the given
// .nox.yaml, so a scan of it issues exactly one batch query per source asked.
func lockfileProject(t *testing.T, noxYAML string) string {
	t.Helper()
	dir := t.TempDir()
	lock := `{"packages":{"node_modules/lodash":{"version":"4.17.15"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(noxYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A scan with nothing configured asks the intelligence service, and verifies
// the answer against the reference database. The default is compiled in, so
// the test reaches it through NOX_INTEL_ENDPOINT — the same fallback a
// pipeline uses to point every nox command at a self-hosted service.
func TestScan_IntelligenceIsTheDefaultSource(t *testing.T) {
	intel, intelBatches := advisoryProbe(t)
	ref, refBatches := advisoryProbe(t)
	t.Setenv(IntelligenceEndpointEnv, intel.URL)

	dir := lockfileProject(t, "scan:\n  osv:\n    base_url: "+ref.URL+"\n    cache_disabled: true\n")
	if _, err := RunScanWithOptions(dir, ScanOptions{}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if n := intelBatches.Load(); n != 1 {
		t.Errorf("intelligence service was asked %d times, want 1", n)
	}
	if n := refBatches.Load(); n != 1 {
		t.Errorf("reference database was asked %d times for verification, want 1", n)
	}
}

// `scan.intelligence.disabled` is the opt-out: the reference database is asked
// directly and the service is never contacted, even with an endpoint in the
// environment.
func TestScan_IntelligenceDisabledAsksTheReferenceDirectly(t *testing.T) {
	intel, intelBatches := advisoryProbe(t)
	ref, refBatches := advisoryProbe(t)
	t.Setenv(IntelligenceEndpointEnv, intel.URL)

	dir := lockfileProject(t, "scan:\n  intelligence:\n    disabled: true\n  osv:\n    base_url: "+ref.URL+"\n    cache_disabled: true\n")
	if _, err := RunScanWithOptions(dir, ScanOptions{}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if n := intelBatches.Load(); n != 0 {
		t.Errorf("intelligence service was asked %d times with intelligence disabled", n)
	}
	if n := refBatches.Load(); n != 1 {
		t.Errorf("reference database was asked %d times, want 1", n)
	}
}

// --offline still means nobody is asked. The default source must not have
// opened a path around the one switch operators rely on to keep a scan local.
func TestScan_OfflineAsksNobody(t *testing.T) {
	intel, intelBatches := advisoryProbe(t)
	ref, refBatches := advisoryProbe(t)
	t.Setenv(IntelligenceEndpointEnv, intel.URL)

	dir := lockfileProject(t, "scan:\n  osv:\n    base_url: "+ref.URL+"\n    cache_disabled: true\n")
	if _, err := RunScanWithOptions(dir, ScanOptions{Offline: true}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if n := intelBatches.Load() + refBatches.Load(); n != 0 {
		t.Errorf("an offline scan made %d network lookups", n)
	}
}

// advisoryReference is an OSV-compatible endpoint that publishes one advisory
// for every query, with the detail lookup hydration needs.
func advisoryReference(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			_, _ = w.Write([]byte(`{"id":"GHSA-ref-0001","summary":"reference advisory","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-ref-0001","modified":"2026-01-01T00:00:00Z"}]}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The promise in docs/intelligence.md: an unreachable service degrades to
// exactly the OSV scan nox always ran. The release E2E found the degradation
// said "withheld 4 record(s) … cannot be trusted to report completely" — the
// verifier could not tell a source that never answered from one that
// withheld everything. It must say unreachable, keep the reference's records,
// and never call silence a suppression.
func TestScan_UnreachableIntelligenceIsAnsweredByTheReference(t *testing.T) {
	ref := advisoryReference(t)
	t.Setenv(IntelligenceEndpointEnv, "http://127.0.0.1:1")

	dir := lockfileProject(t, "scan:\n  osv:\n    base_url: "+ref.URL+"\n    cache_disabled: true\n")
	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var vulns int
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "VULN-001" {
			vulns++
		}
	}
	if vulns != 1 {
		t.Errorf("the reference's advisory was lost: %d VULN-001 findings, want 1", vulns)
	}

	kinds := map[string]int{}
	for _, d := range res.Degradations {
		kinds[string(d.Kind)]++
	}
	if kinds[string(degrade.IntelUnreachable)] != 1 {
		t.Errorf("unreachable service not reported exactly once: %v", kinds)
	}
	if kinds[string(degrade.IntelSuppression)] != 0 {
		t.Errorf("an unreachable service was reported as withholding records: %v", kinds)
	}
	if kinds[string(degrade.OSV)] != 0 {
		t.Errorf("the reference answered, yet the scan claims to be under-reported: %v", kinds)
	}
}
