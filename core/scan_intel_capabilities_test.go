package core

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// headerProbe is an OSV-compatible endpoint that records the value of
// X-Nox-Client-Capabilities on every batch query it receives.
func headerProbe(t *testing.T) (srv *httptest.Server, seenFn func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			mu.Lock()
			seen = append(seen, r.Header.Get("X-Nox-Client-Capabilities"))
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// The intelligence source declares mirror-lag, because the verifier it runs
// under applies the lag rule; the OSV.dev reference never sees the header.
func TestScan_OnlyTheIntelligenceSourceDeclaresMirrorLag(t *testing.T) {
	intel, intelSeen := headerProbe(t)
	ref, refSeen := headerProbe(t)
	t.Setenv(IntelligenceEndpointEnv, intel.URL)

	dir := lockfileProject(t, "scan:\n  osv:\n    base_url: "+ref.URL+"\n    cache_disabled: true\n")
	if _, err := RunScanWithOptions(dir, ScanOptions{}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if got := intelSeen(); len(got) != 1 || got[0] != "mirror-lag" {
		t.Errorf("intelligence capabilities = %q, want [mirror-lag]", got)
	}
	if got := refSeen(); len(got) != 1 || got[0] != "" {
		t.Errorf("reference capabilities = %q, want one request without the header", got)
	}
}

// With verification off nothing separates lag from withholding, so the scan
// declares no capability and the service answers it live.
func TestScan_UnverifiedScanDeclaresNoCapabilities(t *testing.T) {
	intel, intelSeen := headerProbe(t)
	t.Setenv(IntelligenceEndpointEnv, intel.URL)

	dir := lockfileProject(t, "scan:\n  intelligence:\n    verify_against_osv: false\n  osv:\n    cache_disabled: true\n")
	if _, err := RunScanWithOptions(dir, ScanOptions{}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if got := intelSeen(); len(got) != 1 || got[0] != "" {
		t.Errorf("capabilities = %q, want one request without the header", got)
	}
}
