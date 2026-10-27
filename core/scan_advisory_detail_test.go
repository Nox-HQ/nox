package core

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// detailReference is an OSV-compatible endpoint that finds one advisory for
// every query and answers its detail request with failFirst failures (HTTP 500)
// before a full record. failFirst < 0 fails forever.
func detailReference(t *testing.T, failFirst int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var detailCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if id, ok := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); ok {
			n := detailCalls.Add(1)
			if failFirst < 0 || n <= failFirst {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{"id":"` + id + `","modified":"2026-01-01T00:00:00Z","summary":"prototype pollution","database_specific":{"severity":"CRITICAL"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-detail-0001","modified":"2026-01-01T00:00:00Z"}]}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &detailCalls
}

func scanDetailProject(t *testing.T, ref *httptest.Server) *ScanResult {
	t.Helper()
	dir := lockfileProject(t, "scan:\n  intelligence:\n    disabled: true\n  osv:\n    base_url: "+ref.URL+"\n    cache_disabled: true\n")
	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	return res
}

// An advisory whose detail request keeps failing keeps a default severity, so a
// severity gate may not see it. The scan must say so with a blocking
// advisory_detail degradation (not a clean scan), and must not call the lookup
// itself failed: the finding is still reported.
func TestScan_PersistentDetailFailureIsABlockingAdvisoryDetailDegradation(t *testing.T) {
	ref, calls := detailReference(t, -1)
	res := scanDetailProject(t, ref)

	var got []string
	for _, d := range res.Degradations {
		if d.Kind == "advisory_detail" {
			got = append(got, d.Detail)
			if !d.Blocks() {
				t.Errorf("advisory_detail must be blocking: %+v", d)
			}
		}
		if d.Kind == "osv_lookup" {
			t.Errorf("a detail failure was reported as a failed lookup: %+v", d)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0], "GHSA-detail-0001") {
		t.Fatalf("advisory_detail degradations = %v, want one naming GHSA-detail-0001", got)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("detail endpoint was asked %d times, want 3 (the request and two retries)", n)
	}
	if len(res.Findings.ActiveFindings()) == 0 {
		t.Error("the finding itself must still be reported")
	}
}

// One 500 is retried and hydrates: nothing is degraded and the severity is real.
func TestScan_TransientDetailFailureIsRetriedAndReportsNothing(t *testing.T) {
	ref, calls := detailReference(t, 1)
	res := scanDetailProject(t, ref)

	for _, d := range res.Degradations {
		if d.Kind == "advisory_detail" || d.Kind == "osv_lookup" {
			t.Errorf("a retried detail fetch left a degradation: %+v", d)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("detail endpoint was asked %d times, want 2 (one failure, one retry)", n)
	}
	var critical bool
	for _, f := range res.Findings.ActiveFindings() {
		if strings.EqualFold(string(f.Severity), "critical") {
			critical = true
		}
	}
	if !critical {
		t.Error("the retried detail did not hydrate the advisory's severity")
	}
}
