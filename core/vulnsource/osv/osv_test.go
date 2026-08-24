package osv

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox/core/vulnsource"
)

// encodeJSON writes JSON to the response writer.
func encodeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding response: %v", err)
	}
}

// decodeJSON reads JSON from the request body.
func decodeJSON(t *testing.T, r *http.Request, v any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Errorf("decoding request: %v", err)
	}
}

func TestQueryOSV_BatchQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Lookup follows each batch result with a /v1/vulns/{id} detail
		// lookup, since querybatch returns only {id, modified}. These tests
		// assert batch behaviour, so answer detail lookups with 404 — hydration
		// fails open and leaves the batch result untouched.
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var req BatchRequest
		decodeJSON(t, r, &req)

		// Return vulns for lodash and express, none for others.
		results := make([]BatchResult, len(req.Queries))
		for i, q := range req.Queries {
			switch q.Package.Name {
			case "lodash":
				results[i] = BatchResult{
					Vulns: []vulnsource.Record{
						{
							ID:      "GHSA-1234-5678-9012",
							Summary: "Prototype pollution in lodash",
							Severity: []vulnsource.Severity{
								{Type: "CVSS_V3", Score: "7.5"},
							},
							Aliases: []string{"CVE-2020-28500"},
						},
					},
				}
			case "express":
				results[i] = BatchResult{
					Vulns: []vulnsource.Record{
						{
							ID:      "GHSA-abcd-efgh-ijkl",
							Summary: "Path traversal in express",
							Severity: []vulnsource.Severity{
								{Type: "CVSS_V3", Score: "9.1"},
							},
							Aliases: []string{"CVE-2024-1234"},
						},
					},
				}
			}
		}

		encodeJSON(t, w, BatchResponse{Results: results})
	}))
	defer srv.Close()

	pkgs := []vulnsource.Query{
		{Name: "express", Version: "4.17.1", Ecosystem: "npm"},
		{Name: "react", Version: "18.0.0", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
	}

	result, err := New(srv.URL, srv.Client(), nil).Lookup(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	// express (index 0) and lodash (index 2) should have vulns.
	if len(result[0]) != 1 {
		t.Fatalf("expected 1 vuln for express, got %d", len(result[0]))
	}
	if result[0][0].ID != "GHSA-abcd-efgh-ijkl" {
		t.Errorf("expected GHSA-abcd-efgh-ijkl, got %s", result[0][0].ID)
	}

	if len(result[1]) != 0 {
		t.Fatalf("expected 0 vulns for react, got %d", len(result[1]))
	}

	if len(result[2]) != 1 {
		t.Fatalf("expected 1 vuln for lodash, got %d", len(result[2]))
	}
	if result[2][0].ID != "GHSA-1234-5678-9012" {
		t.Errorf("expected GHSA-1234-5678-9012, got %s", result[2][0].ID)
	}
}

func TestQueryOSV_LargeBatch(t *testing.T) {
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		var req BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Each batch should have at most 1000 queries.
		if len(req.Queries) > batchLimit {
			t.Errorf("batch size %d exceeds limit %d", len(req.Queries), batchLimit)
		}

		results := make([]BatchResult, len(req.Queries))
		encodeJSON(t, w, BatchResponse{Results: results})
	}))
	defer srv.Close()

	// Create 1500 packages to trigger 2 batches.
	pkgs := make([]vulnsource.Query, 1500)
	for i := range pkgs {
		pkgs[i] = vulnsource.Query{Name: "pkg", Version: "1.0.0", Ecosystem: "npm"}
	}

	_, err := New(srv.URL, srv.Client(), nil).Lookup(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if requestCount.Load() != 2 {
		t.Fatalf("expected 2 batch requests, got %d", requestCount.Load())
	}
}

func TestQueryOSV_NetworkError(t *testing.T) {
	// Use a server that immediately closes the connection.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "not a hijacker", http.StatusInternalServerError)
			return
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer srv.Close()

	pkgs := []vulnsource.Query{
		{Name: "express", Version: "4.17.1", Ecosystem: "npm"},
	}

	result, err := New(srv.URL, srv.Client(), nil).Lookup(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}

	// Should return empty result, not an error.
	if len(result) != 0 {
		t.Fatalf("expected 0 results on network error, got %d", len(result))
	}
}

func TestQueryOSV_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Detail lookups (/v1/vulns/{id}) carry no body and are answered 404;
		// hydration fails open, leaving the batch result as the test expects.
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req BatchRequest
		decodeJSON(t, r, &req)

		results := make([]BatchResult, len(req.Queries))
		encodeJSON(t, w, BatchResponse{Results: results})
	}))
	defer srv.Close()

	pkgs := []vulnsource.Query{
		{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	}

	result, err := New(srv.URL, srv.Client(), nil).Lookup(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected 0 results when no vulns found, got %d", len(result))
	}
}

func TestQueryOSV_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	pkgs := []vulnsource.Query{
		{Name: "express", Version: "4.17.1", Ecosystem: "npm"},
	}

	result, err := New(srv.URL, srv.Client(), nil).Lookup(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected 0 results on 500 status, got %d", len(result))
	}
}

// TestQueryOSV_SkipsUnknownEcosystem is a regression test for the bug where a
// package with an ecosystem OSV doesn't recognise (e.g. a Docker base image,
// ecosystem "docker") was included in the batch query. OSV's /v1/querybatch
// rejects the ENTIRE request with HTTP 400 if any single query names an unknown
// ecosystem, and that 400 was swallowed by graceful degradation — so a repo
// with a Dockerfile silently lost every real Go/npm/PyPI vulnerability finding.
func TestQueryOSV_SkipsUnknownEcosystem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Detail lookups (/v1/vulns/{id}) carry no body and are answered 404;
		// hydration fails open, leaving the batch result as the test expects.
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req BatchRequest
		decodeJSON(t, r, &req)

		// Mimic the real OSV API: reject the whole batch if any query carries an
		// ecosystem the API does not understand.
		valid := map[string]bool{
			"Go": true, "npm": true, "PyPI": true, "RubyGems": true,
			"crates.io": true, "Maven": true, "NuGet": true,
		}
		for _, q := range req.Queries {
			if !valid[q.Package.Ecosystem] {
				http.Error(w, "invalid ecosystem", http.StatusBadRequest)
				return
			}
		}

		results := make([]BatchResult, len(req.Queries))
		for i, q := range req.Queries {
			if q.Package.Name == "esbuild" {
				results[i] = BatchResult{Vulns: []vulnsource.Record{{
					ID:      "GHSA-g7r4-m6w7-qqqr",
					Summary: "arbitrary file read in esbuild dev server",
				}}}
			}
		}
		encodeJSON(t, w, BatchResponse{Results: results})
	}))
	defer srv.Close()

	// A Docker base image (unknown to OSV) mixed in with a real npm package.
	pkgs := []vulnsource.Query{
		{Name: "node", Version: "20-alpine", Ecosystem: "docker"},
		{Name: "esbuild", Version: "0.27.7", Ecosystem: "npm"},
	}

	got, err := New(srv.URL, srv.Client(), nil).Lookup(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	// The npm vuln (index 1) must be found despite the docker package (index 0).
	vulns, ok := got[1]
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected esbuild vuln at index 1, got %#v", got)
	}
	if vulns[0].ID != "GHSA-g7r4-m6w7-qqqr" {
		t.Errorf("unexpected vuln id: %s", vulns[0].ID)
	}
	// The docker package must not be queried (so no index 0 result).
	if _, exists := got[0]; exists {
		t.Errorf("docker package should not have been queried, got result at index 0")
	}
}

// TestQueryOSV_WarnsOnNon200 verifies that when the OSV API returns a non-200
// status, queryOSV degrades gracefully (empty result, no error) BUT emits a
// warning — so an OSV outage is not silently indistinguishable from a clean
// "no known vulnerabilities" scan.
func TestQueryOSV_WarnsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	var logBuf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	got, err := New(srv.URL, srv.Client(), nil).Lookup(context.Background(),
		[]vulnsource.Query{{Name: "lodash", Version: "4.17.0", Ecosystem: "npm"}})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result on degraded lookup, got %#v", got)
	}
	if logged := logBuf.String(); !strings.Contains(logged, "under-reported") || !strings.Contains(logged, "level=WARN") {
		t.Errorf("expected a WARN about under-reporting, got: %q", logged)
	}
}
