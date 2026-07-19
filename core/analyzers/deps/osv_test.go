package deps

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// encodeJSON is a test helper that writes JSON to the response writer.
func encodeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding response: %v", err)
	}
}

// decodeJSON is a test helper that reads JSON from the request body.
func decodeJSON(t *testing.T, r *http.Request, v any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Errorf("decoding request: %v", err)
	}
}

// ---------------------------------------------------------------------------
// queryOSV tests
// ---------------------------------------------------------------------------

// osvFakeAPI returns a test server that models the REAL OSV API contract:
// /v1/querybatch answers with vulnerability IDs ONLY (no severity, summary,
// aliases or affected ranges), and full records are served exclusively from
// /v1/vulns/{id}. Mocking querybatch as if it returned full records — as this
// suite previously did — hides the fact that nox must hydrate, which is
// precisely how every dependency finding came to be reported as "medium" with
// an empty description and no fix version.
//
// details maps vulnerability ID to the full record served from /v1/vulns/{id};
// an ID absent from the map yields 404 so callers can exercise the
// hydration-failure path. vulnsFor maps a package name to the IDs querybatch
// reports for it.
func osvFakeAPI(t *testing.T, vulnsFor map[string][]string, details map[string]osvVuln) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); ok {
			detail, found := details[id]
			if !found {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			encodeJSON(t, w, detail)
			return
		}

		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var req osvBatchRequest
		decodeJSON(t, r, &req)

		results := make([]osvBatchResult, len(req.Queries))
		for i, q := range req.Queries {
			for _, id := range vulnsFor[q.Package.Name] {
				// Deliberately ID-only: this is all the real API returns.
				results[i].Vulns = append(results[i].Vulns, osvVuln{ID: id})
			}
		}
		encodeJSON(t, w, osvBatchResponse{Results: results})
	}))
}

func TestQueryOSV_BatchQuery(t *testing.T) {
	srv := osvFakeAPI(t,
		map[string][]string{
			"lodash":  {"GHSA-1234-5678-9012"},
			"express": {"GHSA-abcd-efgh-ijkl"},
		},
		map[string]osvVuln{
			"GHSA-1234-5678-9012": {
				ID:       "GHSA-1234-5678-9012",
				Summary:  "Prototype pollution in lodash",
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "7.5"}},
				Aliases:  []string{"CVE-2020-28500"},
			},
			"GHSA-abcd-efgh-ijkl": {
				ID:       "GHSA-abcd-efgh-ijkl",
				Summary:  "Path traversal in express",
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "9.1"}},
				Aliases:  []string{"CVE-2024-1234"},
			},
		})
	defer srv.Close()

	pkgs := []Package{
		{Name: "express", Version: "4.17.1", Ecosystem: "npm"},
		{Name: "react", Version: "18.0.0", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
	}

	result, err := queryOSV(context.Background(), srv.Client(), srv.URL, pkgs)
	if err != nil {
		t.Fatalf("queryOSV returned error: %v", err)
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

	// The fields below exist ONLY on the hydrated record. Asserting them is
	// what makes this test capable of catching a regression to the ID-only
	// querybatch data — the bug that made every finding medium-severity with
	// an empty message and no fix version.
	lodash := result[2][0]
	if lodash.Summary != "Prototype pollution in lodash" {
		t.Errorf("summary not hydrated: got %q", lodash.Summary)
	}
	if len(lodash.Severity) != 1 || lodash.Severity[0].Score != "7.5" {
		t.Errorf("severity not hydrated: got %+v", lodash.Severity)
	}
	if len(lodash.Aliases) != 1 || lodash.Aliases[0] != "CVE-2020-28500" {
		t.Errorf("aliases not hydrated: got %v", lodash.Aliases)
	}
	if got := mapOSVSeverity(lodash.Severity, lodash.DatabaseSpecific); got != findings.SeverityHigh {
		t.Errorf("expected high severity after hydration, got %s", got)
	}
}

// TestQueryOSV_HydrationFailureKeepsFinding pins the degradation contract: a
// vulnerability whose detail fetch fails is still reported (with a
// conservative severity) rather than silently dropped.
func TestQueryOSV_HydrationFailureKeepsFinding(t *testing.T) {
	// vulnsFor names an ID that details deliberately does not contain, so
	// /v1/vulns/{id} answers 404.
	srv := osvFakeAPI(t,
		map[string][]string{"lodash": {"GHSA-missing-detail"}},
		map[string]osvVuln{})
	defer srv.Close()

	pkgs := []Package{{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"}}

	result, err := queryOSV(context.Background(), srv.Client(), srv.URL, pkgs)
	if err != nil {
		t.Fatalf("queryOSV returned error: %v", err)
	}
	if len(result[0]) != 1 {
		t.Fatalf("expected the finding to survive a failed detail fetch, got %d", len(result[0]))
	}
	if result[0][0].ID != "GHSA-missing-detail" {
		t.Errorf("expected the stub ID to be preserved, got %s", result[0][0].ID)
	}
}

func TestQueryOSV_LargeBatch(t *testing.T) {
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Each batch should have at most 1000 queries.
		if len(req.Queries) > osvBatchLimit {
			t.Errorf("batch size %d exceeds limit %d", len(req.Queries), osvBatchLimit)
		}

		results := make([]osvBatchResult, len(req.Queries))
		encodeJSON(t, w, osvBatchResponse{Results: results})
	}))
	defer srv.Close()

	// Create 1500 packages to trigger 2 batches.
	pkgs := make([]Package, 1500)
	for i := range pkgs {
		pkgs[i] = Package{Name: "pkg", Version: "1.0.0", Ecosystem: "npm"}
	}

	_, err := queryOSV(context.Background(), srv.Client(), srv.URL, pkgs)
	if err != nil {
		t.Fatalf("queryOSV returned error: %v", err)
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

	pkgs := []Package{
		{Name: "express", Version: "4.17.1", Ecosystem: "npm"},
	}

	result, err := queryOSV(context.Background(), srv.Client(), srv.URL, pkgs)
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
		var req osvBatchRequest
		decodeJSON(t, r, &req)

		results := make([]osvBatchResult, len(req.Queries))
		encodeJSON(t, w, osvBatchResponse{Results: results})
	}))
	defer srv.Close()

	pkgs := []Package{
		{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	}

	result, err := queryOSV(context.Background(), srv.Client(), srv.URL, pkgs)
	if err != nil {
		t.Fatalf("queryOSV returned error: %v", err)
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

	pkgs := []Package{
		{Name: "express", Version: "4.17.1", Ecosystem: "npm"},
	}

	result, err := queryOSV(context.Background(), srv.Client(), srv.URL, pkgs)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected 0 results on 500 status, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// mapOSVSeverity tests
// ---------------------------------------------------------------------------

func TestMapOSVSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    []osvSeverity
		expected findings.Severity
	}{
		{
			name:     "critical CVSS v3",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "9.8"}},
			expected: findings.SeverityCritical,
		},
		{
			name:     "high CVSS v3",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "7.5"}},
			expected: findings.SeverityHigh,
		},
		{
			name:     "medium CVSS v3",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "5.3"}},
			expected: findings.SeverityMedium,
		},
		{
			name:     "low CVSS v3",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "2.1"}},
			expected: findings.SeverityLow,
		},
		{
			name:     "info CVSS v3",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "0.0"}},
			expected: findings.SeverityInfo,
		},
		{
			name:     "boundary critical/high 9.0",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "9.0"}},
			expected: findings.SeverityCritical,
		},
		{
			name:     "boundary high/medium 7.0",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "7.0"}},
			expected: findings.SeverityHigh,
		},
		{
			name:     "boundary medium/low 4.0",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "4.0"}},
			expected: findings.SeverityMedium,
		},
		{
			name:     "boundary low/info 0.1",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "0.1"}},
			expected: findings.SeverityLow,
		},
		{
			name:     "CVSS v2 fallback",
			input:    []osvSeverity{{Type: "CVSS_V2", Score: "8.5"}},
			expected: findings.SeverityHigh,
		},
		{
			name:     "no severity entries",
			input:    nil,
			expected: findings.SeverityMedium,
		},
		{
			name:     "empty slice",
			input:    []osvSeverity{},
			expected: findings.SeverityMedium,
		},
		// The cases below carry CVSS vector strings, which is the form OSV
		// actually publishes. These previously all collapsed to medium.
		{
			name:     "CVSS v3 vector scores 9.8 critical",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			expected: findings.SeverityCritical,
		},
		{
			// CVE-2021-3121 (gogo/protobuf) — the record that exposed the bug.
			name:     "CVSS v3 vector scores 8.6 high",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"}},
			expected: findings.SeverityHigh,
		},
		{
			name:     "CVSS v3 vector with changed scope",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}},
			expected: findings.SeverityMedium,
		},
		{
			name:     "CVSS v3 vector with no impact scores info",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
			expected: findings.SeverityInfo,
		},
		{
			name:     "malformed vector falls back to medium",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:X/AC:L"}},
			expected: findings.SeverityMedium,
		},
		{
			name:     "prefers v3 over v2 regardless of order",
			input:    []osvSeverity{{Type: "CVSS_V2", Score: "2.1"}, {Type: "CVSS_V3", Score: "9.8"}},
			expected: findings.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapOSVSeverity(tt.input, osvDatabaseSpecific{})
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestMapOSVSeverity_DatabaseSpecificFallback covers records that carry no
// parsable CVSS vector — notably CVSS v4-only advisories — where the coarse
// GitHub severity label is the only signal available.
func TestMapOSVSeverity_DatabaseSpecificFallback(t *testing.T) {
	tests := []struct {
		name     string
		sev      []osvSeverity
		label    string
		expected findings.Severity
	}{
		{"critical label", nil, "CRITICAL", findings.SeverityCritical},
		{"high label", nil, "HIGH", findings.SeverityHigh},
		{"github moderate means medium", nil, "MODERATE", findings.SeverityMedium},
		{"low label", nil, "LOW", findings.SeverityLow},
		{"lowercase label", nil, "high", findings.SeverityHigh},
		{"unknown label falls back to medium", nil, "SPICY", findings.SeverityMedium},
		{"no signal at all falls back to medium", nil, "", findings.SeverityMedium},
		{
			name:     "cvss v4 vector is not scored, label wins",
			sev:      []osvSeverity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}},
			label:    "CRITICAL",
			expected: findings.SeverityCritical,
		},
		{
			name:     "parsable vector beats the coarse label",
			sev:      []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			label:    "LOW",
			expected: findings.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapOSVSeverity(tt.sev, osvDatabaseSpecific{Severity: tt.label})
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

// TestCVSS3BaseScore checks the base-score computation against vectors with
// scores published in the CVSS v3.1 specification and the NVD.
func TestCVSS3BaseScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H", 8.6},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, ok := cvssBaseScore(tt.vector)
			if !ok {
				t.Fatalf("expected %s to score, got ok=false", tt.vector)
			}
			if math.Abs(got-tt.want) > 0.05 {
				t.Errorf("expected %.1f, got %.1f", tt.want, got)
			}
		})
	}
}

func TestCVSSBaseScore_Rejects(t *testing.T) {
	for _, vector := range []string{
		"",
		"not a vector",
		"CVSS:3.1/AV:N/AC:L", // missing required metrics
		"CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // unknown AV value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H", // invalid scope
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	} {
		t.Run(vector, func(t *testing.T) {
			if score, ok := cvssBaseScore(vector); ok {
				t.Errorf("expected %q to be rejected, got score %.1f", vector, score)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// fixedVersion tests
// ---------------------------------------------------------------------------

func TestFixedVersion_ExtractsFromAffected(t *testing.T) {
	t.Parallel()

	v := osvVuln{
		ID: "CVE-2024-1234",
		Affected: []osvAffected{{
			Package: osvPackage{Name: "github.com/foo/bar", Ecosystem: "Go"},
			Ranges: []osvRange{{
				Type: "SEMVER",
				Events: []osvEvent{
					{Introduced: "0"},
					{Fixed: "1.2.4"},
				},
			}},
		}},
	}
	got := fixedVersion(&v, "github.com/foo/bar", "go")
	if got != "1.2.4" {
		t.Errorf("expected 1.2.4, got %q", got)
	}
}

func TestFixedVersion_NoMatch(t *testing.T) {
	t.Parallel()

	v := osvVuln{Affected: []osvAffected{{
		Package: osvPackage{Name: "other", Ecosystem: "Go"},
		Ranges:  []osvRange{{Events: []osvEvent{{Fixed: "1.0.0"}}}},
	}}}
	if got := fixedVersion(&v, "github.com/foo/bar", "go"); got != "" {
		t.Errorf("expected empty for non-matching package, got %q", got)
	}
}

func TestFixedVersion_NoFixEvent(t *testing.T) {
	t.Parallel()

	v := osvVuln{Affected: []osvAffected{{
		Package: osvPackage{Name: "p", Ecosystem: "npm"},
		Ranges:  []osvRange{{Events: []osvEvent{{Introduced: "0"}}}},
	}}}
	if got := fixedVersion(&v, "p", "npm"); got != "" {
		t.Errorf("expected empty for unfixed vuln, got %q", got)
	}
}

func TestUpgradeCommand_ByEcosystem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		eco, pkg, ver, want string
	}{
		{"go", "github.com/foo/bar", "1.2.4", "go get github.com/foo/bar@v1.2.4"},
		{"npm", "express", "4.19.0", "npm install express@4.19.0"},
		{"pypi", "requests", "2.32.0", "pip install 'requests>=2.32.0'"},
	}
	for _, tt := range tests {
		got := upgradeCommand(tt.eco, tt.pkg, tt.ver)
		if got != tt.want {
			t.Errorf("upgradeCommand(%s, %s, %s) = %q, want %q", tt.eco, tt.pkg, tt.ver, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ecosystemToOSV tests
// ---------------------------------------------------------------------------

func TestEcosystemToOSV(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"go", "Go"},
		{"npm", "npm"},
		{"pypi", "PyPI"},
		{"rubygems", "RubyGems"},
		{"cargo", "crates.io"},
		{"maven", "Maven"},
		{"gradle", "Maven"},
		{"nuget", "NuGet"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ecosystemToOSV(tt.input)
			if result != tt.expected {
				t.Errorf("ecosystemToOSV(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ScanArtifacts integration tests
// ---------------------------------------------------------------------------

func TestScanArtifacts_WithOSV(t *testing.T) {
	// Mock OSV server returning a vulnerability for lodash.
	srv := osvFakeAPI(t,
		map[string][]string{"lodash": {"GHSA-test-vuln-0001"}},
		map[string]osvVuln{
			"GHSA-test-vuln-0001": {
				ID:       "GHSA-test-vuln-0001",
				Summary:  "Prototype Pollution in lodash",
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "7.4"}},
				Aliases:  []string{"CVE-2021-23337"},
				Details:  "lodash versions prior to 4.17.21 are vulnerable.",
			},
		})
	defer srv.Close()

	tmpDir := t.TempDir()

	// Write a package-lock.json with express and lodash.
	lockContent := []byte(`{
  "packages": {
    "node_modules/express": {"version": "4.18.2"},
    "node_modules/lodash": {"version": "4.17.20"}
  }
}`)
	lockPath := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockPath, lockContent, 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "package-lock.json",
			AbsPath: lockPath,
			Type:    discovery.Lockfile,
			Size:    int64(len(lockContent)),
		},
	}

	analyzer := NewAnalyzer(WithOSVBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	inventory, fs, err := analyzer.ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	// Should have 2 packages.
	pkgs := inventory.Packages()
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	// Should have 1 finding (lodash vuln).
	fList := fs.Findings()
	if len(fList) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fList))
	}

	f := fList[0]
	if f.RuleID != "VULN-001" {
		t.Errorf("expected RuleID VULN-001, got %s", f.RuleID)
	}
	if f.Severity != findings.SeverityHigh {
		t.Errorf("expected severity high, got %s", f.Severity)
	}
	if f.Metadata["vuln_id"] != "GHSA-test-vuln-0001" {
		t.Errorf("expected vuln_id GHSA-test-vuln-0001, got %s", f.Metadata["vuln_id"])
	}
	if f.Metadata["package"] != "lodash" {
		t.Errorf("expected package lodash, got %s", f.Metadata["package"])
	}
	if !strings.Contains(f.Message, "GHSA-test-vuln-0001") {
		t.Errorf("expected message to contain vuln ID, got %s", f.Message)
	}
	if f.Location.FilePath != "package-lock.json" {
		t.Errorf("expected location package-lock.json, got %s", f.Location.FilePath)
	}

	// Verify vulnerabilities stored in inventory.
	allVulns := inventory.AllVulnerabilities()
	if allVulns == nil {
		t.Fatal("expected vulnerabilities in inventory")
	}
	// Find the lodash package index.
	var lodashIdx int
	for i, p := range pkgs {
		if p.Name == "lodash" {
			lodashIdx = i
			break
		}
	}
	vulns := inventory.Vulnerabilities(lodashIdx)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability for lodash, got %d", len(vulns))
	}
	if vulns[0].ID != "GHSA-test-vuln-0001" {
		t.Errorf("expected vuln ID GHSA-test-vuln-0001, got %s", vulns[0].ID)
	}
}

func TestScanArtifacts_OSVDisabled(t *testing.T) {
	// Start a server that should never be called.
	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	lockContent := []byte(`{"packages":{"node_modules/express":{"version":"4.18.2"}}}`)
	lockPath := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockPath, lockContent, 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "package-lock.json",
			AbsPath: lockPath,
			Type:    discovery.Lockfile,
			Size:    int64(len(lockContent)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled(), WithOSVBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	inventory, fs, err := analyzer.ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	if called.Load() {
		t.Fatal("OSV API was called despite being disabled")
	}

	pkgs := inventory.Packages()
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}

	if len(fs.Findings()) != 0 {
		t.Fatalf("expected 0 findings with OSV disabled, got %d", len(fs.Findings()))
	}
}

func TestScanArtifacts_VulnerabilityMetadata(t *testing.T) {
	srv := osvFakeAPI(t,
		map[string][]string{"Django": {"GHSA-django-xss"}},
		map[string]osvVuln{
			"GHSA-django-xss": {
				ID:       "GHSA-django-xss",
				Summary:  "XSS in Django admin",
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "6.1"}},
				Aliases:  []string{"CVE-2023-12345", "PYSEC-2023-001"},
				Details:  "A cross-site scripting vulnerability exists in the Django admin.",
			},
		})
	defer srv.Close()

	tmpDir := t.TempDir()
	reqContent := []byte("Django==4.2.1\n")
	reqPath := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(reqPath, reqContent, 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "requirements.txt",
			AbsPath: reqPath,
			Type:    discovery.Lockfile,
			Size:    int64(len(reqContent)),
		},
	}

	analyzer := NewAnalyzer(WithOSVBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	_, fs, err := analyzer.ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	fList := fs.Findings()
	if len(fList) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fList))
	}

	f := fList[0]
	if f.Metadata["vuln_id"] != "GHSA-django-xss" {
		t.Errorf("expected vuln_id GHSA-django-xss, got %s", f.Metadata["vuln_id"])
	}
	if f.Metadata["package"] != "Django" {
		t.Errorf("expected package Django, got %s", f.Metadata["package"])
	}
	if f.Metadata["version"] != "4.2.1" {
		t.Errorf("expected version 4.2.1, got %s", f.Metadata["version"])
	}
	if f.Metadata["ecosystem"] != "pypi" {
		t.Errorf("expected ecosystem pypi, got %s", f.Metadata["ecosystem"])
	}
	if !strings.Contains(f.Metadata["aliases"], "CVE-2023-12345") {
		t.Errorf("expected aliases to contain CVE-2023-12345, got %s", f.Metadata["aliases"])
	}
	if !strings.Contains(f.Metadata["aliases"], "PYSEC-2023-001") {
		t.Errorf("expected aliases to contain PYSEC-2023-001, got %s", f.Metadata["aliases"])
	}
	if f.Severity != findings.SeverityMedium {
		t.Errorf("expected severity medium (6.1), got %s", f.Severity)
	}
}

// ---------------------------------------------------------------------------
// Rules tests
// ---------------------------------------------------------------------------

func TestAnalyzer_Rules(t *testing.T) {
	a := NewAnalyzer(WithOSVDisabled())
	rs := a.Rules()
	allRules := rs.Rules()

	if len(allRules) < 3 {
		t.Fatalf("expected at least 3 rules (VULN-001, VULN-002, VULN-003), got %d", len(allRules))
	}

	// Verify VULN-001 is present with expected metadata.
	r, ok := rs.ByID("VULN-001")
	if !ok {
		t.Fatal("expected VULN-001 rule to exist")
	}
	if r.Severity != findings.SeverityHigh {
		t.Errorf("expected VULN-001 severity high, got %s", r.Severity)
	}
	if r.Metadata["cwe"] != "CWE-1395" {
		t.Errorf("expected VULN-001 CWE-1395, got %s", r.Metadata["cwe"])
	}

	// Verify VULN-002 and VULN-003 are present.
	if !rs.HasID("VULN-002") {
		t.Error("expected VULN-002 rule to exist")
	}
	if !rs.HasID("VULN-003") {
		t.Error("expected VULN-003 rule to exist")
	}
}

// ---------------------------------------------------------------------------
// PackageInventory vulnerability storage tests
// ---------------------------------------------------------------------------

func TestPackageInventory_Vulnerabilities(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"})
	inv.Add(Package{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"})

	// Initially no vulns.
	if v := inv.Vulnerabilities(0); v != nil {
		t.Fatalf("expected nil vulns initially, got %v", v)
	}
	if v := inv.AllVulnerabilities(); v != nil {
		t.Fatalf("expected nil AllVulnerabilities initially, got %v", v)
	}

	// Set vulns for index 1.
	vulns := []Vulnerability{
		{ID: "GHSA-1", Summary: "test", Severity: findings.SeverityHigh},
	}
	inv.SetVulnerabilities(1, vulns)

	got := inv.Vulnerabilities(1)
	if len(got) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(got))
	}
	if got[0].ID != "GHSA-1" {
		t.Errorf("expected GHSA-1, got %s", got[0].ID)
	}

	all := inv.AllVulnerabilities()
	if len(all) != 1 {
		t.Fatalf("expected 1 entry in AllVulnerabilities, got %d", len(all))
	}
}

// ---------------------------------------------------------------------------
// Functional options tests
// ---------------------------------------------------------------------------

func TestWithOSVDisabled(t *testing.T) {
	a := NewAnalyzer(WithOSVDisabled())
	if a.osvEnabled {
		t.Error("expected osvEnabled to be false")
	}
}

func TestWithHTTPClient(t *testing.T) {
	client := &http.Client{}
	a := NewAnalyzer(WithHTTPClient(client))
	if a.httpClient != client {
		t.Error("expected custom HTTP client to be set")
	}
}

func TestWithOSVBaseURL(t *testing.T) {
	a := NewAnalyzer(WithOSVBaseURL("https://custom.osv.dev"))
	if a.OSVBaseURL != "https://custom.osv.dev" {
		t.Errorf("expected custom URL, got %s", a.OSVBaseURL)
	}
}

func TestNewAnalyzer_Defaults(t *testing.T) {
	a := NewAnalyzer()
	if a.OSVBaseURL != "https://api.osv.dev" {
		t.Errorf("expected default URL, got %s", a.OSVBaseURL)
	}
	if !a.osvEnabled {
		t.Error("expected osvEnabled to be true by default")
	}
	if a.httpClient == nil {
		t.Error("expected default HTTP client")
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
		if id, ok := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); ok {
			if id != "GHSA-g7r4-m6w7-qqqr" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			encodeJSON(t, w, osvVuln{
				ID:      id,
				Summary: "arbitrary file read in esbuild dev server",
			})
			return
		}

		var req osvBatchRequest
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

		// ID-only, as the real querybatch endpoint returns.
		results := make([]osvBatchResult, len(req.Queries))
		for i, q := range req.Queries {
			if q.Package.Name == "esbuild" {
				results[i] = osvBatchResult{Vulns: []osvVuln{{ID: "GHSA-g7r4-m6w7-qqqr"}}}
			}
		}
		encodeJSON(t, w, osvBatchResponse{Results: results})
	}))
	defer srv.Close()

	// A Docker base image (unknown to OSV) mixed in with a real npm package.
	pkgs := []Package{
		{Name: "node", Version: "20-alpine", Ecosystem: "docker"},
		{Name: "esbuild", Version: "0.27.7", Ecosystem: "npm"},
	}

	got, err := queryOSV(context.Background(), srv.Client(), srv.URL, pkgs)
	if err != nil {
		t.Fatalf("queryOSV returned error: %v", err)
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

	got, err := queryOSV(context.Background(), srv.Client(), srv.URL,
		[]Package{{Name: "lodash", Version: "4.17.0", Ecosystem: "npm"}})
	if err != nil {
		t.Fatalf("queryOSV returned error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result on degraded lookup, got %#v", got)
	}
	if logged := logBuf.String(); !strings.Contains(logged, "under-reported") || !strings.Contains(logged, "level=WARN") {
		t.Errorf("expected a WARN about under-reporting, got: %q", logged)
	}
}
