package deps

import (
	"context"
	"encoding/json"
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
		{
			// OSV publishes CVSS as a vector string. The base score is fully
			// determined by the vector, so it is computed rather than defaulted
			// to medium; this is the canonical 9.8 critical vector.
			name:     "CVSS v3 vector string",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			expected: findings.SeverityCritical,
		},
		{
			// v2 vectors use a different formula and are not computed; keep the
			// conservative default rather than guessing.
			// A v2 vector cannot be scored and there is no label to fall back
			// to, so medium here means "unknown" — not "this is a medium
			// vulnerability". The companion case in
			// TestMapOSVSeverity_FallsBackToLabel covers what happens when a
			// label IS available, which is where this previously went wrong.
			name:     "unscorable CVSS v2 vector with no label is unknown",
			input:    []osvSeverity{{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}},
			expected: findings.SeverityMedium,
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

// TestMapOSVSeverity_FallsBackToLabel covers the precedence between a CVSS
// entry and the source database's coarse label.
//
// The rule is "most precise signal wins", and the trap is that presence of a
// CVSS entry is not the same as being able to score it. Returning on any
// CVSS_V2/V3 entry meant an unscorable vector beat an accurate label, so
// advisories that plainly said CRITICAL were reported as medium.
func TestMapOSVSeverity_FallsBackToLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sev      []osvSeverity
		label    string
		expected findings.Severity
	}{
		{
			name:     "unscorable v2 vector yields to the label",
			sev:      []osvSeverity{{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}},
			label:    "CRITICAL",
			expected: findings.SeverityCritical,
		},
		{
			name:     "v4-only advisory uses the label",
			sev:      []osvSeverity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}},
			label:    "HIGH",
			expected: findings.SeverityHigh,
		},
		{
			name:     "a scorable v3 vector beats the label",
			sev:      []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			label:    "LOW",
			expected: findings.SeverityCritical,
		},
		{
			name:     "github MODERATE means medium",
			label:    "MODERATE",
			expected: findings.SeverityMedium,
		},
		{
			name:     "unrecognised label is unknown",
			label:    "SPICY",
			expected: findings.SeverityMedium,
		},
		{
			name:     "no signal at all is unknown",
			expected: findings.SeverityMedium,
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

// ---------------------------------------------------------------------------
// fixedVersion tests
// ---------------------------------------------------------------------------

// affected builds one osvAffected entry with a single range from the given
// events, so the table below reads as version ranges rather than JSON shapes.
func affected(name, eco string, events ...osvEvent) osvAffected {
	return osvAffected{
		Package: osvPackage{Name: name, Ecosystem: eco},
		Ranges:  []osvRange{{Type: "SEMVER", Events: events}},
	}
}

// TestFixedVersion covers the selection of a fix version out of an advisory's
// affected ranges.
//
// The case that matters is an advisory with more than one range: reporting a
// fix from a range the installed version is not in tells the operator to move
// to a version *below* the one they are running. A security scanner that
// recommends a downgrade is worse than one that says nothing, so every case
// where the covering range cannot be identified expects "".
func TestFixedVersion(t *testing.T) {
	t.Parallel()

	// The real GHSA-47m2-4cr7-mhcw, which is how this was found: two affected
	// entries, one per maintained release branch.
	quicGo := []osvAffected{
		affected("github.com/quic-go/quic-go", "Go", osvEvent{Introduced: "0"}, osvEvent{Fixed: "0.49.1"}),
		affected("github.com/quic-go/quic-go", "Go", osvEvent{Introduced: "0.50.0"}, osvEvent{Fixed: "0.54.1"}),
	}

	tests := []struct {
		name      string
		affected  []osvAffected
		pkg, eco  string
		installed string
		want      string
	}{
		{
			name:      "single range covering the installed version",
			affected:  []osvAffected{affected("github.com/foo/bar", "Go", osvEvent{Introduced: "0"}, osvEvent{Fixed: "1.2.4"})},
			pkg:       "github.com/foo/bar",
			eco:       "go",
			installed: "v1.2.0",
			want:      "1.2.4",
		},
		{
			name:      "GHSA-47m2-4cr7-mhcw: installed on the maintained branch",
			affected:  quicGo,
			pkg:       "github.com/quic-go/quic-go",
			eco:       "go",
			installed: "v0.54.0",
			want:      "0.54.1",
		},
		{
			name:      "GHSA-47m2-4cr7-mhcw: installed in the first range",
			affected:  quicGo,
			pkg:       "github.com/quic-go/quic-go",
			eco:       "go",
			installed: "v0.30.2",
			want:      "0.49.1",
		},
		{
			name:      "installed between two ranges is covered by neither",
			affected:  quicGo,
			pkg:       "github.com/quic-go/quic-go",
			eco:       "go",
			installed: "v0.49.5",
			want:      "",
		},
		{
			name:      "installed above every range",
			affected:  quicGo,
			pkg:       "github.com/quic-go/quic-go",
			eco:       "go",
			installed: "v1.0.0",
			want:      "",
		},
		{
			name: "two ranges inside one affected entry",
			affected: []osvAffected{{
				Package: osvPackage{Name: "p", Ecosystem: "npm"},
				Ranges: []osvRange{
					{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}, {Fixed: "1.9.2"}}},
					{Type: "SEMVER", Events: []osvEvent{{Introduced: "2.0.0"}, {Fixed: "2.4.1"}}},
				},
			}},
			pkg:       "p",
			eco:       "npm",
			installed: "2.3.0",
			want:      "2.4.1",
		},
		{
			name: "four events in one range",
			affected: []osvAffected{{
				Package: osvPackage{Name: "p", Ecosystem: "npm"},
				Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{
					{Introduced: "0"}, {Fixed: "1.9.2"},
					{Introduced: "2.0.0"}, {Fixed: "2.4.1"},
				}}},
			}},
			pkg:       "p",
			eco:       "npm",
			installed: "2.3.0",
			want:      "2.4.1",
		},
		{
			name:      "single range with no fix event",
			affected:  []osvAffected{affected("p", "npm", osvEvent{Introduced: "0"})},
			pkg:       "p",
			eco:       "npm",
			installed: "1.0.0",
			want:      "",
		},
		{
			// The branch the operator is on is still unfixed; the older branch
			// has a fix. Reporting it would be the downgrade this test exists
			// to prevent.
			name: "covering range is unfixed while an earlier range is fixed",
			affected: []osvAffected{
				affected("p", "npm", osvEvent{Introduced: "0"}, osvEvent{Fixed: "1.5.0"}),
				affected("p", "npm", osvEvent{Introduced: "2.0.0"}),
			},
			pkg:       "p",
			eco:       "npm",
			installed: "2.1.0",
			want:      "",
		},
		{
			name: "last_affected names no fix",
			affected: []osvAffected{
				affected("p", "npm", osvEvent{Introduced: "0"}, osvEvent{Fixed: "1.5.0"}),
				affected("p", "npm", osvEvent{Introduced: "2.0.0"}, osvEvent{LastAffected: "2.9.9"}),
			},
			pkg:       "p",
			eco:       "npm",
			installed: "2.5.0",
			want:      "",
		},
		{
			name:      "v prefix on the advisory's own versions",
			affected:  []osvAffected{affected("m", "Go", osvEvent{Introduced: "v1.0.0"}, osvEvent{Fixed: "v1.4.0"}), affected("m", "Go", osvEvent{Introduced: "v2.0.0"}, osvEvent{Fixed: "v2.1.0"})},
			pkg:       "m",
			eco:       "go",
			installed: "v2.0.3",
			want:      "v2.1.0",
		},
		{
			// A prerelease sorts below its release, so v0.54.1-rc.1 is still
			// inside [0.50.0, 0.54.1) and the fix still applies.
			name:      "prerelease of the fix version is still affected",
			affected:  quicGo,
			pkg:       "github.com/quic-go/quic-go",
			eco:       "go",
			installed: "v0.54.1-rc.1",
			want:      "0.54.1",
		},
		{
			name:      "prerelease of the introduced version is below the range",
			affected:  quicGo,
			pkg:       "github.com/quic-go/quic-go",
			eco:       "go",
			installed: "v0.50.0-beta1",
			want:      "",
		},
		{
			name:      "installed version carries no usable ordering",
			affected:  quicGo,
			pkg:       "github.com/quic-go/quic-go",
			eco:       "go",
			installed: "latest",
			want:      "",
		},
		{
			name:      "installed version is empty",
			affected:  quicGo,
			pkg:       "github.com/quic-go/quic-go",
			eco:       "go",
			installed: "",
			want:      "",
		},
		{
			name:      "non-matching package",
			affected:  []osvAffected{affected("other", "Go", osvEvent{Fixed: "1.0.0"})},
			pkg:       "github.com/foo/bar",
			eco:       "go",
			installed: "0.1.0",
			want:      "",
		},
		{
			name:      "matching name in a different ecosystem",
			affected:  []osvAffected{affected("p", "npm", osvEvent{Introduced: "0"}, osvEvent{Fixed: "1.0.0"})},
			pkg:       "p",
			eco:       "pypi",
			installed: "0.9.0",
			want:      "",
		},
		{
			name:      "no affected entries at all",
			affected:  nil,
			pkg:       "p",
			eco:       "npm",
			installed: "1.0.0",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := osvVuln{ID: "CVE-2024-1234", Affected: tt.affected}
			if got := fixedVersion(&v, tt.pkg, tt.eco, tt.installed); got != tt.want {
				t.Errorf("fixedVersion(%s@%s) = %q, want %q", tt.pkg, tt.installed, got, tt.want)
			}
		})
	}
}

// TestFixedVersion_NeverBelowInstalled is the property the table above encodes
// case by case: whatever fixedVersion returns for a comparable installed
// version, acting on it must never be a downgrade.
func TestFixedVersion_NeverBelowInstalled(t *testing.T) {
	t.Parallel()

	v := osvVuln{Affected: []osvAffected{
		affected("github.com/quic-go/quic-go", "Go", osvEvent{Introduced: "0"}, osvEvent{Fixed: "0.49.1"}),
		affected("github.com/quic-go/quic-go", "Go", osvEvent{Introduced: "0.50.0"}, osvEvent{Fixed: "0.54.1"}),
		affected("github.com/quic-go/quic-go", "Go", osvEvent{Introduced: "0.55.0"}, osvEvent{Fixed: "0.55.3"}),
	}}

	for _, installed := range []string{
		"v0.1.0", "v0.49.0", "v0.49.1", "v0.50.0", "v0.53.9",
		"v0.54.0", "v0.54.1", "v0.55.0", "v0.55.2", "v0.55.3", "v1.0.0",
	} {
		fix := fixedVersion(&v, "github.com/quic-go/quic-go", "go", installed)
		if fix == "" {
			continue
		}
		if compareGoVersions(fix, installed) <= 0 {
			t.Errorf("installed %s reported as fixed in %s — following that is a downgrade", installed, fix)
		}
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Detail lookups (/v1/vulns/{id}) carry no body and are answered 404;
		// hydration fails open, leaving the batch result as the test expects.
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req osvBatchRequest
		decodeJSON(t, r, &req)

		results := make([]osvBatchResult, len(req.Queries))
		for i, q := range req.Queries {
			if q.Package.Name == "lodash" {
				results[i] = osvBatchResult{
					Vulns: []osvVuln{
						{
							ID:      "GHSA-test-vuln-0001",
							Summary: "Prototype Pollution in lodash",
							Severity: []osvSeverity{
								{Type: "CVSS_V3", Score: "7.4"},
							},
							Aliases: []string{"CVE-2021-23337"},
							Details: "lodash versions prior to 4.17.21 are vulnerable.",
						},
					},
				}
			}
		}

		encodeJSON(t, w, osvBatchResponse{Results: results})
	}))
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Detail lookups (/v1/vulns/{id}) carry no body and are answered 404;
		// hydration fails open, leaving the batch result as the test expects.
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req osvBatchRequest
		decodeJSON(t, r, &req)

		results := make([]osvBatchResult, len(req.Queries))
		for i, q := range req.Queries {
			if q.Package.Name == "Django" {
				results[i] = osvBatchResult{
					Vulns: []osvVuln{
						{
							ID:      "GHSA-django-xss",
							Summary: "XSS in Django admin",
							Severity: []osvSeverity{
								{Type: "CVSS_V3", Score: "6.1"},
							},
							Aliases: []string{"CVE-2023-12345", "PYSEC-2023-001"},
							Details: "A cross-site scripting vulnerability exists in the Django admin.",
						},
					},
				}
			}
		}

		encodeJSON(t, w, osvBatchResponse{Results: results})
	}))
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
