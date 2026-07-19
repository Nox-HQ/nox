package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/nox-hq/nox/core/findings"
)

// osvBatchLimit is the maximum number of queries per OSV batch request.
const osvBatchLimit = 1000

// osvQuery is a single package query for the OSV batch API.
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

// osvPackage identifies a package by name and ecosystem.
type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvBatchRequest is the request body for POST /v1/querybatch.
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

// osvBatchResponse is the response from the OSV batch endpoint.
type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

// osvBatchResult holds vulnerabilities for a single query.
type osvBatchResult struct {
	Vulns []osvVuln `json:"vulns"`
}

// osvVuln is a single vulnerability from OSV.
type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Aliases  []string      `json:"aliases"`
	Details  string        `json:"details"`
	Affected []osvAffected `json:"affected"`
}

// osvSeverity holds a CVSS or other severity score.
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvAffected describes packages and version ranges affected by a vuln.
type osvAffected struct {
	Package           osvPackage           `json:"package"`
	Ranges            []osvRange           `json:"ranges"`
	EcosystemSpecific osvEcosystemSpecific `json:"ecosystem_specific"`
}

// osvEcosystemSpecific carries per-ecosystem detail. For Go, OSV scopes an
// advisory to the import paths it actually affects — a module-level match alone
// overstates exposure (e.g. GO-2026-5932 affects only x/crypto/openpgp, not
// every consumer of x/crypto).
type osvEcosystemSpecific struct {
	Imports []osvImport `json:"imports"`
}

// osvImport is a single affected import path within a module.
type osvImport struct {
	Path string `json:"path"`
}

// osvRange is a version range with events marking introduction / fix.
type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

// osvEvent is a single point in a version range. Either Introduced or
// Fixed (or LastAffected) is populated; the others are empty.
type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// fixedVersion returns the lowest fixed version listed across the affected
// entries that match the given package name + ecosystem. Returns "" when
// the OSV record names no fix (an unfixed vulnerability).
func fixedVersion(vuln *osvVuln, pkgName, ecosystem string) string {
	want := strings.ToLower(pkgName)
	wantEco := ecosystemToOSV(ecosystem)
	var first string
	for _, aff := range vuln.Affected {
		if !strings.EqualFold(aff.Package.Name, want) {
			continue
		}
		if aff.Package.Ecosystem != "" && aff.Package.Ecosystem != wantEco {
			continue
		}
		for _, r := range aff.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && first == "" {
					first = e.Fixed
				}
			}
		}
	}
	return first
}

// queryOSV queries the OSV.dev batch API for known vulnerabilities affecting
// the given packages. It batches requests in groups of osvBatchLimit and
// returns a map from package index to the vulnerabilities found.
//
// On network errors the function returns an empty map (graceful degradation)
// rather than failing the scan, honouring Nox's offline-first design.
func queryOSV(ctx context.Context, client *http.Client, baseURL string, pkgs []Package) (map[int][]osvVuln, error) {
	result := make(map[int][]osvVuln)

	// Only query packages whose ecosystem OSV.dev actually understands. Other
	// "packages" reach the inventory too — notably Docker base images (ecosystem
	// "docker") from Dockerfile scanning — and OSV's /v1/querybatch rejects the
	// WHOLE request with HTTP 400 if any single query carries an unknown
	// ecosystem. That 400 was being swallowed by the graceful-degradation path
	// below, silently dropping every real Go/npm/PyPI result in the batch. So a
	// repo with a Dockerfile got zero dependency-CVE findings. Filter first, and
	// remember each kept query's original index so results map back correctly.
	type indexed struct {
		orig int
		pkg  Package
	}
	queryable := make([]indexed, 0, len(pkgs))
	for i, p := range pkgs {
		if _, ok := osvEcosystem(p.Ecosystem); ok {
			queryable = append(queryable, indexed{orig: i, pkg: p})
		}
	}

	for start := 0; start < len(queryable); start += osvBatchLimit {
		end := start + osvBatchLimit
		if end > len(queryable) {
			end = len(queryable)
		}
		batch := queryable[start:end]

		queries := make([]osvQuery, len(batch))
		for i, item := range batch {
			eco, _ := osvEcosystem(item.pkg.Ecosystem)
			queries[i] = osvQuery{
				Package: osvPackage{
					Name:      item.pkg.Name,
					Ecosystem: eco,
				},
				Version: item.pkg.Version,
			}
		}

		body, err := json.Marshal(osvBatchRequest{Queries: queries})
		if err != nil {
			return nil, fmt.Errorf("marshalling OSV request: %w", err)
		}

		url := strings.TrimRight(baseURL, "/") + "/v1/querybatch"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("creating OSV request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			// Network error — degrade gracefully, but say so: a silent empty
			// result is indistinguishable from "no vulnerabilities found".
			slog.WarnContext(ctx, "OSV query failed; dependency vulnerabilities may be under-reported",
				"error", err, "queries", len(queries))
			return result, nil
		}

		vulns, decodeErr := decodeBatchResponse(resp)
		_ = resp.Body.Close()
		if decodeErr != nil {
			// Non-200 status or undecodable body — same risk: don't report a
			// clean scan when the lookup actually failed.
			slog.WarnContext(ctx, "OSV query returned an error; dependency vulnerabilities may be under-reported",
				"error", decodeErr, "queries", len(queries))
			return result, nil
		}

		for i, br := range vulns {
			if len(br.Vulns) > 0 {
				result[batch[i].orig] = br.Vulns
			}
		}
	}

	// /v1/querybatch returns only {id, modified}; fetch the detail that
	// severity mapping and import-path scoping depend on. Each result slice is
	// hydrated in place — never reassigned — because map iteration order is
	// randomised and rebuilding the map from a flattened slice would attribute
	// vulnerabilities to the wrong packages.
	var ids []string
	for _, vs := range result {
		for _, v := range vs {
			ids = append(ids, v.ID)
		}
	}
	details := fetchVulnDetails(ctx, client, baseURL, ids)
	for _, vs := range result {
		applyVulnDetails(vs, details)
	}

	return result, nil
}

// osvHydrateConcurrency bounds in-flight detail lookups so a large dependency
// tree does not open hundreds of simultaneous connections to OSV.
const osvHydrateConcurrency = 8

// hydrateVulnDetails fills in the fields /v1/querybatch does not return.
//
// The batch endpoint answers only "which advisory IDs match this package", as
// {id, modified} pairs — no severity, summary or affected ranges. Everything
// downstream therefore fell back to defaults: every dependency finding was
// reported at SeverityMedium with an empty summary, regardless of its real
// CVSS. Since enforcing gates key on high/critical, a critical dependency CVE
// could never block a build.
//
// Each distinct ID is fetched once from /v1/vulns/{id} and the result is copied
// into every osvVuln sharing it. Hydration is best-effort: on any failure the
// original entry is left untouched, so a lookup problem degrades severity
// accuracy but never loses a finding.
func hydrateVulnDetails(ctx context.Context, client *http.Client, baseURL string, vulns []osvVuln) {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	applyVulnDetails(vulns, fetchVulnDetails(ctx, client, baseURL, ids))
}

// fetchVulnDetails retrieves advisory detail for each distinct ID, concurrently
// and at most once per ID. IDs that cannot be fetched are simply absent from
// the returned map, which callers treat as "leave the finding as it is".
func fetchVulnDetails(ctx context.Context, client *http.Client, baseURL string, ids []string) map[string]osvVuln {
	unique := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id != "" {
			unique[id] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return nil
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		failures int
	)
	out := make(map[string]osvVuln, len(unique))
	sem := make(chan struct{}, osvHydrateConcurrency)

	for id := range unique {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			detail, err := fetchVulnDetail(ctx, client, baseURL, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				return
			}
			out[id] = detail
		}(id)
	}
	wg.Wait()

	if failures > 0 {
		slog.WarnContext(ctx, "OSV detail lookup failed for some advisories; severity may be under-reported",
			"failed", failures, "total", len(unique))
	}
	return out
}

// applyVulnDetails copies fetched detail onto the matching entries in vulns,
// in place. Only fields the batch response could not supply are overwritten.
func applyVulnDetails(vulns []osvVuln, details map[string]osvVuln) {
	for i := range vulns {
		detail, ok := details[vulns[i].ID]
		if !ok {
			continue
		}
		if detail.Summary != "" {
			vulns[i].Summary = detail.Summary
		}
		if detail.Details != "" {
			vulns[i].Details = detail.Details
		}
		if len(detail.Severity) > 0 {
			vulns[i].Severity = detail.Severity
		}
		if len(detail.Aliases) > 0 {
			vulns[i].Aliases = detail.Aliases
		}
		if len(detail.Affected) > 0 {
			vulns[i].Affected = detail.Affected
		}
	}
}

// fetchVulnDetail retrieves a single advisory from OSV's /v1/vulns/{id}.
func fetchVulnDetail(ctx context.Context, client *http.Client, baseURL, id string) (osvVuln, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/vulns/" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return osvVuln{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return osvVuln{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return osvVuln{}, fmt.Errorf("OSV vuln lookup for %s returned status %d", id, resp.StatusCode)
	}

	var v osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return osvVuln{}, err
	}
	return v, nil
}

// decodeBatchResponse reads and decodes an OSV batch response. It returns
// an error for non-200 status codes or decode failures.
func decodeBatchResponse(resp *http.Response) ([]osvBatchResult, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}
	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, err
	}
	return batchResp.Results, nil
}

// mapOSVSeverity converts OSV severity entries to a nox Severity.
// It looks for a CVSS_V3 score first, then falls back to CVSS_V2.
// If no score is found, it returns SeverityMedium as a conservative default.
func mapOSVSeverity(sev []osvSeverity) findings.Severity {
	for _, s := range sev {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			return cvssToSeverity(s.Score)
		}
	}
	return findings.SeverityMedium
}

// cvssToSeverity converts a CVSS vector string or numeric score to a Severity.
// It extracts the base score from either a bare number ("9.8") or a CVSS
// vector string by looking for a trailing numeric value.
func cvssToSeverity(score string) findings.Severity {
	// Try parsing as a plain float first (e.g. "9.8").
	f, err := strconv.ParseFloat(score, 64)
	if err != nil {
		// OSV publishes CVSS as a vector string, e.g.
		// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". The base score is not
		// embedded in it, but it is fully determined by it, so compute it.
		if base, ok := cvssV3BaseScore(score); ok {
			f = base
		} else {
			// Unrecognised format (e.g. a CVSS v2 or v4 vector): stay
			// conservative rather than guessing.
			return findings.SeverityMedium
		}
	}

	switch {
	case f >= 9.0:
		return findings.SeverityCritical
	case f >= 7.0:
		return findings.SeverityHigh
	case f >= 4.0:
		return findings.SeverityMedium
	case f >= 0.1:
		return findings.SeverityLow
	default:
		return findings.SeverityInfo
	}
}

// upgradeCommand returns the canonical one-liner an operator can run to
// upgrade a package to its fixed version. Returns "" for ecosystems we
// don't have a templated command for (the operator can still see fixed_in).
func upgradeCommand(ecosystem, pkg, fixedVer string) string {
	switch ecosystem {
	case "go":
		return fmt.Sprintf("go get %s@v%s", pkg, strings.TrimPrefix(fixedVer, "v"))
	case "npm":
		return fmt.Sprintf("npm install %s@%s", pkg, fixedVer)
	case "pypi":
		return fmt.Sprintf("pip install '%s>=%s'", pkg, fixedVer)
	case "rubygems":
		return fmt.Sprintf("bundle update %s --conservative", pkg)
	case "cargo":
		return fmt.Sprintf("cargo update -p %s --precise %s", pkg, fixedVer)
	case "maven", "gradle":
		return fmt.Sprintf("upgrade %s to %s in your build file", pkg, fixedVer)
	case "nuget":
		return fmt.Sprintf("dotnet add package %s --version %s", pkg, fixedVer)
	default:
		return ""
	}
}

// osvEcosystem maps a nox internal ecosystem name to the ecosystem string
// expected by the OSV.dev API. The bool is false when OSV has no matching
// ecosystem (e.g. "docker" base images), so callers can skip those packages
// rather than poisoning a batch query — OSV rejects an entire /v1/querybatch
// request with HTTP 400 if any one query names an unknown ecosystem.
func osvEcosystem(eco string) (string, bool) {
	switch eco {
	case "go":
		return "Go", true
	case "npm":
		return "npm", true
	case "pypi":
		return "PyPI", true
	case "rubygems":
		return "RubyGems", true
	case "cargo":
		return "crates.io", true
	case "maven":
		return "Maven", true
	case "gradle":
		return "Maven", true
	case "nuget":
		return "NuGet", true
	default:
		return "", false
	}
}

// ecosystemToOSV maps nox's internal ecosystem names to the ecosystem strings
// expected by the OSV.dev API, returning the input unchanged for ecosystems
// OSV does not recognise (used only for best-effort name/version matching in
// already-returned records, not for issuing queries).
func ecosystemToOSV(eco string) string {
	if osv, ok := osvEcosystem(eco); ok {
		return osv
	}
	return eco
}
