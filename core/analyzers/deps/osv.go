package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	urlpkg "net/url"
	"sort"
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
//
// Note that /v1/querybatch populates ONLY ID (and "modified"). Every other
// field here arrives exclusively from the per-vulnerability hydration call,
// GET /v1/vulns/{id} — see hydrateVulns. Consuming these fields off a raw
// querybatch response yields empty severity, summary, aliases and fix data.
type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Aliases  []string      `json:"aliases"`
	Details  string        `json:"details"`
	Affected []osvAffected `json:"affected"`

	// DatabaseSpecific carries source-database annotations. GitHub advisories
	// populate a coarse severity label here, which we use as a fallback when
	// no machine-parsable CVSS vector is present (notably for CVSS v4-only
	// records).
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}

// osvDatabaseSpecific holds the subset of source-specific annotations we read.
type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

// osvSeverity holds a CVSS or other severity score.
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvAffected describes packages and version ranges affected by a vuln.
// We only consume Package and Ranges — the broader OSV schema includes
// many additional fields not yet used here.
type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
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

	// /v1/querybatch answers only "which packages are affected, by which IDs".
	// Every field an operator actually needs — severity, summary, aliases, and
	// the fixed version — lives on the full record, so hydrate each distinct ID
	// via GET /v1/vulns/{id}. Cost scales with vulnerabilities found, not
	// packages scanned: a 62-package Go module with one affected dependency
	// costs 7 extra requests.
	hydrateVulns(ctx, client, baseURL, result)

	return result, nil
}

// osvHydrateConcurrency bounds in-flight per-vulnerability detail requests so a
// badly vulnerable repo cannot open hundreds of sockets against OSV at once.
const osvHydrateConcurrency = 8

// hydrateVulns replaces each stub vulnerability in result (as returned by
// /v1/querybatch, which carries only an ID) with its full OSV record fetched
// from GET /v1/vulns/{id}. Distinct IDs are fetched once each, concurrently.
//
// Hydration is best-effort: an ID that fails to fetch keeps its stub record, so
// the finding is still reported — with a conservative severity — rather than
// dropped. Failures are logged, because a silently under-described finding is
// indistinguishable from a fully-described one.
//
// Results are written back deterministically: concurrency affects only fetch
// order, never the contents or ordering of result.
func hydrateVulns(ctx context.Context, client *http.Client, baseURL string, result map[int][]osvVuln) {
	ids := make([]string, 0)
	seen := make(map[string]bool)
	for _, vulns := range result {
		for i := range vulns {
			if id := vulns[i].ID; id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	sort.Strings(ids)

	var mu sync.Mutex
	details := make(map[string]osvVuln, len(ids))
	var failed int

	sem := make(chan struct{}, osvHydrateConcurrency)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			detail, err := fetchVulnDetail(ctx, client, baseURL, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				return
			}
			details[id] = detail
		}(id)
	}
	wg.Wait()

	if failed > 0 {
		slog.WarnContext(ctx, "some OSV vulnerability details could not be fetched; those findings keep a conservative severity and carry no fix version",
			"failed", failed, "total", len(ids))
	}

	for pkgIdx, vulns := range result {
		for i := range vulns {
			if detail, ok := details[vulns[i].ID]; ok {
				result[pkgIdx][i] = detail
			}
		}
	}
}

// fetchVulnDetail retrieves the full OSV record for a single vulnerability ID.
func fetchVulnDetail(ctx context.Context, client *http.Client, baseURL, id string) (osvVuln, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/vulns/" + urlpkg.PathEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return osvVuln{}, fmt.Errorf("creating OSV detail request for %s: %w", id, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return osvVuln{}, fmt.Errorf("fetching OSV detail for %s: %w", id, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return osvVuln{}, fmt.Errorf("OSV detail for %s returned status %d", id, resp.StatusCode)
	}

	var detail osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return osvVuln{}, fmt.Errorf("decoding OSV detail for %s: %w", id, err)
	}

	// Confirm we got back the record we asked for. Any JSON object decodes
	// into osvVuln without error — an intercepting proxy or captive portal
	// answering 200 with unrelated JSON would otherwise yield a well-formed
	// but entirely empty vulnerability, silently blanking a real finding's
	// severity and fix version.
	if detail.ID != id {
		return osvVuln{}, fmt.Errorf("OSV detail for %s returned mismatched record %q", id, detail.ID)
	}
	return detail, nil
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

// mapOSVSeverity converts an OSV record's severity information to a nox
// Severity, preferring the most precise source available:
//
//  1. A CVSS v3 vector in severity[] — the base score is computed from the
//     vector per the CVSS v3.1 specification.
//  2. A bare numeric score in severity[] (some databases publish this).
//  3. The coarse database_specific.severity label (CRITICAL / HIGH /
//     MODERATE / LOW), which is how we recover a real severity for records
//     that carry only a CVSS v4 vector.
//
// It returns SeverityMedium only when none of the above is present, which is
// a genuine "unknown", not — as was previously the case — the outcome for
// every record OSV actually publishes.
func mapOSVSeverity(sev []osvSeverity, dbSpecific osvDatabaseSpecific) findings.Severity {
	// Prefer v3 over v2 regardless of ordering in the record.
	for _, want := range []string{"CVSS_V3", "CVSS_V2"} {
		for _, s := range sev {
			if s.Type != want {
				continue
			}
			if score, ok := cvssBaseScore(s.Score); ok {
				return scoreToSeverity(score)
			}
		}
	}

	if s, ok := severityFromLabel(dbSpecific.Severity); ok {
		return s
	}

	return findings.SeverityMedium
}

// severityFromLabel maps a coarse textual severity label to a nox Severity.
// GitHub advisories use "MODERATE" where most other sources say "MEDIUM".
func severityFromLabel(label string) (findings.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return findings.SeverityCritical, true
	case "HIGH":
		return findings.SeverityHigh, true
	case "MODERATE", "MEDIUM":
		return findings.SeverityMedium, true
	case "LOW":
		return findings.SeverityLow, true
	default:
		return "", false
	}
}

// scoreToSeverity buckets a CVSS base score using the standard qualitative
// severity rating scale.
func scoreToSeverity(f float64) findings.Severity {
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

// cvssBaseScore returns the CVSS base score for the given score field, which
// OSV publishes either as a bare number ("9.8") or — far more commonly — as a
// full CVSS vector string ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H").
//
// Vectors are scored per the CVSS v3.1 specification, section 7.1. CVSS v4
// vectors use a different, substantially more complex scoring algorithm and
// are deliberately not attempted here; callers fall back to the coarse
// database_specific label for those.
func cvssBaseScore(score string) (float64, bool) {
	score = strings.TrimSpace(score)
	if score == "" {
		return 0, false
	}

	if f, err := strconv.ParseFloat(score, 64); err == nil {
		return f, true
	}
	if !strings.HasPrefix(score, "CVSS:3.") {
		return 0, false
	}
	return cvss3BaseScore(score)
}

// cvss3Weights maps each CVSS v3 base metric abbreviation to its numeric
// weight. Privileges Required is scope-dependent and handled separately.
var cvss3Weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// cvss3PRWeights maps Privileges Required to its weight. The value depends on
// Scope: a changed scope raises the weight for L and H.
var cvss3PRWeights = map[bool]map[string]float64{
	false: {"N": 0.85, "L": 0.62, "H": 0.27}, // scope unchanged
	true:  {"N": 0.85, "L": 0.68, "H": 0.50}, // scope changed
}

// cvss3BaseScore computes the CVSS v3.1 base score from a vector string.
// It returns false when a required base metric is absent or carries an
// unrecognised value — a malformed vector must not silently score as 0.0.
func cvss3BaseScore(vector string) (float64, bool) {
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		key, val, found := strings.Cut(part, ":")
		if found {
			metrics[key] = val
		}
	}

	scopeChanged := metrics["S"] == "C"
	if metrics["S"] != "C" && metrics["S"] != "U" {
		return 0, false
	}

	weight := func(metric string) (float64, bool) {
		val, ok := metrics[metric]
		if !ok {
			return 0, false
		}
		if metric == "PR" {
			w, ok := cvss3PRWeights[scopeChanged][val]
			return w, ok
		}
		w, ok := cvss3Weights[metric][val]
		return w, ok
	}

	av, okAV := weight("AV")
	ac, okAC := weight("AC")
	pr, okPR := weight("PR")
	ui, okUI := weight("UI")
	c, okC := weight("C")
	i, okI := weight("I")
	a, okA := weight("A")
	if !okAV || !okAC || !okPR || !okUI || !okC || !okI || !okA {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui

	base := impact + exploitability
	if scopeChanged {
		base *= 1.08
	}
	return cvssRoundUp(math.Min(base, 10)), true
}

// cvssRoundUp implements the CVSS v3.1 Roundup function: the smallest number
// to one decimal place that is greater than or equal to the input. The integer
// arithmetic mirrors the specification's reference implementation, which avoids
// the floating-point edge cases a naive math.Ceil(x*10)/10 hits.
func cvssRoundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000) + 1) / 10.0
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
