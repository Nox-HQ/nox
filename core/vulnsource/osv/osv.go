// Package osv implements vulnsource.Source against the OSV.dev API.
//
// Everything in here is an OSV wire artifact: batch size limits, the ecosystem
// vocabulary, the two-step query-then-hydrate protocol, and the failure modes
// peculiar to that API. None of it is visible through the vulnsource.Source
// interface, which is the point — a different source answering the same
// question should not have to reproduce OSV's protocol to be substitutable.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/nox-hq/nox/core/degrade"
	"github.com/nox-hq/nox/core/vulnsource"
)

// DefaultBaseURL is the public OSV.dev API endpoint.
const DefaultBaseURL = "https://api.osv.dev"

// batchLimit is the maximum number of queries per OSV batch request.
const batchLimit = 1000

// hydrateConcurrency bounds in-flight detail lookups so a large dependency tree
// does not open hundreds of simultaneous connections to OSV.
const hydrateConcurrency = 8

// The batch wire types are exported deliberately. OSV's protocol is the
// interchange baseline any nox vulnerability source must be able to speak, so a
// server implementing it — or a test standing in for one — shares these
// definitions rather than restating them and drifting.

// Query is a single package query for the OSV batch API.
type Query struct {
	Package vulnsource.Package `json:"package"`
	Version string             `json:"version"`
}

// BatchRequest is the request body for POST /v1/querybatch.
type BatchRequest struct {
	Queries []Query `json:"queries"`
}

// BatchResponse is the response from the OSV batch endpoint.
type BatchResponse struct {
	Results []BatchResult `json:"results"`
}

// BatchResult holds vulnerabilities for a single query.
type BatchResult struct {
	Vulns []vulnsource.Record `json:"vulns"`
}

// Source queries an OSV-wire-protocol endpoint for known vulnerabilities.
type Source struct {
	name    string
	baseURL string
	client  *http.Client
	deg     *degrade.Degradations
}

// New returns a Source querying baseURL through client, named "osv.dev". deg
// may be nil, in which case degradation records are discarded — library callers
// that supply no collector behave exactly as they did before.
func New(baseURL string, client *http.Client, deg *degrade.Degradations) *Source {
	return NewNamed("osv.dev", baseURL, client, deg)
}

// NewNamed returns a Source under a caller-chosen name.
//
// The OSV wire protocol is spoken by more than OSV.dev — a NOX Intelligence
// endpoint serves it as its baseline surface — so the implementation is shared
// while the identity is not. Without this, a degradation comparing two such
// sources reads "osv.dev withheld a record published by osv.dev", which names
// neither the source at fault nor the one that caught it.
func NewNamed(name, baseURL string, client *http.Client, deg *degrade.Degradations) *Source {
	if name == "" {
		name = "osv.dev"
	}
	return &Source{name: name, baseURL: baseURL, client: client, deg: deg}
}

// Name identifies this source in degradation records and provenance.
func (s *Source) Name() string { return s.name }

// Lookup queries the OSV.dev batch API for vulnerabilities affecting qs. It
// batches requests in groups of batchLimit and returns a map from the caller's
// query index to the vulnerabilities found.
//
// On network errors it returns the results gathered so far rather than failing
// the scan, honouring nox's offline-first design — and records a degradation,
// because a silent empty result is indistinguishable from "no vulnerabilities
// found".
func (s *Source) Lookup(ctx context.Context, qs []vulnsource.Query) (map[int][]vulnsource.Record, error) {
	result := make(map[int][]vulnsource.Record)

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
		q    vulnsource.Query
	}
	queryable := make([]indexed, 0, len(qs))
	for i, q := range qs {
		if _, ok := Ecosystem(q.Ecosystem); ok {
			queryable = append(queryable, indexed{orig: i, q: q})
		}
	}

	for start := 0; start < len(queryable); start += batchLimit {
		end := start + batchLimit
		if end > len(queryable) {
			end = len(queryable)
		}
		batch := queryable[start:end]

		queries := make([]Query, len(batch))
		for i, item := range batch {
			eco, _ := Ecosystem(item.q.Ecosystem)
			queries[i] = Query{
				Package: vulnsource.Package{
					Name:      item.q.Name,
					Ecosystem: eco,
				},
				Version: item.q.Version,
			}
		}

		body, err := json.Marshal(BatchRequest{Queries: queries})
		if err != nil {
			return nil, fmt.Errorf("marshalling OSV request: %w", err)
		}

		url := strings.TrimRight(s.baseURL, "/") + "/v1/querybatch"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("creating OSV request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			// Network error — degrade gracefully, but say so: a silent empty
			// result is indistinguishable from "no vulnerabilities found".
			slog.WarnContext(ctx, "OSV query failed; dependency vulnerabilities may be under-reported",
				"error", err, "queries", len(queries))
			s.deg.Add(degrade.OSV,
				fmt.Sprintf("vulnerability lookup failed for %d packages: %v", len(queries), err),
				"dependency vulnerabilities are under-reported; this scan cannot confirm the absence of known CVEs")
			return result, nil
		}

		vulns, decodeErr := decodeBatchResponse(resp)
		_ = resp.Body.Close()
		if decodeErr != nil {
			// Non-200 status or undecodable body — same risk: don't report a
			// clean scan when the lookup actually failed.
			slog.WarnContext(ctx, "OSV query returned an error; dependency vulnerabilities may be under-reported",
				"error", decodeErr, "queries", len(queries))
			s.deg.Add(degrade.OSV,
				fmt.Sprintf("vulnerability lookup failed for %d packages: %v", len(queries), decodeErr),
				"dependency vulnerabilities are under-reported; this scan cannot confirm the absence of known CVEs")
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
	details := fetchVulnDetails(ctx, s.client, s.baseURL, ids)
	for _, vs := range result {
		applyVulnDetails(vs, details)
	}

	return result, nil
}

// HydrateDetails fills in the fields /v1/querybatch does not return.
//
// The batch endpoint answers only "which advisory IDs match this package", as
// {id, modified} pairs — no severity, summary or affected ranges. Everything
// downstream therefore fell back to defaults: every dependency finding was
// reported at SeverityMedium with an empty summary, regardless of its real
// CVSS. Since enforcing gates key on high/critical, a critical dependency CVE
// could never block a build.
//
// Each distinct ID is fetched once from /v1/vulns/{id} and the result is copied
// into every Record sharing it. Hydration is best-effort: on any failure the
// original entry is left untouched, so a lookup problem degrades severity
// accuracy but never loses a finding.
func HydrateDetails(ctx context.Context, client *http.Client, baseURL string, vulns []vulnsource.Record) {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	applyVulnDetails(vulns, fetchVulnDetails(ctx, client, baseURL, ids))
}

// fetchVulnDetails retrieves advisory detail for each distinct ID, concurrently
// and at most once per ID. IDs that cannot be fetched are simply absent from
// the returned map, which callers treat as "leave the finding as it is".
func fetchVulnDetails(ctx context.Context, client *http.Client, baseURL string, ids []string) map[string]vulnsource.Record {
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
	out := make(map[string]vulnsource.Record, len(unique))
	sem := make(chan struct{}, hydrateConcurrency)

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
func applyVulnDetails(vulns []vulnsource.Record, details map[string]vulnsource.Record) {
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
		if detail.DatabaseSpecific.Severity != "" {
			vulns[i].DatabaseSpecific = detail.DatabaseSpecific
		}
		// OSV.dev never sends this, but a service speaking the OSV wire
		// protocol does — and the detail endpoint is the only place it can
		// arrive, since querybatch returns nothing but {id, modified}. Dropping
		// it here would silently strip status and corroboration from every
		// record in production while hand-built unit tests kept passing.
		if detail.Intelligence != nil {
			vulns[i].Intelligence = detail.Intelligence
		}
	}
}

// fetchVulnDetail retrieves a single advisory from OSV's /v1/vulns/{id}.
func fetchVulnDetail(ctx context.Context, client *http.Client, baseURL, id string) (vulnsource.Record, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/vulns/" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return vulnsource.Record{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return vulnsource.Record{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return vulnsource.Record{}, fmt.Errorf("OSV vuln lookup for %s returned status %d", id, resp.StatusCode)
	}

	var v vulnsource.Record
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return vulnsource.Record{}, err
	}

	// Confirm we got back the record we asked for. Any JSON object decodes into
	// a Record without error, so an intercepting proxy or captive portal
	// answering 200 with unrelated JSON would otherwise yield a well-formed but
	// entirely empty advisory — silently blanking a real finding's severity and
	// fix version, which is exactly the failure hydration exists to prevent.
	if v.ID != id {
		return vulnsource.Record{}, fmt.Errorf("OSV vuln lookup for %s returned mismatched record %q", id, v.ID)
	}
	return v, nil
}

// decodeBatchResponse reads and decodes an OSV batch response. It returns
// an error for non-200 status codes or decode failures.
func decodeBatchResponse(resp *http.Response) ([]BatchResult, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}
	var br BatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, err
	}
	return br.Results, nil
}

// Ecosystem maps a nox internal ecosystem name to the ecosystem string expected
// by the OSV.dev API. The bool is false when OSV has no matching ecosystem
// (e.g. "docker" base images), so callers can skip those packages rather than
// poisoning a batch query — OSV rejects an entire /v1/querybatch request with
// HTTP 400 if any one query names an unknown ecosystem.
func Ecosystem(eco string) (string, bool) {
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

// EcosystemName maps nox's internal ecosystem names to the ecosystem strings
// expected by the OSV.dev API, returning the input unchanged for ecosystems OSV
// does not recognise (used only for best-effort name/version matching in
// already-returned records, not for issuing queries).
func EcosystemName(eco string) string {
	if osv, ok := Ecosystem(eco); ok {
		return osv
	}
	return eco
}
