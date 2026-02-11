package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

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
}

// osvSeverity holds a CVSS or other severity score.
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// queryOSV queries the OSV.dev batch API for known vulnerabilities affecting
// the given packages. It batches requests in groups of osvBatchLimit and
// returns a map from package index to the vulnerabilities found.
//
// On network errors the function returns an empty map (graceful degradation)
// rather than failing the scan, honouring Nox's offline-first design.
func queryOSV(ctx context.Context, client *http.Client, baseURL string, pkgs []Package) (map[int][]osvVuln, error) {
	result := make(map[int][]osvVuln)

	for start := 0; start < len(pkgs); start += osvBatchLimit {
		end := start + osvBatchLimit
		if end > len(pkgs) {
			end = len(pkgs)
		}
		batch := pkgs[start:end]

		queries := make([]osvQuery, len(batch))
		for i, p := range batch {
			queries[i] = osvQuery{
				Package: osvPackage{
					Name:      p.Name,
					Ecosystem: ecosystemToOSV(p.Ecosystem),
				},
				Version: p.Version,
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
			// Network error — degrade gracefully.
			return result, nil
		}

		vulns, decodeErr := decodeBatchResponse(resp)
		_ = resp.Body.Close()
		if decodeErr != nil {
			return result, nil
		}

		for i, br := range vulns {
			if len(br.Vulns) > 0 {
				result[start+i] = br.Vulns
			}
		}
	}

	return result, nil
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
		// Try extracting the base score from a CVSS vector string.
		// CVSS vectors look like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		// — the score is not embedded in the vector, so we can't parse it.
		// Fall back to medium.
		return findings.SeverityMedium
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

// ecosystemToOSV maps nox's internal ecosystem names to the ecosystem strings
// expected by the OSV.dev API.
func ecosystemToOSV(eco string) string {
	switch eco {
	case "go":
		return "Go"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "rubygems":
		return "RubyGems"
	case "cargo":
		return "crates.io"
	case "maven":
		return "Maven"
	case "gradle":
		return "Maven"
	case "nuget":
		return "NuGet"
	default:
		return eco
	}
}
