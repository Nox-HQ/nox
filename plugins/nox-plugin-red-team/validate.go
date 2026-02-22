package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

// validationResult represents the result of a single exploit validation check.
type validationResult struct {
	RuleID     string
	Severity   pluginv1.Severity
	Confidence pluginv1.Confidence
	Message    string
	Validated  bool
	Technique  string
	Proof      string
}

// httpClient is a package-level variable for test injection.
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	},
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// runValidation performs exploit validation against a target URL.
func runValidation(ctx context.Context, targetURL string, findingIDs, techFilter map[string]bool) []validationResult {
	var results []validationResult

	if shouldRun(techFilter, "headers") {
		results = append(results, validateHeaders(ctx, targetURL)...)
	}
	if shouldRun(techFilter, "tls") {
		results = append(results, validateTLS(ctx, targetURL)...)
	}
	if shouldRun(techFilter, "rate_limit") {
		results = append(results, validateRateLimit(ctx, targetURL)...)
	}

	return results
}

func shouldRun(techFilter map[string]bool, technique string) bool {
	if len(techFilter) == 0 {
		return true
	}
	return techFilter[technique]
}

// validateHeaders checks for missing security headers.
func validateHeaders(ctx context.Context, targetURL string) []validationResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	var results []validationResult
	requiredHeaders := map[string]string{
		"Strict-Transport-Security": "HSTS",
		"X-Content-Type-Options":    "X-Content-Type-Options",
		"X-Frame-Options":           "X-Frame-Options",
		"Content-Security-Policy":   "CSP",
	}

	var missing []string
	for header, label := range requiredHeaders {
		if resp.Header.Get(header) == "" {
			missing = append(missing, label)
		}
	}

	if len(missing) > 0 {
		results = append(results, validationResult{
			RuleID:     "REDTEAM-006",
			Severity:   sdk.SeverityMedium,
			Confidence: sdk.ConfidenceHigh,
			Message:    fmt.Sprintf("Validated: security headers missing — %s", strings.Join(missing, ", ")),
			Validated:  true,
			Technique:  "headers",
			Proof:      fmt.Sprintf("HTTP %d response missing headers: %s", resp.StatusCode, strings.Join(missing, ", ")),
		})
	}

	return results
}

// validateTLS checks for TLS misconfiguration.
func validateTLS(ctx context.Context, targetURL string) []validationResult {
	if !strings.HasPrefix(targetURL, "https://") {
		return []validationResult{
			{
				RuleID:     "REDTEAM-009",
				Severity:   sdk.SeverityHigh,
				Confidence: sdk.ConfidenceHigh,
				Message:    "Validated: TLS misconfiguration — endpoint not using HTTPS",
				Validated:  true,
				Technique:  "tls",
				Proof:      fmt.Sprintf("Target URL uses HTTP instead of HTTPS: %s", targetURL),
			},
		}
	}

	// Try connecting with TLS to verify certificate.
	host := strings.TrimPrefix(targetURL, "https://")
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		if strings.Contains(err.Error(), "certificate") {
			return []validationResult{
				{
					RuleID:     "REDTEAM-009",
					Severity:   sdk.SeverityHigh,
					Confidence: sdk.ConfidenceHigh,
					Message:    "Validated: TLS certificate error",
					Validated:  true,
					Technique:  "tls",
					Proof:      fmt.Sprintf("TLS connection failed: %v", err),
				},
			}
		}
		return nil
	}
	_ = conn.Close()

	return nil
}

// validateRateLimit checks if rate limiting is in place by sending burst requests.
func validateRateLimit(ctx context.Context, targetURL string) []validationResult {
	const burstCount = 10
	successCount := 0

	for i := 0; i < burstCount; i++ {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			break
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			break
		}
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			return nil // Rate limiting is active.
		}
		if resp.StatusCode < 500 {
			successCount++
		}
	}

	if successCount >= burstCount {
		return []validationResult{
			{
				RuleID:     "REDTEAM-010",
				Severity:   sdk.SeverityMedium,
				Confidence: sdk.ConfidenceMedium,
				Message:    fmt.Sprintf("Validated: rate limiting absent — %d/%d requests succeeded without throttling", successCount, burstCount),
				Validated:  true,
				Technique:  "rate_limit",
				Proof:      fmt.Sprintf("Sent %d requests in burst, all succeeded (no 429 responses)", burstCount),
			},
		}
	}

	return nil
}
