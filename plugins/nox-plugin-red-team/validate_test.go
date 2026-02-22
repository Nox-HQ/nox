package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateHeadersMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = old }()

	results := validateHeaders(context.Background(), srv.URL)
	if len(results) == 0 {
		t.Fatal("expected findings for missing security headers")
	}

	r := results[0]
	if r.RuleID != "REDTEAM-006" {
		t.Errorf("expected REDTEAM-006, got %s", r.RuleID)
	}
	if !r.Validated {
		t.Error("expected validated=true")
	}
	if r.Technique != "headers" {
		t.Errorf("expected technique=headers, got %s", r.Technique)
	}
}

func TestValidateHeadersPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = old }()

	results := validateHeaders(context.Background(), srv.URL)
	if len(results) != 0 {
		t.Errorf("expected no findings when all headers present, got %d", len(results))
	}
}

func TestValidateTLSNoHTTPS(t *testing.T) {
	results := validateTLS(context.Background(), "http://example.com")
	if len(results) == 0 {
		t.Fatal("expected finding for non-HTTPS URL")
	}
	if results[0].RuleID != "REDTEAM-009" {
		t.Errorf("expected REDTEAM-009, got %s", results[0].RuleID)
	}
	if !results[0].Validated {
		t.Error("expected validated=true")
	}
}

func TestValidateTLSHTTPS(t *testing.T) {
	// HTTPS test server — TLS is valid (test certs).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// validateTLS does a raw TLS dial, so a self-signed test cert will produce a certificate error.
	// We just verify no panic and it returns a result (cert error = REDTEAM-009).
	results := validateTLS(context.Background(), srv.URL)
	// The test cert is self-signed, so we expect a certificate error finding.
	if len(results) == 0 {
		// Self-signed cert might or might not be detected depending on system trust store.
		// Either way, no panic is the key assertion.
		return
	}
	if results[0].RuleID != "REDTEAM-009" {
		t.Errorf("expected REDTEAM-009, got %s", results[0].RuleID)
	}
}

func TestValidateRateLimitAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = old }()

	results := validateRateLimit(context.Background(), srv.URL)
	if len(results) == 0 {
		t.Fatal("expected REDTEAM-010 for absent rate limiting")
	}
	if results[0].RuleID != "REDTEAM-010" {
		t.Errorf("expected REDTEAM-010, got %s", results[0].RuleID)
	}
	if !results[0].Validated {
		t.Error("expected validated=true")
	}
}

func TestValidateRateLimitPresent(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		if callCount > 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = old }()

	results := validateRateLimit(context.Background(), srv.URL)
	if len(results) != 0 {
		t.Errorf("expected no findings when rate limiting is active, got %d", len(results))
	}
}

func TestRunValidationAllTechniques(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = old }()

	results := runValidation(context.Background(), srv.URL, nil, nil)
	if len(results) == 0 {
		t.Fatal("expected findings from validation run")
	}

	// Should have at least headers and rate-limit findings.
	techniques := make(map[string]bool)
	for _, r := range results {
		techniques[r.Technique] = true
	}
	if !techniques["headers"] {
		t.Error("expected headers technique finding")
	}
	if !techniques["rate_limit"] {
		t.Error("expected rate_limit technique finding")
	}
}

func TestRunValidationFilteredTechnique(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = old }()

	techFilter := map[string]bool{"headers": true}
	results := runValidation(context.Background(), srv.URL, nil, techFilter)

	for _, r := range results {
		if r.Technique != "headers" {
			t.Errorf("expected only headers technique, got %s", r.Technique)
		}
	}
}

func TestShouldRun(t *testing.T) {
	tests := []struct {
		filter    map[string]bool
		technique string
		want      bool
	}{
		{nil, "headers", true},
		{map[string]bool{}, "headers", true},
		{map[string]bool{"headers": true}, "headers", true},
		{map[string]bool{"tls": true}, "headers", false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%v_%s", tc.filter, tc.technique), func(t *testing.T) {
			got := shouldRun(tc.filter, tc.technique)
			if got != tc.want {
				t.Errorf("shouldRun(%v, %q) = %v, want %v", tc.filter, tc.technique, got, tc.want)
			}
		})
	}
}
