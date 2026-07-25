package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// newTestChecker points a checker at a test server, with no politeness delay.
func newTestChecker(base string) *checker {
	c := newChecker(&http.Client{}, 0)
	c.pypiBase = base + "/pypi"
	c.npmBase = base
	return c
}

func TestCheckerRegisteredNeverSquattable(t *testing.T) {
	// A registered package always returns 200. It must NEVER be reported
	// unregistered — the core no-false-accusation guarantee.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"info":{}}`))
	}))
	defer srv.Close()

	c := newTestChecker(srv.URL)
	got := c.check(context.Background(), "requests", "pypi")
	if got.verdict != registered {
		t.Fatalf("200 must classify as registered, got %q", got.verdict)
	}
	if _, ok := scoreSquattable(candidateStub(), got, "2026-07-25"); ok {
		t.Fatalf("a registered package must never be scored squattable")
	}
}

func TestCheckerReverifies404(t *testing.T) {
	// A single 404 is not proof. Only a name that returns 404 TWICE is trusted
	// as unregistered.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestChecker(srv.URL)
	got := c.check(context.Background(), "openai-utils", "pypi")
	if got.verdict != unregistered {
		t.Fatalf("two 404s must classify as unregistered, got %q", got.verdict)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("expected exactly 2 registry queries (initial + re-verify), got %d", n)
	}
}

func TestChecker404ThenRegisteredIsNotSquattable(t *testing.T) {
	// Eventual consistency: first query 404, second 200. Must be treated as
	// registered and never asserted claimable.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestChecker(srv.URL)
	got := c.check(context.Background(), "flaky-name", "pypi")
	if got.verdict == unregistered {
		t.Fatalf("404-then-200 must NOT be unregistered, got %q", got.verdict)
	}
	if _, ok := scoreSquattable(candidateStub(), got, "2026-07-25"); ok {
		t.Fatalf("404-then-200 must never be scored squattable")
	}
}

func TestCheckerBacksOffOn429(t *testing.T) {
	// First response 429, then 404 twice. The checker retries past the 429 and
	// still lands on the correct unregistered verdict.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestChecker(srv.URL)
	c.maxRetries = 5
	got := c.check(context.Background(), "anthropic-async", "pypi")
	if got.verdict != unregistered {
		t.Fatalf("expected unregistered after backoff, got %q (note: %s)", got.verdict, got.note)
	}
}

func TestCheckerSendsPoliteUserAgent(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestChecker(srv.URL)
	c.check(context.Background(), "x", "npm")
	if !strings.Contains(ua, "nox-slopfeed") {
		t.Fatalf("expected descriptive User-Agent, got %q", ua)
	}
}

func candidateStub() candidate {
	return candidate{name: "openai-utils", ecosystem: "pypi", pattern: "obvious", prior: 0.78}
}
