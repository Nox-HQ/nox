package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox/registry"
)

// captureStderr mirrors captureStdout for the warning channel —
// deprecation notices are diagnostics, so they must not pollute the
// stdout table that operators pipe into other tools.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stderr = orig
	return <-done
}

// serveDeprecatedIndex serves an index where one plugin is deprecated
// and points at a replacement.
func serveDeprecatedIndex(t *testing.T) *httptest.Server {
	t.Helper()
	idx := registry.Index{
		SchemaVersion: "2",
		GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Plugins: []registry.PluginEntry{
			{
				Name:            "nox/policy-gate",
				Description:     "Policy gating for CI",
				Track:           registry.TrackPolicyGovernance,
				Deprecated:      true,
				DeprecationNote: "Superseded by nox/grc. Install nox/grc instead.",
				Versions: []registry.VersionEntry{
					{Version: "0.2.0", APIVersion: "v1", Digest: "sha256:aaa"},
				},
			},
			{
				Name:        "nox/grc",
				Description: "Governance, risk and compliance",
				Track:       registry.TrackPolicyGovernance,
				Versions: []registry.VersionEntry{
					{Version: "0.3.0", APIVersion: "v1", Digest: "sha256:bbb"},
				},
			},
		},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(idx)
	}))
}

func TestPluginSearch_MarksDeprecatedEntries(t *testing.T) {
	srv := serveDeprecatedIndex(t)
	defer srv.Close()
	setupPluginTestState(t, srv)

	out := captureStdout(t, func() {
		if code := runPlugin([]string{"search", "policy-gate"}); code != 0 {
			t.Errorf("search: expected exit 0, got %d", code)
		}
	})

	if !strings.Contains(out, "DEPRECATED") {
		t.Errorf("search output should mark the deprecated plugin, got:\n%s", out)
	}
}

func TestPluginSearch_LeavesActiveEntriesUnmarked(t *testing.T) {
	srv := serveDeprecatedIndex(t)
	defer srv.Close()
	setupPluginTestState(t, srv)

	out := captureStdout(t, func() {
		if code := runPlugin([]string{"search", "grc"}); code != 0 {
			t.Errorf("search: expected exit 0, got %d", code)
		}
	})

	if strings.Contains(out, "DEPRECATED") {
		t.Errorf("active plugin must not be marked deprecated, got:\n%s", out)
	}
}

func TestPluginSearch_WarnsWithReplacementOnStderr(t *testing.T) {
	srv := serveDeprecatedIndex(t)
	defer srv.Close()
	setupPluginTestState(t, srv)

	errOut := captureStderr(t, func() {
		_ = runPlugin([]string{"search", "policy-gate"})
	})

	if !strings.Contains(errOut, "nox/grc") {
		t.Errorf("search warning should name the replacement, got:\n%s", errOut)
	}
}

func TestPluginInfo_ShowsDeprecation(t *testing.T) {
	srv := serveDeprecatedIndex(t)
	defer srv.Close()
	setupPluginTestState(t, srv)

	out := captureStdout(t, func() {
		if code := runPlugin([]string{"info", "nox/policy-gate"}); code != 0 {
			t.Errorf("info: expected exit 0, got %d", code)
		}
	})

	if !strings.Contains(out, "DEPRECATED") {
		t.Errorf("info should surface deprecation, got:\n%s", out)
	}
	if !strings.Contains(out, "nox/grc") {
		t.Errorf("info should name the replacement, got:\n%s", out)
	}
}

// TestPluginInstall_WarnsButDoesNotBlock — deprecated plugins stay
// installable on purpose: existing users must keep working, so the
// deprecation must never be the reason an install fails.
func TestPluginInstall_WarnsButDoesNotBlock(t *testing.T) {
	srv := serveDeprecatedIndex(t)
	defer srv.Close()
	setupPluginTestState(t, srv)

	errOut := captureStderr(t, func() {
		// The install proceeds past the deprecation check and only
		// fails later at the artifact fetch (no real artifact here).
		_ = runPlugin([]string{"install", "nox/policy-gate@0.2.0"})
	})

	if !strings.Contains(errOut, "deprecated") {
		t.Errorf("install should warn about deprecation, got:\n%s", errOut)
	}
	if !strings.Contains(errOut, "nox/grc") {
		t.Errorf("install warning should name the replacement, got:\n%s", errOut)
	}
	// The warning must be advisory — it must not short-circuit before
	// the fetch, which is what "still proceed" means in practice.
	if !strings.Contains(errOut, "fetching") {
		t.Errorf("install should proceed to the fetch step, got:\n%s", errOut)
	}
}

func TestPluginInstall_NoWarningForActivePlugin(t *testing.T) {
	srv := serveDeprecatedIndex(t)
	defer srv.Close()
	setupPluginTestState(t, srv)

	errOut := captureStderr(t, func() {
		_ = runPlugin([]string{"install", "nox/grc@0.3.0"})
	})

	if strings.Contains(errOut, "deprecated") {
		t.Errorf("active plugin install must not warn, got:\n%s", errOut)
	}
}
