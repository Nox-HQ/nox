package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// runResolveVersion runs resolve_version (and the helper it delegates to)
// against a stub API, and reports the resolved version plus exit status.
func runResolveVersion(t *testing.T, base, version string) (string, bool) {
	t.Helper()
	fns := extractShellFunc(t, "api_get") + "\n" + extractShellFunc(t, "resolve_version")
	script := fns + "\nresolve_version \"" + version + "\"\n"
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(),
		"NOX_RETRY_BACKOFF_SECS=0",
		"NOX_API_BASE="+base,
	)
	b, err := cmd.Output()
	return strings.TrimSpace(string(b)), err == nil
}

// fetch_asset was hardened against GitHub's release throttle (see
// TestActionFetchAsset_RetriesTransientThrottle) but resolve_version, which runs
// FIRST, was left on a bare `curl -fsSL` that exits non-zero on any 403 — so the
// action died before ever reaching the retry-hardened download.
//
// This is not hypothetical. Nox-HQ/nox-plugin-risk-score#21 and
// nox-plugin-sast#22 both sat blocked on `Nox PR Gate (high/critical)` failing
// 9s in with `curl: (22) The requested URL returned error: 403`, and the gate's
// own SARIF upload then failed with "Path does not exist" — two red checks, no
// scan, nothing to do with security.
//
// A gate that goes red because GitHub throttled an API call is one people learn
// to re-run without reading, which is the failure mode the fetch_asset comment
// already argues against. The same argument applies one function earlier.
func TestActionResolveVersion_RetriesTransientThrottle(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&n, 1) <= 2 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"tag_name": "v1.18.0"}`))
	}))
	defer srv.Close()

	got, ok := runResolveVersion(t, srv.URL, "latest")
	if !ok {
		t.Fatalf("resolve_version gave up on a throttle that cleared; got %q", got)
	}
	if got != "1.18.0" {
		t.Errorf("resolved version = %q, want 1.18.0", got)
	}
	if attempts := atomic.LoadInt32(&n); attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// Retrying must not turn a genuine outage into a hang or, worse, into a silent
// success that installs nothing. When the lookup never recovers the action still
// has to fail loudly.
func TestActionResolveVersion_StillFailsWhenThrottleNeverClears(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	if got, ok := runResolveVersion(t, srv.URL, "latest"); ok {
		t.Errorf("resolve_version succeeded against a permanently throttled API, returning %q", got)
	}
}

// An explicit version must never touch the network at all — pinning is the
// escape hatch from exactly this flake, so it cannot depend on the API being up.
func TestActionResolveVersion_PinnedVersionSkipsTheAPI(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	got, ok := runResolveVersion(t, srv.URL, "1.17.0")
	if !ok || got != "1.17.0" {
		t.Fatalf("pinned version did not pass through: got %q ok=%v", got, ok)
	}
	if attempts := atomic.LoadInt32(&n); attempts != 0 {
		t.Errorf("pinned version made %d API call(s); it must not touch the network", attempts)
	}
}

// action.sh sends `Authorization: Bearer ${GITHUB_TOKEN}` when the variable is
// set — but a composite action's step only sees what its own `env:` block maps,
// and action.yml never mapped GITHUB_TOKEN. So `${GITHUB_TOKEN:+...}` expanded
// to nothing on every real run and BOTH the version lookup and the asset
// download went out unauthenticated, sharing the runner IP's 60-requests/hour
// anonymous budget with every other job on that host. That is why a fleet of
// plugin CI runs could reproduce the 403 at all.
//
// Same shape as the fail-on-degraded defect: action.sh reads an env var,
// action.yml has to supply it, and nothing connects the two halves.
func TestActionYAMLSuppliesTheTokenActionSHReads(t *testing.T) {
	sh, err := os.ReadFile(filepath.Join("..", "action.sh"))
	if err != nil {
		t.Fatalf("read action.sh: %v", err)
	}
	if !strings.Contains(string(sh), "GITHUB_TOKEN") {
		t.Skip("action.sh no longer authenticates its GitHub API calls")
	}

	yml, err := os.ReadFile(filepath.Join("..", "action.yml"))
	if err != nil {
		t.Fatalf("read action.yml: %v", err)
	}
	if !strings.Contains(string(yml), "GITHUB_TOKEN:") {
		t.Error("action.sh authenticates with GITHUB_TOKEN but action.yml's env block never " +
			"maps it, so the header is empty on every run and both API calls are anonymous " +
			"(60/hour per runner IP) — add `GITHUB_TOKEN: ${{ github.token }}`")
	}
}
