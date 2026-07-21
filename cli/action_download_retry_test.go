package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// extractShellFunc pulls a single function out of action.sh so a test can run it
// without executing the whole action.
func extractShellFunc(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "action.sh"))
	if err != nil {
		t.Fatalf("read action.sh: %v", err)
	}
	re := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(name) + `\(\) \{.*?^\}`)
	m := re.FindString(string(src))
	if m == "" {
		t.Fatalf("function %s not found in action.sh", name)
	}
	return m
}

func runFetchAsset(t *testing.T, fn, url, out string) (string, bool) {
	t.Helper()
	script := fn + "\ncode=$(fetch_asset \"" + url + "\" \"" + out + "\") && st=0 || st=1\necho \"$code\"\nexit $st\n"
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "NOX_RETRY_BACKOFF_SECS=0")
	b, err := cmd.Output()
	return strings.TrimSpace(string(b)), err == nil
}

// A single-shot download failed a security gate on HTTP 403: GitHub throttles
// release-asset downloads when many jobs fetch at once, and a burst of plugin CI
// runs triggered exactly that. A gate that goes red for a reason unrelated to
// security is one people learn to re-run without reading it.
func TestActionFetchAsset_RetriesTransientThrottle(t *testing.T) {
	fn := extractShellFunc(t, "fetch_asset")

	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&n, 1) <= 2 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("payload-ok"))
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "asset.tar.gz")
	code, ok := runFetchAsset(t, fn, srv.URL+"/nox.tar.gz", out)
	if !ok || code != "200" {
		t.Fatalf("expected recovery after throttling; got HTTP %q ok=%v", code, ok)
	}
	body, err := os.ReadFile(out)
	if err != nil || string(body) != "payload-ok" {
		t.Fatalf("downloaded content wrong: %q err=%v", string(body), err)
	}
	if got := atomic.LoadInt32(&n); got < 3 {
		t.Errorf("expected at least 3 attempts, got %d", got)
	}
}

// Retrying must not turn a real failure into a hang or a false success.
func TestActionFetchAsset_StillFailsWhenErrorPersists(t *testing.T) {
	fn := extractShellFunc(t, "fetch_asset")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "asset.tar.gz")
	code, ok := runFetchAsset(t, fn, srv.URL+"/nox.tar.gz", out)
	if ok {
		t.Fatal("a persistently failing download must not report success")
	}
	if code != "403" {
		t.Errorf("expected the final status to be reported as 403, got %q", code)
	}
}
