package mcpfeed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func feedServer(t *testing.T, status int, body []byte, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case r.URL.Path == "/v1/feeds/mcp/status":
			_, _ = w.Write([]byte(`{"enabled":false,"state":"disabled","disabled_reason":"no feed signing key is configured"}`))
		case status == http.StatusOK:
			_, _ = w.Write(body)
		default:
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"no MCP advisory feed has been published yet"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLoadFetchesVerifiesAndCaches(t *testing.T) {
	body, verify := serviceFeed(t)
	var hits atomic.Int32
	srv := feedServer(t, 200, body, &hits)
	dir := t.TempDir()
	opts := Options{URL: srv.URL + "/v1/feeds/mcp", CacheDir: dir, TTL: time.Hour, Verify: verify}

	l, err := Load(context.Background(), opts)
	if err != nil || l.FromCache || len(l.Entries) != 6 {
		t.Fatalf("first load = %+v, %v", l, err)
	}
	// Within the TTL a second scan makes no request.
	hits.Store(0)
	l, err = Load(context.Background(), opts)
	if err != nil || !l.FromCache || hits.Load() != 0 {
		t.Fatalf("second load: cache=%v requests=%d err=%v", l != nil && l.FromCache, hits.Load(), err)
	}
	// Offline never touches the network and still works from the cache.
	opts.URL = srv.URL + "/v1/feeds/mcp"
	opts.Offline = true
	hits.Store(0)
	if l, err = Load(context.Background(), opts); err != nil || !l.FromCache || hits.Load() != 0 {
		t.Fatalf("offline load: %v %v requests=%d", l, err, hits.Load())
	}
}

func TestLoadOfflineWithoutACacheFailsClosed(t *testing.T) {
	_, verify := serviceFeed(t)
	_, err := Load(context.Background(), Options{URL: "https://intel.example/v1/feeds/mcp", CacheDir: t.TempDir(), Offline: true, Verify: verify})
	if err == nil {
		t.Fatal("offline with no cache must not produce a feed")
	}
}

// A cache is re-verified on every read: planting bytes in it grants nothing.
func TestLoadReverifiesTheCache(t *testing.T) {
	body, verify := serviceFeed(t)
	var hits atomic.Int32
	srv := feedServer(t, 200, body, &hits)
	dir := t.TempDir()
	opts := Options{URL: srv.URL + "/v1/feeds/mcp", CacheDir: dir, Verify: verify, Offline: true}
	path := cachePath(dir, opts.URL)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	tampered := edit(t, func(f *Feed) { f.Entries = f.Entries[:1] })
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := Load(context.Background(), opts); err == nil {
		t.Fatalf("a tampered cache was trusted: %+v", l)
	}
}

// The service withholding the feed is not the same as the feed being empty, and
// the explanation is the service's own.
func TestLoadReportsAnUnpublishedFeedAsSuch(t *testing.T) {
	_, verify := serviceFeed(t)
	var hits atomic.Int32
	srv := feedServer(t, 404, nil, &hits)
	_, err := Load(context.Background(), Options{URL: srv.URL + "/v1/feeds/mcp", CacheDir: t.TempDir(), Verify: verify})
	var np *NotPublishedError
	if !errors.As(err, &np) {
		t.Fatalf("err = %v, want NotPublishedError", err)
	}
	if np.Reason != "no feed signing key is configured" {
		t.Errorf("reason = %q, want the service's own disabled_reason", np.Reason)
	}
}

func TestLoadFallsBackToAVerifiedCacheOnANetworkFailure(t *testing.T) {
	body, verify := serviceFeed(t)
	var hits atomic.Int32
	srv := feedServer(t, 200, body, &hits)
	dir := t.TempDir()
	url := srv.URL + "/v1/feeds/mcp"
	if _, err := Load(context.Background(), Options{URL: url, CacheDir: dir, Verify: verify}); err != nil {
		t.Fatal(err)
	}
	srv.Close() // the network goes away
	l, err := Load(context.Background(), Options{URL: url, CacheDir: dir, Verify: verify})
	if err != nil || !l.FromCache || l.RefreshErr == nil {
		t.Fatalf("expected the cached copy with the refresh error recorded: %+v %v", l, err)
	}
}

// A fetched feed that fails verification is not hidden behind the cache: that
// is a tampered answer, and it is surfaced.
func TestLoadDoesNotMaskATamperedFetchWithTheCache(t *testing.T) {
	good, verify := serviceFeed(t)
	bad := edit(t, func(f *Feed) { f.Entries[0].Summary = "tampered" })
	var serve atomic.Pointer[[]byte]
	serve.Store(&good)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(*serve.Load())
	}))
	defer srv.Close()
	dir := t.TempDir()
	opts := Options{URL: srv.URL + "/v1/feeds/mcp", CacheDir: dir, Verify: verify}
	if _, err := Load(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	serve.Store(&bad)
	l, err := Load(context.Background(), opts)
	if err == nil || !errors.Is(err, ErrDigest) {
		t.Fatalf("a tampered fetch must fail with the digest error, got %+v, %v", l, err)
	}
}

func TestLoadRejectsNonHTTPURLs(t *testing.T) {
	_, verify := serviceFeed(t)
	for _, u := range []string{"", "file:///etc/passwd", "ftp://x/y", "/local/path", "https://"} {
		if _, err := Load(context.Background(), Options{URL: u, Verify: verify, CacheDir: t.TempDir()}); err == nil {
			t.Errorf("%q must be rejected", u)
		}
	}
	if _, err := Load(context.Background(), Options{URL: "https://x.example/v1/feeds/mcp", CacheDir: t.TempDir()}); err == nil {
		t.Error("no verifier must be rejected")
	}
}
