package image

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
)

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// Docker Hub answers a pull from three hosts: the registry, the token service
// its challenge names, and the storage host its blob requests redirect to. A
// scan that says what it contacted has to name all three, and the redirect
// target is the one a client never chose.
func TestContactedNamesEveryHostAsked(t *testing.T) {
	reg := newRegistry(t) // also the token service: its challenge names itself
	digest := reg.image(t, layer(t, file{name: "etc/os-release", body: alpineRelease}, file{name: "lib/apk/db/installed", body: apkInstalled}))

	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reg.mu.Lock()
		defer reg.mu.Unlock()
		body, ok := reg.blobs[strings.TrimPrefix(req.URL.Path, "/")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(storage.Close)

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if i := strings.Index(req.URL.Path, "/blobs/"); i >= 0 && req.Header.Get("Authorization") != "" {
			http.Redirect(w, req, storage.URL+"/"+req.URL.Path[i+len("/blobs/"):], http.StatusTemporaryRedirect)
			return
		}
		reg.serve(w, req)
	}))
	t.Cleanup(front.Close)

	c := &Client{HTTP: front.Client(), CacheDir: t.TempDir(), registryOverride: front.URL}
	if got := c.Contacted(); len(got) != 0 {
		t.Fatalf("Contacted() = %q before any read", got)
	}
	if _, err := c.Contents(context.Background(), "golang", digest); err != nil {
		t.Fatal(err)
	}
	want := []string{hostOf(t, front.URL), hostOf(t, reg.srv.URL), hostOf(t, storage.URL)}
	sort.Strings(want)
	if got := c.Contacted(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("Contacted() = %q, want registry, token service and storage host %q", got, want)
	}

	// The same image through a new client over the same cache: every blob is
	// on disk, so no host is asked and none is named.
	cached := &Client{HTTP: front.Client(), CacheDir: c.CacheDir, registryOverride: front.URL}
	if _, err := cached.Contents(context.Background(), "golang", digest); err != nil {
		t.Fatal(err)
	}
	if got := cached.Contacted(); len(got) != 0 {
		t.Errorf("Contacted() = %q for a read the cache answered", got)
	}
}

// A request that failed was still made.
func TestContactedCountsARefusedPull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := &Client{HTTP: srv.Client(), CacheDir: t.TempDir(), registryOverride: srv.URL}
	if _, err := c.Contents(context.Background(), "golang", "sha256:"+strings.Repeat("a", 64)); err == nil {
		t.Fatal("a 403 was read as an image")
	}
	if got := c.Contacted(); len(got) != 1 || got[0] != hostOf(t, srv.URL) {
		t.Errorf("Contacted() = %q, want the host that refused", got)
	}
}
