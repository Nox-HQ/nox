package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testIndex() Index {
	return Index{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, 2, 8, 0, 0, 0, 0, time.UTC),
		Plugins: []PluginEntry{
			{
				Name:        "nox/dast",
				Description: "Web DAST scanner",
				Homepage:    "https://github.com/nox-hq/dast",
				Versions: []VersionEntry{
					{
						Version:      "1.0.0",
						APIVersion:   "v1",
						PublishedAt:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
						Digest:       "sha256:aaa",
						Capabilities: []string{"dast.scan"},
						RiskClass:    "active",
					},
					{
						Version:    "1.2.0",
						APIVersion: "v1",
						PublishedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
						Digest:     "sha256:bbb",
						RiskClass:  "active",
					},
					{
						Version:    "2.0.0-beta.1",
						APIVersion: "v1",
						PublishedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
						Digest:     "sha256:ccc",
						RiskClass:  "active",
					},
				},
			},
			{
				Name:        "nox/sbom",
				Description: "SBOM generator plugin",
				Versions: []VersionEntry{
					{
						Version:    "0.5.0",
						APIVersion: "v1",
						Digest:     "sha256:ddd",
						RiskClass:  "passive",
					},
				},
			},
		},
	}
}

func testIndexV2() Index {
	return Index{
		SchemaVersion: "2",
		GeneratedAt:   time.Date(2026, 2, 8, 0, 0, 0, 0, time.UTC),
		Plugins: []PluginEntry{
			{
				Name:        "nox/sast",
				Description: "Static analysis extensions",
				Track:       TrackCoreAnalysis,
				Tags:        []string{"sast", "vulnerabilities"},
				Maintainers: []string{"nox-hq"},
				License:     "Apache-2.0",
				Repository:  "https://github.com/nox-hq/nox-plugin-sast",
				Versions: []VersionEntry{
					{
						Version:       "1.0.0",
						APIVersion:    "v1",
						Digest:        "sha256:eee",
						RiskClass:     "passive",
						MinNoxVersion: "0.1.0",
					},
				},
			},
			{
				Name:        "nox/dast",
				Description: "Web DAST scanner",
				Track:       TrackDynamicRuntime,
				Tags:        []string{"dast", "owasp"},
				Versions: []VersionEntry{
					{
						Version:    "1.0.0",
						APIVersion: "v1",
						Digest:     "sha256:fff",
						RiskClass:  "active",
					},
				},
			},
			{
				Name:        "nox/ai-inventory",
				Description: "Deep AI component inventory",
				Track:       TrackAISecurity,
				Tags:        []string{"ai", "inventory", "llm"},
				Versions: []VersionEntry{
					{
						Version:    "1.0.0",
						APIVersion: "v1",
						Digest:     "sha256:ggg",
						RiskClass:  "passive",
					},
				},
			},
		},
	}
}

func serveIndex(t *testing.T, idx Index) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(idx); err != nil {
			t.Errorf("encoding index: %v", err)
		}
	}))
}

func newTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	return NewClient(
		WithCacheDir(t.TempDir()),
		WithCacheTTL(1*time.Hour),
	)
}

func TestClientAddRemoveSources(t *testing.T) {
	c := NewClient(WithCacheDir(t.TempDir()))

	if err := c.AddSource(Source{Name: "a", URL: "https://example.com/a"}); err != nil {
		t.Fatalf("AddSource: %v", err)
	}
	if err := c.AddSource(Source{Name: "b", URL: "https://example.com/b"}); err != nil {
		t.Fatalf("AddSource: %v", err)
	}
	// Duplicate URL silently skipped.
	if err := c.AddSource(Source{Name: "a-dup", URL: "https://example.com/a"}); err != nil {
		t.Fatalf("AddSource dup: %v", err)
	}

	sources := c.Sources()
	if len(sources) != 2 {
		t.Fatalf("sources count = %d, want 2", len(sources))
	}

	if err := c.RemoveSource("a"); err != nil {
		t.Fatalf("RemoveSource: %v", err)
	}
	if len(c.Sources()) != 1 {
		t.Fatalf("sources count after remove = %d, want 1", len(c.Sources()))
	}

	if err := c.RemoveSource("nonexistent"); err == nil {
		t.Error("expected error removing nonexistent source")
	}
}

func TestClientAddSourceValidation(t *testing.T) {
	c := NewClient(WithCacheDir(t.TempDir()))

	if err := c.AddSource(Source{Name: "", URL: "https://example.com"}); err == nil {
		t.Error("expected error for empty name")
	}
	if err := c.AddSource(Source{Name: "test", URL: ""}); err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestClientSearch(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	results, err := c.Search(ctx, "dast")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("search results = %d, want 1", len(results))
	}
	if results[0].Name != "nox/dast" {
		t.Errorf("result name = %q, want %q", results[0].Name, "nox/dast")
	}

	// Search by description.
	results, err = c.Search(ctx, "sbom")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("search results = %d, want 1", len(results))
	}
	if results[0].Name != "nox/sbom" {
		t.Errorf("result name = %q, want %q", results[0].Name, "nox/sbom")
	}

	// Case insensitive.
	results, err = c.Search(ctx, "DAST")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("search results for DAST = %d, want 1", len(results))
	}

	// No match.
	results, err = c.Search(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("search results = %d, want 0", len(results))
	}
}

func TestClientResolveExact(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	ve, err := c.Resolve(ctx, "nox/dast", "1.0.0")
	if err != nil {
		t.Fatalf("Resolve exact: %v", err)
	}
	if ve.Version != "1.0.0" {
		t.Errorf("version = %q, want %q", ve.Version, "1.0.0")
	}
}

func TestClientResolveCaret(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	// ^1.0.0 should match highest 1.x.x (1.2.0, not 2.0.0-beta.1)
	ve, err := c.Resolve(ctx, "nox/dast", "^1.0.0")
	if err != nil {
		t.Fatalf("Resolve caret: %v", err)
	}
	if ve.Version != "1.2.0" {
		t.Errorf("version = %q, want %q", ve.Version, "1.2.0")
	}
}

func TestClientResolveTilde(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	// ~1.0.0 should match only 1.0.x
	ve, err := c.Resolve(ctx, "nox/dast", "~1.0.0")
	if err != nil {
		t.Fatalf("Resolve tilde: %v", err)
	}
	if ve.Version != "1.0.0" {
		t.Errorf("version = %q, want %q", ve.Version, "1.0.0")
	}
}

func TestClientResolveGTE(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	// >=1.0.0 should match highest (2.0.0-beta.1 is pre-release, so 1.2.0 wins
	// because 1.2.0 stable > 2.0.0-beta.1? No — 2.0.0-beta.1 has major 2 which
	// is higher in numeric comparison. Pre-release only affects same major.minor.patch.
	// So 2.0.0-beta.1 > 1.2.0.
	ve, err := c.Resolve(ctx, "nox/dast", ">=1.0.0")
	if err != nil {
		t.Fatalf("Resolve gte: %v", err)
	}
	// 2.0.0-beta.1 has higher major than 1.2.0
	if ve.Version != "2.0.0-beta.1" {
		t.Errorf("version = %q, want %q", ve.Version, "2.0.0-beta.1")
	}
}

func TestClientResolveWildcard(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	ve, err := c.Resolve(ctx, "nox/dast", "*")
	if err != nil {
		t.Fatalf("Resolve wildcard: %v", err)
	}
	if ve.Version != "2.0.0-beta.1" {
		t.Errorf("version = %q, want %q", ve.Version, "2.0.0-beta.1")
	}
}

func TestClientResolveNoMatch(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	_, err := c.Resolve(ctx, "nox/dast", "99.0.0")
	if err == nil {
		t.Error("expected error for no matching version")
	}

	_, err = c.Resolve(ctx, "nonexistent/plugin", "*")
	if err == nil {
		t.Error("expected error for nonexistent plugin")
	}
}

func TestClientResolveWithFilter(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	// Filter that rejects everything.
	_, err := c.Resolve(ctx, "nox/dast", "*", WithFilter(func(p PluginEntry) bool {
		return false
	}))
	if err == nil {
		t.Error("expected error when filter rejects all")
	}

	// Filter that accepts only passive risk class plugins.
	ve, err := c.Resolve(ctx, "nox/sbom", "*", WithFilter(func(p PluginEntry) bool {
		for _, v := range p.Versions {
			if v.RiskClass == "passive" {
				return true
			}
		}
		return false
	}))
	if err != nil {
		t.Fatalf("Resolve with filter: %v", err)
	}
	if ve.Version != "0.5.0" {
		t.Errorf("version = %q, want %q", ve.Version, "0.5.0")
	}
}

func TestClientResolveInvalidConstraint(t *testing.T) {
	c := NewClient(WithCacheDir(t.TempDir()))
	_ = c.AddSource(Source{Name: "test", URL: "https://example.com"})

	_, err := c.Resolve(context.Background(), "anything", ">=not-a-version")
	if err == nil {
		t.Error("expected error for invalid constraint")
	}
}

func TestClientRefresh(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	cacheDir := t.TempDir()
	c := NewClient(
		WithCacheDir(cacheDir),
		WithCacheTTL(0), // always stale
	)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	if err := c.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// After refresh, cache should have the index.
	fc := newFileCache(cacheDir, 24*time.Hour)
	cached, err := fc.load(Source{Name: "test", URL: srv.URL})
	if err != nil {
		t.Fatalf("cache load after refresh: %v", err)
	}
	if len(cached.Plugins) != 2 {
		t.Errorf("cached plugins = %d, want 2", len(cached.Plugins))
	}
}

func TestClientOfflineFallback(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)

	cacheDir := t.TempDir()
	c := NewClient(
		WithCacheDir(cacheDir),
		WithCacheTTL(0), // always stale, so it tries to fetch
	)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	// First, populate cache.
	if err := c.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Now shut down server to simulate offline.
	srv.Close()

	// Search should still work from stale cache.
	results, err := c.Search(ctx, "dast")
	if err != nil {
		t.Fatalf("Search offline: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("offline search results = %d, want 1", len(results))
	}
}

func TestClientServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(
		WithCacheDir(t.TempDir()),
		WithCacheTTL(0),
	)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	_, err := c.Search(context.Background(), "anything")
	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestClientNoSources(t *testing.T) {
	c := NewClient(WithCacheDir(t.TempDir()))

	// No sources = no results, no error.
	results, err := c.Search(context.Background(), "anything")
	if err != nil {
		t.Fatalf("Search with no sources: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results = %d, want 0", len(results))
	}
}

func TestClientWithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	c := NewClient(
		WithCacheDir(t.TempDir()),
		WithHTTPClient(customClient),
	)
	if c.httpClient != customClient {
		t.Error("custom HTTP client not applied")
	}
}

func TestClientSourcesReturnsCopy(t *testing.T) {
	c := NewClient(WithCacheDir(t.TempDir()))
	_ = c.AddSource(Source{Name: "a", URL: "https://example.com/a"})

	sources := c.Sources()
	sources[0].Name = "mutated"

	if c.Sources()[0].Name != "a" {
		t.Error("Sources() should return a copy, not a reference")
	}
}

func TestClientResolveCopiesResult(t *testing.T) {
	idx := testIndex()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	ve1, err := c.Resolve(ctx, "nox/dast", "1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	ve1.Version = "mutated"

	ve2, err := c.Resolve(ctx, "nox/dast", "1.0.0")
	if err != nil {
		t.Fatalf("Resolve again: %v", err)
	}
	if ve2.Version != "1.0.0" {
		t.Error("Resolve should return independent copies")
	}
}

func TestClientSearchV2TrackFilter(t *testing.T) {
	idx := testIndexV2()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	// Search with track filter — only core-analysis plugins.
	results, err := c.Search(ctx, "", WithTrackFilter(TrackCoreAnalysis))
	if err != nil {
		t.Fatalf("Search with track: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("search results = %d, want 1", len(results))
	}
	if results[0].Name != "nox/sast" {
		t.Errorf("result = %q, want nox/sast", results[0].Name)
	}

	// Search with AI track.
	results, err = c.Search(ctx, "", WithTrackFilter(TrackAISecurity))
	if err != nil {
		t.Fatalf("Search ai-security: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("search results = %d, want 1", len(results))
	}
	if results[0].Name != "nox/ai-inventory" {
		t.Errorf("result = %q, want nox/ai-inventory", results[0].Name)
	}
}

func TestClientSearchV2TagFilter(t *testing.T) {
	idx := testIndexV2()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	// Search with tag filter.
	results, err := c.Search(ctx, "", WithTagFilter("ai", "llm"))
	if err != nil {
		t.Fatalf("Search with tags: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("search results = %d, want 1", len(results))
	}
	if results[0].Name != "nox/ai-inventory" {
		t.Errorf("result = %q, want nox/ai-inventory", results[0].Name)
	}

	// Tag that doesn't match any.
	results, err = c.Search(ctx, "", WithTagFilter("nonexistent"))
	if err != nil {
		t.Fatalf("Search with nonexistent tag: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("search results = %d, want 0", len(results))
	}
}

func TestClientSearchByTrackName(t *testing.T) {
	idx := testIndexV2()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	// Query text matches track name.
	results, err := c.Search(ctx, "ai-security")
	if err != nil {
		t.Fatalf("Search by track name: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("search results = %d, want 1", len(results))
	}
	if results[0].Name != "nox/ai-inventory" {
		t.Errorf("result = %q, want nox/ai-inventory", results[0].Name)
	}
}

func TestClientSearchByTag(t *testing.T) {
	idx := testIndexV2()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	ctx := context.Background()

	// Query text matches a tag.
	results, err := c.Search(ctx, "owasp")
	if err != nil {
		t.Fatalf("Search by tag: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("search results = %d, want 1", len(results))
	}
	if results[0].Name != "nox/dast" {
		t.Errorf("result = %q, want nox/dast", results[0].Name)
	}
}

func TestClientSchemaV2Accepted(t *testing.T) {
	idx := testIndexV2()
	srv := serveIndex(t, idx)
	defer srv.Close()

	c := NewClient(
		WithCacheDir(t.TempDir()),
		WithCacheTTL(0),
	)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	// Schema v2 should be accepted.
	results, err := c.Search(context.Background(), "sast")
	if err != nil {
		t.Fatalf("Search v2 index: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("search results = %d, want 1", len(results))
	}
}

func TestClientInvalidSchemaVersionV99(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"99","plugins":[]}`))
	}))
	defer srv.Close()

	c := NewClient(
		WithCacheDir(t.TempDir()),
		WithCacheTTL(0),
	)
	_ = c.AddSource(Source{Name: "test", URL: srv.URL})

	_, err := c.Search(context.Background(), "anything")
	if err == nil {
		t.Error("expected error for unsupported schema version 99")
	}
}
