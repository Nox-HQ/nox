package registry

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheStoreAndLoad(t *testing.T) {
	dir := t.TempDir()
	c := newFileCache(dir, 1*time.Hour)

	src := Source{Name: "test", URL: "https://example.com/index.json"}
	idx := &Index{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Plugins: []PluginEntry{
			{Name: "test/plugin", Description: "A test plugin"},
		},
	}

	if err := c.store(src, idx); err != nil {
		t.Fatalf("store: %v", err)
	}

	loaded, err := c.load(src)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.SchemaVersion != idx.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", loaded.SchemaVersion, idx.SchemaVersion)
	}
	if len(loaded.Plugins) != 1 {
		t.Fatalf("plugins count = %d, want 1", len(loaded.Plugins))
	}
	if loaded.Plugins[0].Name != "test/plugin" {
		t.Errorf("plugin name = %q, want %q", loaded.Plugins[0].Name, "test/plugin")
	}
}

func TestCacheLoadMissing(t *testing.T) {
	dir := t.TempDir()
	c := newFileCache(dir, 1*time.Hour)

	src := Source{Name: "missing", URL: "https://example.com/missing.json"}
	_, err := c.load(src)
	if err == nil {
		t.Fatal("expected error for missing cache file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

func TestCacheIsStaleTTL(t *testing.T) {
	dir := t.TempDir()
	src := Source{Name: "test", URL: "https://example.com/index.json"}
	idx := &Index{SchemaVersion: "1"}

	// Zero TTL → always stale.
	c := newFileCache(dir, 0)
	if err := c.store(src, idx); err != nil {
		t.Fatalf("store: %v", err)
	}
	if !c.isStale(src) {
		t.Error("expected stale with zero TTL")
	}

	// Large TTL → never stale (for a file just written).
	c2 := newFileCache(dir, 24*time.Hour)
	if c2.isStale(src) {
		t.Error("expected not stale with 24h TTL on fresh file")
	}
}

func TestCacheIsStaleMissingFile(t *testing.T) {
	dir := t.TempDir()
	c := newFileCache(dir, 1*time.Hour)

	src := Source{Name: "missing", URL: "https://example.com/does-not-exist.json"}
	if !c.isStale(src) {
		t.Error("expected stale for missing file")
	}
}

func TestCacheCorruptFile(t *testing.T) {
	dir := t.TempDir()
	c := newFileCache(dir, 1*time.Hour)

	src := Source{Name: "corrupt", URL: "https://example.com/corrupt.json"}
	path := c.path(src)

	if err := os.WriteFile(path, []byte("not valid json{{{"), 0o644); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, err := c.load(src)
	if err == nil {
		t.Fatal("expected error for corrupt cache file")
	}
}

func TestCachePath(t *testing.T) {
	dir := t.TempDir()
	c := newFileCache(dir, 1*time.Hour)

	s1 := Source{Name: "a", URL: "https://example.com/one.json"}
	s2 := Source{Name: "b", URL: "https://example.com/two.json"}
	s3 := Source{Name: "a-copy", URL: "https://example.com/one.json"}

	p1 := c.path(s1)
	p2 := c.path(s2)
	p3 := c.path(s3)

	if p1 == p2 {
		t.Error("different URLs should produce different cache paths")
	}
	if p1 != p3 {
		t.Error("same URL should produce same cache path regardless of name")
	}

	// Verify it's under the cache dir.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	realP1, err := filepath.EvalSymlinks(filepath.Dir(p1))
	if err != nil {
		// path may not exist yet since we didn't store, check against dir directly
		if filepath.Dir(p1) != dir {
			t.Errorf("cache path %q not under dir %q", p1, dir)
		}
	} else if realP1 != real {
		t.Errorf("cache path dir %q != %q", realP1, real)
	}
}

func TestCacheAtomicWriteNoTmpLeftover(t *testing.T) {
	dir := t.TempDir()
	c := newFileCache(dir, 1*time.Hour)

	src := Source{Name: "test", URL: "https://example.com/index.json"}
	idx := &Index{SchemaVersion: "1"}

	if err := c.store(src, idx); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Check no .tmp files remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover tmp file: %s", e.Name())
		}
	}
}
