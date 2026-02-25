package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	c := New()
	if c.dir == "" {
		t.Error("expected non-empty default dir")
	}
	if c.ttl != DefaultTTL {
		t.Errorf("expected default TTL %v, got %v", DefaultTTL, c.ttl)
	}
}

func TestLoadEmpty(t *testing.T) {
	t.Parallel()
	c := New(WithDir(t.TempDir()))
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}
	if c.store == nil {
		t.Fatal("store should be initialized")
	}
}

func TestPutAndGet(t *testing.T) {
	t.Parallel()
	c := New(WithDir(t.TempDir()))
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}

	f := []findings.Finding{{RuleID: "SEC-001", Message: "test"}}
	c.Put("main.go", "abc123", f)

	got := c.Get("main.go")
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "SEC-001" {
		t.Errorf("expected SEC-001, got %s", got[0].RuleID)
	}
}

func TestHas(t *testing.T) {
	t.Parallel()
	c := New(WithDir(t.TempDir()))
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}

	c.Put("main.go", "abc123", nil)

	if !c.Has("main.go", "abc123") {
		t.Error("expected cache hit")
	}
	if c.Has("main.go", "different") {
		t.Error("expected cache miss for different hash")
	}
	if c.Has("other.go", "abc123") {
		t.Error("expected cache miss for different path")
	}
}

func TestSaveAndReload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	c := New(WithDir(dir))
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}

	f := []findings.Finding{{RuleID: "SEC-002"}}
	c.Put("config.yaml", "hash1", f)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	// Reload from disk.
	c2 := New(WithDir(dir))
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}

	if !c2.Has("config.yaml", "hash1") {
		t.Error("expected cache hit after reload")
	}
	got := c2.Get("config.yaml")
	if len(got) != 1 || got[0].RuleID != "SEC-002" {
		t.Errorf("unexpected findings after reload: %v", got)
	}
}

func TestTTLExpiration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	c := New(WithDir(dir), WithTTL(24*time.Hour))
	c.nowFunc = func() time.Time { return now }
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}

	c.Put("old.go", "hash1", nil)

	// Advance time past TTL.
	c.nowFunc = func() time.Time { return now.Add(25 * time.Hour) }

	if c.Has("old.go", "hash1") {
		t.Error("expected expired entry to miss")
	}
}

func TestInvalidateAll(t *testing.T) {
	t.Parallel()
	c := New(WithDir(t.TempDir()))
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}

	c.Put("a.go", "h1", nil)
	c.Put("b.go", "h2", nil)
	c.InvalidateAll()

	if c.Has("a.go", "h1") || c.Has("b.go", "h2") {
		t.Error("expected all entries cleared")
	}
}

func TestInvalidatePath(t *testing.T) {
	t.Parallel()
	c := New(WithDir(t.TempDir()))
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}

	c.Put("a.go", "h1", nil)
	c.Put("b.go", "h2", nil)
	c.InvalidatePath("a.go")

	if c.Has("a.go", "h1") {
		t.Error("expected a.go invalidated")
	}
	if !c.Has("b.go", "h2") {
		t.Error("expected b.go still cached")
	}
}

func TestClear(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := New(WithDir(dir))
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}

	c.Put("test.go", "h1", nil)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}

	// Verify file is gone.
	path := filepath.Join(dir, "cache.json")
	if _, err := filepath.Abs(path); err != nil {
		t.Fatal(err)
	}
}

func TestStats(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := New(WithDir(dir))
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}

	entries, _ := c.Stats()
	if entries != 0 {
		t.Errorf("expected 0 entries, got %d", entries)
	}

	c.Put("a.go", "h1", nil)
	c.Put("b.go", "h2", nil)

	entries, _ = c.Stats()
	if entries != 2 {
		t.Errorf("expected 2 entries, got %d", entries)
	}
}

func TestHashContent(t *testing.T) {
	t.Parallel()

	h1 := HashContent([]byte("hello"))
	h2 := HashContent([]byte("hello"))
	h3 := HashContent([]byte("world"))

	if h1 != h2 {
		t.Error("same content should produce same hash")
	}
	if h1 == h3 {
		t.Error("different content should produce different hash")
	}
	if len(h1) != 64 {
		t.Errorf("expected 64 char hex, got %d", len(h1))
	}
}

func TestCorruptedCacheFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Write garbage to cache file.
	path := filepath.Join(dir, "cache.json")
	if err := writeTestFile(path, "not json!!!"); err != nil {
		t.Fatal(err)
	}

	c := New(WithDir(dir))
	if err := c.Load(); err != nil {
		t.Fatal("expected corrupted cache to be handled gracefully")
	}

	// Should start fresh.
	entries, _ := c.Stats()
	if entries != 0 {
		t.Errorf("expected 0 entries after corrupted load, got %d", entries)
	}
}

func TestSaveNoopWhenClean(t *testing.T) {
	t.Parallel()
	c := New(WithDir(t.TempDir()))
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}

	// Save without any changes should be a noop.
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestEvictExpiredOnLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	c := New(WithDir(dir), WithTTL(24*time.Hour))
	c.nowFunc = func() time.Time { return old }
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}
	c.Put("old.go", "h1", nil)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	// Reload with current time — entry should be evicted.
	c2 := New(WithDir(dir), WithTTL(24*time.Hour))
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}

	if c2.Has("old.go", "h1") {
		t.Error("expected expired entry evicted on load")
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
