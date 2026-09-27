package fsutil

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The cache returns exactly what os.ReadFile returns.
func TestReadCacheReturnsTheFile(t *testing.T) {
	p := writeFile(t, t.TempDir(), "a.txt", "hello")
	c := NewReadCache(1 << 20)
	for range 3 {
		got, err := c.ReadFile(p)
		if err != nil || string(got) != "hello" {
			t.Fatalf("ReadFile = %q, %v", got, err)
		}
	}
}

// A second read of a cached file does not touch the disk: after the file is
// removed, the cached bytes are still served.
func TestReadCacheServesRepeatReadsFromMemory(t *testing.T) {
	p := writeFile(t, t.TempDir(), "a.txt", "hello")
	c := NewReadCache(1 << 20)
	if _, err := c.ReadFile(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ReadFile(p); err != nil || string(got) != "hello" {
		t.Fatalf("second read = %q, %v; want the cached bytes", got, err)
	}
}

// The budget holds: the least recently used file is evicted, and a file larger
// than the whole budget is returned without being kept.
func TestReadCacheStaysWithinBudget(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a", "aaaa")
	b := writeFile(t, dir, "b", "bbbb")
	big := writeFile(t, dir, "big", "0123456789")
	c := NewReadCache(8)
	for _, p := range []string{a, b} {
		if _, err := c.ReadFile(p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ReadFile(a); err != nil { // a is now most recent
		t.Fatal(err)
	}
	c3 := writeFile(t, dir, "c", "cccc")
	if _, err := c.ReadFile(c3); err != nil { // evicts b
		t.Fatal(err)
	}
	if got, err := c.ReadFile(big); err != nil || string(got) != "0123456789" {
		t.Fatalf("oversized file = %q, %v", got, err)
	}
	if c.used > c.budget {
		t.Fatalf("cache holds %d bytes over a budget of %d", c.used, c.budget)
	}
	if _, ok := c.entries[b]; ok {
		t.Error("the least recently used file was not evicted")
	}
	if _, ok := c.entries[big]; ok {
		t.Error("a file larger than the budget was kept")
	}
}

// A failed read is not cached: once the file exists, it is read.
func TestReadCacheDoesNotCacheErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "late.txt")
	c := NewReadCache(1 << 20)
	if _, err := c.ReadFile(p); err == nil {
		t.Fatal("reading a missing file succeeded")
	}
	writeFile(t, dir, "late.txt", "now")
	if got, err := c.ReadFile(p); err != nil || string(got) != "now" {
		t.Fatalf("after creation = %q, %v", got, err)
	}
}

// Concurrent readers of one file all get its content (run with -race).
func TestReadCacheIsSafeForConcurrentReaders(t *testing.T) {
	p := writeFile(t, t.TempDir(), "a.txt", string(bytes.Repeat([]byte("x"), 1<<16)))
	c := NewReadCache(1 << 20)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			got, err := c.ReadFile(p)
			if err != nil || len(got) != 1<<16 {
				t.Errorf("concurrent read = %d bytes, %v", len(got), err)
			}
		})
	}
	wg.Wait()
}

// A nil cache reads from disk.
func TestNilReadCacheReadsFromDisk(t *testing.T) {
	p := writeFile(t, t.TempDir(), "a.txt", "hi")
	var c *ReadCache
	if got, err := c.ReadFile(p); err != nil || string(got) != "hi" {
		t.Fatalf("nil cache = %q, %v", got, err)
	}
}
