package fsutil

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "store.json")

	if err := AtomicWriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // temp dir
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if string(got) != `{"a":1}` {
		t.Fatalf("content = %q", got)
	}
	// Permissions honoured, and no temp file left behind.
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("expected only the target file, got %d entries (temp left behind?)", len(entries))
	}
}

// Concurrent writers to the same path must not corrupt each other — the whole
// reason for unique temp names. The fixed-".tmp" copies this replaces could
// collide; this asserts the shared writer does not.
func TestAtomicWriteFileConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := AtomicWriteFile(path, []byte(`{"ok":true}`), 0o644); err != nil {
				t.Errorf("concurrent write: %v", err)
			}
		}()
	}
	wg.Wait()
	// The file exists and is one of the complete writes, never a mangled mix.
	got, err := os.ReadFile(path) //nolint:gosec // temp dir
	if err != nil || string(got) != `{"ok":true}` {
		t.Fatalf("final content = %q, err = %v", got, err)
	}
	// No stray temp files survived.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected 1 file, got %d — temp files leaked under contention", len(entries))
	}
}
