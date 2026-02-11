package oci

import (
	"os"
	"path/filepath"
	"testing"
)

// populateCache creates fake blobs and extracted dirs in the store's cache.
func populateCache(t *testing.T, cacheDir string, hexDigests []string) {
	t.Helper()
	for _, hex := range hexDigests {
		// Create blob.
		blobDir := filepath.Join(cacheDir, "sha256", hex[:2])
		if err := os.MkdirAll(blobDir, 0o755); err != nil {
			t.Fatalf("MkdirAll blob: %v", err)
		}
		blobPath := filepath.Join(blobDir, hex)
		if err := os.WriteFile(blobPath, []byte("blob-"+hex), 0o644); err != nil {
			t.Fatalf("WriteFile blob: %v", err)
		}

		// Create extracted dir.
		extractDir := filepath.Join(cacheDir, "extracted", hex[:2], hex)
		if err := os.MkdirAll(extractDir, 0o755); err != nil {
			t.Fatalf("MkdirAll extracted: %v", err)
		}
		if err := os.WriteFile(filepath.Join(extractDir, "binary"), []byte("bin-"+hex), 0o755); err != nil {
			t.Fatalf("WriteFile extracted binary: %v", err)
		}
	}
}

func TestGCRemovesUnreferenced(t *testing.T) {
	cacheDir := t.TempDir()
	store := NewStore(WithCacheDir(cacheDir))

	hexDigests := []string{
		"aaaa000000000000000000000000000000000000000000000000000000000000",
		"bbbb000000000000000000000000000000000000000000000000000000000000",
		"cccc000000000000000000000000000000000000000000000000000000000000",
	}

	populateCache(t, cacheDir, hexDigests)

	// Keep only the first digest.
	result, err := store.GC(GCOptions{
		ReferencedDigests: []string{"sha256:" + hexDigests[0]},
	})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}

	if len(result.RemovedBlobs) != 2 {
		t.Errorf("RemovedBlobs = %d, want 2", len(result.RemovedBlobs))
	}
	if len(result.RemovedDirs) != 2 {
		t.Errorf("RemovedDirs = %d, want 2", len(result.RemovedDirs))
	}
	if result.BytesReclaimed <= 0 {
		t.Error("BytesReclaimed should be positive")
	}

	// Verify kept blob still exists.
	keptBlob := filepath.Join(cacheDir, "sha256", hexDigests[0][:2], hexDigests[0])
	if _, err := os.Stat(keptBlob); err != nil {
		t.Errorf("kept blob should still exist: %v", err)
	}

	// Verify removed blobs are gone.
	for _, hex := range hexDigests[1:] {
		removedBlob := filepath.Join(cacheDir, "sha256", hex[:2], hex)
		if _, err := os.Stat(removedBlob); !os.IsNotExist(err) {
			t.Errorf("blob %s should have been removed", hex[:8])
		}
	}
}

func TestGCDryRun(t *testing.T) {
	cacheDir := t.TempDir()
	store := NewStore(WithCacheDir(cacheDir))

	hexDigests := []string{
		"dddd000000000000000000000000000000000000000000000000000000000000",
		"eeee000000000000000000000000000000000000000000000000000000000000",
	}

	populateCache(t, cacheDir, hexDigests)

	// Dry run: nothing is referenced.
	result, err := store.GC(GCOptions{
		ReferencedDigests: nil,
		DryRun:            true,
	})
	if err != nil {
		t.Fatalf("GC dry run: %v", err)
	}

	if len(result.RemovedBlobs) != 2 {
		t.Errorf("RemovedBlobs (dry run) = %d, want 2", len(result.RemovedBlobs))
	}
	if result.BytesReclaimed <= 0 {
		t.Error("BytesReclaimed (dry run) should be positive")
	}

	// Verify nothing was actually deleted.
	for _, hex := range hexDigests {
		blobPath := filepath.Join(cacheDir, "sha256", hex[:2], hex)
		if _, err := os.Stat(blobPath); err != nil {
			t.Errorf("blob %s should still exist in dry run: %v", hex[:8], err)
		}
	}
}

func TestGCEmptyStore(t *testing.T) {
	cacheDir := t.TempDir()
	store := NewStore(WithCacheDir(cacheDir))

	result, err := store.GC(GCOptions{})
	if err != nil {
		t.Fatalf("GC empty store: %v", err)
	}

	if len(result.RemovedBlobs) != 0 {
		t.Errorf("RemovedBlobs = %d, want 0", len(result.RemovedBlobs))
	}
	if len(result.RemovedDirs) != 0 {
		t.Errorf("RemovedDirs = %d, want 0", len(result.RemovedDirs))
	}
	if result.BytesReclaimed != 0 {
		t.Errorf("BytesReclaimed = %d, want 0", result.BytesReclaimed)
	}
}

func TestGCKeepsAllReferenced(t *testing.T) {
	cacheDir := t.TempDir()
	store := NewStore(WithCacheDir(cacheDir))

	hexDigests := []string{
		"ffff000000000000000000000000000000000000000000000000000000000000",
		"1111000000000000000000000000000000000000000000000000000000000000",
	}

	populateCache(t, cacheDir, hexDigests)

	// Reference all digests.
	refs := make([]string, len(hexDigests))
	for i, h := range hexDigests {
		refs[i] = "sha256:" + h
	}

	result, err := store.GC(GCOptions{
		ReferencedDigests: refs,
	})
	if err != nil {
		t.Fatalf("GC all referenced: %v", err)
	}

	if len(result.RemovedBlobs) != 0 {
		t.Errorf("RemovedBlobs = %d, want 0 (all referenced)", len(result.RemovedBlobs))
	}
	if len(result.RemovedDirs) != 0 {
		t.Errorf("RemovedDirs = %d, want 0 (all referenced)", len(result.RemovedDirs))
	}
}

// TestGCRemovesAllUnreferenced tests GC when no digests are referenced.
func TestGCRemovesAllUnreferenced(t *testing.T) {
	cacheDir := t.TempDir()
	store := NewStore(WithCacheDir(cacheDir))

	hexDigests := []string{
		"aaaa111100000000000000000000000000000000000000000000000000000000",
		"bbbb222200000000000000000000000000000000000000000000000000000000",
	}

	populateCache(t, cacheDir, hexDigests)

	result, err := store.GC(GCOptions{
		ReferencedDigests: nil, // Nothing referenced
	})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}

	if len(result.RemovedBlobs) != 2 {
		t.Errorf("RemovedBlobs = %d, want 2", len(result.RemovedBlobs))
	}
	if len(result.RemovedDirs) != 2 {
		t.Errorf("RemovedDirs = %d, want 2", len(result.RemovedDirs))
	}
	if result.BytesReclaimed <= 0 {
		t.Error("BytesReclaimed should be positive")
	}

	// Verify all blobs are gone.
	for _, hex := range hexDigests {
		blobPath := filepath.Join(cacheDir, "sha256", hex[:2], hex)
		if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
			t.Errorf("blob %s should have been removed", hex[:8])
		}
	}

	// Verify shard directories were cleaned up.
	for _, hex := range hexDigests {
		shardDir := filepath.Join(cacheDir, "sha256", hex[:2])
		if _, err := os.Stat(shardDir); !os.IsNotExist(err) {
			t.Errorf("shard dir %s should have been removed", hex[:2])
		}
	}
}

// TestGCWithNonDirectoryInShard tests that GC ignores non-directory entries
// in the shard root (e.g. stray files).
func TestGCWithNonDirectoryInShard(t *testing.T) {
	cacheDir := t.TempDir()
	store := NewStore(WithCacheDir(cacheDir))

	// Create the sha256 root and put a stray file in it.
	blobRoot := filepath.Join(cacheDir, "sha256")
	if err := os.MkdirAll(blobRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobRoot, "stray-file"), []byte("stray"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := store.GC(GCOptions{})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}

	// The stray file should be ignored (not a directory shard).
	if len(result.RemovedBlobs) != 0 {
		t.Errorf("RemovedBlobs = %d, want 0", len(result.RemovedBlobs))
	}
}

// TestDirSize tests the dirSize helper function.
func TestDirSize(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a file with known content.
	content := "hello world, this is a test file for dirSize"
	if err := os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	size, err := dirSize(tmpDir)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if size != int64(len(content)) {
		t.Errorf("dirSize = %d, want %d", size, len(content))
	}
}

// TestDirSizeNestedDirs tests dirSize with nested directories.
func TestDirSizeNestedDirs(t *testing.T) {
	tmpDir := t.TempDir()

	sub := filepath.Join(tmpDir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	f1 := "file one"
	f2 := "file two content"
	if err := os.WriteFile(filepath.Join(tmpDir, "f1.txt"), []byte(f1), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f2.txt"), []byte(f2), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	size, err := dirSize(tmpDir)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	want := int64(len(f1) + len(f2))
	if size != want {
		t.Errorf("dirSize = %d, want %d", size, want)
	}
}

// TestDirSizeNonexistent tests dirSize with a nonexistent path.
func TestDirSizeNonexistent(t *testing.T) {
	_, err := dirSize("/nonexistent/path")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

// TestDirSizeSingleFile tests dirSize on a single file (not a directory).
func TestDirSizeSingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "single.txt")
	content := "single file"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	size, err := dirSize(path)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if size != int64(len(content)) {
		t.Errorf("dirSize = %d, want %d", size, len(content))
	}
}
