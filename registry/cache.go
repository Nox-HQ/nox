package registry

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// fileCache stores registry indexes on disk with TTL-based staleness checks.
type fileCache struct {
	dir string
	ttl time.Duration
}

func newFileCache(dir string, ttl time.Duration) *fileCache {
	return &fileCache{dir: dir, ttl: ttl}
}

// load reads a cached index for the given source. Returns os.ErrNotExist if
// the cache file does not exist.
func (c *fileCache) load(source Source) (*Index, error) {
	data, err := os.ReadFile(c.path(source))
	if err != nil {
		return nil, err
	}

	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("corrupt cache for %q: %w", source.Name, err)
	}
	return &idx, nil
}

// store writes an index to the cache using atomic write (temp file + rename).
func (c *fileCache) store(source Source, idx *Index) error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}

	data, err := json.Marshal(idx)
	if err != nil {
		return fmt.Errorf("marshaling index: %w", err)
	}

	target := c.path(source)
	tmp := target + ".tmp"

	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing temp cache file: %w", err)
	}

	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming cache file: %w", err)
	}

	return nil
}

// isStale returns true if the cached index for the source is missing or older
// than the configured TTL.
func (c *fileCache) isStale(source Source) bool {
	info, err := os.Stat(c.path(source))
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) > c.ttl
}

// path returns the deterministic cache file path for a source, derived from
// the SHA-256 hash of the source URL (truncated to 16 hex characters).
func (c *fileCache) path(source Source) string {
	h := sha256.Sum256([]byte(source.URL))
	name := fmt.Sprintf("%x.json", h[:8]) // 16 hex chars
	return filepath.Join(c.dir, name)
}
