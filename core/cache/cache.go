// Package cache provides a content-addressable scan cache that stores findings
// keyed by file path and SHA-256 hash. On subsequent scans, files whose content
// hash matches the cache can skip re-analysis.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nox-hq/nox/core/fsutil"

	"github.com/nox-hq/nox/core/findings"
)

// DefaultDir returns the default cache directory (~/.nox/cache/scan/).
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".nox", "cache", "scan")
	}
	return filepath.Join(home, ".nox", "cache", "scan")
}

// DefaultTTL is the default cache entry time-to-live.
const DefaultTTL = 7 * 24 * time.Hour

// Entry is a single cached scan result for a file.
type Entry struct {
	SHA256    string             `json:"sha256"`
	Findings  []findings.Finding `json:"findings"`
	CreatedAt time.Time          `json:"created_at"`
}

// Store is the on-disk cache structure. It maps relative file paths to entries.
type Store struct {
	Entries map[string]Entry `json:"entries"`
	Version string           `json:"version"`
}

// ScanCache provides content-addressable caching for scan results.
type ScanCache struct {
	mu      sync.Mutex
	dir     string
	ttl     time.Duration
	store   *Store
	dirty   bool
	nowFunc func() time.Time
}

// Option configures a ScanCache.
type Option func(*ScanCache)

// WithDir sets the cache directory.
func WithDir(dir string) Option {
	return func(c *ScanCache) { c.dir = dir }
}

// WithTTL sets the cache entry TTL.
func WithTTL(ttl time.Duration) Option {
	return func(c *ScanCache) { c.ttl = ttl }
}

// New creates a new ScanCache. If no options are provided, defaults are used.
func New(opts ...Option) *ScanCache {
	c := &ScanCache{
		dir:     DefaultDir(),
		ttl:     DefaultTTL,
		nowFunc: time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Load reads the cache from disk. If the cache file does not exist, an empty
// store is initialized.
func (c *ScanCache) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.storePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			c.store = &Store{Entries: make(map[string]Entry), Version: "1"}
			return nil
		}
		return fmt.Errorf("reading cache: %w", err)
	}

	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		// Corrupted cache — start fresh.
		c.store = &Store{Entries: make(map[string]Entry), Version: "1"}
		return nil
	}
	if s.Entries == nil {
		s.Entries = make(map[string]Entry)
	}
	c.store = &s
	c.evictExpired()
	return nil
}

// Has returns true if the cache contains a valid entry for the given path
// and content hash.
func (c *ScanCache) Has(path, sha256Hash string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.store == nil {
		return false
	}
	entry, ok := c.store.Entries[path]
	if !ok {
		return false
	}
	if entry.SHA256 != sha256Hash {
		return false
	}
	if c.nowFunc().Sub(entry.CreatedAt) > c.ttl {
		delete(c.store.Entries, path)
		c.dirty = true
		return false
	}
	return true
}

// Get returns cached findings for the given path, or nil if not cached.
func (c *ScanCache) Get(path string) []findings.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.store == nil {
		return nil
	}
	entry, ok := c.store.Entries[path]
	if !ok {
		return nil
	}
	return entry.Findings
}

// Put stores findings for the given path and content hash.
func (c *ScanCache) Put(path, sha256Hash string, f []findings.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.store == nil {
		c.store = &Store{Entries: make(map[string]Entry), Version: "1"}
	}
	c.store.Entries[path] = Entry{
		SHA256:    sha256Hash,
		Findings:  f,
		CreatedAt: c.nowFunc(),
	}
	c.dirty = true
}

// Save writes the cache to disk if dirty. Uses atomic write (temp + rename).
func (c *ScanCache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.dirty || c.store == nil {
		return nil
	}

	data, err := json.Marshal(c.store)
	if err != nil {
		return fmt.Errorf("marshaling cache: %w", err)
	}
	if err := fsutil.AtomicWriteFile(c.storePath(), data, 0o644); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}

	c.dirty = false
	return nil
}

// InvalidateAll clears the entire cache.
func (c *ScanCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.store = &Store{Entries: make(map[string]Entry), Version: "1"}
	c.dirty = true
}

// InvalidatePath removes a single path from the cache.
func (c *ScanCache) InvalidatePath(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.store == nil {
		return
	}
	delete(c.store.Entries, path)
	c.dirty = true
}

// Stats returns cache statistics.
func (c *ScanCache) Stats() (entries int, sizeBytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.store == nil {
		return 0, 0
	}
	entries = len(c.store.Entries)

	info, err := os.Stat(c.storePath())
	if err == nil {
		sizeBytes = info.Size()
	}
	return entries, sizeBytes
}

// Clear removes the cache file from disk.
func (c *ScanCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.store = &Store{Entries: make(map[string]Entry), Version: "1"}
	c.dirty = false

	path := c.storePath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing cache: %w", err)
	}
	return nil
}

// HashContent returns the SHA-256 hex digest of the given content.
func HashContent(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

func (c *ScanCache) storePath() string {
	return filepath.Join(c.dir, "cache.json")
}

func (c *ScanCache) evictExpired() {
	now := c.nowFunc()
	for path, entry := range c.store.Entries {
		if now.Sub(entry.CreatedAt) > c.ttl {
			delete(c.store.Entries, path)
			c.dirty = true
		}
	}
}
