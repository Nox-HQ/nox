package osv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nox-hq/nox/core/vulnsource"
)

// AdvisoryCache stores hydrated advisory documents between scans.
//
// Nearly all the traffic a dependency scan generates is advisory detail. A
// seven-package corpus producing 114 findings issues 1 batch query and 114
// detail fetches — half a megabyte — and issues exactly the same 114 on the
// next scan, and the next, for every developer and every CI run.
//
// The batch query is never cached. It is one cheap request, and it answers the
// only question whose answer actually changes often: which advisories match
// this package version right now. Caching that would introduce a window in
// which a freshly published CVE is invisible, which is the one thing a
// vulnerability scanner must not do.
//
// Advisory documents are cached, and keyed on the advisory id together with
// OSV's own `modified` stamp. That is a validator rather than a guess: an
// entry is reusable for exactly as long as upstream has not changed the
// advisory, and is missed the moment it does. There is no staleness window to
// tune and no TTL to get wrong.
type AdvisoryCache interface {
	// Get returns the cached advisory for (id, validator), if present.
	Get(id, validator string) (vulnsource.Record, bool)
	// Put stores an advisory under the validator the caller will look it up
	// with. Failures are silently ignored: a cache that cannot write must slow
	// a scan down, never fail it.
	Put(id, validator string, rec vulnsource.Record)
}

// entry is the stored envelope.
//
// The validator is recorded alongside the advisory rather than being read back
// off the record, because the two are not always the same string. OSV returns
// `modified` truncated to microseconds in a batch response and to nanoseconds
// in a detail response — 2026-08-10T15:39:09.350867Z against
// ...350867226Z — for roughly half of all advisories.
//
// Keying the stored copy on the detail's value while looking it up with the
// batch's meant those advisories missed on every single scan, refetched, and
// rewrote the same file. The cache appeared to work: entry count was stable,
// nothing errored, and half the traffic simply never went away. Storing the
// validator the caller queries by removes the whole class of problem, and does
// not depend on either endpoint's timestamp formatting staying put.
type entry struct {
	ID        string            `json:"id"`
	Validator string            `json:"validator"`
	Record    vulnsource.Record `json:"record"`
}

// pruneAfter bounds how long an untouched entry survives. Advisories are small,
// but a long-lived workstation should not accumulate documents for packages it
// stopped depending on years ago.
const pruneAfter = 90 * 24 * time.Hour

// DefaultCacheDir returns the default advisory cache directory
// (~/.nox/cache/advisories/).
func DefaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".nox", "cache", "advisories")
	}
	return filepath.Join(home, ".nox", "cache", "advisories")
}

// FileCache is a filesystem-backed AdvisoryCache.
//
// Every operation fails open. A corrupt file, an unreadable directory, a full
// disk — each is treated as a miss, because a scan that fails because its cache
// is broken is worse than a scan that is merely slow.
type FileCache struct {
	dir string

	mu  sync.RWMutex
	mem map[string]vulnsource.Record
}

// NewFileCache returns a cache rooted at dir. An empty dir uses
// DefaultCacheDir.
func NewFileCache(dir string) *FileCache {
	if dir == "" {
		dir = DefaultCacheDir()
	}
	return &FileCache{dir: dir, mem: make(map[string]vulnsource.Record)}
}

// key derives the on-disk name from the advisory's identity and version. Both
// are hashed together so a changed advisory cannot collide with its own older
// copy, and so an id containing path separators cannot escape the cache
// directory.
func key(id, validator string) string {
	sum := sha256.Sum256([]byte(id + "\x00" + validator))
	return hex.EncodeToString(sum[:])
}

func (c *FileCache) path(k string) string { return filepath.Join(c.dir, k+".json") }

// Get returns the cached advisory for (id, modified).
func (c *FileCache) Get(id, validator string) (vulnsource.Record, bool) {
	if id == "" || validator == "" {
		// Without a validator there is nothing to key on, and reusing an
		// advisory whose version is unknown is exactly the staleness this
		// design exists to avoid.
		return vulnsource.Record{}, false
	}
	k := key(id, validator)

	c.mu.RLock()
	rec, ok := c.mem[k]
	c.mu.RUnlock()
	if ok {
		return rec, true
	}

	body, err := os.ReadFile(c.path(k))
	if err != nil {
		return vulnsource.Record{}, false
	}
	var e entry
	if err := json.Unmarshal(body, &e); err != nil {
		return vulnsource.Record{}, false
	}
	// Verify the entry is the one asked for. A hash collision is vanishingly
	// unlikely; a truncated or hand-edited file is not, and serving the wrong
	// advisory would silently mislabel a finding.
	if e.ID != id || e.Validator != validator || e.Record.ID != id {
		return vulnsource.Record{}, false
	}

	c.mu.Lock()
	c.mem[k] = e.Record
	c.mu.Unlock()
	return e.Record, true
}

// Put stores an advisory under the validator the caller will query by.
func (c *FileCache) Put(id, validator string, rec vulnsource.Record) {
	if id == "" || validator == "" || rec.ID == "" {
		return
	}
	k := key(id, validator)

	c.mu.Lock()
	c.mem[k] = rec
	c.mu.Unlock()

	body, err := json.Marshal(entry{ID: id, Validator: validator, Record: rec})
	if err != nil {
		return
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return
	}
	// Write to a temporary file and rename, so a scan interrupted mid-write
	// leaves the previous entry intact rather than a half-written one that
	// would be read back as a miss forever.
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, c.path(k)); err != nil {
		_ = os.Remove(tmpName)
	}
}

// Prune removes entries untouched for longer than pruneAfter. It is best
// effort and reports how many entries it removed.
func (c *FileCache) Prune(now time.Time) int {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > pruneAfter {
			if os.Remove(filepath.Join(c.dir, e.Name())) == nil {
				removed++
			}
		}
	}
	return removed
}

// Stats reports the number of entries and their total size on disk.
func (c *FileCache) Stats() (entries int, bytes int64) {
	items, err := os.ReadDir(c.dir)
	if err != nil {
		return 0, 0
	}
	for _, e := range items {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		entries++
		bytes += info.Size()
	}
	return entries, bytes
}

// Clear removes every cached advisory.
func (c *FileCache) Clear() error {
	c.mu.Lock()
	c.mem = make(map[string]vulnsource.Record)
	c.mu.Unlock()
	return os.RemoveAll(c.dir)
}
