package fsutil

import (
	"container/list"
	"os"
	"sync"
)

// ReadCache shares file reads between the analyzers of one scan.
//
// Every analyzer reads the files it examines itself -- secrets, AI, data, IaC,
// taint and a dozen more -- so one scan opened each file up to fifteen times.
// On the 2026-09-27 profile of crewAI that was 21% of CPU, almost all of it in
// open(2) (#736). The analyzers run in parallel over broadly the same artifact
// order, so a bounded cache sees each file while it is still hot: the first
// analyzer to ask reads it, the others share the bytes.
//
// It never changes what an analyzer sees: the bytes are exactly os.ReadFile's.
// Callers must not modify the returned slice; every analyzer in nox only reads
// content, and one that needs to edit bytes copies them (see the secrets
// analyzer's notebook handling).
//
// A read in flight is shared too, so two analyzers asking for the same file at
// once cause one read. Errors are not cached: a failed read is retried by the
// next caller, exactly as os.ReadFile would behave.
type ReadCache struct {
	mu       sync.Mutex
	budget   int64
	used     int64
	order    *list.List // front = most recently used; values are *cacheEntry
	entries  map[string]*list.Element
	inflight map[string]*inflightRead
}

type cacheEntry struct {
	path string
	data []byte
}

type inflightRead struct {
	done chan struct{}
	data []byte
	err  error
}

// NewReadCache returns a cache that holds at most budget bytes of file
// content. A file larger than the budget is read and returned but not kept.
func NewReadCache(budget int64) *ReadCache {
	return &ReadCache{
		budget:   budget,
		order:    list.New(),
		entries:  map[string]*list.Element{},
		inflight: map[string]*inflightRead{},
	}
}

// ReadFile returns the content of path, from the cache when it holds it. A nil
// *ReadCache reads straight from disk, so callers need no second code path.
func (c *ReadCache) ReadFile(path string) ([]byte, error) {
	if c == nil {
		return os.ReadFile(path) // #nosec G304 -- callers pass discovered artifact paths
	}
	c.mu.Lock()
	if el, ok := c.entries[path]; ok {
		c.order.MoveToFront(el)
		data := el.Value.(*cacheEntry).data
		c.mu.Unlock()
		return data, nil
	}
	if r, ok := c.inflight[path]; ok {
		c.mu.Unlock()
		<-r.done
		return r.data, r.err
	}
	r := &inflightRead{done: make(chan struct{})}
	c.inflight[path] = r
	c.mu.Unlock()

	r.data, r.err = os.ReadFile(path) // #nosec G304 -- callers pass discovered artifact paths
	close(r.done)

	c.mu.Lock()
	delete(c.inflight, path)
	if r.err == nil && int64(len(r.data)) <= c.budget {
		c.entries[path] = c.order.PushFront(&cacheEntry{path: path, data: r.data})
		c.used += int64(len(r.data))
		for c.used > c.budget {
			oldest := c.order.Back()
			e := oldest.Value.(*cacheEntry)
			c.order.Remove(oldest)
			delete(c.entries, e.path)
			c.used -= int64(len(e.data))
		}
	}
	c.mu.Unlock()
	return r.data, r.err
}
