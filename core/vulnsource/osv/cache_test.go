package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/vulnsource"
)

func advisory(id, modified, summary string) vulnsource.Record {
	return vulnsource.Record{
		ID: id, Modified: modified, Summary: summary,
		Severity: []vulnsource.Severity{{Type: "CVSS_V3", Score: "9.8"}},
	}
}

// The cache key is the advisory's own version. An entry is reusable while
// upstream has not changed the advisory, and missed the instant it does — no
// staleness window, no TTL to get wrong.
func TestFileCache_KeyedOnModified(t *testing.T) {
	c := NewFileCache(t.TempDir())
	c.Put("GHSA-1", "2026-01-01T00:00:00Z", advisory("GHSA-1", "2026-01-01T00:00:00Z", "first"))

	got, ok := c.Get("GHSA-1", "2026-01-01T00:00:00Z")
	if !ok || got.Summary != "first" {
		t.Fatalf("same version should hit: %+v ok=%v", got, ok)
	}

	if _, ok := c.Get("GHSA-1", "2026-06-01T00:00:00Z"); ok {
		t.Error("a changed advisory served a stale cached copy")
	}
}

// Without a validator there is nothing safe to key on.
func TestFileCache_NoValidatorNeverCaches(t *testing.T) {
	c := NewFileCache(t.TempDir())
	c.Put("GHSA-1", "", advisory("GHSA-1", "", "no version"))
	if _, ok := c.Get("GHSA-1", ""); ok {
		t.Error("an advisory with no modified stamp was cached")
	}
}

// Entries survive process restarts — that is the entire point.
func TestFileCache_PersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	NewFileCache(dir).Put("GHSA-2", "2026-01-01T00:00:00Z", advisory("GHSA-2", "2026-01-01T00:00:00Z", "persisted"))

	got, ok := NewFileCache(dir).Get("GHSA-2", "2026-01-01T00:00:00Z")
	if !ok || got.Summary != "persisted" {
		t.Fatalf("entry did not survive: %+v ok=%v", got, ok)
	}
}

// A corrupt or mismatched entry is a miss, never a wrong answer. Serving the
// wrong advisory would silently mislabel a finding.
func TestFileCache_CorruptEntryIsAMiss(t *testing.T) {
	dir := t.TempDir()
	c := NewFileCache(dir)
	c.Put("GHSA-3", "2026-01-01T00:00:00Z", advisory("GHSA-3", "2026-01-01T00:00:00Z", "good"))

	// Drop the in-memory layer so the read goes to disk.
	c = NewFileCache(dir)
	path := filepath.Join(dir, key("GHSA-3", "2026-01-01T00:00:00Z")+".json")
	if err := os.WriteFile(path, []byte("{ truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("GHSA-3", "2026-01-01T00:00:00Z"); ok {
		t.Error("a corrupt entry was served")
	}

	// A well-formed file holding the wrong advisory is also a miss.
	other, _ := json.Marshal(entry{
		ID: "GHSA-3", Validator: "2026-01-01T00:00:00Z",
		Record: advisory("GHSA-OTHER", "2026-01-01T00:00:00Z", "wrong"),
	})
	if err := os.WriteFile(path, other, 0o600); err != nil {
		t.Fatal(err)
	}
	c = NewFileCache(dir)
	if _, ok := c.Get("GHSA-3", "2026-01-01T00:00:00Z"); ok {
		t.Error("an entry holding a different advisory was served")
	}
}

// A cache that cannot write must slow a scan down, never fail it.
func TestFileCache_UnwritableFailsOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested")
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewFileCache(dir)
	c.Put("GHSA-4", "2026-01-01T00:00:00Z", advisory("GHSA-4", "2026-01-01T00:00:00Z", "x")) // must not panic
	if _, ok := NewFileCache(dir).Get("GHSA-4", "2026-01-01T00:00:00Z"); ok {
		t.Error("an unwritable cache reported a hit")
	}
}

func TestFileCache_PrunesStaleEntries(t *testing.T) {
	dir := t.TempDir()
	c := NewFileCache(dir)
	c.Put("GHSA-5", "2026-01-01T00:00:00Z", advisory("GHSA-5", "2026-01-01T00:00:00Z", "old"))

	path := filepath.Join(dir, key("GHSA-5", "2026-01-01T00:00:00Z")+".json")
	old := time.Now().Add(-pruneAfter - time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if n := c.Prune(time.Now()); n != 1 {
		t.Errorf("pruned %d entries, want 1", n)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("stale entry survived pruning")
	}
}

// The end-to-end property: the batch query stays live on every lookup while
// advisory detail is served from cache. That is what removes ~99% of the
// traffic without ever hiding a newly published advisory.
func TestSource_CachesDetailButNeverTheBatch(t *testing.T) {
	var batches, details atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			batches.Add(1)
			encodeJSON(t, w, BatchResponse{Results: []BatchResult{{
				Vulns: []vulnsource.Record{{ID: "GHSA-9", Modified: "2026-01-01T00:00:00Z"}},
			}}})
			return
		}
		details.Add(1)
		encodeJSON(t, w, advisory("GHSA-9", "2026-01-01T00:00:00Z", "detailed"))
	}))
	defer srv.Close()

	cache := NewFileCache(t.TempDir())
	src := New(srv.URL, srv.Client(), nil).WithCache(cache)
	qs := []vulnsource.Query{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"}}

	for i := range 3 {
		got, err := src.Lookup(context.Background(), qs)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(got[0]) != 1 || got[0][0].Summary != "detailed" {
			t.Fatalf("run %d returned %+v; every run must be fully hydrated", i, got[0])
		}
	}

	if b := batches.Load(); b != 3 {
		t.Errorf("batch queries = %d, want 3 — the batch must never be cached", b)
	}
	if d := details.Load(); d != 1 {
		t.Errorf("detail fetches = %d, want 1 — detail must be cached after the first", d)
	}
}

// When upstream changes the advisory, the next scan refetches it.
func TestSource_RefetchesWhenAdvisoryChanges(t *testing.T) {
	var details atomic.Int32
	modified := "2026-01-01T00:00:00Z"
	summary := "original"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			encodeJSON(t, w, BatchResponse{Results: []BatchResult{{
				Vulns: []vulnsource.Record{{ID: "GHSA-9", Modified: modified}},
			}}})
			return
		}
		details.Add(1)
		encodeJSON(t, w, advisory("GHSA-9", modified, summary))
	}))
	defer srv.Close()

	src := New(srv.URL, srv.Client(), nil).WithCache(NewFileCache(t.TempDir()))
	qs := []vulnsource.Query{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"}}

	if _, err := src.Lookup(context.Background(), qs); err != nil {
		t.Fatal(err)
	}
	modified, summary = "2026-06-01T00:00:00Z", "revised upward to critical"

	got, err := src.Lookup(context.Background(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if got[0][0].Summary != "revised upward to critical" {
		t.Errorf("summary = %q; a revised advisory was served from cache",
			got[0][0].Summary)
	}
	if d := details.Load(); d != 2 {
		t.Errorf("detail fetches = %d, want 2 — the changed advisory must be refetched", d)
	}
}

// OSV reports `modified` truncated to microseconds in a batch response and to
// nanoseconds in a detail response, for roughly half of all advisories:
//
//	batch  2026-08-10T15:39:09.350867Z
//	detail 2026-08-10T15:39:09.350867226Z
//
// Storing the advisory under the detail's value while looking it up with the
// batch's meant those advisories missed on every scan, refetched, and rewrote
// the same file. Nothing errored and the entry count stayed flat, so the cache
// looked healthy while half the traffic never went away. Only a request count
// exposed it.
func TestSource_CachesDespiteDivergentTimestampPrecision(t *testing.T) {
	const (
		batchStamp  = "2026-08-10T15:39:09.350867Z"
		detailStamp = "2026-08-10T15:39:09.350867226Z"
	)
	var details atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			encodeJSON(t, w, BatchResponse{Results: []BatchResult{{
				Vulns: []vulnsource.Record{{ID: "GHSA-P", Modified: batchStamp}},
			}}})
			return
		}
		details.Add(1)
		encodeJSON(t, w, advisory("GHSA-P", detailStamp, "detailed"))
	}))
	defer srv.Close()

	src := New(srv.URL, srv.Client(), nil).WithCache(NewFileCache(t.TempDir()))
	qs := []vulnsource.Query{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"}}

	for i := range 4 {
		if _, err := src.Lookup(context.Background(), qs); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if d := details.Load(); d != 1 {
		t.Errorf("detail fetches = %d, want 1 — the advisory is being refetched "+
			"every scan because it is stored under a validator no lookup uses", d)
	}
}
