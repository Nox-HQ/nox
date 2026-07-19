package degrade

import (
	"strings"
	"sync"
	"testing"
)

func TestDegradations_NilReceiverIsSafe(t *testing.T) {
	t.Parallel()

	// Library callers that do not want degradation reporting pass nil. That
	// must not panic, or every optional call site would need a guard.
	var d *Degradations
	d.Add(OSV, "detail", "impact")

	if got := d.Len(); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
	if got := d.Items(); got != nil {
		t.Errorf("expected nil items, got %v", got)
	}
}

func TestDegradations_ItemsAreDeterministic(t *testing.T) {
	t.Parallel()

	// Analyzers run in parallel, so insertion order varies run to run. Nox
	// guarantees identical output for identical input, so Items must sort.
	build := func(order []Kind) []Degradation {
		d := &Degradations{}
		for _, k := range order {
			d.Add(k, string(k)+"-detail", "impact")
		}
		return d.Items()
	}

	forward := build([]Kind{OSV, Lockfile, Plugin, Baseline})
	reverse := build([]Kind{Baseline, Plugin, Lockfile, OSV})

	if len(forward) != len(reverse) {
		t.Fatalf("length mismatch: %d vs %d", len(forward), len(reverse))
	}
	for i := range forward {
		if forward[i] != reverse[i] {
			t.Errorf("index %d differs: %+v vs %+v", i, forward[i], reverse[i])
		}
	}
}

func TestDegradations_SortsByKindThenDetail(t *testing.T) {
	t.Parallel()

	d := &Degradations{}
	d.Add(OSV, "zzz", "impact")
	d.Add(Lockfile, "bbb", "impact")
	d.Add(OSV, "aaa", "impact")

	items := d.Items()
	want := []struct{ kind, detail string }{
		{string(Lockfile), "bbb"},
		{string(OSV), "aaa"},
		{string(OSV), "zzz"},
	}
	if len(items) != len(want) {
		t.Fatalf("expected %d items, got %d", len(want), len(items))
	}
	for i, w := range want {
		if string(items[i].Kind) != w.kind || items[i].Detail != w.detail {
			t.Errorf("index %d: expected %s/%s, got %s/%s", i, w.kind, w.detail, items[i].Kind, items[i].Detail)
		}
	}
}

func TestDegradations_ConcurrentAdd(t *testing.T) {
	t.Parallel()

	// The collector is shared across the parallel analyzer errgroup, so it
	// must tolerate concurrent writes. Run with -race to make this meaningful.
	d := &Degradations{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Add(OSV, "concurrent", "impact")
		}()
	}
	wg.Wait()

	if got := d.Len(); got != 50 {
		t.Errorf("expected 50 degradations, got %d", got)
	}
}

func TestDegradation_StringIncludesImpact(t *testing.T) {
	t.Parallel()

	// The impact text is the part that tells an operator whether to trust the
	// scan, so it must not be dropped from the rendered form.
	d := Degradation{Kind: OSV, Detail: "lookup failed", Impact: "CVEs under-reported"}
	got := d.String()
	for _, want := range []string{"osv_lookup", "lookup failed", "CVEs under-reported"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q to contain %q", got, want)
		}
	}
}
