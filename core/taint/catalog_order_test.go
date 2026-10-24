package taint

import (
	"slices"
	"strings"
	"testing"
)

// The catalog is indexed by maps, and Go randomizes map iteration on every
// range. Every listing it hands out therefore has to impose an order, or any
// caller that keeps "the first one seen" reports a different answer per run.
// That is not hypothetical: the taintflow rule catalog took the first sink seen
// for each rule ID, and TAINT-005's SARIF description alternated between
// code_injection (CWE-95) and unsafe_deserialization (CWE-502) across identical
// scans of one tree.
//
// The order is asserted rather than sampled: a listing that iterates a map
// passes a repeated-equality check whenever the map happens to have one entry,
// and fails it only by chance otherwise.
func TestCatalogListingsAreSorted(t *testing.T) {
	cat := MustDefault()

	langs := cat.Languages()
	if len(langs) < 2 {
		t.Fatalf("Languages() = %v: too few to tell sorted from unsorted", langs)
	}
	if !slices.IsSorted(langs) {
		t.Errorf("Languages() is not sorted: %v", langs)
	}

	for _, lang := range langs {
		if s := cat.Sinks(lang); !slices.IsSortedFunc(s, func(a, b Sink) int { return strings.Compare(a.Call, b.Call) }) {
			t.Errorf("Sinks(%q) is not sorted by call", lang)
		}
		if s := cat.Sources(lang); !slices.IsSortedFunc(s, func(a, b Source) int { return strings.Compare(a.Call, b.Call) }) {
			t.Errorf("Sources(%q) is not sorted by call", lang)
		}
		if s := cat.Sanitizers(lang); !slices.IsSortedFunc(s, func(a, b Sanitizer) int { return strings.Compare(a.Call, b.Call) }) {
			t.Errorf("Sanitizers(%q) is not sorted by call", lang)
		}
	}
}
