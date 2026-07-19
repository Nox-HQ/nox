package degrade

import (
	"fmt"
	"sort"
	"sync"
)

// Kind classifies why part of a scan could not run.
type Kind string

const (
	// OSV means a vulnerability lookup against OSV.dev failed, so
	// dependency vulnerabilities are under-reported.
	OSV Kind = "osv_lookup"

	// Lockfile means a lockfile was found but could not be parsed,
	// so its packages are absent from the inventory and from vulnerability
	// matching.
	Lockfile Kind = "lockfile_parse"

	// VulnData means an embedded vulnerability dataset (known
	// malicious packages, popular-package lists) failed to load, silently
	// disabling the detections built on it.
	VulnData Kind = "vuln_data_load"

	// Plugin means an analysis plugin failed to run, so any findings
	// it would have produced are missing.
	Plugin Kind = "plugin"

	// Baseline means a baseline file existed but could not be read,
	// so new-vs-known classification is not being applied.
	Baseline Kind = "baseline"

	// Suppression means a file could not be re-read to apply inline
	// suppression comments, so its findings are reported unsuppressed.
	Suppression Kind = "suppression"
)

// Degradation records that some part of the scan did not run to completion.
//
// This type exists because a security scanner's most dangerous failure mode is
// not crashing — it is reporting "no findings" when it never actually looked.
// Nox degrades gracefully in many places by design (an OSV outage should not
// fail a build), but graceful degradation is only safe if it is *visible*.
// Every site that swallows an error to keep the scan running records a
// Degradation here so the operator, and CI, can tell the difference between
// "clean" and "did not check".
type Degradation struct {
	// Kind classifies the failure so callers can filter programmatically.
	Kind Kind

	// Detail is a human-readable explanation naming the affected subject
	// (a file path, package count, plugin name).
	Detail string

	// Impact states, in the operator's terms, what may now be missing from
	// the results. This is the field that answers "should I trust this scan?".
	Impact string
}

// String renders a degradation as a single diagnostic line.
func (d Degradation) String() string {
	return fmt.Sprintf("%s: %s (%s)", d.Kind, d.Detail, d.Impact)
}

// Degradations is a concurrency-safe collector for Degradation records.
//
// Analyzers run in parallel, so the collector is shared across goroutines. The
// zero value is ready to use; a nil *Degradations silently discards records so
// that callers which do not care (tests, library users) need not construct one.
type Degradations struct {
	mu    sync.Mutex
	items []Degradation
}

// Add records a degradation. It is safe to call concurrently, and safe to call
// on a nil receiver.
func (d *Degradations) Add(kind Kind, detail, impact string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.items = append(d.items, Degradation{Kind: kind, Detail: detail, Impact: impact})
}

// Items returns the collected degradations in a deterministic order: by kind,
// then detail. Analyzers run concurrently, so insertion order varies between
// runs — sorting keeps scan output reproducible, which nox guarantees.
func (d *Degradations) Items() []Degradation {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]Degradation, len(d.items))
	copy(out, d.items)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

// Len reports how many degradations were recorded.
func (d *Degradations) Len() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.items)
}
