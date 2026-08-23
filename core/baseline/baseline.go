// Package baseline provides finding baseline management for tracking known
// findings that should not trigger CI failures. Baselines are stored as JSON
// files with fingerprint-based O(1) lookup.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nox-hq/nox/core/fsutil"

	"github.com/nox-hq/nox/core/findings"
)

const schemaVersion = "1.0.0"

// Entry represents a single baselined finding.
type Entry struct {
	Fingerprint string            `json:"fingerprint"`
	RuleID      string            `json:"rule_id"`
	FilePath    string            `json:"file_path"`
	Severity    findings.Severity `json:"severity"`
	Reason      string            `json:"reason,omitempty"`
	Owner       string            `json:"owner,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
}

// Baseline holds a set of baselined finding entries with fast fingerprint lookup.
type Baseline struct {
	SchemaVersion string  `json:"schema_version"`
	Entries       []Entry `json:"entries"`
	index         map[string]*Entry
}

// Load reads a baseline file from path. If the file does not exist, an empty
// baseline is returned with no error.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{
				SchemaVersion: schemaVersion,
				index:         make(map[string]*Entry),
			}, nil
		}
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}

	b.buildIndex()
	return &b, nil
}

// Save writes the baseline to path using atomic temp-file + rename.
func (b *Baseline) Save(path string) error {
	b.SchemaVersion = schemaVersion

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling baseline: %w", err)
	}
	data = append(data, '\n')

	if err := fsutil.AtomicWriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing baseline: %w", err)
	}
	return nil
}

// Match returns the matching baseline entry for a finding, or nil if none.
// Expired entries are not matched.
//
// A finding that inherited a retired rule ID is also looked up under the
// fingerprint that retired rule would have produced (see
// findings.Finding.AliasFingerprints). Without that fallback, retiring a
// duplicate rule ID would silently un-baseline every finding accepted under it:
// the fingerprint hashes the rule ID, so the entry an operator committed would
// simply stop matching and the finding would resurface as new.
func (b *Baseline) Match(f *findings.Finding) *Entry {
	if f == nil {
		return nil
	}
	if e := b.lookup(f.Fingerprint); e != nil {
		return e
	}
	for _, fp := range f.AliasFingerprints {
		if e := b.lookup(fp); e != nil {
			return e
		}
	}
	return nil
}

// lookup returns the unexpired entry for a fingerprint, or nil.
func (b *Baseline) lookup(fingerprint string) *Entry {
	if fingerprint == "" {
		return nil
	}
	e, ok := b.index[fingerprint]
	if !ok {
		return nil
	}
	if e.ExpiresAt != nil && time.Now().After(*e.ExpiresAt) {
		return nil
	}
	return e
}

// Add appends an entry to the baseline and updates the index.
func (b *Baseline) Add(e *Entry) {
	if e == nil {
		return
	}
	b.Entries = append(b.Entries, *e)
	if b.index == nil {
		b.index = make(map[string]*Entry)
	}
	b.index[e.Fingerprint] = &b.Entries[len(b.Entries)-1]
}

// Prune removes entries whose fingerprints are not present in the current
// findings slice. Returns the number of entries removed.
func (b *Baseline) Prune(current []findings.Finding) int {
	active := make(map[string]struct{}, len(current))
	for i := range current {
		active[current[i].Fingerprint] = struct{}{}
	}

	kept := make([]Entry, 0, len(b.Entries))
	removed := 0
	for i := range b.Entries {
		entry := b.Entries[i]
		if _, ok := active[entry.Fingerprint]; ok {
			kept = append(kept, entry)
		} else {
			removed++
		}
	}

	b.Entries = kept
	b.buildIndex()
	return removed
}

// Len returns the number of entries in the baseline.
func (b *Baseline) Len() int {
	return len(b.Entries)
}

// ExpiredCount returns the number of entries that have expired.
func (b *Baseline) ExpiredCount() int {
	now := time.Now()
	count := 0
	for i := range b.Entries {
		entry := b.Entries[i]
		if entry.ExpiresAt != nil && now.After(*entry.ExpiresAt) {
			count++
		}
	}
	return count
}

// StatusSummary is the aggregate view of a baseline: its size, how many entries
// have expired, and the per-severity breakdown. Both the CLI `baseline show` and
// the MCP baseline_status tool project from this, so the two cannot report a
// baseline differently — and BySeverity is keyed by findings.Severity so a
// consumer iterating findings.SeverityOrder gets a deterministic order.
type StatusSummary struct {
	Total      int
	Expired    int
	BySeverity map[findings.Severity]int
}

// Status returns the aggregate status of the baseline. It is the single source
// both adapters use, replacing two ad-hoc per-severity loops (one of which
// iterated a map in non-deterministic order).
func (b *Baseline) Status() StatusSummary {
	bySev := make(map[findings.Severity]int, len(b.Entries))
	for i := range b.Entries {
		bySev[b.Entries[i].Severity]++
	}
	return StatusSummary{
		Total:      b.Len(),
		Expired:    b.ExpiredCount(),
		BySeverity: bySev,
	}
}

// DefaultPath returns the conventional baseline file location within a project.
func DefaultPath(root string) string {
	return filepath.Join(root, ".nox", "baseline.json")
}

// FromFindings creates baseline entries from a slice of findings.
func FromFindings(ff []findings.Finding) []Entry {
	entries := make([]Entry, 0, len(ff))
	now := time.Now().UTC()
	for i := range ff {
		finding := ff[i]
		entries = append(entries, Entry{
			Fingerprint: finding.Fingerprint,
			RuleID:      finding.RuleID,
			FilePath:    finding.Location.FilePath,
			Severity:    finding.Severity,
			CreatedAt:   now,
		})
	}
	return entries
}

func (b *Baseline) buildIndex() {
	b.index = make(map[string]*Entry, len(b.Entries))
	for i := range b.Entries {
		b.index[b.Entries[i].Fingerprint] = &b.Entries[i]
	}
}
