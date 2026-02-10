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

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating baseline directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming baseline file: %w", err)
	}

	return nil
}

// Match returns the matching baseline entry for a finding, or nil if none.
// Expired entries are not matched.
func (b *Baseline) Match(f findings.Finding) *Entry {
	e, ok := b.index[f.Fingerprint]
	if !ok {
		return nil
	}
	if e.ExpiresAt != nil && time.Now().After(*e.ExpiresAt) {
		return nil
	}
	return e
}

// Add appends an entry to the baseline and updates the index.
func (b *Baseline) Add(e Entry) {
	b.Entries = append(b.Entries, e)
	if b.index == nil {
		b.index = make(map[string]*Entry)
	}
	b.index[e.Fingerprint] = &b.Entries[len(b.Entries)-1]
}

// Prune removes entries whose fingerprints are not present in the current
// findings slice. Returns the number of entries removed.
func (b *Baseline) Prune(current []findings.Finding) int {
	active := make(map[string]struct{}, len(current))
	for _, f := range current {
		active[f.Fingerprint] = struct{}{}
	}

	kept := make([]Entry, 0, len(b.Entries))
	removed := 0
	for _, e := range b.Entries {
		if _, ok := active[e.Fingerprint]; ok {
			kept = append(kept, e)
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
	for _, e := range b.Entries {
		if e.ExpiresAt != nil && now.After(*e.ExpiresAt) {
			count++
		}
	}
	return count
}

// DefaultPath returns the conventional baseline file location within a project.
func DefaultPath(root string) string {
	return filepath.Join(root, ".nox", "baseline.json")
}

// FromFindings creates baseline entries from a slice of findings.
func FromFindings(ff []findings.Finding) []Entry {
	entries := make([]Entry, 0, len(ff))
	now := time.Now().UTC()
	for _, f := range ff {
		entries = append(entries, Entry{
			Fingerprint: f.Fingerprint,
			RuleID:      f.RuleID,
			FilePath:    f.Location.FilePath,
			Severity:    f.Severity,
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
