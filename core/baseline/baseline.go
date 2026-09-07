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
	// index holds EVERY entry per fingerprint, not the last one written.
	//
	// It used to hold one, and that quietly made a baseline unable to express
	// "two of these were accepted" — which matters because two genuinely
	// distinct findings share a fingerprint whenever a rule's message is a
	// static description. See Matcher.
	index map[string][]*Entry
}

// Load reads a baseline file from path. If the file does not exist, an empty
// baseline is returned with no error.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{
				SchemaVersion: schemaVersion,
				index:         make(map[string][]*Entry),
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
	for _, e := range b.index[fingerprint] {
		if e.ExpiresAt != nil && time.Now().After(*e.ExpiresAt) {
			continue
		}
		return e
	}
	return nil
}

// live returns the unexpired entries for a fingerprint, in file order.
func (b *Baseline) live(fingerprint string) []*Entry {
	if fingerprint == "" {
		return nil
	}
	out := make([]*Entry, 0, len(b.index[fingerprint]))
	for _, e := range b.index[fingerprint] {
		if e.ExpiresAt != nil && time.Now().After(*e.ExpiresAt) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Add appends an entry to the baseline and updates the index.
func (b *Baseline) Add(e *Entry) {
	if e == nil {
		return
	}
	b.Entries = append(b.Entries, *e)
	// Appending can reallocate the slice, which invalidates every pointer the
	// index holds. Rebuilding is O(n) per Add and this is not a hot path;
	// keeping stale pointers would be a bug that only appears past the
	// slice's initial capacity, which is the hardest kind to find.
	b.buildIndex()
}

// Prune removes entries whose fingerprints are not present in the current
// findings slice. Returns the number of entries removed.
func (b *Baseline) Prune(current []findings.Finding) int {
	// Counted, not a presence set. Entries are consumed one per finding now, so
	// a baseline holding four entries for a fingerprint that only two findings
	// still match is carrying two spares — and a spare is exactly what absorbs
	// the next occurrence without anyone accepting it. Pruning to the live
	// count keeps the file honest about how many were accepted.
	active := make(map[string]int, len(current))
	for i := range current {
		active[current[i].Fingerprint]++
	}

	kept := make([]Entry, 0, len(b.Entries))
	removed := 0
	for i := range b.Entries {
		entry := b.Entries[i]
		if active[entry.Fingerprint] > 0 {
			active[entry.Fingerprint]--
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
	b.index = make(map[string][]*Entry, len(b.Entries))
	for i := range b.Entries {
		fp := b.Entries[i].Fingerprint
		b.index[fp] = append(b.index[fp], &b.Entries[i])
	}
}

// Matcher applies a baseline to ONE scan's findings, consuming an entry per
// finding it suppresses.
//
// Baseline.Match answers "is this fingerprint accepted?", which sounds like the
// right question and is not. Under fingerprint v2 the digest is
// sha256(rule_id || path || message), and FindingSet.Add passes the finding's
// Message as content — so a rule whose message is a static description produces
// ONE fingerprint for every occurrence in a file. Four workflow steps with
// continue-on-error are four real findings and one digest.
//
// With a fingerprint-only lookup, accepting one of them accepted all four, and
// — the part that makes this a false negative rather than an inconvenience — it
// accepted the fifth somebody added a month later. That finding was born
// baselined. `nox scan` printed "0 findings (3 suppressed)" for a file whose
// problems had grown by half.
//
// Counting fixes it without giving back what v2 bought. An entry records that
// ONE instance was accepted:
//
//   - the code moves — one finding, one entry, still matched, which is the
//     whole reason the line was dropped from the digest
//   - a second instance appears — no entry left to consume, so it is reported
//   - an instance is removed — a spare entry remains, and Prune clears it
//
// A Matcher is single-use and not safe for concurrent use: the scan applies a
// baseline in one pass over an already-sorted finding set, so the assignment is
// deterministic without any ordering rule of its own.
type Matcher struct {
	b         *Baseline
	remaining map[string]int
}

// NewMatcher returns a consuming matcher over b. A nil Baseline yields a
// matcher that suppresses nothing.
func (b *Baseline) NewMatcher() *Matcher {
	m := &Matcher{b: b, remaining: map[string]int{}}
	if b == nil {
		return m
	}
	for fp := range b.index {
		m.remaining[fp] = len(b.live(fp))
	}
	return m
}

// Match returns the entry accepting f, consuming it, or nil when the baseline
// has no unconsumed entry for this finding.
//
// The alias fallback is preserved: a finding that inherited a retired rule ID
// is looked up under the fingerprint that rule would have produced, so retiring
// a duplicate rule ID does not un-baseline every finding accepted under it.
func (m *Matcher) Match(f *findings.Finding) *Entry {
	if m == nil || m.b == nil || f == nil {
		return nil
	}
	if e := m.consume(f.Fingerprint); e != nil {
		return e
	}
	for _, fp := range f.AliasFingerprints {
		if e := m.consume(fp); e != nil {
			return e
		}
	}
	return nil
}

// consume takes one entry for fingerprint if any remain.
func (m *Matcher) consume(fingerprint string) *Entry {
	if fingerprint == "" || m.remaining[fingerprint] <= 0 {
		return nil
	}
	live := m.b.live(fingerprint)
	if len(live) == 0 {
		return nil
	}
	// Which entry is handed back does not affect suppression — they share a
	// fingerprint — but taking them in file order keeps the reported reason
	// stable across runs.
	e := live[len(live)-m.remaining[fingerprint]]
	m.remaining[fingerprint]--
	return e
}
