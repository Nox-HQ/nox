package mcpdrift

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nox-hq/nox/core/fsutil"
)

const baselineSchemaVersion = "1.0.0"

// Meta holds the non-diffable half of a baseline: how and when it was captured.
// It is deliberately kept OUT of Manifest so that the comparable state carries
// no timestamps — two captures of an unchanged server diff to nothing even
// though their capture times differ.
type Meta struct {
	// Command is the server launch command that produced this baseline, recorded
	// so `nox mcp drift` re-captures the same server and a reviewer can see what
	// was launched.
	Command []string `json:"command"`
	// CapturedAt is when the baseline was captured (informational only; never
	// part of the drift comparison).
	CapturedAt time.Time `json:"captured_at"`
	// Fingerprint is the manifest fingerprint at capture time — a quick
	// equality check and a stable identifier to reference in reviews.
	Fingerprint string `json:"fingerprint"`
}

// Baseline is the reviewable, diffable record of an MCP server's tool manifest.
// It is JSON on disk: commit it, diff it in a PR, and review drift as data.
type Baseline struct {
	SchemaVersion string   `json:"schema_version"`
	Meta          Meta     `json:"meta"`
	Manifest      Manifest `json:"manifest"`
}

// NewBaseline builds a Baseline from a freshly captured manifest and the command
// that produced it. CapturedAt honors SOURCE_DATE_EPOCH-style reproducibility by
// accepting the timestamp from the caller.
func NewBaseline(command []string, m Manifest, capturedAt time.Time) *Baseline {
	return &Baseline{
		SchemaVersion: baselineSchemaVersion,
		Meta: Meta{
			Command:     command,
			CapturedAt:  capturedAt.UTC(),
			Fingerprint: m.Fingerprint(),
		},
		Manifest: m,
	}
}

// DefaultPath returns the conventional MCP baseline location within a project,
// mirroring the finding baseline's `.nox/` convention.
func DefaultPath(root string) string {
	return filepath.Join(root, ".nox", "mcp-baseline.json")
}

// Load reads a baseline from path. A missing file is an error here (unlike the
// finding baseline): drift detection is meaningless without a recorded baseline,
// so the caller should surface "capture one first" rather than silently compare
// against nothing.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading mcp baseline %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing mcp baseline %s: %w", path, err)
	}
	// Re-canonicalize schemas: the on-disk (indented) form differs byte-wise
	// from a fresh compact capture, which would otherwise report phantom drift.
	b.Manifest.normalize()
	return &b, nil
}

// Save writes the baseline to path using atomic temp-file + rename, matching the
// finding baseline's durability guarantee. Output is deterministic: sorted keys
// (via the Manifest canonicalization) and stable 2-space indentation.
func (b *Baseline) Save(path string) error {
	b.SchemaVersion = baselineSchemaVersion

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling mcp baseline: %w", err)
	}
	data = append(data, '\n')

	if err := fsutil.AtomicWriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing mcp baseline: %w", err)
	}
	return nil
}
