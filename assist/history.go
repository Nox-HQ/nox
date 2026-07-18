package assist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// HistorySchemaVersion identifies the on-disk format of triage-history.json.
const HistorySchemaVersion = "1.0"

// DefaultHistoryPath is the workspace-relative path used when no override is given.
const DefaultHistoryPath = ".nox/triage-history.json"

// TriageDecision captures one user-confirmed triage outcome. Fingerprint is the
// finding's stable fingerprint (per the canonical findings schema); ContextHash
// is a hash of the matched-line snippet that disambiguates similar findings.
type TriageDecision struct {
	Fingerprint      string    `json:"fingerprint"`
	ContextHash      string    `json:"context_hash"`
	RuleID           string    `json:"rule_id"`
	Verdict          string    `json:"verdict"`
	AdjustedSeverity string    `json:"adjusted_severity,omitempty"`
	Rationale        string    `json:"rationale,omitempty"`
	DecidedBy        string    `json:"decided_by,omitempty"`
	DecidedAt        time.Time `json:"decided_at"`
}

// TriageHistory is a JSON-backed store of past triage decisions.
//
// Operations are safe for concurrent use within a process via the embedded
// mutex; cross-process safety is provided by the temp-file + rename pattern in
// Save (atomic on POSIX filesystems).
type TriageHistory struct {
	SchemaVersion string            `json:"schema_version"`
	Decisions     []TriageDecision  `json:"decisions"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Source        map[string]string `json:"source,omitempty"`

	mu   sync.RWMutex
	path string
}

// NewTriageHistory returns an empty history bound to the given path.
func NewTriageHistory(path string) *TriageHistory {
	return &TriageHistory{
		SchemaVersion: HistorySchemaVersion,
		Decisions:     nil,
		path:          path,
	}
}

// LoadTriageHistory reads the history file at path. A missing file is not an
// error; an empty history is returned and bound to the path.
func LoadTriageHistory(path string) (*TriageHistory, error) {
	h := NewTriageHistory(path)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return h, nil
		}
		return nil, fmt.Errorf("read triage history %s: %w", path, err)
	}
	if len(raw) == 0 {
		return h, nil
	}
	if err := json.Unmarshal(raw, h); err != nil {
		return nil, fmt.Errorf("parse triage history %s: %w", path, err)
	}
	if h.SchemaVersion == "" {
		h.SchemaVersion = HistorySchemaVersion
	}
	h.path = path
	return h, nil
}

// Path returns the file path bound to this history.
func (h *TriageHistory) Path() string { return h.path }

// Add records (or replaces) a decision identified by Fingerprint+ContextHash.
// DecidedAt is set to time.Now() when zero.
func (h *TriageHistory) Add(d TriageDecision) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if d.DecidedAt.IsZero() {
		d.DecidedAt = time.Now().UTC()
	}
	for i := range h.Decisions {
		if h.Decisions[i].Fingerprint == d.Fingerprint &&
			h.Decisions[i].ContextHash == d.ContextHash {
			h.Decisions[i] = d
			h.UpdatedAt = time.Now().UTC()
			return
		}
	}
	h.Decisions = append(h.Decisions, d)
	h.UpdatedAt = time.Now().UTC()
}

// Lookup returns the most recent decision for the (fingerprint, contextHash) pair.
func (h *TriageHistory) Lookup(fingerprint, contextHash string) (TriageDecision, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := len(h.Decisions) - 1; i >= 0; i-- {
		d := h.Decisions[i]
		if d.Fingerprint == fingerprint && d.ContextHash == contextHash {
			return d, true
		}
	}
	return TriageDecision{}, false
}

// Similar returns up to maxN past decisions for the same RuleID, ordered by
// recency. Used as few-shot examples for LLM prompts.
func (h *TriageHistory) Similar(ruleID string, maxN int) []TriageDecision {
	if maxN <= 0 {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()

	matched := make([]TriageDecision, 0, maxN)
	for i := len(h.Decisions) - 1; i >= 0; i-- {
		if h.Decisions[i].RuleID == ruleID {
			matched = append(matched, h.Decisions[i])
			if len(matched) >= maxN {
				break
			}
		}
	}
	return matched
}

// Save writes the history atomically: temp file + rename. The parent directory
// is created with mode 0o755 if missing.
func (h *TriageHistory) Save() error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.path == "" {
		return errors.New("triage history has no bound path")
	}
	dir := filepath.Dir(h.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("ensure triage history dir %s: %w", dir, err)
	}

	if h.SchemaVersion == "" {
		h.SchemaVersion = HistorySchemaVersion
	}
	if h.UpdatedAt.IsZero() {
		h.UpdatedAt = time.Now().UTC()
	}

	body, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal triage history: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".triage-history-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp triage history: %w", err)
	}
	tmpPath := tmp.Name()
	// Cleanup errors below are deliberately discarded: each path is already
	// returning the error that actually matters, and a failed temp-file removal
	// must not mask it. Assigning to _ states that intent explicitly.
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp triage history: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp triage history: %w", err)
	}
	if err := os.Rename(tmpPath, h.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename triage history into place: %w", err)
	}
	return nil
}

// Export writes the history to dest in canonical JSON form for team sharing.
// Decisions are sorted by RuleID then DecidedAt to produce a stable diff.
func (h *TriageHistory) Export(dest string) error {
	h.mu.RLock()
	out := struct {
		SchemaVersion string            `json:"schema_version"`
		Decisions     []TriageDecision  `json:"decisions"`
		UpdatedAt     time.Time         `json:"updated_at"`
		Source        map[string]string `json:"source,omitempty"`
	}{
		SchemaVersion: h.SchemaVersion,
		Decisions:     append([]TriageDecision(nil), h.Decisions...),
		UpdatedAt:     h.UpdatedAt,
		Source:        h.Source,
	}
	h.mu.RUnlock()

	sort.SliceStable(out.Decisions, func(i, j int) bool {
		if out.Decisions[i].RuleID != out.Decisions[j].RuleID {
			return out.Decisions[i].RuleID < out.Decisions[j].RuleID
		}
		return out.Decisions[i].DecidedAt.Before(out.Decisions[j].DecidedAt)
	})

	body, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal triage history for export: %w", err)
	}
	if err := os.WriteFile(dest, body, 0o644); err != nil {
		return fmt.Errorf("write export %s: %w", dest, err)
	}
	return nil
}

// Import merges decisions from src into h. Existing decisions with the same
// Fingerprint+ContextHash are overwritten only if the imported DecidedAt is
// strictly newer; otherwise the local decision wins (last-writer-wins by time).
// Returns the number of decisions added or replaced.
func (h *TriageHistory) Import(src string) (int, error) {
	raw, err := os.ReadFile(src)
	if err != nil {
		return 0, fmt.Errorf("read import %s: %w", src, err)
	}
	var imported TriageHistory
	if err := json.Unmarshal(raw, &imported); err != nil {
		return 0, fmt.Errorf("parse import %s: %w", src, err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	index := make(map[string]int, len(h.Decisions))
	for i, d := range h.Decisions {
		index[decisionKey(d)] = i
	}

	changed := 0
	for _, d := range imported.Decisions {
		key := decisionKey(d)
		if idx, ok := index[key]; ok {
			if d.DecidedAt.After(h.Decisions[idx].DecidedAt) {
				h.Decisions[idx] = d
				changed++
			}
			continue
		}
		h.Decisions = append(h.Decisions, d)
		index[key] = len(h.Decisions) - 1
		changed++
	}
	if changed > 0 {
		h.UpdatedAt = time.Now().UTC()
	}
	return changed, nil
}

// HashContext returns the canonical context hash used to disambiguate findings
// with the same fingerprint but different surrounding code (e.g. a recurring
// rule that fires in many call sites).
func HashContext(snippet string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(snippet)))
	return hex.EncodeToString(sum[:])
}

func decisionKey(d TriageDecision) string {
	return d.Fingerprint + "|" + d.ContextHash
}

// FewShotExamples renders past decisions as plain-text examples suitable for
// inlining into a triage system prompt. Returns an empty string when len(ds)==0.
func FewShotExamples(ds []TriageDecision) string {
	if len(ds) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Past decisions for this rule (most recent first):\n")
	for i, d := range ds {
		fmt.Fprintf(&b, "%d. verdict=%s severity=%s rationale=%q\n",
			i+1, d.Verdict, d.AdjustedSeverity, d.Rationale)
	}
	return b.String()
}
