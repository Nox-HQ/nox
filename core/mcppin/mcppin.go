// Package mcppin provides rug-pull detection for MCP servers (OWASP MCP04).
//
// An MCP "rug pull" is a trust-after-install attack: a server is reviewed and
// approved with a benign definition, then its definition is silently changed
// afterwards to widen its command, arguments, environment, or embedded tool
// descriptions. The host keeps trusting the server because approval happened
// once, against the old definition.
//
// mcppin pins a SHA-256 hash of each discovered MCP server's canonicalized
// definition on first observation and flags any subsequent change as an
// MCP-015 finding. State is explicit and lives on disk under ~/.nox/, mirroring
// the core scan cache — the core analyzers stay pure and deterministic, and
// rug-pull detection is opt-in at the orchestration layer.
package mcppin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

// RuleID is the rule identifier emitted on detected definition drift.
const RuleID = "MCP-015"

// DefaultDir returns the default pin directory (~/.nox/cache/mcp-pins/).
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".nox", "cache", "mcp-pins")
	}
	return filepath.Join(home, ".nox", "cache", "mcp-pins")
}

// Pin is a single pinned MCP server definition.
type Pin struct {
	Hash      string    `json:"hash"`
	FirstSeen time.Time `json:"first_seen"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store is the on-disk pin structure, mapping a stable server identity
// ("<path>::<server>") to its pinned definition.
type Store struct {
	Pins    map[string]Pin `json:"pins"`
	Version string         `json:"version"`
}

// Pinner pins MCP server definitions and detects drift across scans.
type Pinner struct {
	mu      sync.Mutex
	dir     string
	store   *Store
	dirty   bool
	nowFunc func() time.Time
}

// Option configures a Pinner.
type Option func(*Pinner)

// WithDir sets the pin directory.
func WithDir(dir string) Option {
	return func(p *Pinner) { p.dir = dir }
}

// WithNow overrides the clock (for deterministic tests).
func WithNow(now func() time.Time) Option {
	return func(p *Pinner) { p.nowFunc = now }
}

// New creates a Pinner. Call Load before use and Save afterwards.
func New(opts ...Option) *Pinner {
	p := &Pinner{
		dir:     DefaultDir(),
		nowFunc: time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Load reads the pin store from disk, initializing an empty store if absent or
// corrupted.
func (p *Pinner) Load() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := os.ReadFile(p.storePath())
	if err != nil {
		if os.IsNotExist(err) {
			p.store = newStore()
			return nil
		}
		return fmt.Errorf("reading mcp pins: %w", err)
	}

	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		// Corrupted store — start fresh rather than fail the scan.
		p.store = newStore()
		return nil
	}
	if s.Pins == nil {
		s.Pins = make(map[string]Pin)
	}
	p.store = &s
	return nil
}

// CheckArtifact extracts MCP server definitions from an mcp.json-style file and
// returns MCP-015 findings for any server whose definition changed since it was
// last pinned. First observations are recorded silently (approval baseline);
// unchanged definitions produce nothing. On drift, the pin is updated to the
// new definition so a single change alerts exactly once.
func (p *Pinner) CheckArtifact(path string, content []byte) []findings.Finding {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.store == nil {
		p.store = newStore()
	}

	servers := extractServerDefs(content)
	if len(servers) == 0 {
		return nil
	}

	now := p.nowFunc()
	var out []findings.Finding

	// Deterministic iteration order for stable output.
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		hash := servers[name]
		key := path + "::" + name

		existing, ok := p.store.Pins[key]
		switch {
		case !ok:
			// First observation — record the approval baseline, no finding.
			p.store.Pins[key] = Pin{Hash: hash, FirstSeen: now, UpdatedAt: now}
			p.dirty = true
		case existing.Hash == hash:
			// Unchanged — trusted.
		default:
			// Drift — the definition changed after it was first pinned.
			out = append(out, driftFinding(path, name, existing.Hash, hash))
			existing.Hash = hash
			existing.UpdatedAt = now
			p.store.Pins[key] = existing
			p.dirty = true
		}
	}

	return out
}

// Save writes the pin store to disk if dirty, using an atomic temp+rename.
func (p *Pinner) Save() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.dirty || p.store == nil {
		return nil
	}

	if err := os.MkdirAll(p.dir, 0o755); err != nil {
		return fmt.Errorf("creating mcp pin dir: %w", err)
	}

	data, err := json.Marshal(p.store)
	if err != nil {
		return fmt.Errorf("marshaling mcp pins: %w", err)
	}

	tmp := p.storePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing mcp pin temp: %w", err)
	}
	if err := os.Rename(tmp, p.storePath()); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming mcp pins: %w", err)
	}

	p.dirty = false
	return nil
}

// Clear removes the pin store from disk and resets in-memory state. Use this to
// re-approve all servers from their current definitions.
func (p *Pinner) Clear() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.store = newStore()
	p.dirty = false
	if err := os.Remove(p.storePath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing mcp pins: %w", err)
	}
	return nil
}

func (p *Pinner) storePath() string {
	return filepath.Join(p.dir, "pins.json")
}

func newStore() *Store {
	return &Store{Pins: make(map[string]Pin), Version: "1"}
}

// extractServerDefs parses an mcp.json-style file and returns a map of server
// name to the SHA-256 hash of its canonicalized definition. Returns an empty
// map for files without a parseable mcpServers object.
func extractServerDefs(content []byte) map[string]string {
	var config struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil
	}

	out := make(map[string]string, len(config.MCPServers))
	for name, raw := range config.MCPServers {
		out[name] = canonicalHash(raw)
	}
	return out
}

// canonicalHash produces a key-order-independent SHA-256 of a JSON value. It
// re-decodes into generic Go values and re-marshals; encoding/json sorts map
// keys, so two semantically identical definitions hash identically regardless
// of formatting or key order.
func canonicalHash(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Unparseable fragment — hash the raw bytes so drift is still detected.
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	canonical, err := json.Marshal(v)
	if err != nil {
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func driftFinding(path, server, oldHash, newHash string) findings.Finding {
	return findings.Finding{
		RuleID:     RuleID,
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: path, StartLine: 1, EndLine: 1},
		Message: fmt.Sprintf(
			"MCP server %q definition changed after it was first approved "+
				"(pinned %s, now %s). Review the change before trusting it — a "+
				"silently mutated server definition is the MCP rug-pull pattern "+
				"(OWASP MCP04). If the change is intended, clear the MCP pin store "+
				"to re-approve from the current definition.",
			server, shortHash(oldHash), shortHash(newHash)),
		Metadata: map[string]string{
			"cwe":         "CWE-494",
			"server":      server,
			"old_hash":    oldHash,
			"new_hash":    newHash,
			"owasp-mcp":   "MCP04",
			"detector":    "rug-pull",
			"remediation": "Diff the MCP server definition against its approved state. Confirm the command, arguments, environment, and any embedded tool definitions are still what you reviewed. Re-approve only after verifying the change is legitimate.",
		},
	}
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
