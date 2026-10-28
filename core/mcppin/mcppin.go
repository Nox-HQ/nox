// Package mcppin provides rug-pull detection for MCP servers (OWASP MCP04).
//
// An MCP "rug pull" is a trust-after-install attack: a server is reviewed and
// approved with a benign definition, then its definition is silently changed
// afterwards to widen its command, arguments, environment, or embedded tool
// descriptions. The host keeps trusting the server because approval happened
// once, against the old definition.
//
// The approval is PROJECT STATE, not machine state. It lives in a file the
// repository commits (.nox/mcp-pins.json, next to .nox/baseline.json and
// .nox/mcp-baseline.json), written by `nox mcp pin` after a person has read the
// definitions. Three properties follow, and each is a reason the previous design
// (a cache under ~/.nox that recorded a server the first time it saw it and
// overwrote its own pin when it reported a change) was replaced:
//
//   - A scan only reads the file. It never writes it, so scanning twice gives the
//     same answer, and a change is reported on every scan until a person
//     acknowledges it by re-pinning. The old store consumed the alert by showing
//     it once.
//   - The file travels with the repository, so a fresh CI runner sees the same
//     approval a developer did. The old store was empty on every clean runner, so
//     the check could never fire there.
//   - A repository with MCP servers and no pin file is a state the scan reports
//     (the caller turns it into a degradation); it is not silently "first seen".
package mcppin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fsutil"
	"github.com/nox-hq/nox/core/mcpconfig"
)

// RuleID is the rule identifier emitted on detected definition drift.
const RuleID = "MCP-015"

// SchemaVersion is the pin file format version. Version 1 was the home-directory
// cache and is not read.
const SchemaVersion = "2"

// RelPath is the pin file location relative to the project root, as shown to
// users in messages.
const RelPath = ".nox/mcp-pins.json"

// DefaultPath returns the conventional pin file location within a project,
// mirroring the finding baseline's `.nox/` convention.
func DefaultPath(root string) string {
	return filepath.Join(root, ".nox", "mcp-pins.json")
}

// LegacyDir returns the directory the earlier, hidden-state design wrote to
// (~/.nox/cache/mcp-pins). Nothing reads it any more; it is exposed only so the
// caller can tell an operator that it is being ignored.
func LegacyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".nox", "cache", "mcp-pins")
	}
	return filepath.Join(home, ".nox", "cache", "mcp-pins")
}

// Lock is the reviewable pin file: a stable server identity
// ("<config path>::<server>") mapped to the SHA-256 of its canonical definition.
// It carries no timestamps, so re-pinning an unchanged project rewrites the same
// bytes and a pin change is a clean diff in review.
type Lock struct {
	Version string            `json:"version"`
	Pins    map[string]string `json:"pins"`
}

// NewLock returns an empty lock.
func NewLock() *Lock {
	return &Lock{Version: SchemaVersion, Pins: map[string]string{}}
}

// Load reads the pin file. exists is false (with a nil error) when there is no
// file, which is a normal state the caller must report, not treat as approval.
// A file that exists but cannot be read or parsed is an error: resetting it to
// empty would silently re-approve every server, which is the one thing this
// package exists to prevent.
func Load(path string) (lock *Lock, exists bool, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- project pin file under the scan root
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("reading mcp pins: %w", err)
	}
	var l Lock
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, true, fmt.Errorf("mcp pin file %s is corrupt and was not reset (fix it, or re-pin deliberately with `nox mcp pin`): %w", path, err)
	}
	if l.Version != SchemaVersion {
		return nil, true, fmt.Errorf("mcp pin file %s has version %q, want %q (re-pin with `nox mcp pin`)", path, l.Version, SchemaVersion)
	}
	if l.Pins == nil {
		l.Pins = map[string]string{}
	}
	return &l, true, nil
}

// Save writes the lock atomically with sorted keys and a trailing newline.
func (l *Lock) Save(path string) error {
	data, err := json.MarshalIndent(l, "", "  ") // map keys marshal sorted
	if err != nil {
		return fmt.Errorf("marshaling mcp pins: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := fsutil.AtomicWriteFile(path, data, 0o644); err != nil { // #nosec G306 -- committed, reviewable file
		return fmt.Errorf("writing mcp pins: %w", err)
	}
	return nil
}

// Definitions returns the pin key and hash of every server defined in an
// mcp.json-style file. A parse failure is an error, not an empty result: an
// empty result means "this file pins nothing", which for rug-pull detection is
// indistinguishable from "everything is fine".
func Definitions(path string, content []byte) (map[string]string, error) {
	servers, err := mcpconfig.ParseServersAt(path, content)
	if err != nil {
		return nil, fmt.Errorf("extracting MCP server definitions from %s: %w", path, err)
	}
	out := make(map[string]string, len(servers))
	for name, raw := range servers {
		out[Key(path, name)] = mcpconfig.CanonicalHash(raw)
	}
	return out, nil
}

// Key is the stable identity of a server within a project.
func Key(path, server string) string { return path + "::" + server }

// Check compares one config file's servers with the lock and returns an MCP-015
// finding for every server whose definition changed since it was pinned, and for
// every server that was never pinned. It does not modify the lock, so the same
// inputs always give the same findings, and a finding stays until the lock is
// updated by `nox mcp pin`. A pinned server that is no longer defined is not a
// finding: removing a server cannot widen what the host trusts.
func (l *Lock) Check(path string, content []byte) ([]findings.Finding, error) {
	defs, err := Definitions(path, content)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(defs))
	for k := range defs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []findings.Finding
	for _, k := range keys {
		server := strings.TrimPrefix(k, path+"::")
		pinned, ok := l.Pins[k]
		switch {
		case !ok:
			out = append(out, unpinnedFinding(path, server, defs[k]))
		case pinned != defs[k]:
			out = append(out, driftFinding(path, server, pinned, defs[k]))
		}
	}
	return out, nil
}

func driftFinding(path, server, oldHash, newHash string) findings.Finding {
	return findings.Finding{
		RuleID:     RuleID,
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: path, StartLine: 1, EndLine: 1},
		Message: fmt.Sprintf(
			"MCP server %q definition changed after it was pinned in %s "+
				"(pinned %s, now %s). Review the change before trusting it — a "+
				"silently mutated server definition is the MCP rug-pull pattern "+
				"(OWASP MCP04). This is reported on every scan until you accept it: "+
				"if the change is intended, run `nox mcp pin` and commit the updated pin file.",
			server, RelPath, shortHash(oldHash), shortHash(newHash)),
		Metadata: map[string]string{
			"cwe":         "CWE-494",
			"server":      server,
			"change":      "modified",
			"old_hash":    oldHash,
			"new_hash":    newHash,
			"owasp-mcp":   "MCP04",
			"owasp-asi":   "ASI04",
			"detector":    "rug-pull",
			"remediation": "Diff the MCP server definition against its pinned state (git diff on the config). Confirm the command, arguments, environment, and any embedded tool definitions are still what you reviewed. Run `nox mcp pin` only after verifying the change is legitimate, and commit " + RelPath + ".",
		},
	}
}

func unpinnedFinding(path, server, hash string) findings.Finding {
	return findings.Finding{
		RuleID:     RuleID,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: path, StartLine: 1, EndLine: 1},
		Message: fmt.Sprintf(
			"MCP server %q (%s) is not in %s, so a later change to it could not be "+
				"detected. Review its definition, then run `nox mcp pin` and commit the "+
				"updated pin file to approve it.",
			server, shortHash(hash), RelPath),
		Metadata: map[string]string{
			"cwe":         "CWE-494",
			"server":      server,
			"change":      "unpinned",
			"new_hash":    hash,
			"owasp-mcp":   "MCP04",
			"owasp-asi":   "ASI04",
			"detector":    "rug-pull",
			"remediation": "Review the server's command, arguments, environment and tool definitions, then run `nox mcp pin` and commit " + RelPath + ".",
		},
	}
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
