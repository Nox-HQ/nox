package mcpdrift

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/nox-hq/nox/core/mcpconfig"
)

// Tool is one MCP tool as recorded in a baseline: its name, the description the
// server advertises (the text an LLM reads as instructions), and its input
// schema. These three fields are the review-time attack surface — a rug-pull
// changes one of them after approval.
type Tool struct {
	Name string `json:"name"`
	// Description is the advertised tool description. Rug-pull vector: an
	// injected instruction can be swapped in here post-review.
	Description string `json:"description"`
	// InputSchema is the tool's JSON Schema, canonicalized (sorted keys) so the
	// stored form is stable and diffs reflect semantic change, not key order.
	// Stored as a raw JSON message; empty when the server advertised none.
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// Manifest is the comparable state of an MCP server: the set of tools it
// advertises, plus the server identity from the initialize handshake. This is
// the *diffable* half of a baseline — it contains no timestamps, so two
// captures of an unchanged server are byte-identical.
type Manifest struct {
	ProtocolVersion string `json:"protocol_version"`
	ServerName      string `json:"server_name"`
	ServerVersion   string `json:"server_version"`
	Tools           []Tool `json:"tools"`
}

// buildManifest canonicalizes raw wire data into a stable Manifest: tools
// sorted by name, each schema re-serialized with sorted keys.
func buildManifest(init initializeResult, raw []rawTool) Manifest {
	tools := make([]Tool, 0, len(raw))
	for i := range raw {
		tools = append(tools, Tool{
			Name:        raw[i].Name,
			Description: raw[i].Description,
			InputSchema: canonicalizeJSON(raw[i].InputSchema),
		})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	return Manifest{
		ProtocolVersion: init.ProtocolVersion,
		ServerName:      init.ServerInfo.Name,
		ServerVersion:   init.ServerInfo.Version,
		Tools:           tools,
	}
}

// canonicalizeJSON re-marshals arbitrary JSON so object keys are sorted and
// insignificant whitespace is removed. Go's encoding/json marshals map keys in
// sorted order, so a round-trip through map[string]any / any yields a stable
// canonical form. Invalid or empty input returns nil (no schema recorded).
func canonicalizeJSON(raw json.RawMessage) json.RawMessage {
	out := mcpconfig.Canonicalize(raw)
	// A schema of `null` or `{}` carries no information; drop it so an absent
	// schema and an empty one compare equal. (Canonicalize already returns nil
	// for empty/invalid input.)
	if len(out) == 0 || string(out) == "{}" || string(out) == "null" {
		return nil
	}
	return out
}

// Fingerprint returns a stable, order-independent digest of the manifest's
// comparable state. Two manifests with the same tools (names, descriptions,
// canonical schemas) and server identity produce the same fingerprint.
func (m Manifest) Fingerprint() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", m.ProtocolVersion, m.ServerName, m.ServerVersion)
	// Tools are already sorted by name in buildManifest; sort defensively in
	// case a Manifest was constructed by hand (e.g. in tests).
	tools := make([]Tool, len(m.Tools))
	copy(tools, m.Tools)
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	for i := range tools {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", tools[i].Name, tools[i].Description, string(tools[i].InputSchema))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}

// normalize re-canonicalizes every tool's schema in place. It is applied after
// loading a baseline from disk: json.MarshalIndent pretty-prints embedded
// json.RawMessage schemas when writing the file, so the bytes read back carry
// indentation that a fresh (compact) capture does not. Re-canonicalizing makes
// a loaded baseline compare byte-for-byte with a fresh capture of the same
// server — otherwise a round-trip would fingerprint differently and report
// phantom drift.
func (m *Manifest) normalize() {
	for i := range m.Tools {
		m.Tools[i].InputSchema = canonicalizeJSON(m.Tools[i].InputSchema)
	}
	sort.Slice(m.Tools, func(i, j int) bool { return m.Tools[i].Name < m.Tools[j].Name })
}

// toolByName indexes tools for diffing.
func (m Manifest) toolByName() map[string]Tool {
	idx := make(map[string]Tool, len(m.Tools))
	for i := range m.Tools {
		idx[m.Tools[i].Name] = m.Tools[i]
	}
	return idx
}
