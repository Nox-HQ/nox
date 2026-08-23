// Package mcpconfig holds the shared primitives for reading MCP client configs
// and computing the canonical identity of a server definition.
//
// Three packages reason about the same file format for the same threat — MCP
// rug-pull (mcppin), tool/server shadowing (mcpshadow), and tool-manifest drift
// (mcpdrift). Each had grown its own copy of "canonicalize this JSON so key
// order does not matter, then hash it", and two of them re-declared the same
// `{mcpServers: {...}}` parse. That hash is the TRUST ANCHOR for rug-pull
// detection (OWASP MCP04 / CWE-494): if one copy's canonicalization drifted from
// another, the packages would disagree on whether two server definitions are
// "the same", silently weakening detection. One canonicalizer, here, keeps that
// from happening.
package mcpconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Canonicalize re-marshals arbitrary JSON so object keys are sorted and
// insignificant whitespace is removed, yielding a stable byte form two equal-
// but-differently-ordered fragments share. Go's encoding/json marshals map keys
// in sorted order, so a round-trip through `any` is a canonical form. Invalid or
// empty input returns nil.
func Canonicalize(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return out
}

// CanonicalHash returns the SHA-256 of the canonical form of raw, hex-encoded.
//
// If the fragment cannot be canonicalized (unparseable, or a marshal failure),
// it hashes the RAW bytes instead — never returns an empty hash. Failing to a
// raw-byte hash keeps drift detectable: an attacker cannot dodge the check by
// serving a fragment nox cannot parse, because that still produces a stable,
// comparable digest.
func CanonicalHash(raw json.RawMessage) string {
	canonical := Canonicalize(raw)
	if canonical == nil {
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// ParseServers extracts the raw server definitions from an mcp.json-style
// config: the value of the top-level `mcpServers` object, each server's
// definition left as raw JSON for the caller to hash or inspect. A config that
// is valid JSON without an `mcpServers` object returns an empty map and no
// error; malformed JSON returns an error, so a caller can tell "no servers
// here" from "could not read this file" — a scanner that conflates the two is
// blind exactly where an attacker wants it to be.
func ParseServers(content []byte) (map[string]json.RawMessage, error) {
	var config struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("parsing mcp config: %w", err)
	}
	return config.MCPServers, nil
}
