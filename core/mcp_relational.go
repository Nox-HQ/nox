package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/mcppin"
	"github.com/nox-hq/nox/core/mcpshadow"
)

// mcpConfigBaseNames mirrors the bare filenames discovery treats as MCP client
// configs. The set is small and stable; duplicating it here keeps the relational
// pass from depending on unexported discovery internals. The content check below
// is the real gate — a file that structurally carries an mcpServers object is
// treated as a config even if its name is unusual, and even if it fails to
// parse (which is exactly the malformed-but-clearly-MCP case we must not skip).
var mcpConfigBaseNames = map[string]bool{
	"mcp.json":                   true,
	"claude_desktop_config.json": true,
	"cline_mcp_settings.json":    true,
	"mcp_config.json":            true,
}

// looksLikeMCPConfig reports whether an artifact should be treated as an MCP
// client config for the relational pass.
func looksLikeMCPConfig(path string, content []byte) bool {
	base := strings.ToLower(filepath.Base(path))
	if mcpConfigBaseNames[base] || strings.HasSuffix(base, ".mcp.json") {
		return true
	}
	// Structural signal: an mcpServers key present in the bytes. This matches
	// even when the JSON does not parse, so a rogue config with a trailing comma
	// is still recognised as an MCP config and degraded, not silently ignored.
	return bytes.Contains(content, []byte("mcpServers"))
}

// mcpPinDir resolves the rug-pull pin store directory for a scan target. It is a
// variable so tests can redirect it to a throwaway location.
//
// Production default: a per-target subdirectory of the shared pin cache in
// ~/.nox (mcppin's documented home). It is keyed by the target's absolute path
// so that:
//   - the store is never written INTO the scanned tree, so a later scan does not
//     rediscover pins.json as an artifact (its SHA-256 hashes would otherwise
//     look like high-entropy secrets and make output non-deterministic);
//   - two different repos that both define a server named "fs" in "mcp.json" get
//     independent baselines instead of colliding on the "mcp.json::fs" key and
//     flagging each other as drift.
var mcpPinDir = func(target string) string {
	abs, err := filepath.Abs(target)
	if err != nil {
		abs = target
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(mcppin.DefaultDir(), "targets", hex.EncodeToString(sum[:])[:16])
}

// runMCPRelationalPass runs the two MCP detectors the per-file regex engine
// structurally cannot: server/tool shadowing across the whole config set
// (MCP-023/024, core/mcpshadow) and rug-pull definition drift (MCP-015,
// core/mcppin). Both need the full multi-config inventory, so — like the
// agentflow/plugin passes — they run here and add their findings to allFindings
// BEFORE refinement, so the findings are deduped, suppressed, baseline-matched,
// and policy-gated like any other.
//
// It never aborts the scan. A single unreadable or malformed config, or an
// unreadable pin store, becomes a visible degradation (so "no MCP findings" is
// not silently mistaken for "safe") and the pass moves on.
func runMCPRelationalPass(ctx context.Context, target string, artifacts []discovery.Artifact, allFindings *findings.FindingSet, deg *degrade.Degradations) {
	type cfgFile struct {
		relPath string
		content []byte
		parseOK bool
	}

	// Collect candidate configs in deterministic path order so shadowing output
	// (which cites the "first" config) and pin iteration are reproducible.
	var configs []cfgFile
	for i := range artifacts {
		a := &artifacts[i]
		if a.Type != discovery.AIComponent {
			continue
		}
		content, err := os.ReadFile(a.AbsPath)
		if err != nil {
			// The AI analyzer reads the same artifact and already surfaces an
			// unreadable file; do not double-report here.
			continue
		}
		if !looksLikeMCPConfig(a.Path, content) {
			continue
		}
		configs = append(configs, cfgFile{relPath: a.Path, content: content})
	}
	if len(configs) == 0 {
		return
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].relPath < configs[j].relPath })

	// Shadowing (stateless). Parse each config; a malformed one is degraded and
	// dropped from the comparison set rather than silently vanishing.
	var servers []mcpshadow.Server
	for i := range configs {
		if err := ctx.Err(); err != nil {
			return
		}
		s, err := mcpshadow.ParseConfig(configs[i].relPath, configs[i].content)
		if err != nil {
			deg.Add(degrade.MCP,
				fmt.Sprintf("%s could not be parsed: %v", configs[i].relPath, err),
				"MCP shadowing and rug-pull checks were skipped for this file; a server or tool it defines is not compared against the others")
			continue
		}
		configs[i].parseOK = true
		servers = append(servers, s...)
	}
	for _, f := range mcpshadow.Detect(servers) {
		allFindings.Add(f)
	}

	// Rug-pull (stateful). A pin store that exists but cannot be read is a hard
	// stop for pinning: re-baselining it would silently disarm the very check it
	// exists for. Surface it and run no pin check this scan.
	pinner := mcppin.New(mcppin.WithDir(mcpPinDir(target)))
	if err := pinner.Load(); err != nil {
		deg.Add(degrade.MCP,
			fmt.Sprintf("MCP pin store could not be loaded: %v", err),
			"rug-pull (MCP-015) detection did not run this scan; a tampered MCP server definition would not be reported. Re-approve deliberately by clearing the MCP pin store.")
		return
	}
	for i := range configs {
		if err := ctx.Err(); err != nil {
			return
		}
		if !configs[i].parseOK {
			continue // already degraded during the shadowing parse above
		}
		drift, err := pinner.CheckArtifact(configs[i].relPath, configs[i].content)
		if err != nil {
			// parseOK implies this parses, so this is defensive; never abort the
			// scan for one file.
			deg.Add(degrade.MCP,
				fmt.Sprintf("%s: rug-pull check failed: %v", configs[i].relPath, err),
				"MCP-015 rug-pull detection was skipped for this file")
			continue
		}
		for _, f := range drift {
			allFindings.Add(f)
		}
	}
	if err := pinner.Save(); err != nil {
		deg.Add(degrade.MCP,
			fmt.Sprintf("MCP pin store could not be saved: %v", err),
			"newly observed MCP server definitions were not persisted; drift from this scan's baseline may not be detected next scan")
	}
}
