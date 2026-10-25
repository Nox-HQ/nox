package core

import (
	"bytes"
	"context"
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

// mcpConfigFile is one discovered MCP client config.
type mcpConfigFile struct {
	relPath string
	content []byte
	parseOK bool
}

// collectMCPConfigs returns the MCP client configs among artifacts in path
// order, so shadowing output (which cites the "first" config) and pin checks are
// reproducible. It is shared by the scan and by `nox mcp pin`, so the file set
// that is pinned is exactly the file set that is checked.
func collectMCPConfigs(artifacts []discovery.Artifact) []mcpConfigFile {
	var configs []mcpConfigFile
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
		configs = append(configs, mcpConfigFile{relPath: a.Path, content: content})
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].relPath < configs[j].relPath })
	return configs
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
	configs := collectMCPConfigs(artifacts)
	if len(configs) == 0 {
		return
	}

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

	checkMCPPins(ctx, target, configs, allFindings, deg)
}

// checkMCPPins compares every parseable MCP config with the project's pin file
// (MCP-015). It only reads: the pin file is reviewed, committed project state,
// and a scan that edited it would consume its own alerts.
//
// The three states that are not "checked and clean" are all reported, because
// "no MCP-015" must not be readable as "no rug pull":
//   - no pin file: nothing to compare against, so the check cannot run;
//   - an unreadable or wrong-version pin file: re-baselining it would silently
//     approve everything, so no check runs;
//   - a config that did not parse (already degraded by the caller).
func checkMCPPins(ctx context.Context, target string, configs []mcpConfigFile, allFindings *findings.FindingSet, deg *degrade.Degradations) {
	pinPath := mcppin.DefaultPath(ConfigRoot(target))
	lock, exists, err := mcppin.Load(pinPath)
	if err != nil {
		deg.Add(degrade.MCP,
			fmt.Sprintf("MCP pin file could not be loaded: %v", err),
			"rug-pull (MCP-015) detection did not run this scan; a tampered MCP server definition would not be reported")
		return
	}
	if !exists {
		if countMCPServers(configs) == 0 {
			return // nothing defined, so nothing a pin could protect
		}
		// Advisory, not blocking: the operator has not set pinning up, so this
		// reports a capability they have not asked for (and must not turn every
		// existing repository with an MCP config red under --fail-on-degraded).
		// It is still printed and recorded, which is what keeps it from being
		// read as "no rug pull".
		deg.AddAdvisory(degrade.MCP,
			fmt.Sprintf("no MCP pin file at %s, so a changed MCP server definition (rug pull, MCP-015) cannot be detected%s",
				mcppin.RelPath, legacyPinNote()),
			"review the server definitions, run `nox mcp pin`, and commit "+mcppin.RelPath+"; until then MCP-015 cannot report anything")
		return
	}
	for i := range configs {
		if err := ctx.Err(); err != nil {
			return
		}
		if !configs[i].parseOK {
			continue // already degraded during the shadowing parse
		}
		drift, err := lock.Check(configs[i].relPath, configs[i].content)
		if err != nil {
			deg.Add(degrade.MCP,
				fmt.Sprintf("%s: rug-pull check failed: %v", configs[i].relPath, err),
				"MCP-015 rug-pull detection was skipped for this file")
			continue
		}
		for _, f := range drift {
			allFindings.Add(f)
		}
	}
}

// legacyPinNote tells an operator who used the earlier hidden-state design that
// its cache is not read. It stays silent when there is nothing to ignore.
func legacyPinNote() string {
	if _, err := os.Stat(filepath.Join(mcppin.LegacyDir(), "targets")); err == nil {
		return " (the per-user pin cache that earlier nox versions kept under ~/.nox/cache/mcp-pins is no longer read: it was machine state nobody reviewed and it is empty on a clean CI runner)"
	}
	return ""
}

// countMCPServers counts the servers defined across the parseable configs.
func countMCPServers(configs []mcpConfigFile) int {
	n := 0
	for i := range configs {
		if !configs[i].parseOK {
			continue
		}
		if defs, err := mcppin.Definitions(configs[i].relPath, configs[i].content); err == nil {
			n += len(defs)
		}
	}
	return n
}

// MCPPinResult describes what PinMCPServers wrote.
type MCPPinResult struct {
	Path    string   // pin file written
	Servers int      // servers now pinned
	Added   []string // pin keys not in the previous file
	Changed []string // pin keys whose definition differs from the previous file
	Removed []string // pin keys no longer defined anywhere
}

// PinMCPServers records the current definition of every MCP server under target
// in the project's pin file, replacing it. This is the explicit acknowledgement
// MCP-015 waits for: a person has reviewed the definitions and accepts them. It
// uses the scan's own discovery, so the set pinned is the set checked. A config
// that does not parse is an error here rather than a skipped file, because
// pinning around it would approve a server nobody could read.
func PinMCPServers(ctx context.Context, target string, opts ScanOptions) (*MCPPinResult, error) { //nolint:gocritic // mirrors RunScanContext
	target, err := discovery.ResolveRoot(target)
	if err != nil {
		return nil, err
	}
	cfg, err := LoadScanConfig(target)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	artifacts, err := discoverArtifacts(target, cfg, opts, &degrade.Degradations{})
	if err != nil {
		return nil, err
	}
	next := mcppin.NewLock()
	for _, c := range collectMCPConfigs(artifacts) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		defs, err := mcppin.Definitions(c.relPath, c.content)
		if err != nil {
			return nil, err
		}
		for k, h := range defs {
			next.Pins[k] = h
		}
	}

	path := mcppin.DefaultPath(ConfigRoot(target))
	prev, exists, err := mcppin.Load(path)
	if err != nil && exists {
		// A damaged pin file may be replaced deliberately: that is what this
		// command is for. The error is not hidden, it is the reason for the run.
		prev = nil
	}
	res := &MCPPinResult{Path: path, Servers: len(next.Pins)}
	for k, h := range next.Pins {
		switch old, ok := prevPin(prev, k); {
		case !ok:
			res.Added = append(res.Added, k)
		case old != h:
			res.Changed = append(res.Changed, k)
		}
	}
	if prev != nil {
		for k := range prev.Pins {
			if _, ok := next.Pins[k]; !ok {
				res.Removed = append(res.Removed, k)
			}
		}
	}
	sort.Strings(res.Added)
	sort.Strings(res.Changed)
	sort.Strings(res.Removed)
	if err := next.Save(path); err != nil {
		return nil, err
	}
	return res, nil
}

func prevPin(l *mcppin.Lock, k string) (string, bool) {
	if l == nil {
		return "", false
	}
	h, ok := l.Pins[k]
	return h, ok
}
