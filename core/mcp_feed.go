package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/slopfeed"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/mcpconfig"
	"github.com/nox-hq/nox/core/mcpfeed"
)

// degradeMCPFeed is the degradation kind for the MCP advisory feed.
const degradeMCPFeed = degrade.Kind("mcp_feed")

// MCPFeedRuleID is the rule an MCP advisory match is reported under.
const MCPFeedRuleID = "MCP-026"

// maxAdvisoryIDs bounds how many advisories one finding names in its message.
const maxAdvisoryIDs = 5

// runMCPFeedPass joins the MCP servers a scan found with NOX Intelligence's
// signed MCP advisory feed and reports "an advisory affects this MCP server
// package" for the ones whose exact pinned version an advisory's own interval
// contains.
//
// What it says and does not say. An entry says a public advisory affects this
// package in these ranges and that the package or the advisory concerns MCP. It
// never says the server is exploitable, and absence from the feed is absence from
// the feed. A server launched without a pinned version (`npx -y pkg`) cannot be
// range-matched; when advisories exist for its package that is reported as such,
// at info severity, not as a match.
//
// It is quiet unless it has something to check: no registry-launched server, no
// network use and no degradation. Past that it never fails the scan. A feed that
// is not available, cannot be verified or cannot be fetched becomes a
// degradation that says the servers were NOT checked, because an empty result
// must not read as "no advisories".
func runMCPFeedPass(ctx context.Context, target string, cfg *ScanConfig, opts ScanOptions, artifacts []discovery.Artifact, allFindings *findings.FindingSet, deg *degrade.Degradations) { //nolint:gocritic // mirrors RunScanContext
	fc := cfg.Scan.MCPFeed
	if fc.Disabled || cfg.Scan.OSV.Disabled {
		return
	}
	servers := mcpFeedServers(artifacts)
	if len(servers) == 0 {
		return
	}
	feedURL := fc.ResolvedURL(cfg.Scan.Intelligence)
	if feedURL == "" {
		return // the operator opted out of the intelligence service and named no feed
	}

	if fc.SignatureKeyPath == "" {
		deg.AddAdvisory(degradeMCPFeed,
			fmt.Sprintf("%d MCP server package(s) were not checked against the MCP advisory feed: no public key is pinned (scan.mcp_feed.signature_key_path)", len(servers)),
			"known advisories for these packages are not reported; fetch "+feedURL+".pub.pem once, review it, commit it and name it in scan.mcp_feed.signature_key_path")
		return
	}
	verify, err := loadFeedVerifier(target, fc.SignatureKeyPath)
	if err != nil {
		deg.Add(degradeMCPFeed, fmt.Sprintf("the pinned MCP advisory feed key could not be used: %v", err),
			"MCP server packages were not checked against the advisory feed")
		return
	}
	refresh := mcpfeed.DefaultRefresh
	if fc.Refresh != "" {
		if refresh, err = parseFeedRefresh(fc.Refresh); err != nil {
			deg.Add(degradeMCPFeed, fmt.Sprintf("parsing scan.mcp_feed.refresh %q: %v", fc.Refresh, err),
				"MCP server packages were not checked against the advisory feed")
			return
		}
	}
	cacheDir := fc.CacheDir
	if cacheDir != "" && !filepath.IsAbs(cacheDir) {
		cacheDir = filepath.Join(scanRootDir(target), cacheDir)
	}

	loaded, err := mcpfeed.Load(ctx, mcpfeed.Options{URL: feedURL, CacheDir: cacheDir, TTL: refresh, Offline: opts.Offline, Verify: verify})
	if err != nil {
		recordMCPFeedFailure(deg, feedURL, len(servers), opts.Offline, err)
		return
	}
	if loaded.RefreshErr != nil {
		deg.AddAdvisory(degradeMCPFeed,
			fmt.Sprintf("the MCP advisory feed could not be refreshed (%v); the verified copy generated %s was used", loaded.RefreshErr, loaded.GeneratedAt),
			"advisories published since that copy are not reported")
	}
	for _, h := range loaded.Check(servers) {
		allFindings.Add(mcpFeedFinding(h))
	}
}

// recordMCPFeedFailure turns a load failure into the degradation that says what
// was not checked and why. A service that has not published a feed is not an
// outage and not the operator's to fix, so it does not fail a build; anything
// else (a feed that does not verify, an unreachable service with no cache) does.
func recordMCPFeedFailure(deg *degrade.Degradations, feedURL string, servers int, offline bool, err error) {
	impact := "MCP server packages were not checked against the advisory feed; an empty result is not \"no advisories\""
	var np *mcpfeed.NotPublishedError
	switch {
	case errors.As(err, &np):
		deg.AddAdvisory(degradeMCPFeed,
			fmt.Sprintf("the MCP advisory feed is not available from %s: %v", feedURL, err), impact)
	case offline:
		deg.AddAdvisory(degradeMCPFeed,
			fmt.Sprintf("%d MCP server package(s) were not checked: the scan is offline and no verified copy of the MCP advisory feed is cached (%v)", servers, err), impact)
	default:
		deg.Add(degradeMCPFeed, fmt.Sprintf("the MCP advisory feed %s could not be used: %v", feedURL, err), impact)
	}
}

// loadFeedVerifier reads the pinned key. A relative path is relative to the scan
// root, as for the slopsquat feed.
func loadFeedVerifier(target, keyPath string) (slopfeed.SignatureVerifier, error) {
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(scanRootDir(target), keyPath)
	}
	pem, err := os.ReadFile(keyPath) // #nosec G304 -- operator-configured key path
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", keyPath, err)
	}
	v, err := slopfeed.PEMEd25519Verifier(pem)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", keyPath, err)
	}
	return v, nil
}

// mcpFeedServers lists the MCP servers across the scan's client configs whose
// launch names a registry package. Configs that do not parse are skipped: the
// relational pass already degrades them.
func mcpFeedServers(artifacts []discovery.Artifact) []mcpfeed.Server {
	var out []mcpfeed.Server
	for _, c := range collectMCPConfigs(artifacts) {
		defs, err := mcpconfig.ParseServersAt(c.relPath, c.content)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(defs))
		for n := range defs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			launch, err := mcpconfig.ParseLaunch(defs[n])
			if err != nil {
				continue
			}
			pkg, ok := mcpconfig.PackageOf(launch)
			if !ok {
				continue
			}
			out = append(out, mcpfeed.Server{Config: c.relPath, Line: serverKeyLine(c.content, n), Name: n, Package: pkg})
		}
	}
	return out
}

// serverKeyLine is the 1-based line on which a config names a server, or 1.
func serverKeyLine(content []byte, name string) int {
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(name) + `"\s*:`)
	if loc := re.FindIndex(content); loc != nil {
		return bytes.Count(content[:loc[0]], []byte("\n")) + 1
	}
	return 1
}

// mcpFeedFinding reports one hit: one finding per server and match mode, so a
// server with several advisories is one thing to look at.
func mcpFeedFinding(h mcpfeed.Hit) findings.Finding {
	pkg := h.Server.Package
	ids := make([]string, 0, len(h.Entries))
	weakest, malicious := mcpfeed.BasisPackageName, false
	for _, e := range h.Entries {
		ids = append(ids, e.AdvisoryID)
		if e.Basis == mcpfeed.BasisAdvisoryText {
			weakest = mcpfeed.BasisAdvisoryText
		}
		if e.Kind == mcpfeed.KindMaliciousPackage {
			malicious = true
		}
	}
	listed := ids
	if len(listed) > maxAdvisoryIDs {
		listed = append(append([]string(nil), ids[:maxAdvisoryIDs]...), fmt.Sprintf("and %d more", len(ids)-maxAdvisoryIDs))
	}
	basis := "its name"
	if weakest == mcpfeed.BasisAdvisoryText {
		basis = "the advisory's own text only (the weakest basis: the package's name does not say MCP)"
	}
	sev, conf := findings.SeverityMedium, findings.ConfidenceMedium
	var msg string
	switch h.Mode {
	case mcpfeed.ModeRange:
		if malicious {
			sev = findings.SeverityHigh
		}
		if weakest == mcpfeed.BasisAdvisoryText {
			conf = findings.ConfidenceLow
		}
		msg = fmt.Sprintf("An advisory affects this MCP server package: server %q runs %s@%s, and the NOX Intelligence MCP advisory feed lists %s as covering that version. The feed classifies the package as MCP-related by %s. This says a public advisory covers this version; it does not say your use of the server is exploitable.",
			h.Server.Name, pkg.Name, pkg.Version, strings.Join(listed, ", "), basis)
	case mcpfeed.ModeUnevaluated:
		sev, conf = findings.SeverityLow, findings.ConfidenceLow
		msg = fmt.Sprintf("An advisory names this MCP server package but its affected versions could not be evaluated: server %q runs %s@%s, and the feed lists %s with a version range nox cannot test. Check the advisory for whether %s is covered.",
			h.Server.Name, pkg.Name, pkg.Version, strings.Join(listed, ", "), pkg.Version)
	default: // ModeUnpinned
		sev, conf = findings.SeverityInfo, findings.ConfidenceLow
		msg = fmt.Sprintf("Cannot be checked: server %q launches %s without a pinned version, so the version that runs is whatever the registry serves, and the MCP advisory feed lists %s for it (%s) which cannot be range-matched against an unknown version. Pin an exact version to find out whether %s covers it.",
			h.Server.Name, pkg.Name, plural(len(ids), "1 advisory", fmt.Sprintf("%d advisories", len(ids))), strings.Join(listed, ", "), plural(len(ids), "it", "any of them"))
	}
	return findings.Finding{
		RuleID:     MCPFeedRuleID,
		Severity:   sev,
		Confidence: conf,
		Location:   findings.Location{FilePath: h.Server.Config, StartLine: h.Server.Line, EndLine: h.Server.Line},
		Message:    msg,
		Metadata: map[string]string{
			"cwe":        "CWE-1395",
			"owasp-mcp":  "MCP04",
			"server":     h.Server.Name,
			"ecosystem":  pkg.Ecosystem,
			"package":    pkg.Name,
			"version":    pkg.Version,
			"match":      string(h.Mode),
			"advisories": strings.Join(ids, ","),
			"basis":      weakest,
			"source":     "nox-intelligence mcp-advisories/v1",
		},
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
