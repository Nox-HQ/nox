package core

import (
	"context"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/graph"
)

// PluginScanOutput is the result of running the analysis plugins declared in
// .nox.yaml plugins.required against a scan target. It is produced by
// ScanPluginHook and merged into the scan pipeline.
type PluginScanOutput struct {
	Findings    []findings.Finding
	Enrichments []findings.Enrichment
	Graphs      []graph.Graph

	// Degradations reports plugins that were required but did not contribute —
	// not installed, binary missing, failed to register, or failed to run.
	//
	// The last of those was missing for a long time and cost the most. An
	// invocation failure has the identical consequence to the other three —
	// the plugin's findings are absent — but it was recorded only as a
	// diagnostic printed to stderr, so it never reached [degraded], the
	// findings JSON, the MCP surface, or --fail-on-degraded (#479).
	//
	// These are not hook errors: the hook succeeds, having run whatever
	// plugins it could. Without a channel for them, a required security plugin
	// that was never installed produced a clean scan and a passing gate, which
	// is the exact failure the degradation mechanism exists to prevent.
	Degradations []Degradation
}

// ScanPluginHook runs the analysis plugins listed in a project's .nox.yaml
// plugins.required and returns their findings, enrichments and graphs so the
// scan pipeline can merge them with the built-in analyzers. It is nil unless
// the CLI registers an implementation.
//
// It is a package-level hook rather than a direct call because running a
// plugin needs the plugin host and the installed-plugin state, which live in
// packages that import core — calling them from core would create an import
// cycle. The CLI registers the implementation in an init function.
//
// Implementations must be safe to call with an empty required list (returning
// nil, nil) and must never panic: a plugin failure is reported as a non-fatal
// error and the built-in scan still completes.
var ScanPluginHook func(ctx context.Context, target string, required []string) (*PluginScanOutput, error)

// PostScanPluginHook runs the "post-scan" plugin tools — those declaring
// requires_scan_context=true — which need the findings the core scan just
// produced. The reachability plugin is the canonical case: it classifies the
// VULN findings against the workspace's imports (reachable / unreachable /
// undetermined). Implementations enrich the given ScanResult IN PLACE (adding
// findings and enrichments) using the plugin host's InvokePostScan.
//
// It runs before refinement so its findings are deduped, suppressed, and
// policy-gated like any other. Same import-cycle rationale, nil-safety, and
// non-fatal-failure contract as ScanPluginHook; the CLI registers it.
var PostScanPluginHook func(ctx context.Context, result *ScanResult, target string, required []string) error
