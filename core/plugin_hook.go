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
