package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/plugin"
)

// init registers the analysis-plugin runner with the core scan pipeline.
// core defines the hook but cannot run plugins itself without importing the
// plugin host + installed-plugin state (which would create an import cycle),
// so the CLI wires the implementation here.
func init() {
	core.ScanPluginHook = runScanPlugins
	core.PostScanPluginHook = runPostScanPlugins
}

// installedPluginBinaries resolves each required plugin name to its installed
// binary path. Missing or not-yet-installed plugins are skipped (scan-time
// auto-install may have been disabled or failed) rather than aborting the scan.
func installedPluginBinaries(required []string) ([]string, error) {
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		return nil, fmt.Errorf("loading plugin state: %w", err)
	}
	var binaries []string
	for _, name := range required {
		ip := st.FindPlugin(name)
		if ip == nil {
			continue
		}
		if _, statErr := os.Stat(ip.BinaryPath); statErr != nil {
			continue
		}
		binaries = append(binaries, ip.BinaryPath)
	}
	return binaries, nil
}

// runPostScanPlugins invokes the post-scan (scan-context) tools of every
// installed plugin named in .nox.yaml plugins.required — those declaring
// requires_scan_context=true, notably reachability — passing them the findings
// the core scan just produced and merging their results into result in place.
// Missing plugins are skipped; failures surface as diagnostics and never abort
// the scan.
func runPostScanPlugins(ctx context.Context, result *core.ScanResult, target string, required []string) error {
	if len(required) == 0 || result == nil {
		return nil
	}

	binaries, err := installedPluginBinaries(required)
	if err != nil {
		return err
	}
	if len(binaries) == 0 {
		return nil
	}

	absTarget, absErr := filepath.Abs(target)
	if absErr != nil {
		absTarget = target
	}

	policy := plugin.DefaultPolicy()
	if cfg, cfgErr := plugin.LoadConfig(filepath.Join(target, ".nox.yaml")); cfgErr == nil {
		policy = cfg.PluginPolicy.ToPolicy()
	}

	host := plugin.NewHost(plugin.WithPolicy(&policy))
	defer func() { _ = host.Close() }()
	for _, bin := range binaries {
		if regErr := host.RegisterBinary(ctx, bin, nil); regErr != nil {
			return fmt.Errorf("registering plugin %q: %w", bin, regErr)
		}
	}

	if invErr := host.InvokePostScan(ctx, result, absTarget); invErr != nil {
		return fmt.Errorf("post-scan plugins: %w", invErr)
	}
	for _, d := range host.Diagnostics() {
		fmt.Fprintf(os.Stderr, "[plugin %s] %s: %s\n", d.Severity, d.Source, d.Message)
	}
	return nil
}

// runScanPlugins runs the `scan` tool of every installed plugin named in
// .nox.yaml plugins.required against target and returns the merged findings,
// enrichments and graphs. Missing plugins are skipped (auto-install already
// ran earlier in the scan command); individual plugin failures surface as
// host diagnostics and never abort the scan.
func runScanPlugins(ctx context.Context, target string, required []string) (*core.PluginScanOutput, error) {
	if len(required) == 0 {
		return nil, nil
	}

	binaries, err := installedPluginBinaries(required)
	if err != nil {
		return nil, err
	}

	policy := plugin.DefaultPolicy()
	if cfg, cfgErr := plugin.LoadConfig(filepath.Join(target, ".nox.yaml")); cfgErr == nil {
		policy = cfg.PluginPolicy.ToPolicy()
	}
	return runPluginBinaries(ctx, target, binaries, &policy)
}

// runPluginBinaries registers the given plugin binaries with a host, runs
// their `scan` tool against target, and converts the proto output into core
// findings/enrichments/graphs. It is separated from runScanPlugins so it can
// be exercised against a freshly-built plugin binary without touching the
// installed-plugin state.
func runPluginBinaries(ctx context.Context, target string, binaries []string, policy *plugin.Policy) (*core.PluginScanOutput, error) {
	if len(binaries) == 0 {
		return nil, nil
	}
	if policy == nil {
		p := plugin.DefaultPolicy()
		policy = &p
	}

	// Plugins run as subprocesses whose working directory is not guaranteed
	// to match nox's, so a relative target (commonly ".") would make a plugin
	// walk the wrong tree and silently find nothing. Always hand the plugin an
	// absolute workspace root.
	absTarget, absErr := filepath.Abs(target)
	if absErr != nil {
		absTarget = target
	}

	host := plugin.NewHost(plugin.WithPolicy(policy))
	defer func() { _ = host.Close() }()

	for _, bin := range binaries {
		if regErr := host.RegisterBinary(ctx, bin, nil); regErr != nil {
			return nil, fmt.Errorf("registering plugin %q: %w", bin, regErr)
		}
	}

	// Run the analysis `scan` tool across every plugin that declares it.
	// workspace_root is passed both as the host workspace argument and in the
	// input map, since plugins read it from req.Input["workspace_root"].
	input := map[string]any{"workspace_root": absTarget}
	responses, err := host.InvokeAll(ctx, "scan", input, absTarget)
	if err != nil {
		return nil, fmt.Errorf("invoking analysis plugins: %w", err)
	}

	out := &core.PluginScanOutput{}
	for _, r := range responses {
		if r.Response == nil {
			continue
		}
		for _, pf := range r.Response.GetFindings() {
			out.Findings = append(out.Findings, plugin.ProtoFindingToGo(pf, r.PluginName))
		}
		for _, pe := range r.Response.GetEnrichments() {
			out.Enrichments = append(out.Enrichments, plugin.ProtoEnrichmentToGo(pe))
		}
		for _, pg := range r.Response.GetGraphs() {
			out.Graphs = append(out.Graphs, plugin.ProtoGraphToGo(pg))
		}
	}

	// Surface plugin diagnostics (timeouts, partial failures) to stderr so a
	// silently-empty plugin run is visible without failing the scan.
	for _, d := range host.Diagnostics() {
		fmt.Fprintf(os.Stderr, "[plugin %s] %s: %s\n", d.Severity, d.Source, d.Message)
	}

	return out, nil
}
