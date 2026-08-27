package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/plugin"
	"github.com/nox-hq/nox/registry"
)

// init registers the analysis-plugin runner with the core scan pipeline.
// core defines the hook but cannot run plugins itself without importing the
// plugin host + installed-plugin state (which would create an import cycle),
// so the CLI wires the implementation here.
func init() {
	core.ScanPluginHook = runScanPlugins
	core.PostScanPluginHook = runPostScanPlugins
}

// installedPlugin pairs a plugin binary with the registry track it was
// installed under. The track selects the safety profile the host enforces, so
// it travels with the path rather than being looked up again later.
type installedPlugin struct {
	// name is the registry name (e.g. "nox/taint-analysis"), carried so a
	// registration failure can name the plugin it degraded rather than only
	// its cache path.
	name  string
	path  string
	track registry.Track
}

// installedPluginBinaries resolves the plugins to run: every INSTALLED plugin,
// plus a degradation for any name in `required` that is not installed or not
// usable.
//
// Installing a plugin is the opt-in. It used to be necessary but not
// sufficient — a plugin only ran if it was ALSO named in plugins.required — so
// the natural CI shape (`nox plugin install …` then `nox scan .`) got part of
// the plugin's coverage and no indication anything was missing. Worse, it
// looked like it worked: the built-in Go taint model still produced
// TAINT-002/004, so only the plugin's extra detections (TAINT-003) were absent.
// `required` now means what its name says — fail if absent — rather than
// doubling as an activation switch (#403).
//
// An empty track — a sideloaded plugin, or one installed before tracks were
// recorded — is passed through as-is, which the host resolves to the strict
// default policy.
func installedPluginBinaries(required []string) ([]installedPlugin, []core.Degradation, error) {
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		return nil, nil, fmt.Errorf("loading plugin state: %w", err)
	}

	var binaries []installedPlugin
	var missing []core.Degradation

	isRequired := make(map[string]bool, len(required))
	for _, name := range required {
		isRequired[name] = true
	}

	// An installed plugin that nothing declared does not run — but it must not
	// do so silently. Installing a security plugin and getting part of its
	// coverage is more dangerous than getting none, because the output looks
	// like it worked: the built-in Go taint model still reports TAINT-002/004,
	// so only the plugin's extra detections are absent and nothing says so
	// (#403).
	//
	// Running it regardless was tried and measured first. It collapses the
	// precision corpus — 1.0000 to 0.3394, 72 new false positives — because a
	// plugin installed for one purpose (risk scoring, remediation) then
	// contributes its rules to every scan. Declaration stays the activation
	// switch; what changes is that skipping one is now visible.
	//
	// Reported as ONE entry, not one per plugin: a developer machine can carry
	// twenty installed plugins, and twenty degradations on every scan is noise
	// that trains people to skip the section the important entries live in.
	var undeclared []string
	for i := range st.Plugins {
		if !isRequired[st.Plugins[i].Name] {
			undeclared = append(undeclared, st.Plugins[i].Name)
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		missing = append(missing, core.Degradation{
			Kind: degrade.Plugin,
			Detail: fmt.Sprintf("%d installed plugin(s) are not listed in plugins.required and did not run: %s",
				len(undeclared), strings.Join(undeclared, ", ")),
			Impact: "their findings are absent from this scan; add the ones you want to plugins.required in .nox.yaml",
		})
	}

	names := required

	for _, name := range names {
		// A plugin the project REQUIRED and did not get is reported, not
		// skipped. Silently continuing here meant a CI job listing a security
		// plugin, failing to install it, and exiting 0 with a clean report —
		// even under --fail-on-degraded, whose help text promises otherwise.
		// A required entry may carry a version constraint — `nox/foo@^0.2.0` —
		// because that is the syntax `nox plugin install` documents and
		// accepts. This lookup used to match the whole string as a name, so
		// such an entry could never resolve: nox reported
		// `required plugin "nox/triage-agent@^0.2.0" is not installed` while
		// nox/triage-agent 0.2.2 sat in the state file, and the plugin
		// silently never ran.
		lookupName, constraint := parseNameVersion(name)
		ip := st.FindPlugin(lookupName)
		if ip == nil {
			missing = append(missing, core.Degradation{
				Kind:   degrade.Plugin,
				Detail: fmt.Sprintf("required plugin %q is not installed", lookupName),
				Impact: "findings this plugin would have produced are missing from this scan",
			})
			continue
		}
		// The constraint is enforced, not merely parsed. Matching the name and
		// ignoring the version would hand a repository whatever happens to be
		// installed, which is the one outcome a pin exists to prevent — and in
		// a security scanner, quietly running a different version of a check
		// than the one asked for is its own defect.
		if ok, cErr := constraintSatisfied(constraint, ip.Version); cErr != nil || !ok {
			detail := fmt.Sprintf("required plugin %q is not satisfied: version %s is installed",
				name, ip.Version)
			if cErr != nil {
				detail = fmt.Sprintf("required plugin %q could not be resolved: %v", name, cErr)
			}
			missing = append(missing, core.Degradation{
				Kind:   degrade.Plugin,
				Detail: detail,
				Impact: "findings this plugin would have produced are missing from this scan",
			})
			continue
		}
		if _, statErr := os.Stat(ip.BinaryPath); statErr != nil {
			missing = append(missing, core.Degradation{
				Kind:   degrade.Plugin,
				Detail: fmt.Sprintf("required plugin %q has no usable binary at %s: %v", name, ip.BinaryPath, statErr),
				Impact: "findings this plugin would have produced are missing from this scan",
			})
			continue
		}

		// Integrity gate: the binary the host is about to exec must match the
		// digest measured when the plugin was installed and verified. state.json
		// is writable by anything running as the user — including a plugin
		// subprocess, the very principal the sandbox is meant to contain — so a
		// plugin that runs once and then overwrites its own binary would
		// otherwise be re-launched as a still-"trusted" plugin. Refusing on
		// mismatch means tampering can only stop a plugin, never escalate it.
		// Only enforced when a digest was recorded (installs predating the field,
		// and any where the hash could not be read, fall through unchanged).
		if ip.BinaryDigest != "" {
			got, digErr := fileDigest(ip.BinaryPath)
			if digErr != nil || got != ip.BinaryDigest {
				missing = append(missing, core.Degradation{
					Kind:   degrade.Plugin,
					Detail: fmt.Sprintf("required plugin %q failed its integrity check: the binary at %s does not match the digest recorded at install", name, ip.BinaryPath),
					Impact: "the plugin was not run because its binary changed since install; reinstall it with `nox plugin install` if the change is expected",
				})
				continue
			}
		}

		binaries = append(binaries, installedPlugin{
			name:  name,
			path:  ip.BinaryPath,
			track: registry.Track(ip.Track),
		})
	}
	return binaries, missing, nil
}

// runPostScanPlugins invokes the post-scan (scan-context) tools of every
// installed plugin named in .nox.yaml plugins.required — those declaring
// requires_scan_context=true, notably reachability — passing them the findings
// the core scan just produced and merging their results into result in place.
// Missing plugins are skipped; failures surface as diagnostics and never abort
// the scan.
func runPostScanPlugins(ctx context.Context, result *core.ScanResult, target string, required []string) error {
	if result == nil {
		return nil
	}

	binaries, _, err := installedPluginBinaries(required)
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
	var overrides plugin.Policy
	ignoreTrackProfiles := false
	if cfg, cfgErr := plugin.LoadConfig(filepath.Join(core.ConfigRoot(target), ".nox.yaml")); cfgErr == nil {
		policy = cfg.PluginPolicy.ToPolicy()
		overrides = cfg.PluginPolicy.Overrides()
		ignoreTrackProfiles = cfg.PluginPolicy.IgnoreTrackProfiles
	}

	host := plugin.NewHost(
		plugin.WithPolicy(&policy),
		plugin.WithPolicyOverrides(&overrides),
		plugin.WithIgnoreTrackProfiles(ignoreTrackProfiles),
	)
	defer func() { _ = host.Close() }()
	// Per-plugin registration, for the same reason as the scan phase: one
	// rejected plugin must not stop the others from annotating the findings.
	registered := 0
	for _, bin := range binaries {
		if regErr := host.RegisterBinaryWithTrack(ctx, bin.path, nil, bin.track); regErr != nil {
			label := bin.name
			if label == "" {
				label = bin.path
			}
			fmt.Fprintf(os.Stderr, "[plugin warn] %s: not registered for post-scan: %v\n", label, regErr)
			result.Degradations = append(result.Degradations, core.Degradation{
				Kind:   degrade.Plugin,
				Detail: fmt.Sprintf("required plugin %q was not registered for post-scan: %v", label, regErr),
				Impact: "enrichments this plugin would have added are missing from these findings",
			})
			continue
		}
		registered++
	}
	if registered == 0 {
		return nil
	}

	if invErr := host.InvokePostScan(ctx, result, absTarget); invErr != nil {
		return fmt.Errorf("post-scan plugins: %w", invErr)
	}
	// Same reasoning as the scan phase: an enrichment that never ran is absent
	// from the findings, and absence has to be reported somewhere a gate can
	// see it. A post-scan plugin is where reachability annotations come from,
	// so its silent failure downgrades a finding's context without changing
	// the finding — the hardest kind of gap to notice by reading output.
	postDiags := host.Diagnostics()
	for _, d := range postDiags {
		fmt.Fprintf(os.Stderr, "[plugin %s] %s: %s\n", d.Severity, d.Source, d.Message)
	}
	result.Degradations = append(result.Degradations, errorDegradations(postDiags, "post-scan ",
		"enrichments this plugin would have added are missing from these findings")...)
	return nil
}

// errorDegradations converts the host's error-severity diagnostics into
// degradations.
//
// A plugin that fails to INVOKE has the identical consequence to one that was
// never installed or failed to register — its findings are absent — but only
// the latter two produced a degradation. The invocation failure printed one
// line to stderr above a green verdict: not in [degraded], not in the findings
// JSON, not on the MCP or LSP surfaces, and invisible to --fail-on-degraded,
// whose help text promises to "exit non-zero if any check could not complete".
//
// That gap let a repository run `nox scan . -severity-threshold high` as the
// security step of its push gate, with the plugin named in plugins.required,
// and be told pass for as long as the plugin had been broken (#479).
//
// The scan still succeeds and still exits 0 by default. Running the plugins
// that worked is the right behaviour, and promoting a partial run to a hard
// failure is the operator's call via --fail-on-degraded. What changes is that
// the choice is theirs to make, because the fact now reaches every surface.
func errorDegradations(diags []plugin.Diagnostic, phase, impact string) []core.Degradation {
	var out []core.Degradation
	for _, d := range diags {
		if !strings.EqualFold(d.Severity, "error") {
			continue
		}
		out = append(out, core.Degradation{
			Kind:   degrade.Plugin,
			Detail: fmt.Sprintf("required %splugin %q failed to run: %s", phase, d.Source, d.Message),
			Impact: impact,
		})
	}
	return out
}

// pluginScanInput builds the input map sent to every plugin's `scan` tool.
//
// It exists as its own function so the wiring is testable: a guard on
// scanExcludePatterns alone proves the patterns can be read, not that they are
// ever sent, and "read but never sent" is precisely the shape of #455.
func pluginScanInput(target, absTarget string) map[string]any {
	input := map[string]any{"workspace_root": absTarget}
	if excl := scanExcludePatterns(target); len(excl) > 0 {
		// []any, not []string. structpb.NewStruct accepts []any and rejects
		// []string outright, and it converts the WHOLE input map or none of
		// it — so one wrongly-typed value does not degrade that value, it
		// fails the request and the plugin never runs.
		//
		// The blast radius was every scan-tool plugin in any workspace whose
		// .nox.yaml set scan.exclude, which is the ordinary case: excluding
		// lockfiles is the first thing most repos do. The plugin error was
		// recorded as a diagnostic and the scan still reported pass, so a
		// repository could declare a plugin in plugins.required and have it
		// silently contribute nothing for as long as the exclusions existed.
		vals := make([]any, len(excl))
		for i, p := range excl {
			vals[i] = p
		}
		input["exclude"] = vals
	}
	return input
}

// scanExcludePatterns returns the scan.exclude patterns from the workspace's
// .nox.yaml, so plugins that walk the tree themselves can honour them.
//
// A missing or unreadable config yields no patterns rather than an error: the
// scan itself has already reported any config problem, and refusing to run the
// plugins over it would turn a config warning into lost coverage.
func scanExcludePatterns(target string) []string {
	cfg, err := core.LoadScanConfig(core.ConfigRoot(target))
	if err != nil || cfg == nil {
		return nil
	}
	return cfg.Scan.Exclude
}

// runScanPlugins runs the `scan` tool of every installed plugin named in
// .nox.yaml plugins.required against target and returns the merged findings,
// enrichments and graphs. Missing plugins are skipped (auto-install already
// ran earlier in the scan command); individual plugin failures surface as
// host diagnostics and never abort the scan.
func runScanPlugins(ctx context.Context, target string, required []string) (*core.PluginScanOutput, error) {

	binaries, missing, err := installedPluginBinaries(required)
	if err != nil {
		return nil, err
	}

	policy := plugin.DefaultPolicy()
	var overrides plugin.Policy
	ignoreTrackProfiles := false
	if cfg, cfgErr := plugin.LoadConfig(filepath.Join(core.ConfigRoot(target), ".nox.yaml")); cfgErr == nil {
		policy = cfg.PluginPolicy.ToPolicy()
		overrides = cfg.PluginPolicy.Overrides()
		ignoreTrackProfiles = cfg.PluginPolicy.IgnoreTrackProfiles
	}
	out, err := runPluginBinaries(ctx, target, binaries, &policy, &overrides, ignoreTrackProfiles)
	if err != nil {
		return nil, err
	}
	if out == nil && len(missing) > 0 {
		out = &core.PluginScanOutput{}
	}
	if out != nil {
		out.Degradations = append(out.Degradations, missing...)
	}
	return out, nil
}

// runPluginBinaries registers the given plugin binaries with a host, runs
// their `scan` tool against target, and converts the proto output into core
// findings/enrichments/graphs. It is separated from runScanPlugins so it can
// be exercised against a freshly-built plugin binary without touching the
// installed-plugin state.
func runPluginBinaries(ctx context.Context, target string, binaries []installedPlugin, policy, overrides *plugin.Policy, ignoreTrackProfiles bool) (*core.PluginScanOutput, error) {
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

	if overrides == nil {
		overrides = &plugin.Policy{}
	}

	host := plugin.NewHost(
		plugin.WithPolicy(policy),
		plugin.WithPolicyOverrides(overrides),
		plugin.WithIgnoreTrackProfiles(ignoreTrackProfiles),
	)
	defer func() { _ = host.Close() }()

	// Register each plugin independently. A plugin the host rejects — a policy
	// gate such as needs_confirmation, a failed handshake, a binary that is not
	// a plugin at all — is degraded on its own and the rest still run.
	// Aborting the batch here meant one gated plugin silently disabled every
	// other required detector, which is the failure mode degradations exist to
	// prevent: the scan looked clean because nothing ran.
	var regDegradations []core.Degradation
	registered := 0
	for _, bin := range binaries {
		if regErr := host.RegisterBinaryWithTrack(ctx, bin.path, nil, bin.track); regErr != nil {
			label := bin.name
			if label == "" {
				label = bin.path
			}
			regDegradations = append(regDegradations, core.Degradation{
				Kind:   degrade.Plugin,
				Detail: fmt.Sprintf("required plugin %q was not registered: %v", label, regErr),
				Impact: "findings this plugin would have produced are missing from this scan; other plugins still ran",
			})
			continue
		}
		registered++
	}
	if registered == 0 {
		// Nothing registered: return the degradations so the operator learns
		// why, rather than an empty success.
		return &core.PluginScanOutput{Degradations: regDegradations}, nil
	}

	// Run the analysis `scan` tool across every plugin that declares it.
	// workspace_root is passed both as the host workspace argument and in the
	// input map, since plugins read it from req.Input["workspace_root"].
	//
	// exclude carries the operator's scan.exclude patterns. A plugin walks the
	// workspace itself, so without them it cannot honour the exclusions the
	// operator wrote — nox/sast aborted its entire scan on a minified bundle in
	// node_modules and the path could not be excluded, so SAST coverage was
	// silently absent on any machine where dependencies happened to be
	// installed (#455). The host still drops findings under excluded paths
	// afterwards, but post-filtering cannot stop a plugin walking into a
	// directory it should never have entered.
	input := pluginScanInput(target, absTarget)
	responses, err := host.InvokeAll(ctx, "scan", input, absTarget)
	if err != nil {
		return nil, fmt.Errorf("invoking analysis plugins: %w", err)
	}

	out := &core.PluginScanOutput{Degradations: regDegradations}
	for _, r := range responses {
		if r.Response == nil {
			continue
		}
		for _, pf := range r.Response.GetFindings() {
			out.Findings = append(out.Findings, plugin.ProtoFindingToGo(pf, r.PluginName, absTarget))
		}
		for _, pe := range r.Response.GetEnrichments() {
			out.Enrichments = append(out.Enrichments, plugin.ProtoEnrichmentToGo(pe))
		}
		for _, pg := range r.Response.GetGraphs() {
			out.Graphs = append(out.Graphs, plugin.ProtoGraphToGo(pg))
		}
	}

	// Surface plugin diagnostics to stderr, and record the error-severity ones
	// as degradations.
	//
	// stderr alone was not enough. A required plugin that fails to INVOKE has
	// the same consequence as one that fails to register or was never
	// installed — its findings are absent — but only the latter two produced a
	// degradation. The invocation failure printed one line above a green
	// verdict, did not appear in [degraded], did not reach the findings JSON,
	// the MCP surface or the LSP, and was invisible to --fail-on-degraded,
	// whose help text promises to "exit non-zero if any check could not
	// complete".
	//
	// That gap let kraftsport-coach run `nox scan . -severity-threshold high`
	// as the security step of its push gate, with nox/taint-analysis named in
	// plugins.required, and be told pass for as long as the plugin had been
	// broken (#479).
	//
	// The scan still succeeds and still exits 0 by default: running the
	// plugins that worked is the right behaviour, and turning a partial run
	// into a hard failure is the operator's call via --fail-on-degraded. What
	// changes is that the choice is now theirs to make, because the fact
	// reaches every surface instead of scrolling past on stderr.
	diags := host.Diagnostics()
	for _, d := range diags {
		fmt.Fprintf(os.Stderr, "[plugin %s] %s: %s\n", d.Severity, d.Source, d.Message)
	}
	out.Degradations = append(out.Degradations, errorDegradations(diags, "",
		"findings this plugin would have produced are missing from this scan; other plugins still ran")...)

	return out, nil
}
