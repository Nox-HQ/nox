package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/plugin"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/registry/oci"
	"github.com/nox-hq/nox/registry/trust"
)

// runPlugin dispatches plugin subcommands.
func runPlugin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin <search|info|install|update|list|remove|call|init|test|entry>")
		return 2
	}

	switch args[0] {
	case "search":
		return runPluginSearch(args[1:])
	case "info":
		return runPluginInfo(args[1:])
	case "install":
		return runPluginInstall(args[1:])
	case "update":
		return runPluginUpdate(args[1:])
	case "list":
		return runPluginList(args[1:])
	case "remove":
		return runPluginRemove(args[1:])
	case "call":
		return runPluginCall(args[1:])
	case "init":
		return runPluginInit(args[1:])
	case "test":
		return runPluginTest(args[1:])
	case "entry":
		return runPluginEntry(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown plugin command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: nox plugin <search|info|install|update|list|remove|call|init|test|entry>")
		return 2
	}
}

// newRegistryClient creates a registry client configured from state sources.
func newRegistryClient(st *State) *registry.Client {
	cacheDir := filepath.Join(noxHome(), "cache", "registry")
	c := registry.NewClient(registry.WithCacheDir(cacheDir))
	for _, s := range st.Sources {
		_ = c.AddSource(s)
	}
	return c
}

// newOCIStore creates an OCI artifact store using the nox home cache.
func newOCIStore() *oci.Store {
	return newOCIStoreWithPolicy("")
}

// newOCIStoreWithPolicy creates an OCI store whose verifier enforces
// the named trust policy ("permissive" / "default" / "enterprise").
// Empty string falls through to the package default ("permissive"
// for now while signatures are still rolling out across plugins).
func newOCIStoreWithPolicy(policyName string) *oci.Store {
	cacheDir := filepath.Join(noxHome(), "cache", "artifacts")
	verifier := trust.NewVerifier(trust.WithPolicy(policyFromName(policyName)))
	return oci.NewStore(
		oci.WithCacheDir(cacheDir),
		oci.WithVerifier(verifier),
	)
}

// trustViolationsBlock is the single trust-policy gate shared by the install
// and update paths. Store.Fetch is fail-open by contract: it records policy
// violations in VerifyResult but still returns a runnable BinaryPath, delegating
// enforcement to the caller. Having each caller re-implement that check is how
// `nox plugin update` came to silently install artifacts `nox plugin install`
// would refuse — so both now route through here.
//
// It returns the violation messages to surface and whether they are fatal under
// the policy (never fatal for a permissive policy or an explicit
// --allow-unverified). No violations ⇒ (nil, false).
func trustViolationsBlock(vr trust.VerifyResult, policyName string, allowUnverified bool) (msgs []string, fatal bool) {
	if len(vr.Violations) == 0 {
		return nil, false
	}
	for _, v := range vr.Violations {
		msgs = append(msgs, v.Message)
	}
	return msgs, !allowUnverified && policyName != "permissive"
}

// policyFromName resolves a config / flag string into a trust.Policy.
// Empty / unknown names map to the default policy (TrustCommunity
// minimum) — every published plugin in the official registry now
// ships with cosign keyless signatures, and the install path
// promotes a passing cosign verify to TrustCommunity. Operators who
// want to install unsigned artifacts pass --allow-unverified or
// --trust-policy permissive explicitly.
func policyFromName(name string) trust.Policy {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "permissive":
		return trust.PermissivePolicy()
	case "enterprise":
		return trust.EnterprisePolicy()
	}
	return trust.DefaultPolicy()
}

// resolveTrustPolicy combines the operator's CLI flags and the
// project's .nox.yaml trust_policy into a single policy name. Order
// of precedence (highest wins): --allow-unverified, --require-verified,
// --require-signature, --trust-policy=NAME, .nox.yaml plugins.trust_policy,
// fallback "default" (every official plugin ships cosign-signed; the
// promoted Level satisfies the policy without operator intervention).
func resolveTrustPolicy(override string, requireVerified, requireSignature, allowUnverified bool) string {
	if allowUnverified {
		return "permissive"
	}
	if requireVerified {
		return "enterprise"
	}
	if requireSignature {
		return "default"
	}
	if override != "" {
		return strings.ToLower(strings.TrimSpace(override))
	}
	cwd, _ := os.Getwd()
	cfg, err := nox.LoadScanConfig(cwd)
	if err == nil && cfg.Plugins.TrustPolicy != "" {
		return strings.ToLower(strings.TrimSpace(cfg.Plugins.TrustPolicy))
	}
	return "default"
}

// runPluginSearch searches registries for plugins matching a query.
func runPluginSearch(args []string) int {
	fs := flag.NewFlagSet("plugin search", flag.ContinueOnError)
	var trackFlag string
	fs.StringVar(&trackFlag, "track", "", "filter by track (e.g. core-analysis, ai-security)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin search [--track <track>] <query>")
		return 2
	}

	query := remaining[0]
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	if len(st.Sources) == 0 {
		fmt.Fprintln(os.Stderr, "No registries configured. Add one with: nox registry add <url>")
		return 2
	}

	client := newRegistryClient(st)
	ctx := context.Background()

	var searchOpts []registry.SearchOption
	if trackFlag != "" {
		searchOpts = append(searchOpts, registry.WithTrackFilter(registry.Track(trackFlag)))
	}

	results, err := client.Search(ctx, query, searchOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: searching registries: %v\n", err)
		return 2
	}

	if len(results) == 0 {
		fmt.Println("No plugins found.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tTRACK\tDESCRIPTION\tLATEST")
	for i := range results {
		p := &results[i]
		latest := ""
		if len(p.Versions) > 0 {
			latest = p.Versions[len(p.Versions)-1].Version
		}
		track := string(p.Track)
		if track == "" {
			track = "-"
		}
		desc := p.Description
		if p.Deprecated {
			desc = "[DEPRECATED] " + desc
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, track, desc, latest)
	}
	_ = w.Flush()

	// Migration notices go to stderr so the table on stdout stays pipeable.
	for i := range results {
		warnIfDeprecated(&results[i])
	}
	return 0
}

// warnIfDeprecated prints a migration notice for a retired plugin.
//
// The registry carried "deprecated" and "deprecation_note" for two releases
// before anything read them, so search and install happily kept recommending
// retired plugins. The warning is advisory and never blocks: existing installs
// must keep working.
func warnIfDeprecated(p *registry.PluginEntry) {
	if p == nil || !p.Deprecated {
		return
	}
	if p.DeprecationNote != "" {
		fmt.Fprintf(os.Stderr, "warning: %s is deprecated — %s\n", p.Name, p.DeprecationNote)
		return
	}
	fmt.Fprintf(os.Stderr, "warning: %s is deprecated and no longer maintained\n", p.Name)
}

// runPluginInfo shows detailed information about a plugin.
func runPluginInfo(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin info <name>")
		return 2
	}

	name := args[0]
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	if len(st.Sources) == 0 {
		fmt.Fprintln(os.Stderr, "No registries configured. Add one with: nox registry add <url>")
		return 2
	}

	client := newRegistryClient(st)
	ctx := context.Background()

	results, err := client.Search(ctx, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: searching registries: %v\n", err)
		return 2
	}

	// Find exact match.
	var found *registry.PluginEntry
	for i := range results {
		if results[i].Name == name {
			found = &results[i]
			break
		}
	}

	if found == nil {
		fmt.Fprintf(os.Stderr, "Plugin %q not found in registries.\n", name)
		return 2
	}

	fmt.Printf("Name:        %s\n", found.Name)
	fmt.Printf("Description: %s\n", found.Description)
	if found.Deprecated {
		note := found.DeprecationNote
		if note == "" {
			note = "no longer maintained"
		}
		fmt.Printf("Status:      DEPRECATED — %s\n", note)
	}
	if found.Track != "" {
		fmt.Printf("Track:       %s\n", found.Track)
	}
	if found.Homepage != "" {
		fmt.Printf("Homepage:    %s\n", found.Homepage)
	}
	if found.Repository != "" {
		fmt.Printf("Repository:  %s\n", found.Repository)
	}
	if found.License != "" {
		fmt.Printf("License:     %s\n", found.License)
	}
	if len(found.Tags) > 0 {
		fmt.Printf("Tags:        %s\n", strings.Join(found.Tags, ", "))
	}
	if len(found.Maintainers) > 0 {
		fmt.Printf("Maintainers: %s\n", strings.Join(found.Maintainers, ", "))
	}
	fmt.Printf("Versions:    %d\n", len(found.Versions))
	for i := range found.Versions {
		v := &found.Versions[i]
		caps := ""
		if len(v.Capabilities) > 0 {
			caps = " (" + strings.Join(v.Capabilities, ", ") + ")"
		}
		risk := ""
		if v.RiskClass != "" {
			risk = " [" + v.RiskClass + "]"
		}
		fmt.Printf("  %s%s%s\n", v.Version, caps, risk)
	}

	if ip := st.FindPlugin(name); ip != nil {
		fmt.Printf("\nInstalled:   %s (trust: %s)\n", ip.Version, ip.TrustLevel)
	}

	return 0
}

// runPluginInstall installs a plugin from a registry.
func runPluginInstall(args []string) int {
	fs := flag.NewFlagSet("plugin install", flag.ContinueOnError)
	var (
		requireSignature bool
		requireVerified  bool
		allowUnverified  bool
		policyOverride   string
	)
	fs.BoolVar(&requireSignature, "require-signature", false, "fail install when artifact has no valid signature (any signer)")
	fs.BoolVar(&requireVerified, "require-verified", false, "fail install when signer key is not in the local keyring")
	fs.BoolVar(&allowUnverified, "allow-unverified", false, "accept unsigned artifacts (overrides .nox.yaml trust_policy)")
	fs.StringVar(&policyOverride, "trust-policy", "", "override trust policy: permissive, default, enterprise")
	var localPath string
	fs.StringVar(&localPath, "local", "", "install an unsigned plugin binary from a local path (development only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	if localPath != "" {
		if len(rest) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: nox plugin install --local <path> <name>")
			return 2
		}
		return installLocalPlugin(rest[0], localPath)
	}
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin install [--require-signature|--require-verified|--allow-unverified] <name[@version]> | --local <path> <name>")
		return 2
	}

	nameVer := rest[0]
	name, constraint := parseNameVersion(nameVer)

	// Validate before the name reaches registry resolution or the on-disk
	// store. The URI and MCP install paths already gate on these; the direct
	// CLI path did not, so a traversal/injection payload in a plugin ref went
	// straight through. Same allowlist, now enforced on every install path.
	if !plugin.IsSafeName(name) {
		fmt.Fprintf(os.Stderr, "error: unsafe plugin name %q\n", name)
		return 2
	}
	if constraint != "*" && !plugin.IsSafeVersionConstraint(constraint) {
		fmt.Fprintf(os.Stderr, "error: unsafe version constraint %q\n", constraint)
		return 2
	}

	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	if len(st.Sources) == 0 {
		fmt.Fprintln(os.Stderr, "No registries configured. Add one with: nox registry add <url>")
		return 2
	}

	// If already installed at the requested version, skip.
	if ip := st.FindPlugin(name); ip != nil && constraint != "*" && ip.Version == constraint {
		fmt.Printf("%s@%s is already installed.\n", name, ip.Version)
		return 0
	}

	policyName := resolveTrustPolicy(policyOverride, requireVerified, requireSignature, allowUnverified)
	client := newRegistryClient(st)
	store := newOCIStoreWithPolicy(policyName)
	ctx := context.Background()

	ve, err := client.Resolve(ctx, name, constraint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: resolving %s@%s: %v\n", name, constraint, err)
		return 2
	}

	// Warn before downloading, but do not block: retired plugins must stay
	// installable so existing pipelines keep working.
	if entries, searchErr := client.Search(ctx, name); searchErr == nil {
		for i := range entries {
			if entries[i].Name == name {
				warnIfDeprecated(&entries[i])
				break
			}
		}
	}

	// If already installed at the resolved version, skip.
	if ip := st.FindPlugin(name); ip != nil && ip.Version == ve.Version {
		fmt.Printf("%s@%s is already installed.\n", name, ve.Version)
		return 0
	}

	artifact, err := store.Fetch(ctx, name, ve)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: fetching %s@%s: %v\n", name, ve.Version, err)
		return 2
	}

	trustLevel := artifact.VerifyResult.Level.String()
	fmt.Printf("Trust: %s", trustLevel)
	if artifact.VerifyResult.SignerName != "" {
		fmt.Printf(" (signer: %s)", artifact.VerifyResult.SignerName)
	}
	fmt.Println()

	if msgs, fatal := trustViolationsBlock(artifact.VerifyResult, policyName, allowUnverified); len(msgs) > 0 {
		for _, m := range msgs {
			label := "warning"
			if fatal {
				label = "error"
			}
			fmt.Fprintf(os.Stderr, "  %s: %s\n", label, m)
		}
		if fatal {
			fmt.Fprintf(os.Stderr, "Install blocked by trust policy %q. Override with --allow-unverified or set plugins.trust_policy: permissive in .nox.yaml.\n", policyName)
			return 2
		}
	}

	now := time.Now()
	ip := &InstalledPlugin{
		Name:        name,
		Version:     ve.Version,
		Digest:      artifact.Digest,
		BinaryPath:  artifact.BinaryPath,
		TrustLevel:  trustLevel,
		RiskClass:   ve.RiskClass,
		Track:       string(trackForPlugin(ctx, client, name)),
		InstalledAt: now,
		UpdatedAt:   now,
	}
	ip.RecordBinaryDigest()
	st.AddPlugin(ip)

	if err := SaveState(statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving state: %v\n", err)
		return 2
	}

	fmt.Printf("Installed %s@%s (%s)\n", name, ve.Version, trustLevel)

	// Installing is a machine-level action; enabling is a project-level one.
	// Saying so here is the difference between a user's next scan working and
	// them concluding the plugin found nothing. Only shown when the project
	// does not already require it, so the common case stays quiet. See #376.
	if cwd, wdErr := os.Getwd(); wdErr == nil {
		if !projectEnablesPlugin(requiredPluginsForDir(cwd), name) {
			fmt.Print(enablePluginHint(name))
		}
	}
	return 0
}

// runPluginUpdate updates installed plugins to their latest versions.
func runPluginUpdate(args []string) int {
	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	if len(st.Sources) == 0 {
		fmt.Fprintln(os.Stderr, "No registries configured. Add one with: nox registry add <url>")
		return 2
	}

	// Determine which plugins to update.
	var targets []string
	if len(args) > 0 {
		targets = []string{args[0]}
	} else {
		for i := range st.Plugins {
			targets = append(targets, st.Plugins[i].Name)
		}
	}

	if len(targets) == 0 {
		fmt.Println("No plugins installed.")
		return 0
	}

	client := newRegistryClient(st)
	// Update must enforce the same trust policy as install. It previously used
	// the permissive-by-construction default store and never inspected
	// VerifyResult, so a higher version published in a configured registry — or
	// a MITM'd/stale unsigned index — was installed unverified. Resolve the
	// operator's policy (.nox.yaml plugins.trust_policy, else "default") and
	// build a policy-aware store so violations are both produced and gated.
	policyName := resolveTrustPolicy("", false, false, false)
	store := newOCIStoreWithPolicy(policyName)
	ctx := context.Background()

	updated := 0
	for _, name := range targets {
		ip := st.FindPlugin(name)
		if ip == nil {
			fmt.Fprintf(os.Stderr, "warning: %s is not installed, skipping\n", name)
			continue
		}

		ve, err := client.Resolve(ctx, name, "*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot resolve %s: %v\n", name, err)
			continue
		}

		if ve.Version == ip.Version {
			fmt.Printf("%s@%s is up to date.\n", name, ip.Version)
			continue
		}

		artifact, err := store.Fetch(ctx, name, ve)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot fetch %s@%s: %v\n", name, ve.Version, err)
			continue
		}

		// Fail closed: a new version that violates the trust policy is skipped,
		// not silently installed. The currently-installed version stays in place.
		if msgs, fatal := trustViolationsBlock(artifact.VerifyResult, policyName, false); fatal {
			for _, m := range msgs {
				fmt.Fprintf(os.Stderr, "warning: not updating %s@%s: %s\n", name, ve.Version, m)
			}
			fmt.Fprintf(os.Stderr, "Skipped %s: new version blocked by trust policy %q (run `nox plugin install %s@%s --allow-unverified` to override).\n", name, policyName, name, ve.Version)
			continue
		}

		now := time.Now()
		newIP := &InstalledPlugin{
			Name:        name,
			Version:     ve.Version,
			Digest:      artifact.Digest,
			BinaryPath:  artifact.BinaryPath,
			TrustLevel:  artifact.VerifyResult.Level.String(),
			RiskClass:   ve.RiskClass,
			Track:       string(trackForPlugin(ctx, client, name)),
			InstalledAt: ip.InstalledAt,
			UpdatedAt:   now,
		}
		newIP.RecordBinaryDigest()
		st.AddPlugin(newIP)
		updated++
		fmt.Printf("Updated %s: %s -> %s\n", name, ip.Version, ve.Version)
	}

	// GC old artifacts.
	if updated > 0 {
		_, _ = store.GC(oci.GCOptions{ReferencedDigests: st.InstalledDigests()})
	}

	if err := SaveState(statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving state: %v\n", err)
		return 2
	}

	if updated == 0 {
		fmt.Println("All plugins are up to date.")
	} else {
		fmt.Printf("Updated %d plugin(s).\n", updated)
	}
	return 0
}

// runPluginList lists locally installed plugins.
func runPluginList(args []string) int {
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	if len(st.Plugins) == 0 {
		fmt.Println("No plugins installed.")
		return 0
	}

	// ACTIVE answers the question the other four columns cannot: whether this
	// plugin will actually run here. Installed-but-not-required is a normal
	// state, not an error, but it is indistinguishable from "enabled and found
	// nothing" once a scan comes back quiet. See #376.
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	required := requiredPluginsForDir(cwd)

	var inactive int
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tVERSION\tTRUST\tINSTALLED\tACTIVE HERE")
	for i := range st.Plugins {
		p := &st.Plugins[i]
		active := "no"
		if projectEnablesPlugin(required, p.Name) {
			active = "yes"
		} else {
			inactive++
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			p.Name, p.Version, p.TrustLevel, p.InstalledAt.Format("2006-01-02"), active)
	}
	_ = w.Flush()

	if inactive > 0 {
		fmt.Printf("\n%d installed plugin(s) will not run in this directory: they are not listed\n"+
			"under plugins.required in .nox.yaml. Plugins are opt-in per project so that a\n"+
			"scan does not depend on what happens to be installed on the machine.\n", inactive)
	}
	return 0
}

// runPluginRemove removes an installed plugin.
func runPluginRemove(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin remove <name>")
		return 2
	}

	name := args[0]
	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	ip := st.FindPlugin(name)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "error: plugin %q is not installed\n", name)
		return 2
	}

	ver := ip.Version
	st.RemovePlugin(name)

	// GC unreferenced artifacts.
	store := newOCIStore()
	_, _ = store.GC(oci.GCOptions{ReferencedDigests: st.InstalledDigests()})

	if err := SaveState(statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving state: %v\n", err)
		return 2
	}

	fmt.Printf("Removed %s@%s\n", name, ver)
	return 0
}

// runPluginCall invokes a tool on an installed plugin.
func runPluginCall(args []string) int {
	fs := flag.NewFlagSet("plugin call", flag.ContinueOnError)
	var inputFile string
	fs.StringVar(&inputFile, "input", "", "JSON file with tool input")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	remaining := fs.Args()
	if len(remaining) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin call <name> <tool> [--input <file.json>] [key=value ...]")
		return 2
	}

	pluginName := remaining[0]
	toolName := remaining[1]
	kvArgs := remaining[2:]

	st, err := LoadState(DefaultStatePath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	ip := st.FindPlugin(pluginName)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "error: plugin %q is not installed\n", pluginName)
		return 2
	}

	// Build input map.
	input := make(map[string]any)
	if inputFile != "" {
		data, err := os.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading input file: %v\n", err)
			return 2
		}
		if err := json.Unmarshal(data, &input); err != nil {
			fmt.Fprintf(os.Stderr, "error: parsing input file: %v\n", err)
			return 2
		}
	}
	for _, kv := range kvArgs {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "error: invalid key=value argument: %q\n", kv)
			return 2
		}
		input[parts[0]] = parts[1]
	}

	// Load policy from .nox.yaml if present.
	cwd, _ := os.Getwd()
	cfg, err := plugin.LoadConfig(filepath.Join(cwd, ".nox.yaml"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading config: %v\n", err)
		return 2
	}
	policy := cfg.PluginPolicy.ToPolicy()

	host := plugin.NewHost(plugin.WithPolicy(&policy))
	defer func() { _ = host.Close() }()

	ctx := context.Background()
	if err := host.RegisterBinary(ctx, ip.BinaryPath, nil); err != nil {
		fmt.Fprintf(os.Stderr, "error: registering plugin: %v\n", err)
		return 2
	}

	qualifiedTool := pluginName + "." + toolName
	resp, err := host.InvokeTool(ctx, qualifiedTool, input, cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invoking tool: %v\n", err)
		return 2
	}

	// Print diagnostics to stderr.
	for _, d := range host.Diagnostics() {
		fmt.Fprintf(os.Stderr, "[%s] %s: %s\n", d.Severity, d.Source, d.Message)
	}

	// Print response as JSON to stdout.
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		fmt.Fprintf(os.Stderr, "error: encoding response: %v\n", err)
		return 2
	}

	hasFindings := resp != nil && len(resp.GetFindings()) > 0
	if hasFindings {
		return 1
	}
	return 0
}

// parseNameVersion splits "name@version" into name and constraint.
// If no "@" is present, constraint defaults to "*".
func parseNameVersion(s string) (name, constraint string) {
	if idx := strings.LastIndex(s, "@"); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	return s, "*"
}

// installLocalPlugin registers a plugin binary straight from disk.
//
// Plugin development previously had no way to run a locally built plugin: the
// only install path resolves a name against a registry, downloads a published
// artifact and verifies its signature. That made even a one-line plugin change
// untestable without cutting a release first, which is a poor loop and pushes
// people toward editing ~/.nox/state.json by hand.
//
// The binary is recorded with TrustLevel "local" and no digest, so it is never
// mistaken for a verified marketplace artifact: `nox plugin list` shows it as
// local, and nothing here consults or relaxes the trust policy, because there
// is no signature to reason about. Nothing about the SAFETY policy changes —
// a locally installed plugin is validated against the same policy at
// registration and per-tool at invocation as any other.
func installLocalPlugin(name, path string) int {
	abs, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: resolving %s: %v\n", path, err)
		return 2
	}
	info, err := os.Stat(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %s is a directory; pass the built plugin binary\n", abs)
		return 2
	}
	// Executable bit checked up front: registration would otherwise fail later
	// with a confusing exec error.
	if info.Mode()&0o111 == 0 {
		fmt.Fprintf(os.Stderr, "error: %s is not executable\n", abs)
		return 2
	}

	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	now := time.Now()
	localIP := &InstalledPlugin{
		Name:        name,
		Version:     "local",
		BinaryPath:  abs,
		TrustLevel:  "local",
		InstalledAt: now,
		UpdatedAt:   now,
	}
	// Record the digest even for local plugins: it does not imply marketplace
	// trust (TrustLevel stays "local"), but it still lets the scan path detect
	// if this binary is swapped out from under an installed reference.
	localIP.RecordBinaryDigest()
	st.AddPlugin(localIP)
	if err := SaveState(statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving state: %v\n", err)
		return 2
	}

	fmt.Printf("Installed %s from %s (trust: local, UNSIGNED)\n", name, abs)
	fmt.Fprintln(os.Stderr, "warning: local plugins are unsigned and unverified — for development only. "+
		"Reinstall from the marketplace (nox plugin install "+name+") to return to a verified build.")
	return 0
}
