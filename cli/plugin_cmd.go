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

	"github.com/nox-hq/nox/plugin"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/registry/oci"
)

// runPlugin dispatches plugin subcommands.
func runPlugin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin <search|info|install|update|list|remove|call>")
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
	default:
		fmt.Fprintf(os.Stderr, "unknown plugin command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: nox plugin <search|info|install|update|list|remove|call>")
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
	cacheDir := filepath.Join(noxHome(), "cache", "artifacts")
	return oci.NewStore(oci.WithCacheDir(cacheDir))
}

// runPluginSearch searches registries for plugins matching a query.
func runPluginSearch(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin search <query>")
		return 2
	}

	query := args[0]
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

	results, err := client.Search(ctx, query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: searching registries: %v\n", err)
		return 2
	}

	if len(results) == 0 {
		fmt.Println("No plugins found.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION\tLATEST")
	for _, p := range results {
		latest := ""
		if len(p.Versions) > 0 {
			latest = p.Versions[len(p.Versions)-1].Version
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.Description, latest)
	}
	w.Flush()
	return 0
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
	for i, p := range results {
		if p.Name == name {
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
	if found.Homepage != "" {
		fmt.Printf("Homepage:    %s\n", found.Homepage)
	}
	fmt.Printf("Versions:    %d\n", len(found.Versions))
	for _, v := range found.Versions {
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
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin install <name[@version]>")
		return 2
	}

	nameVer := args[0]
	name, constraint := parseNameVersion(nameVer)

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

	client := newRegistryClient(st)
	store := newOCIStore()
	ctx := context.Background()

	ve, err := client.Resolve(ctx, name, constraint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: resolving %s@%s: %v\n", name, constraint, err)
		return 2
	}

	// If already installed at the resolved version, skip.
	if ip := st.FindPlugin(name); ip != nil && ip.Version == ve.Version {
		fmt.Printf("%s@%s is already installed.\n", name, ve.Version)
		return 0
	}

	artifact, err := store.Fetch(ctx, name, *ve)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: fetching %s@%s: %v\n", name, ve.Version, err)
		return 2
	}

	trustLevel := artifact.VerifyResult.TrustLevel.String()
	fmt.Printf("Trust: %s", trustLevel)
	if artifact.VerifyResult.SignerName != "" {
		fmt.Printf(" (signer: %s)", artifact.VerifyResult.SignerName)
	}
	fmt.Println()

	if len(artifact.VerifyResult.Violations) > 0 {
		for _, v := range artifact.VerifyResult.Violations {
			fmt.Fprintf(os.Stderr, "  warning: %s\n", v.Message)
		}
	}

	now := time.Now()
	st.AddPlugin(InstalledPlugin{
		Name:        name,
		Version:     ve.Version,
		Digest:      artifact.Digest,
		BinaryPath:  artifact.BinaryPath,
		TrustLevel:  trustLevel,
		RiskClass:   ve.RiskClass,
		InstalledAt: now,
		UpdatedAt:   now,
	})

	if err := SaveState(statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving state: %v\n", err)
		return 2
	}

	fmt.Printf("Installed %s@%s (%s)\n", name, ve.Version, trustLevel)
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
		for _, p := range st.Plugins {
			targets = append(targets, p.Name)
		}
	}

	if len(targets) == 0 {
		fmt.Println("No plugins installed.")
		return 0
	}

	client := newRegistryClient(st)
	store := newOCIStore()
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

		artifact, err := store.Fetch(ctx, name, *ve)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot fetch %s@%s: %v\n", name, ve.Version, err)
			continue
		}

		now := time.Now()
		st.AddPlugin(InstalledPlugin{
			Name:        name,
			Version:     ve.Version,
			Digest:      artifact.Digest,
			BinaryPath:  artifact.BinaryPath,
			TrustLevel:  artifact.VerifyResult.TrustLevel.String(),
			RiskClass:   ve.RiskClass,
			InstalledAt: ip.InstalledAt,
			UpdatedAt:   now,
		})
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

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tVERSION\tTRUST\tINSTALLED")
	for _, p := range st.Plugins {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, p.Version, p.TrustLevel, p.InstalledAt.Format("2006-01-02"))
	}
	w.Flush()
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

	host := plugin.NewHost(plugin.WithPolicy(policy))
	defer host.Close()

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
func parseNameVersion(s string) (string, string) {
	if idx := strings.LastIndex(s, "@"); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	return s, "*"
}
