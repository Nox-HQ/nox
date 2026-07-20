package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/registry"
)

// runInstall reads .nox.yaml's plugins.required block and installs every
// listed plugin at the requested version constraint. Operates like
// `npm install` / `bundle install`: idempotent, fast on repeat runs,
// pulls only what's missing or version-mismatched.
//
// On success exits 0; non-zero on any individual plugin failure (the
// rest still attempt to install so a single bad entry doesn't block
// the whole project).
func runInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var (
		root  string
		quiet bool
	)
	fs.StringVar(&root, "root", ".", "project root containing .nox.yaml")
	fs.BoolVar(&quiet, "quiet", false, "suppress per-plugin progress lines")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := nox.LoadScanConfig(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading .nox.yaml: %v\n", err)
		return 2
	}
	if len(cfg.Plugins.Required) == 0 {
		fmt.Fprintln(os.Stderr, "no plugins listed in .nox.yaml (plugins.required is empty)")
		return 0
	}

	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	// Merge any project-declared registries into state for the duration
	// of this install. We don't persist them — they live in .nox.yaml.
	for _, r := range cfg.Plugins.Registries {
		src := parseRegistryRef(r)
		if src.URL == "" {
			continue
		}
		alreadyHave := false
		for _, existing := range st.Sources {
			if existing.URL == src.URL {
				alreadyHave = true
				break
			}
		}
		if !alreadyHave {
			st.Sources = append(st.Sources, src)
		}
	}

	if len(st.Sources) == 0 {
		fmt.Fprintln(os.Stderr, "no registries configured (default registry should auto-add — try `nox doctor`)")
		return 2
	}

	failed := 0
	for _, spec := range cfg.Plugins.Required {
		name, constraint := parseNameVersion(spec)
		if !quiet {
			fmt.Printf("[install] %s@%s\n", name, constraint)
		}
		if err := installOne(name, constraint, st); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", name, err)
			failed++
		}
	}

	if err := SaveState(statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving state: %v\n", err)
		return 2
	}

	if failed > 0 {
		return 1
	}
	if !quiet {
		fmt.Printf("[install] %d plugins resolved.\n", len(cfg.Plugins.Required))
	}
	return 0
}

// autoInstallProjectPlugins is the entry point used by `nox scan` to
// silently install the project's required plugins before the scan
// runs. Tolerates partial failure — the scan should still proceed in
// e.g. offline environments where a plugin can't be fetched.
func autoInstallProjectPlugins(root string, pcfg *nox.PluginsConfig, quiet bool) int {
	_ = root
	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		return 2
	}

	for _, r := range pcfg.Registries {
		src := parseRegistryRef(r)
		if src.URL == "" {
			continue
		}
		alreadyHave := false
		for _, existing := range st.Sources {
			if existing.URL == src.URL {
				alreadyHave = true
				break
			}
		}
		if !alreadyHave {
			st.Sources = append(st.Sources, src)
		}
	}

	// Skip network entirely when nothing's missing.
	missing := 0
	for _, spec := range pcfg.Required {
		name, constraint := parseNameVersion(spec)
		ip := st.FindPlugin(name)
		if ip == nil {
			missing++
			continue
		}
		if constraint != "*" && ip.Version != constraint {
			missing++
		}
	}
	if missing == 0 {
		return 0
	}

	if !quiet {
		fmt.Printf("[plugins] auto-installing %d required plugin(s) from .nox.yaml\n", missing)
	}

	failed := 0
	for _, spec := range pcfg.Required {
		name, constraint := parseNameVersion(spec)
		if err := installOne(name, constraint, st); err != nil {
			fmt.Fprintf(os.Stderr, "[plugins] %s: %v\n", name, err)
			failed++
		}
	}
	if err := SaveState(statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "[plugins] saving state: %v\n", err)
		return 2
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// installOne resolves and installs a single plugin into the given
// state. Idempotent: skips if already present at the resolved version.
// State is mutated in place; caller persists.
func installOne(name, constraint string, st *State) error {
	if ip := st.FindPlugin(name); ip != nil && constraint != "*" && ip.Version == constraint {
		return nil
	}

	client := newRegistryClient(st)
	// Enforce the operator's trust policy here too: this path drives .nox.yaml
	// plugins.required installs (including scan-time auto-install), so a
	// fail-open store would auto-install an unverified plugin during a scan.
	policyName := resolveTrustPolicy("", false, false, false)
	store := newOCIStoreWithPolicy(policyName)
	ctx := context.Background()

	ve, err := client.Resolve(ctx, name, constraint)
	if err != nil {
		return fmt.Errorf("resolving: %w", err)
	}
	if ip := st.FindPlugin(name); ip != nil && ip.Version == ve.Version {
		return nil
	}

	artifact, err := store.Fetch(ctx, name, ve)
	if err != nil {
		return fmt.Errorf("fetching: %w", err)
	}

	// Fail closed: never auto-install an artifact that violates the trust policy.
	if msgs, fatal := trustViolationsBlock(artifact.VerifyResult, policyName, false); fatal {
		return fmt.Errorf("blocked by trust policy %q: %s", policyName, strings.Join(msgs, "; "))
	}

	now := time.Now()
	ip := &InstalledPlugin{
		Name:        name,
		Version:     ve.Version,
		Digest:      artifact.Digest,
		BinaryPath:  artifact.BinaryPath,
		TrustLevel:  artifact.VerifyResult.Level.String(),
		RiskClass:   ve.RiskClass,
		Track:       string(trackForPlugin(ctx, client, name)),
		InstalledAt: now,
		UpdatedAt:   now,
	}
	ip.RecordBinaryDigest()
	st.AddPlugin(ip)
	return nil
}

// parseRegistryRef accepts a bare URL or `name=url` and returns a
// registry.Source. Names are derived from the URL host when omitted.
func parseRegistryRef(ref string) registry.Source {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return registry.Source{}
	}
	if eq := strings.IndexByte(ref, '='); eq > 0 {
		return registry.Source{
			Name: strings.TrimSpace(ref[:eq]),
			URL:  strings.TrimSpace(ref[eq+1:]),
		}
	}
	return registry.Source{Name: deriveSourceName(ref), URL: ref}
}

func deriveSourceName(rawURL string) string {
	// Cheap parse: take the host portion between "://" and the next "/".
	rest := rawURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
