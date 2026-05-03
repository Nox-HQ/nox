package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nox-hq/nox/registry"
)

// bundledPlugins is the set of plugin binary names that ship in the nox
// archive next to the main binary. On first run after install, the
// bootstrap registers them in state so users get the functionality
// without an explicit `nox plugin install`.
var bundledPlugins = []string{
	"nox-plugin-reachability",
}

// defaultRegistrySource is the official nox plugin registry. Auto-added
// to state on first CLI run so `nox plugin search` / `nox plugin install`
// work without `nox registry add`. Operators can remove it via
// `nox registry remove official`.
var defaultRegistrySource = registry.Source{
	Name: "official",
	URL:  "https://raw.githubusercontent.com/nox-hq/nox/main/registry-scaffold/index.json",
}

// bootstrapBundledPlugins registers any plugin binaries that ship in the
// same directory as the running nox binary, plus the official plugin
// registry. Called once at CLI startup; idempotent (existing
// registrations are left alone). Errors are logged-only — bootstrap
// never blocks the CLI from running.
//
// Operator opt-outs:
//   NOX_NO_BUNDLED_PLUGINS=1  — skip bundled-plugin registration
//   NOX_NO_DEFAULT_REGISTRY=1 — skip default-registry auto-add
//
// First-run registrations print a one-line notice on stderr so the
// operator sees what got auto-wired and how to disable it.
func bootstrapBundledPlugins() {
	noxBin, err := os.Executable()
	if err != nil {
		return
	}
	noxBin, err = filepath.EvalSymlinks(noxBin)
	if err != nil {
		return
	}
	binDir := filepath.Dir(noxBin)

	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		return
	}

	changed := false
	notices := make([]string, 0, 2)

	if os.Getenv("NOX_NO_DEFAULT_REGISTRY") == "" {
		hasDefault := false
		for _, s := range st.Sources {
			if s.Name == defaultRegistrySource.Name {
				hasDefault = true
				break
			}
		}
		if !hasDefault {
			st.Sources = append(st.Sources, defaultRegistrySource)
			changed = true
			notices = append(notices, fmt.Sprintf(
				"registered official plugin registry %s (disable: export NOX_NO_DEFAULT_REGISTRY=1)", // nox:ignore SEC-161 -- env var name in user-facing notice, not a credential
				defaultRegistrySource.URL))
		}
	}

	if os.Getenv("NOX_NO_BUNDLED_PLUGINS") == "" {
		for _, name := range bundledPlugins {
			if st.FindPlugin(canonicalName(name)) != nil {
				continue
			}
			path := filepath.Join(binDir, name)
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				continue
			}
			st.AddPlugin(&InstalledPlugin{
				Name:        canonicalName(name),
				Version:     "bundled",
				BinaryPath:  path,
				TrustLevel:  "bundled",
				RiskClass:   "passive",
				InstalledAt: time.Now().UTC(),
				UpdatedAt:   time.Now().UTC(),
			})
			changed = true
			notices = append(notices, fmt.Sprintf(
				"registered bundled plugin %s -> %s (disable: export NOX_NO_BUNDLED_PLUGINS=1)",
				canonicalName(name), path))
		}
	}

	if changed {
		_ = SaveState(statePath, st)
		for _, n := range notices {
			fmt.Fprintf(os.Stderr, "[nox bootstrap] %s\n", n)
		}
	}
}

// canonicalName strips the nox-plugin- prefix so registry lookups by
// short name still hit the bundled record.
func canonicalName(binaryName string) string {
	return strings.TrimPrefix(binaryName, "nox-plugin-")
}
