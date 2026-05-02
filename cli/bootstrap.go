package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// bundledPlugins is the set of plugin binary names that ship in the nox
// archive next to the main binary. On first run after install, the
// bootstrap registers them in state so users get the functionality
// without an explicit `nox plugin install`.
var bundledPlugins = []string{
	"nox-plugin-reachability",
}

// bootstrapBundledPlugins registers any plugin binaries that ship in the
// same directory as the running nox binary. Called once at CLI startup;
// idempotent (existing registrations are left alone).
//
// Errors are logged-only — bootstrap never blocks the CLI from running.
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
	}

	if changed {
		_ = SaveState(statePath, st)
	}
}

// canonicalName strips the nox-plugin- prefix so registry lookups by
// short name still hit the bundled record.
func canonicalName(binaryName string) string {
	return strings.TrimPrefix(binaryName, "nox-plugin-")
}
