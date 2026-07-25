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
	URL:  "https://raw.githubusercontent.com/nox-hq/registry/main/index.json",
}

// legacyRegistryURL is where the index lived before it was extracted into its
// own repository. It is retained ONLY so an existing install — which has the
// old URL written into ~/.nox/state.json and will not be re-bootstrapped — can
// be recognised and migrated, instead of failing with a bare 404 that gives the
// operator nothing to act on.
const legacyRegistryURL = "https://raw.githubusercontent.com/nox-hq/nox/main/registry-scaffold/index.json"

// migrateLegacyRegistrySource rewrites the official source when it still points
// at the pre-extraction location.
//
// The index moved out of the nox repository, so that URL now 404s. Bootstrap
// only ADDS a default source when none exists, which means an existing install
// would otherwise keep the dead URL indefinitely and see every `plugin search`
// and `plugin install` fail for no visible reason.
//
// Only the entry that still carries the exact old URL is touched: a source an
// operator has deliberately re-pointed is left alone.
func migrateLegacyRegistrySource(st *State) bool {
	for i := range st.Sources {
		if st.Sources[i].Name == defaultRegistrySource.Name &&
			st.Sources[i].URL == legacyRegistryURL {
			st.Sources[i].URL = defaultRegistrySource.URL
			fmt.Fprintf(os.Stderr,
				"nox: the plugin registry moved to its own repository; updated the %q source to %s\n",
				defaultRegistrySource.Name, defaultRegistrySource.URL)
			return true
		}
	}
	return false
}

// bootstrapBundledPlugins registers any plugin binaries that ship in the
// same directory as the running nox binary, plus the official plugin
// registry. Called once at CLI startup; idempotent (existing
// registrations are left alone). Errors are logged-only — bootstrap
// never blocks the CLI from running.
//
// Operator opt-outs:
//
//	NOX_NO_BUNDLED_PLUGINS=1  — skip bundled-plugin registration
//	NOX_NO_DEFAULT_REGISTRY=1 — skip default-registry auto-add
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
				"registered official plugin registry %s (disable: export NOX_NO_DEFAULT_REGISTRY=1)",
				defaultRegistrySource.URL))
		} else if migrateLegacyRegistrySource(st) {
			// An existing install already HAS an "official" source, so the
			// branch above never runs for it and the pre-extraction URL would
			// persist forever — 404ing on every search and install.
			changed = true
		}
	}

	if os.Getenv("NOX_NO_BUNDLED_PLUGINS") == "" {
		if bundledNotices := syncBundledPlugins(st, binDir); len(bundledNotices) > 0 {
			notices = append(notices, bundledNotices...)
			changed = true
		}
	}

	if changed {
		_ = SaveState(statePath, st)
		for _, n := range notices {
			fmt.Fprintf(os.Stderr, "[nox bootstrap] %s\n", n)
		}
	}
}

// syncBundledPlugins registers the plugins shipped beside the nox binary
// and keeps existing records pointing at them. It returns one notice per
// change; an empty slice means state is already correct.
//
// Re-pointing is the part that is easy to leave out and expensive to
// omit. The path recorded at registration names the install prefix of
// that release — a Homebrew Cellar directory, say — and upgrading
// deletes it. A record written once and never revisited therefore
// dangles for the life of the install: `doctor` reports "binary missing"
// while `scan` says nothing at all and silently falls back to whatever
// else provides the plugin. That is how a repository ends up analysed by
// a plugin build several versions behind the one the operator installed,
// with no output anywhere saying so.
//
// Only records this function created (TrustLevel "bundled") are touched,
// so a plugin the operator installed deliberately is never overwritten
// by the shipped copy.
func syncBundledPlugins(st *State, binDir string) []string {
	var notices []string
	for _, name := range bundledPlugins {
		path := filepath.Join(binDir, name)
		info, err := os.Stat(path)
		usable := err == nil && info.Mode().IsRegular()

		if existing := st.FindPlugin(canonicalName(name)); existing != nil {
			if existing.TrustLevel == "bundled" && usable && existing.BinaryPath != path {
				existing.BinaryPath = path
				existing.RecordBinaryDigest()
				existing.UpdatedAt = time.Now().UTC()
				notices = append(notices, fmt.Sprintf(
					"re-pointed bundled plugin %s -> %s (previous location is gone)",
					canonicalName(name), path))
			}
			continue
		}
		if !usable {
			continue
		}
		bundledIP := &InstalledPlugin{
			Name:        canonicalName(name),
			Version:     "bundled",
			BinaryPath:  path,
			TrustLevel:  "bundled",
			RiskClass:   "passive",
			InstalledAt: time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}
		bundledIP.RecordBinaryDigest()
		st.AddPlugin(bundledIP)
		notices = append(notices, fmt.Sprintf(
			"registered bundled plugin %s -> %s (disable: export NOX_NO_BUNDLED_PLUGINS=1)",
			canonicalName(name), path))
	}
	return notices
}

// canonicalName strips the nox-plugin- prefix so registry lookups by
// short name still hit the bundled record.
func canonicalName(binaryName string) string {
	return strings.TrimPrefix(binaryName, "nox-plugin-")
}
