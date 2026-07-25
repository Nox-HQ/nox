package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/nox-hq/nox/registry"
)

// retiredBundledPlugins are the plugins nox used to ship inside its own
// release archive and register automatically on first run.
//
// Bundling is gone. It was never a coherent shape: the plugin system exists
// for optional, independently-versioned extension, so a plugin that ships in
// every release paid for both models at once — a process boundary and a
// sandbox policy for code as trusted as nox itself, plus release coupling and
// a bespoke "bundled" trust level with its own failure modes. Two of those
// modes were live in this tree: a record pointing into the package manager's
// install prefix went stale on every upgrade, and the pre-hook that built the
// plugin compiled it once for the release runner, so the macOS and Windows
// archives shipped a Linux x86-64 binary that could not execute at all.
//
// Reachability is now installed like every other plugin:
//
//	nox plugin install nox/reachability
//
// or by declaring it under plugins.required in .nox.yaml, which the scan
// auto-installs.
var retiredBundledPlugins = []string{
	"reachability",
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

// bootstrapState wires up the official plugin registry and retires the
// records left by the removed bundled-plugin mechanism. Called once at CLI
// startup; idempotent. Errors are logged-only — bootstrap never blocks the
// CLI from running.
//
// It no longer looks for plugin binaries beside the nox executable: nox does
// not ship any. See retiredBundledPlugins.
//
// Operator opt-out:
//
//	NOX_NO_DEFAULT_REGISTRY=1 — skip default-registry auto-add
//
// Changes print a one-line notice on stderr so the operator sees what got
// auto-wired, or what was removed and how to get it back.
func bootstrapState() {
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

	if retired := retireBundledPlugins(st); len(retired) > 0 {
		notices = append(notices, retired...)
		changed = true
	}

	if changed {
		_ = SaveState(statePath, st)
		for _, n := range notices {
			fmt.Fprintf(os.Stderr, "[nox bootstrap] %s\n", n)
		}
	}
}

// retireBundledPlugins removes the records the old bundling bootstrap wrote,
// returning one notice per removal.
//
// Leaving them is not an option. The record names a binary inside the install
// prefix, and nox no longer ships that binary, so the path is wrong as soon as
// the package manager cleans up — state would go on claiming an installed
// plugin that is not there, which is precisely the shape that made the
// original defect invisible: `doctor` reports "binary missing" while `scan`
// says nothing at all and quietly runs without the plugin.
//
// The notice is deliberately actionable. On Linux the bundled binary did work,
// so for those installs this is a real change in behaviour and has to be
// visible rather than a silent loss of analysis.
//
// Only records the old bootstrap created (TrustLevel "bundled") are touched; a
// plugin the operator installed themselves is not ours to retire.
func retireBundledPlugins(st *State) []string {
	var notices []string
	for _, name := range retiredBundledPlugins {
		existing := st.FindPlugin(name)
		if existing == nil || existing.TrustLevel != "bundled" {
			continue
		}
		st.RemovePlugin(name)
		notices = append(notices, fmt.Sprintf(
			"%s is no longer bundled with nox; install it with `nox plugin install nox/%s` "+
				"or add it to plugins.required in .nox.yaml", name, name))
	}
	return notices
}

// canonicalName strips the nox-plugin- prefix so registry lookups by
// short name still hit the bundled record.
func canonicalName(binaryName string) string {
	return strings.TrimPrefix(binaryName, "nox-plugin-")
}
