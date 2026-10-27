package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/plugincap"
	"github.com/nox-hq/nox/registry/trust"
)

// RecordBinaryDigest must measure the actual bytes of the executable so the
// scan path has a value to re-check against.
func TestRecordBinaryDigest(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "plugin-bin")
	content := []byte("#!/bin/sh\necho hi\n")
	if err := os.WriteFile(bin, content, 0o755); err != nil {
		t.Fatal(err)
	}

	ip := &InstalledPlugin{Name: "x", BinaryPath: bin}
	ip.RecordBinaryDigest()

	want := trust.ComputeDigest(content).String()
	if ip.BinaryDigest != want {
		t.Fatalf("BinaryDigest = %q, want %q", ip.BinaryDigest, want)
	}

	// No path ⇒ nothing recorded, no panic.
	empty := &InstalledPlugin{Name: "y"}
	empty.RecordBinaryDigest()
	if empty.BinaryDigest != "" {
		t.Fatalf("expected empty digest for empty path, got %q", empty.BinaryDigest)
	}
}

// writePluginState installs a single plugin into a temp NOX_HOME and returns the
// binary path so a test can tamper with it.
func writePluginState(t *testing.T, ip *InstalledPlugin) {
	t.Helper()
	if err := SaveState(DefaultStatePath(), &State{Plugins: []InstalledPlugin{*ip}}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
}

// The integrity gate is the security property: a plugin whose binary matches its
// recorded digest runs; one whose binary changed since install is refused and
// surfaced as a degradation, never silently executed as still-trusted.
func TestInstalledPluginBinaries_IntegrityGate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NOX_HOME", dir)

	bin := filepath.Join(dir, "plugin-bin")
	original := []byte("original trusted binary\n")
	if err := os.WriteFile(bin, original, 0o755); err != nil {
		t.Fatal(err)
	}
	recorded := trust.ComputeDigest(original).String()

	t.Run("matching digest runs", func(t *testing.T) {
		writePluginState(t, &InstalledPlugin{Name: "p", BinaryPath: bin, BinaryDigest: recorded})
		bins, missing, err := installedPluginBinaries([]string{"p"})
		if err != nil {
			t.Fatal(err)
		}
		if len(bins) != 1 {
			t.Fatalf("expected the plugin to run; got %d binaries, missing=%+v", len(bins), missing)
		}
		for _, d := range missing {
			if strings.Contains(d.Detail, "integrity") {
				t.Fatalf("unexpected integrity degradation on a matching binary: %s", d.Detail)
			}
		}
	})

	t.Run("tampered binary is refused", func(t *testing.T) {
		writePluginState(t, &InstalledPlugin{Name: "p", BinaryPath: bin, BinaryDigest: recorded})
		// Overwrite the binary after install — the contained-plugin self-modify case.
		if err := os.WriteFile(bin, []byte("modified malicious binary\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		bins, missing, err := installedPluginBinaries([]string{"p"})
		if err != nil {
			t.Fatal(err)
		}
		if len(bins) != 0 {
			t.Fatalf("tampered plugin must not run; got %d binaries", len(bins))
		}
		var found bool
		for _, d := range missing {
			if d.Kind == degrade.Plugin && strings.Contains(d.Detail, "integrity") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected an integrity degradation; got %+v", missing)
		}
	})

	t.Run("empty recorded digest is not enforced", func(t *testing.T) {
		// Restore a valid binary, install with NO recorded digest (pre-existing
		// install). It must still run — the change is backward compatible.
		if err := os.WriteFile(bin, original, 0o755); err != nil {
			t.Fatal(err)
		}
		writePluginState(t, &InstalledPlugin{Name: "p", BinaryPath: bin, BinaryDigest: ""})
		bins, missing, err := installedPluginBinaries([]string{"p"})
		if err != nil {
			t.Fatal(err)
		}
		if len(bins) != 1 {
			t.Fatalf("plugin without a recorded digest must still run; got %d, missing=%+v", len(bins), missing)
		}
	})
}

// A required entry carrying a version constraint is still required. The
// "installed but not listed in plugins.required" advisory keyed its set by the
// raw entry, so `nox/foo@^0.2.0` never matched the installed `nox/foo` and the
// plugin that ran was reported as one that did not (#829).
func TestInstalledPluginBinaries_UndeclaredIgnoresConstraintSuffix(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NOX_HOME", dir)
	st := &State{Plugins: []InstalledPlugin{
		{Name: "nox/reachability", Version: "0.9.1"},
		{Name: "nox/taint-analysis", Version: "0.7.0"},
		{Name: "nox/grc", Version: "1.0.0"},
	}}
	if err := SaveState(DefaultStatePath(), st); err != nil {
		t.Fatal(err)
	}
	_, missing, err := installedPluginBinaries([]string{"nox/reachability@^0.9.0", "nox/taint-analysis"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range missing {
		if names, ok := plugincap.Undeclared(d.Detail); ok {
			got = names
			if !strings.HasPrefix(d.Detail, "1 installed plugin(s)") {
				t.Errorf("count must match the list: %q", d.Detail)
			}
		}
	}
	if len(got) != 1 || got[0] != "nox/grc" {
		t.Fatalf("only nox/grc is installed and not required; got %v", got)
	}
}
