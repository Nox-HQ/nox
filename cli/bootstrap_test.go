package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBootstrap_RegistersExistingPlugin(t *testing.T) {
	// Set up a fake bin/ directory containing a nox-plugin-reachability
	// "binary" (any regular file works for the registration check).
	binDir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Skip("os.Executable + symlinks behave differently on Windows; covered in integration tests")
	}

	pluginPath := filepath.Join(binDir, "nox-plugin-reachability")
	if err := os.WriteFile(pluginPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	noxPath := filepath.Join(binDir, "nox")
	if err := os.WriteFile(noxPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Override DefaultStatePath via HOME so the bootstrap writes to a
	// temp location.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// We can't override os.Executable directly; instead simulate the
	// bootstrap by walking the same logic with our binDir explicitly.
	// This validates the helper logic without needing to invoke a real
	// binary.
	if err := registerPluginsFromDir(binDir); err != nil {
		t.Fatalf("registerPluginsFromDir: %v", err)
	}

	st, err := LoadState(DefaultStatePath())
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if st.FindPlugin("reachability") == nil {
		t.Fatal("expected reachability plugin to be registered")
	}
}

// registerPluginsFromDir is the test-only seam exercised by
// TestBootstrap_RegistersExistingPlugin. It mirrors the production
// bootstrap logic but takes binDir as an argument so the test can
// supply a temp directory without monkey-patching os.Executable.
func registerPluginsFromDir(binDir string) error {
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		return err
	}
	for _, name := range bundledPlugins {
		if st.FindPlugin(canonicalName(name)) != nil {
			continue
		}
		path := filepath.Join(binDir, name)
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			continue
		}
		st.AddPlugin(&InstalledPlugin{
			Name:       canonicalName(name),
			Version:    "bundled",
			BinaryPath: path,
			TrustLevel: "bundled",
			RiskClass:  "passive",
		})
	}
	return SaveState(DefaultStatePath(), st)
}

func TestCanonicalName(t *testing.T) {
	if got := canonicalName("nox-plugin-reachability"); got != "reachability" {
		t.Errorf("canonicalName: got %q", got)
	}
	if got := canonicalName("reachability"); got != "reachability" {
		t.Errorf("canonicalName(no prefix): got %q", got)
	}
}
