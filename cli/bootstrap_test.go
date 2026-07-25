package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nox-hq/nox/registry"
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
//
// It calls the production syncBundledPlugins rather than restating its
// logic: a seam that re-implements what it is meant to cover passes
// while the real code is broken, which is exactly how the stale-path bug
// below survived.
func registerPluginsFromDir(binDir string) error {
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		return err
	}
	syncBundledPlugins(st, binDir)
	return SaveState(DefaultStatePath(), st)
}

// An upgrade moves the shipped plugin: the release that registered it is
// deleted, and the recorded path with it. The record must follow the
// binary, or the plugin silently stops running while state still claims
// it is installed.
func TestBootstrap_RepointsMovedBundledPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Executable + symlinks behave differently on Windows; covered in integration tests")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	oldDir := t.TempDir()
	oldPath := filepath.Join(oldDir, "nox-plugin-reachability")
	if err := os.WriteFile(oldPath, []byte("#!/bin/sh\n# v1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := registerPluginsFromDir(oldDir); err != nil {
		t.Fatalf("initial register: %v", err)
	}

	// The upgrade: a new prefix holds the binary, the old one is gone.
	newDir := t.TempDir()
	newPath := filepath.Join(newDir, "nox-plugin-reachability")
	if err := os.WriteFile(newPath, []byte("#!/bin/sh\n# v2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(oldDir); err != nil {
		t.Fatal(err)
	}
	if err := registerPluginsFromDir(newDir); err != nil {
		t.Fatalf("re-register: %v", err)
	}

	st, err := LoadState(DefaultStatePath())
	if err != nil {
		t.Fatal(err)
	}
	p := st.FindPlugin("reachability")
	if p == nil {
		t.Fatal("reachability record disappeared")
	}
	if p.BinaryPath != newPath {
		t.Errorf("BinaryPath = %q, want %q — the record still points at the deleted install", p.BinaryPath, newPath)
	}
	if _, err := os.Stat(p.BinaryPath); err != nil {
		t.Errorf("recorded binary is not usable: %v", err)
	}
}

// A plugin the operator installed deliberately outranks the shipped
// copy; re-pointing must never reach across and overwrite it.
func TestBootstrap_LeavesOperatorInstalledPluginAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Executable + symlinks behave differently on Windows; covered in integration tests")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	st, err := LoadState(DefaultStatePath())
	if err != nil {
		t.Fatal(err)
	}
	chosen := "/opt/operator/nox-plugin-reachability"
	st.AddPlugin(&InstalledPlugin{
		Name:       "reachability",
		Version:    "0.7.1",
		BinaryPath: chosen,
		TrustLevel: "community",
		RiskClass:  "passive",
	})

	shipped := t.TempDir()
	if err := os.WriteFile(filepath.Join(shipped, "nox-plugin-reachability"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if n := syncBundledPlugins(st, shipped); len(n) != 0 {
		t.Errorf("notices = %v, want none — the operator's choice was touched", n)
	}
	if got := st.FindPlugin("reachability"); got.BinaryPath != chosen || got.Version != "0.7.1" {
		t.Errorf("record = %+v, want the operator's 0.7.1 at %q", got, chosen)
	}
}

func TestCanonicalName(t *testing.T) {
	if got := canonicalName("nox-plugin-reachability"); got != "reachability" {
		t.Errorf("canonicalName: got %q", got)
	}
	if got := canonicalName("reachability"); got != "reachability" {
		t.Errorf("canonicalName(no prefix): got %q", got)
	}
}

// The registry index moved out of the nox repository. Bootstrap only ADDS a
// default source when none exists, so an existing install keeps whatever is in
// state — which after the move is a dead URL. Without migration every
// `plugin search` and `plugin install` would 404 with nothing actionable.
func TestMigrateLegacyRegistrySource(t *testing.T) {
	st := &State{Sources: []registry.Source{{Name: "official", URL: legacyRegistryURL}}}
	if !migrateLegacyRegistrySource(st) {
		t.Fatal("expected the legacy URL to be migrated")
	}
	if st.Sources[0].URL != defaultRegistrySource.URL {
		t.Errorf("url = %q, want %q", st.Sources[0].URL, defaultRegistrySource.URL)
	}
}

// A source an operator has deliberately re-pointed must not be rewritten.
func TestMigrateLeavesCustomSourcesAlone(t *testing.T) {
	custom := "https://registry.example.internal/index.json"
	st := &State{Sources: []registry.Source{{Name: "official", URL: custom}}}
	if migrateLegacyRegistrySource(st) {
		t.Error("a custom URL must not be migrated")
	}
	if st.Sources[0].URL != custom {
		t.Errorf("url = %q, want it untouched", st.Sources[0].URL)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	st := &State{Sources: []registry.Source{{Name: "official", URL: defaultRegistrySource.URL}}}
	if migrateLegacyRegistrySource(st) {
		t.Error("already-current source should report no change")
	}
}
