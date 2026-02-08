package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nox-hq/nox/registry"
)

func TestLoadState_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.json")
	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState missing file: %v", err)
	}
	if len(st.Sources) != 0 || len(st.Plugins) != 0 {
		t.Fatal("expected empty state for missing file")
	}
}

func TestState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "state.json")

	now := time.Date(2026, 2, 8, 12, 0, 0, 0, time.UTC)
	original := &State{
		Sources: []registry.Source{
			{Name: "official", URL: "https://registry.nox-hq.dev/index.json"},
		},
		Plugins: []InstalledPlugin{
			{
				Name:        "nox/dast",
				Version:     "1.2.0",
				Digest:      "sha256:abc123",
				BinaryPath:  "/home/user/.nox/cache/artifacts/sha256/ab/abc123",
				TrustLevel:  "verified",
				RiskClass:   "active",
				InstalledAt: now,
				UpdatedAt:   now,
			},
		},
	}

	if err := SaveState(path, original); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	if len(loaded.Sources) != 1 || loaded.Sources[0].Name != "official" {
		t.Errorf("sources mismatch: got %+v", loaded.Sources)
	}
	if len(loaded.Plugins) != 1 || loaded.Plugins[0].Name != "nox/dast" {
		t.Errorf("plugins mismatch: got %+v", loaded.Plugins)
	}
	if loaded.Plugins[0].Version != "1.2.0" {
		t.Errorf("version = %q, want %q", loaded.Plugins[0].Version, "1.2.0")
	}
	if loaded.Plugins[0].TrustLevel != "verified" {
		t.Errorf("trust = %q, want %q", loaded.Plugins[0].TrustLevel, "verified")
	}
}

func TestLoadState_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadState(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestState_AddPluginUpsert(t *testing.T) {
	st := &State{}

	st.AddPlugin(InstalledPlugin{Name: "a", Version: "1.0.0"})
	st.AddPlugin(InstalledPlugin{Name: "b", Version: "2.0.0"})
	st.AddPlugin(InstalledPlugin{Name: "a", Version: "1.1.0"})

	if len(st.Plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(st.Plugins))
	}
	if st.FindPlugin("a").Version != "1.1.0" {
		t.Errorf("expected a@1.1.0 after upsert, got %q", st.FindPlugin("a").Version)
	}
}

func TestState_RemovePlugin(t *testing.T) {
	st := &State{}
	st.AddPlugin(InstalledPlugin{Name: "a", Version: "1.0.0"})
	st.AddPlugin(InstalledPlugin{Name: "b", Version: "2.0.0"})

	if !st.RemovePlugin("a") {
		t.Fatal("RemovePlugin should return true for existing plugin")
	}
	if st.RemovePlugin("a") {
		t.Fatal("RemovePlugin should return false for already-removed plugin")
	}
	if len(st.Plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(st.Plugins))
	}
}

func TestState_FindPlugin(t *testing.T) {
	st := &State{}
	st.AddPlugin(InstalledPlugin{Name: "x", Version: "3.0.0"})

	if p := st.FindPlugin("x"); p == nil || p.Version != "3.0.0" {
		t.Error("FindPlugin should return the installed plugin")
	}
	if p := st.FindPlugin("nonexistent"); p != nil {
		t.Error("FindPlugin should return nil for missing plugin")
	}
}

func TestState_InstalledDigests(t *testing.T) {
	st := &State{}
	st.AddPlugin(InstalledPlugin{Name: "a", Digest: "sha256:aaa"})
	st.AddPlugin(InstalledPlugin{Name: "b", Digest: "sha256:bbb"})

	digests := st.InstalledDigests()
	if len(digests) != 2 {
		t.Fatalf("expected 2 digests, got %d", len(digests))
	}
}

func TestDefaultStatePath_NoxHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NOX_HOME", dir)

	path := DefaultStatePath()
	expected := filepath.Join(dir, "state.json")
	if path != expected {
		t.Errorf("DefaultStatePath = %q, want %q", path, expected)
	}
}

func TestSaveState_Atomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	st := &State{Sources: []registry.Source{{Name: "a", URL: "https://a.com"}}}
	if err := SaveState(path, st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Verify temp file was cleaned up.
	tmp := path + ".tmp"
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("temp file should not exist after successful save")
	}
}
