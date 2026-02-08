package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/felixgeelhaar/hardline/registry"
)

// setupStateDir creates a temp HARDLINE_HOME and sets the env var.
func setupStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)
	return dir
}

func TestRunRegistryAdd(t *testing.T) {
	setupStateDir(t)

	code := runRegistry([]string{"add", "https://registry.example.com/index.json"})
	if code != 0 {
		t.Fatalf("registry add: expected exit 0, got %d", code)
	}

	st, err := LoadState(DefaultStatePath())
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(st.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(st.Sources))
	}
	if st.Sources[0].Name != "registry.example.com" {
		t.Errorf("name = %q, want %q", st.Sources[0].Name, "registry.example.com")
	}
	if st.Sources[0].URL != "https://registry.example.com/index.json" {
		t.Errorf("url = %q", st.Sources[0].URL)
	}
}

func TestRunRegistryAdd_WithName(t *testing.T) {
	setupStateDir(t)

	code := runRegistry([]string{"add", "--name", "myregistry", "https://example.com/index.json"})
	if code != 0 {
		t.Fatalf("registry add --name: expected exit 0, got %d", code)
	}

	st, _ := LoadState(DefaultStatePath())
	if st.Sources[0].Name != "myregistry" {
		t.Errorf("name = %q, want %q", st.Sources[0].Name, "myregistry")
	}
}

func TestRunRegistryAdd_DuplicateName(t *testing.T) {
	dir := setupStateDir(t)

	// Pre-populate state with a source.
	st := &State{Sources: []registry.Source{{Name: "existing", URL: "https://a.com"}}}
	if err := SaveState(filepath.Join(dir, "state.json"), st); err != nil {
		t.Fatal(err)
	}

	code := runRegistry([]string{"add", "--name", "existing", "https://b.com"})
	if code != 2 {
		t.Fatalf("duplicate add: expected exit 2, got %d", code)
	}
}

func TestRunRegistryAdd_MissingURL(t *testing.T) {
	setupStateDir(t)

	code := runRegistry([]string{"add"})
	if code != 2 {
		t.Fatalf("missing URL: expected exit 2, got %d", code)
	}
}

func TestRunRegistryList_Empty(t *testing.T) {
	setupStateDir(t)

	code := runRegistry([]string{"list"})
	if code != 0 {
		t.Fatalf("registry list empty: expected exit 0, got %d", code)
	}
}

func TestRunRegistryList_WithSources(t *testing.T) {
	dir := setupStateDir(t)

	st := &State{Sources: []registry.Source{
		{Name: "a", URL: "https://a.com"},
		{Name: "b", URL: "https://b.com"},
	}}
	if err := SaveState(filepath.Join(dir, "state.json"), st); err != nil {
		t.Fatal(err)
	}

	code := runRegistry([]string{"list"})
	if code != 0 {
		t.Fatalf("registry list: expected exit 0, got %d", code)
	}
}

func TestRunRegistryRemove(t *testing.T) {
	dir := setupStateDir(t)

	st := &State{Sources: []registry.Source{
		{Name: "a", URL: "https://a.com"},
		{Name: "b", URL: "https://b.com"},
	}}
	if err := SaveState(filepath.Join(dir, "state.json"), st); err != nil {
		t.Fatal(err)
	}

	code := runRegistry([]string{"remove", "a"})
	if code != 0 {
		t.Fatalf("registry remove: expected exit 0, got %d", code)
	}

	updated, _ := LoadState(filepath.Join(dir, "state.json"))
	if len(updated.Sources) != 1 {
		t.Fatalf("expected 1 source after remove, got %d", len(updated.Sources))
	}
	if updated.Sources[0].Name != "b" {
		t.Errorf("remaining source = %q, want %q", updated.Sources[0].Name, "b")
	}
}

func TestRunRegistryRemove_NotFound(t *testing.T) {
	setupStateDir(t)

	code := runRegistry([]string{"remove", "nonexistent"})
	if code != 2 {
		t.Fatalf("remove nonexistent: expected exit 2, got %d", code)
	}
}

func TestRunRegistryRemove_MissingArg(t *testing.T) {
	setupStateDir(t)

	code := runRegistry([]string{"remove"})
	if code != 2 {
		t.Fatalf("remove no arg: expected exit 2, got %d", code)
	}
}

func TestRunRegistry_NoSubcommand(t *testing.T) {
	code := runRegistry(nil)
	if code != 2 {
		t.Fatalf("no subcommand: expected exit 2, got %d", code)
	}
}

func TestRunRegistry_UnknownSubcommand(t *testing.T) {
	code := runRegistry([]string{"bogus"})
	if code != 2 {
		t.Fatalf("unknown subcommand: expected exit 2, got %d", code)
	}
}

func TestRunRegistryRoundTrip(t *testing.T) {
	setupStateDir(t)

	// Add two registries.
	if code := runRegistry([]string{"add", "--name", "alpha", "https://alpha.dev/index.json"}); code != 0 {
		t.Fatalf("add alpha: exit %d", code)
	}
	if code := runRegistry([]string{"add", "--name", "beta", "https://beta.dev/index.json"}); code != 0 {
		t.Fatalf("add beta: exit %d", code)
	}

	// List should succeed.
	if code := runRegistry([]string{"list"}); code != 0 {
		t.Fatalf("list: exit %d", code)
	}

	// Remove one.
	if code := runRegistry([]string{"remove", "alpha"}); code != 0 {
		t.Fatalf("remove alpha: exit %d", code)
	}

	// Verify only beta remains.
	st, _ := LoadState(DefaultStatePath())
	if len(st.Sources) != 1 || st.Sources[0].Name != "beta" {
		t.Errorf("after round-trip: sources = %+v", st.Sources)
	}
}

func TestRunRegistryAdd_BadURL(t *testing.T) {
	setupStateDir(t)

	// URL with no host can't derive a name.
	code := runRegistry([]string{"add", "not-a-url"})
	if code != 2 {
		t.Fatalf("bad URL: expected exit 2, got %d", code)
	}
}

func TestRunRegistryAdd_CorruptState(t *testing.T) {
	dir := setupStateDir(t)

	// Write corrupt state file.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{bad"), 0o644); err != nil {
		t.Fatal(err)
	}

	code := runRegistry([]string{"add", "--name", "x", "https://x.com"})
	if code != 2 {
		t.Fatalf("corrupt state: expected exit 2, got %d", code)
	}
}
