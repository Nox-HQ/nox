package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/felixgeelhaar/hardline/registry"
)

func testRegistryIndex() registry.Index {
	return registry.Index{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, 2, 8, 0, 0, 0, 0, time.UTC),
		Plugins: []registry.PluginEntry{
			{
				Name:        "hardline/dast",
				Description: "Web DAST scanner",
				Homepage:    "https://github.com/hardline/dast",
				Versions: []registry.VersionEntry{
					{
						Version:      "1.0.0",
						APIVersion:   "v1",
						PublishedAt:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
						Digest:       "sha256:aaa",
						Capabilities: []string{"dast.scan"},
						RiskClass:    "active",
					},
					{
						Version:    "1.2.0",
						APIVersion: "v1",
						PublishedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
						Digest:     "sha256:bbb",
						RiskClass:  "active",
					},
				},
			},
			{
				Name:        "hardline/sbom",
				Description: "SBOM generator plugin",
				Versions: []registry.VersionEntry{
					{
						Version:    "0.5.0",
						APIVersion: "v1",
						Digest:     "sha256:ddd",
						RiskClass:  "passive",
					},
				},
			},
		},
	}
}

func serveTestIndex(t *testing.T) *httptest.Server {
	t.Helper()
	idx := testRegistryIndex()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(idx)
	}))
}

func setupPluginTestState(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	st := &State{
		Sources: []registry.Source{
			{Name: "test", URL: srv.URL},
		},
	}
	if err := SaveState(filepath.Join(dir, "state.json"), st); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunPluginSearch(t *testing.T) {
	srv := serveTestIndex(t)
	defer srv.Close()

	setupPluginTestState(t, srv)

	code := runPlugin([]string{"search", "dast"})
	if code != 0 {
		t.Fatalf("plugin search: expected exit 0, got %d", code)
	}
}

func TestRunPluginSearch_NoResults(t *testing.T) {
	srv := serveTestIndex(t)
	defer srv.Close()

	setupPluginTestState(t, srv)

	code := runPlugin([]string{"search", "nonexistent_xyz"})
	if code != 0 {
		t.Fatalf("plugin search no results: expected exit 0, got %d", code)
	}
}

func TestRunPluginSearch_MissingQuery(t *testing.T) {
	code := runPlugin([]string{"search"})
	if code != 2 {
		t.Fatalf("search missing query: expected exit 2, got %d", code)
	}
}

func TestRunPluginSearch_NoRegistries(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	code := runPlugin([]string{"search", "anything"})
	if code != 2 {
		t.Fatalf("search no registries: expected exit 2, got %d", code)
	}
}

func TestRunPluginInfo(t *testing.T) {
	srv := serveTestIndex(t)
	defer srv.Close()

	setupPluginTestState(t, srv)

	code := runPlugin([]string{"info", "hardline/dast"})
	if code != 0 {
		t.Fatalf("plugin info: expected exit 0, got %d", code)
	}
}

func TestRunPluginInfo_NotFound(t *testing.T) {
	srv := serveTestIndex(t)
	defer srv.Close()

	setupPluginTestState(t, srv)

	code := runPlugin([]string{"info", "hardline/nonexistent"})
	if code != 2 {
		t.Fatalf("plugin info not found: expected exit 2, got %d", code)
	}
}

func TestRunPluginInfo_MissingArg(t *testing.T) {
	code := runPlugin([]string{"info"})
	if code != 2 {
		t.Fatalf("info missing arg: expected exit 2, got %d", code)
	}
}

func TestRunPluginInfo_ShowsInstalled(t *testing.T) {
	srv := serveTestIndex(t)
	defer srv.Close()

	dir := setupPluginTestState(t, srv)

	// Pre-install a plugin in state.
	st, _ := LoadState(filepath.Join(dir, "state.json"))
	st.AddPlugin(InstalledPlugin{
		Name:       "hardline/dast",
		Version:    "1.0.0",
		TrustLevel: "verified",
	})
	_ = SaveState(filepath.Join(dir, "state.json"), st)

	code := runPlugin([]string{"info", "hardline/dast"})
	if code != 0 {
		t.Fatalf("plugin info installed: expected exit 0, got %d", code)
	}
}

func TestRunPluginList_Empty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	code := runPlugin([]string{"list"})
	if code != 0 {
		t.Fatalf("plugin list empty: expected exit 0, got %d", code)
	}
}

func TestRunPluginList_WithPlugins(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	now := time.Now()
	st := &State{
		Plugins: []InstalledPlugin{
			{Name: "hardline/dast", Version: "1.2.0", TrustLevel: "verified", InstalledAt: now},
			{Name: "hardline/sbom", Version: "0.5.0", TrustLevel: "community", InstalledAt: now},
		},
	}
	_ = SaveState(filepath.Join(dir, "state.json"), st)

	code := runPlugin([]string{"list"})
	if code != 0 {
		t.Fatalf("plugin list: expected exit 0, got %d", code)
	}
}

func TestRunPluginRemove(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	st := &State{
		Plugins: []InstalledPlugin{
			{Name: "hardline/dast", Version: "1.2.0", Digest: "sha256:bbb"},
			{Name: "hardline/sbom", Version: "0.5.0", Digest: "sha256:ddd"},
		},
	}
	_ = SaveState(filepath.Join(dir, "state.json"), st)

	code := runPlugin([]string{"remove", "hardline/dast"})
	if code != 0 {
		t.Fatalf("plugin remove: expected exit 0, got %d", code)
	}

	updated, _ := LoadState(filepath.Join(dir, "state.json"))
	if len(updated.Plugins) != 1 {
		t.Fatalf("expected 1 plugin after remove, got %d", len(updated.Plugins))
	}
	if updated.Plugins[0].Name != "hardline/sbom" {
		t.Errorf("remaining plugin = %q", updated.Plugins[0].Name)
	}
}

func TestRunPluginRemove_NotInstalled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	code := runPlugin([]string{"remove", "nonexistent"})
	if code != 2 {
		t.Fatalf("remove nonexistent: expected exit 2, got %d", code)
	}
}

func TestRunPluginRemove_MissingArg(t *testing.T) {
	code := runPlugin([]string{"remove"})
	if code != 2 {
		t.Fatalf("remove no arg: expected exit 2, got %d", code)
	}
}

func TestRunPlugin_NoSubcommand(t *testing.T) {
	code := runPlugin(nil)
	if code != 2 {
		t.Fatalf("no subcommand: expected exit 2, got %d", code)
	}
}

func TestRunPlugin_UnknownSubcommand(t *testing.T) {
	code := runPlugin([]string{"bogus"})
	if code != 2 {
		t.Fatalf("unknown subcommand: expected exit 2, got %d", code)
	}
}

func TestRunPluginCall_MissingArgs(t *testing.T) {
	code := runPlugin([]string{"call"})
	if code != 2 {
		t.Fatalf("call no args: expected exit 2, got %d", code)
	}

	code = runPlugin([]string{"call", "myplugin"})
	if code != 2 {
		t.Fatalf("call one arg: expected exit 2, got %d", code)
	}
}

func TestRunPluginCall_NotInstalled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	code := runPlugin([]string{"call", "nonexistent", "tool"})
	if code != 2 {
		t.Fatalf("call not installed: expected exit 2, got %d", code)
	}
}

func TestRunPluginInstall_MissingArg(t *testing.T) {
	code := runPlugin([]string{"install"})
	if code != 2 {
		t.Fatalf("install no arg: expected exit 2, got %d", code)
	}
}

func TestRunPluginInstall_NoRegistries(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	code := runPlugin([]string{"install", "some-plugin"})
	if code != 2 {
		t.Fatalf("install no registries: expected exit 2, got %d", code)
	}
}

func TestRunPluginUpdate_NoPlugins(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	// No sources means early "no registries" exit.
	code := runPlugin([]string{"update"})
	if code != 2 {
		t.Fatalf("update no registries: expected exit 2, got %d", code)
	}
}

func TestRunPluginUpdate_EmptyWithSources(t *testing.T) {
	srv := serveTestIndex(t)
	defer srv.Close()

	setupPluginTestState(t, srv)

	// No plugins installed.
	code := runPlugin([]string{"update"})
	if code != 0 {
		t.Fatalf("update no plugins: expected exit 0, got %d", code)
	}
}

func TestRunPluginUpdate_SpecificNotInstalled(t *testing.T) {
	srv := serveTestIndex(t)
	defer srv.Close()

	setupPluginTestState(t, srv)

	code := runPlugin([]string{"update", "nonexistent"})
	if code != 0 {
		t.Fatalf("update nonexistent: expected exit 0, got %d", code)
	}
}

func TestParseNameVersion(t *testing.T) {
	tests := []struct {
		input      string
		wantName   string
		wantVer    string
	}{
		{"myplugin", "myplugin", "*"},
		{"myplugin@1.0.0", "myplugin", "1.0.0"},
		{"org/plugin@^2.0.0", "org/plugin", "^2.0.0"},
		{"a@b@c", "a@b", "c"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, ver := parseNameVersion(tt.input)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if ver != tt.wantVer {
				t.Errorf("ver = %q, want %q", ver, tt.wantVer)
			}
		})
	}
}

func TestRunPluginInstall_ResolveError(t *testing.T) {
	srv := serveTestIndex(t)
	defer srv.Close()

	setupPluginTestState(t, srv)

	// Try to install a plugin that doesn't exist in the registry.
	code := runPlugin([]string{"install", "nonexistent/plugin@1.0.0"})
	if code != 2 {
		t.Fatalf("install nonexistent: expected exit 2, got %d", code)
	}
}

func TestRunMainRegistryCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	code := run([]string{"registry", "list"})
	if code != 0 {
		t.Fatalf("run registry list: expected exit 0, got %d", code)
	}
}

func TestRunMainPluginCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARDLINE_HOME", dir)

	code := run([]string{"plugin", "list"})
	if code != 0 {
		t.Fatalf("run plugin list: expected exit 0, got %d", code)
	}
}
