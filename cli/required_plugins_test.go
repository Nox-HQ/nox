package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/registry"
)

// registryServer serves an index listing a deprecated nox/taint-analysis and
// counts the requests it answers.
func registryServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	idx := registry.Index{
		SchemaVersion: "1",
		Plugins: []registry.PluginEntry{{
			Name:            "nox/taint-analysis",
			Deprecated:      true,
			DeprecationNote: "superseded by nox core's taint engine",
			Versions:        []registry.VersionEntry{{Version: "0.7.3", APIVersion: "v1"}},
		}},
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(idx)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// saveTestState writes a state with the registry as its only source and the
// given plugins installed, under a NOX_HOME of its own.
func saveTestState(t *testing.T, srvURL string, installed ...InstalledPlugin) {
	t.Helper()
	t.Setenv("NOX_HOME", t.TempDir())
	st := &State{Sources: []registry.Source{{Name: "test", URL: srvURL}}, Plugins: installed}
	if err := SaveState(DefaultStatePath(), st); err != nil {
		t.Fatal(err)
	}
}

// TestUnsatisfiedRequired is #936: a range constraint was compared to the
// installed version as a string, so `^0.7.0` never equalled `0.7.3` and every
// scan re-resolved every required plugin against the registry.
func TestUnsatisfiedRequired(t *testing.T) {
	st := &State{Plugins: []InstalledPlugin{
		{Name: "nox/a", Version: "0.7.3"},
		{Name: "nox/b", Version: "0.1.9"},
		{Name: "nox/c", Version: "1.0.0"},
	}}
	required := []string{
		"nox/a@^0.7.0", // satisfied by a range
		"nox/b@^0.2.0", // installed, but too old
		"nox/c",        // any version
		"nox/c@1.0.0",  // exact
		"nox/d@^1.0.0", // not installed
		"nox/a@bogus",  // unparseable: only an exact match satisfies it
	}
	got := unsatisfiedRequired(required, st)
	want := []string{"nox/b@^0.2.0", "nox/d@^1.0.0", "nox/a@bogus"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unsatisfiedRequired = %q, want %q", got, want)
	}
}

// TestAutoInstallMakesNoRequestWhenSatisfied: an installed version inside the
// constraint is not "missing", so the scan does not ask the registry.
func TestAutoInstallMakesNoRequestWhenSatisfied(t *testing.T) {
	srv, hits := registryServer(t)
	saveTestState(t, srv.URL, InstalledPlugin{Name: "nox/taint-analysis", Version: "0.7.3"})

	pcfg := &nox.PluginsConfig{Required: []string{"nox/taint-analysis@^0.7.0"}}
	if rc := autoInstallProjectPlugins(t.TempDir(), pcfg, true, false); rc != 0 {
		t.Errorf("rc = %d, want 0", rc)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("a satisfied requirement made %d registry request(s)", n)
	}
}

// TestAutoInstallUnderOfflineMakesNoRequest: --offline promises no network.
// A missing required plugin is reported, not installed.
func TestAutoInstallUnderOfflineMakesNoRequest(t *testing.T) {
	srv, hits := registryServer(t)
	saveTestState(t, srv.URL)

	pcfg := &nox.PluginsConfig{Required: []string{"nox/taint-analysis@^0.7.0"}}
	if rc := autoInstallProjectPlugins(t.TempDir(), pcfg, true, true); rc == 0 {
		t.Error("rc = 0 with a required plugin left uninstalled")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("--offline made %d registry request(s)", n)
	}
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if st.FindPlugin("nox/taint-analysis") != nil {
		t.Error("--offline installed a plugin")
	}
}

// TestWarnDeprecatedRequired: a required plugin the registry retired is named
// on every scan, from the cached index and without a request, so it is seen by
// the projects that already have it installed and never run `plugin install`.
func TestWarnDeprecatedRequired(t *testing.T) {
	srv, hits := registryServer(t)
	saveTestState(t, srv.URL, InstalledPlugin{Name: "nox/taint-analysis", Version: "0.7.3"})
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		t.Fatal(err)
	}

	var none bytes.Buffer
	warnDeprecatedRequired(&none, []string{"nox/taint-analysis@^0.7.0"}, st)
	if none.Len() != 0 || hits.Load() != 0 {
		t.Fatalf("with nothing cached: wrote %q and made %d request(s); want silence and none", none.String(), hits.Load())
	}

	c := registry.NewClient(registry.WithCacheDir(filepath.Join(noxHome(), "cache", "registry")))
	_ = c.AddSource(st.Sources[0])
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	hits.Store(0)

	var out bytes.Buffer
	warnDeprecatedRequired(&out, []string{"nox/taint-analysis@^0.7.0", "nox/other"}, st)
	got := out.String()
	if !strings.Contains(got, "nox/taint-analysis is deprecated") || !strings.Contains(got, "superseded by nox core's taint engine") {
		t.Errorf("warning = %q; want it to name the plugin and carry the registry's note", got)
	}
	if strings.Contains(got, "nox/other") {
		t.Errorf("warning = %q; named a plugin the registry does not retire", got)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the warning made %d registry request(s)", n)
	}
}
