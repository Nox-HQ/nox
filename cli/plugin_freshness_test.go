package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox/registry"
)

func freshnessState(t *testing.T, generated time.Time, installed string) {
	t.Helper()
	idx := testRegistryIndex()
	idx.GeneratedAt = generated
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(idx)
	}))
	t.Cleanup(srv.Close)
	dir := setupPluginTestState(t, srv)
	if installed != "" {
		st := &State{
			Sources: []registry.Source{{Name: "test", URL: srv.URL}},
			Plugins: []InstalledPlugin{{Name: "nox/dast", Version: installed}},
		}
		if err := SaveState(filepath.Join(dir, "state.json"), st); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPluginSearchAndInfoWarnWhenInstalledIsAheadOfIndex(t *testing.T) {
	for _, cmd := range [][]string{{"search", "dast"}, {"info", "nox/dast"}} {
		freshnessState(t, time.Now().Add(-time.Hour), "1.3.0")
		var code int
		out := captureStderr(t, func() { code = runPlugin(cmd) })
		if code != 0 {
			t.Fatalf("%v exited %d", cmd, code)
		}
		if !strings.Contains(out, "installed nox/dast 1.3.0 is newer than the registry index's highest version (1.2.0)") {
			t.Errorf("%v: no ahead-of-index warning:\n%s", cmd, out)
		}
		if strings.Contains(out, "generated") {
			t.Errorf("%v: a fresh index must not be called stale:\n%s", cmd, out)
		}
	}
}

func TestPluginSearchAndInfoWarnWhenIndexIsStale(t *testing.T) {
	for _, cmd := range [][]string{{"search", "dast"}, {"info", "nox/dast"}} {
		freshnessState(t, time.Now().Add(-30*24*time.Hour), "1.0.0")
		out := captureStderr(t, func() { runPlugin(cmd) })
		if !strings.Contains(out, "the registry index was generated") || !strings.Contains(out, "30 days ago") {
			t.Errorf("%v: no stale-index warning:\n%s", cmd, out)
		}
		if strings.Contains(out, "is newer than") {
			t.Errorf("%v: an older install is not ahead of the index:\n%s", cmd, out)
		}
	}
}

func TestPluginSearchLabelsLatest(t *testing.T) {
	freshnessState(t, time.Now(), "")
	var code int
	out := captureStdout(t, func() { code = runPlugin([]string{"search", "dast"}) })
	if code != 0 || !strings.Contains(out, "LATEST (highest in registry index)") {
		t.Errorf("LATEST is not labelled:\n%s", out)
	}
}
