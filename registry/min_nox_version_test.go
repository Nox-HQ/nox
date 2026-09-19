package registry

import (
	"context"
	"strings"
	"testing"
)

// minimum_nox_version was in the schema and written by `nox plugin entry`, but
// nothing read it, so a plugin needing a newer host installed on an older one
// and failed at every scan. nox/freshness 0.1.0 is the case: it needs 1.38.3.
func freshnessIndex() Index {
	return Index{SchemaVersion: "1", Plugins: []PluginEntry{{
		Name: "nox/freshness", Track: "supply-chain",
		Versions: []VersionEntry{
			{Version: "0.0.9"},
			{Version: "0.1.0", MinNoxVersion: "1.38.3"},
		},
	}}}
}

func resolveFreshness(t *testing.T, nox string) (*VersionEntry, error) {
	t.Helper()
	srv := serveIndex(t, freshnessIndex())
	t.Cleanup(srv.Close)
	c := newTestClient(t, srv.URL)
	if err := c.AddSource(Source{Name: "test", URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	return c.Resolve(context.Background(), "nox/freshness", "*", WithNoxVersion(nox))
}

func TestResolveSkipsAVersionThatNeedsANewerNox(t *testing.T) {
	ve, err := resolveFreshness(t, "1.38.2")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ve.Version != "0.0.9" {
		t.Errorf("nox 1.38.2 resolved %s; 0.1.0 needs 1.38.3, so it should get 0.0.9", ve.Version)
	}
}

func TestResolveTakesTheNewestVersionWhenNoxIsNewEnough(t *testing.T) {
	for _, nox := range []string{"1.38.3", "v1.39.0"} {
		ve, err := resolveFreshness(t, nox)
		if err != nil || ve.Version != "0.1.0" {
			t.Errorf("nox %s: got %v %v, want 0.1.0", nox, ve, err)
		}
	}
}

// A dev build names no release, so it must not guess a version to compare.
func TestResolveIgnoresTheMinimumOnADevBuild(t *testing.T) {
	ve, err := resolveFreshness(t, "dev")
	if err != nil || ve.Version != "0.1.0" {
		t.Errorf("dev build: got %v %v, want 0.1.0", ve, err)
	}
}

// When every matching version needs a newer nox, say that -- not "no version
// matches", which sends the operator looking at the constraint.
func TestResolveSaysWhichNoxIsNeeded(t *testing.T) {
	srv := serveIndex(t, freshnessIndex())
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if err := c.AddSource(Source{Name: "test", URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	_, err := c.Resolve(context.Background(), "nox/freshness", "0.1.0", WithNoxVersion("1.38.2"))
	if err == nil || !strings.Contains(err.Error(), "requires nox >= 1.38.3") || !strings.Contains(err.Error(), "1.38.2") {
		t.Fatalf("want an error naming nox 1.38.3 and 1.38.2, got %v", err)
	}
}
