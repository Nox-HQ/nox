package main

import (
	"testing"

	"github.com/nox-hq/nox/registry"
)

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
