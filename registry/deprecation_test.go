package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadScaffoldIndex decodes the index.json that ships in this repo and
// is published as the official registry, so tests can assert on the
// real shipped data rather than a hand-written fixture.
func loadScaffoldIndex(t *testing.T) Index {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "registry-scaffold", "index.json"))
	if err != nil {
		t.Fatalf("reading scaffold index: %v", err)
	}
	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatalf("parsing scaffold index: %v", err)
	}
	return idx
}

func TestPluginEntryParsesDeprecationFields(t *testing.T) {
	// The registry index carries deprecation as structured data so
	// consumers can react to it; before this existed the only signal
	// was a hand-written "[DEPRECATED]" prefix in the description.
	raw := `{
		"name": "nox/policy-gate",
		"description": "Policy gate",
		"deprecated": true,
		"deprecation_note": "Superseded by nox/grc. Install nox/grc instead.",
		"versions": [{"version": "0.2.0", "api_version": "v1", "digest": "sha256:aaa"}]
	}`

	var p PluginEntry
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !p.Deprecated {
		t.Error("Deprecated should be true")
	}
	if want := "Superseded by nox/grc. Install nox/grc instead."; p.DeprecationNote != want {
		t.Errorf("DeprecationNote = %q, want %q", p.DeprecationNote, want)
	}
}

func TestPluginEntryDeprecationRoundTrip(t *testing.T) {
	original := PluginEntry{
		Name:            "nox/baseline-mgmt",
		Description:     "Baseline management",
		Deprecated:      true,
		DeprecationNote: "Superseded by built-in nox baseline commands.",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PluginEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Deprecated != original.Deprecated {
		t.Errorf("Deprecated = %v, want %v", decoded.Deprecated, original.Deprecated)
	}
	if decoded.DeprecationNote != original.DeprecationNote {
		t.Errorf("DeprecationNote = %q, want %q", decoded.DeprecationNote, original.DeprecationNote)
	}
}

func TestPluginEntryOmitsDeprecationWhenUnset(t *testing.T) {
	// Non-deprecated plugins are the overwhelming majority; emitting
	// "deprecated": false on every entry would bloat the index and
	// churn the diff for every regeneration.
	data, err := json.Marshal(PluginEntry{Name: "nox/sast", Description: "SAST"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	for _, field := range []string{"deprecated", "deprecation_note"} {
		if _, ok := m[field]; ok {
			t.Errorf("%s should be omitted when unset", field)
		}
	}
}

func TestScaffoldIndexTracksAreValid(t *testing.T) {
	// Guards the shipped index against tracks that exist only in the
	// JSON — an unrecognized track silently breaks --track filtering
	// and renders as a raw string on the marketplace site.
	idx := loadScaffoldIndex(t)

	for i := range idx.Plugins {
		p := &idx.Plugins[i]
		if p.Track == "" {
			continue
		}
		if !ValidTrack(p.Track) {
			t.Errorf("%s declares unknown track %q", p.Name, p.Track)
		}
	}
}
