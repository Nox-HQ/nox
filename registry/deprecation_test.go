package registry

import (
	"encoding/json"
	"testing"
)

// TestPluginEntry_DeprecationRoundTrips guards the bug this fixes: the registry
// index carried "deprecated" and "deprecation_note" for two releases while
// PluginEntry had no such fields, so they decoded to nothing and every consumer
// silently ignored them. A retired plugin kept being resolved and installed
// with no warning.
func TestPluginEntry_DeprecationRoundTrips(t *testing.T) {
	t.Parallel()

	raw := `{
		"name": "nox/policy-gate",
		"description": "Policy gating",
		"versions": [],
		"deprecated": true,
		"deprecation_note": "superseded by core policy.fail_on"
	}`

	var p PluginEntry
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshalling entry: %v", err)
	}

	if !p.Deprecated {
		t.Error("deprecated was not decoded; the index field is inert")
	}
	if p.DeprecationNote != "superseded by core policy.fail_on" {
		t.Errorf("deprecation_note = %q, want the superseded-by text", p.DeprecationNote)
	}

	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshalling entry: %v", err)
	}
	var decoded PluginEntry
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("re-unmarshalling entry: %v", err)
	}
	if decoded.Deprecated != p.Deprecated || decoded.DeprecationNote != p.DeprecationNote {
		t.Errorf("round-trip lost deprecation data: %+v", decoded)
	}
}

// TestPluginEntry_DeprecationOmittedWhenUnset keeps non-deprecated entries
// byte-identical to before, so adding the fields does not churn the index.
func TestPluginEntry_DeprecationOmittedWhenUnset(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(PluginEntry{Name: "nox/example"})
	if err != nil {
		t.Fatalf("marshalling entry: %v", err)
	}
	for _, field := range []string{"deprecated", "deprecation_note"} {
		if containsField(string(encoded), field) {
			t.Errorf("expected %q to be omitted for a live plugin, got %s", field, encoded)
		}
	}
}

func containsField(encoded, field string) bool {
	needle := `"` + field + `"`
	for i := 0; i+len(needle) <= len(encoded); i++ {
		if encoded[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
