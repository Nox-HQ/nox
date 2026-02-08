package registry

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIndexJSONRoundTrip(t *testing.T) {
	original := Index{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, 2, 8, 0, 0, 0, 0, time.UTC),
		Plugins: []PluginEntry{
			{
				Name:        "nox/dast",
				Description: "Web DAST scanner",
				Homepage:    "https://github.com/nox-hq/dast",
				Versions: []VersionEntry{
					{
						Version:      "1.2.0",
						APIVersion:   "v1",
						PublishedAt:  time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
						Digest:       "sha256:abc123",
						Capabilities: []string{"dast.scan"},
						RiskClass:    "active",
						Artifacts: []PlatformArtifact{
							{
								OS:     "linux",
								Arch:   "amd64",
								URL:    "https://example.com/dast-linux-amd64.tar.gz",
								Size:   12345678,
								Digest: "sha256:def456",
							},
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Index
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.SchemaVersion != original.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", decoded.SchemaVersion, original.SchemaVersion)
	}
	if !decoded.GeneratedAt.Equal(original.GeneratedAt) {
		t.Errorf("generated_at = %v, want %v", decoded.GeneratedAt, original.GeneratedAt)
	}
	if len(decoded.Plugins) != 1 {
		t.Fatalf("plugins count = %d, want 1", len(decoded.Plugins))
	}

	p := decoded.Plugins[0]
	if p.Name != "nox/dast" {
		t.Errorf("plugin name = %q, want %q", p.Name, "nox/dast")
	}
	if len(p.Versions) != 1 {
		t.Fatalf("versions count = %d, want 1", len(p.Versions))
	}
	if len(p.Versions[0].Artifacts) != 1 {
		t.Fatalf("artifacts count = %d, want 1", len(p.Versions[0].Artifacts))
	}
	if p.Versions[0].Artifacts[0].Size != 12345678 {
		t.Errorf("artifact size = %d, want 12345678", p.Versions[0].Artifacts[0].Size)
	}
}

func TestPluginEntryOmitsEmptyHomepage(t *testing.T) {
	entry := PluginEntry{
		Name:        "test/plugin",
		Description: "A test plugin",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	if _, ok := m["homepage"]; ok {
		t.Error("homepage should be omitted when empty")
	}
}
