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

func TestIndexV2JSONRoundTrip(t *testing.T) {
	original := Index{
		SchemaVersion: "2",
		GeneratedAt:   time.Date(2026, 2, 8, 0, 0, 0, 0, time.UTC),
		Plugins: []PluginEntry{
			{
				Name:        "nox/sast",
				Description: "Static analysis extensions",
				Homepage:    "https://github.com/nox-hq/nox-plugin-sast",
				Track:       TrackCoreAnalysis,
				Tags:        []string{"sast", "vulnerabilities", "code-analysis"},
				Maintainers: []string{"nox-hq"},
				License:     "Apache-2.0",
				Repository:  "https://github.com/nox-hq/nox-plugin-sast",
				Versions: []VersionEntry{
					{
						Version:       "1.0.0",
						APIVersion:    "v1",
						PublishedAt:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
						Digest:        "sha256:abc123",
						Capabilities:  []string{"sast.scan"},
						RiskClass:     "passive",
						MinNoxVersion: "0.1.0",
						ChangelogURL:  "https://github.com/nox-hq/nox-plugin-sast/blob/main/CHANGELOG.md",
						Artifacts: []PlatformArtifact{
							{OS: "linux", Arch: "amd64", URL: "https://example.com/sast-linux-amd64.tar.gz", Size: 5000000, Digest: "sha256:def456"},
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

	if decoded.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want %q", decoded.SchemaVersion, "2")
	}

	p := decoded.Plugins[0]
	if p.Track != TrackCoreAnalysis {
		t.Errorf("track = %q, want %q", p.Track, TrackCoreAnalysis)
	}
	if len(p.Tags) != 3 {
		t.Fatalf("tags count = %d, want 3", len(p.Tags))
	}
	if p.Tags[0] != "sast" {
		t.Errorf("tags[0] = %q, want %q", p.Tags[0], "sast")
	}
	if len(p.Maintainers) != 1 || p.Maintainers[0] != "nox-hq" {
		t.Errorf("maintainers = %v, want [nox-hq]", p.Maintainers)
	}
	if p.License != "Apache-2.0" {
		t.Errorf("license = %q, want %q", p.License, "Apache-2.0")
	}
	if p.Repository != "https://github.com/nox-hq/nox-plugin-sast" {
		t.Errorf("repository = %q", p.Repository)
	}

	v := p.Versions[0]
	if v.MinNoxVersion != "0.1.0" {
		t.Errorf("minimum_nox_version = %q, want %q", v.MinNoxVersion, "0.1.0")
	}
	if v.ChangelogURL != "https://github.com/nox-hq/nox-plugin-sast/blob/main/CHANGELOG.md" {
		t.Errorf("changelog_url = %q", v.ChangelogURL)
	}
}

func TestV1IndexParsesWithoutV2Fields(t *testing.T) {
	// A v1 index has no track/tags/maintainers — ensure they decode as zero values.
	v1JSON := `{
		"schema_version": "1",
		"generated_at": "2026-02-08T00:00:00Z",
		"plugins": [{
			"name": "nox/legacy",
			"description": "Legacy v1 plugin",
			"versions": [{
				"version": "0.1.0",
				"api_version": "v1",
				"digest": "sha256:aaa"
			}]
		}]
	}`

	var idx Index
	if err := json.Unmarshal([]byte(v1JSON), &idx); err != nil {
		t.Fatalf("unmarshal v1: %v", err)
	}

	p := idx.Plugins[0]
	if p.Track != "" {
		t.Errorf("v1 plugin should have empty track, got %q", p.Track)
	}
	if len(p.Tags) != 0 {
		t.Errorf("v1 plugin should have no tags, got %v", p.Tags)
	}
	if len(p.Maintainers) != 0 {
		t.Errorf("v1 plugin should have no maintainers, got %v", p.Maintainers)
	}
	if p.License != "" {
		t.Errorf("v1 plugin should have empty license, got %q", p.License)
	}
	if p.Versions[0].MinNoxVersion != "" {
		t.Errorf("v1 version should have empty min_nox_version, got %q", p.Versions[0].MinNoxVersion)
	}
}

func TestPluginEntryOmitsEmptyFields(t *testing.T) {
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

	for _, field := range []string{"homepage", "track", "tags", "maintainers", "license", "repository"} {
		if _, ok := m[field]; ok {
			t.Errorf("%s should be omitted when empty", field)
		}
	}
}

func TestTrackCatalog(t *testing.T) {
	catalog := TrackCatalog()
	if len(catalog) != 10 {
		t.Fatalf("track catalog has %d entries, want 10", len(catalog))
	}

	tracks := AllTracks()
	if len(tracks) != 10 {
		t.Fatalf("AllTracks has %d entries, want 10", len(tracks))
	}

	for i, info := range catalog {
		if info.Track != tracks[i] {
			t.Errorf("catalog[%d].Track = %q, want %q", i, info.Track, tracks[i])
		}
		if info.DisplayName == "" {
			t.Errorf("catalog[%d].DisplayName is empty", i)
		}
		if info.Description == "" {
			t.Errorf("catalog[%d].Description is empty", i)
		}
	}
}

func TestValidTrack(t *testing.T) {
	if !ValidTrack(TrackCoreAnalysis) {
		t.Error("core-analysis should be valid")
	}
	if !ValidTrack(TrackAgentAssistance) {
		t.Error("agent-assistance should be valid")
	}
	if ValidTrack("nonexistent") {
		t.Error("nonexistent should be invalid")
	}
	if ValidTrack("") {
		t.Error("empty string should be invalid")
	}
}
