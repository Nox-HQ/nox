package registry

import "time"

// Source represents a registry endpoint that serves plugin indexes.
type Source struct {
	Name string `json:"name"` // e.g. "official", "enterprise"
	URL  string `json:"url"`  // e.g. "https://registry.hardline.dev/index.json"
}

// Index is the top-level registry index document served by a Source.
type Index struct {
	SchemaVersion string        `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Plugins       []PluginEntry `json:"plugins"`
}

// PluginEntry describes a plugin available in the registry.
type PluginEntry struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Homepage    string         `json:"homepage,omitempty"`
	Versions    []VersionEntry `json:"versions"`
}

// VersionEntry describes a specific version of a plugin.
type VersionEntry struct {
	Version      string             `json:"version"`
	APIVersion   string             `json:"api_version"`
	PublishedAt  time.Time          `json:"published_at"`
	Digest       string             `json:"digest"`
	Capabilities []string           `json:"capabilities,omitempty"`
	RiskClass    string             `json:"risk_class,omitempty"`
	Artifacts    []PlatformArtifact `json:"artifacts"`
	Signature    []byte             `json:"signature,omitempty"`
	SignerKeyPEM []byte             `json:"signer_key_pem,omitempty"`
}

// PlatformArtifact describes a platform-specific binary for a plugin version.
type PlatformArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}
