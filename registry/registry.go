package registry

import "time"

// Track identifies the functional category a plugin belongs to.
type Track string

const (
	TrackCoreAnalysis       Track = "core-analysis"
	TrackDynamicRuntime     Track = "dynamic-runtime"
	TrackAISecurity         Track = "ai-security"
	TrackThreatModeling     Track = "threat-modeling"
	TrackSupplyChain        Track = "supply-chain"
	TrackIntelligence       Track = "intelligence"
	TrackPolicyGovernance   Track = "policy-governance"
	TrackIncidentReadiness  Track = "incident-readiness"
	TrackDeveloperExperience Track = "developer-experience"
	TrackAgentAssistance    Track = "agent-assistance"
)

// AllTracks returns all defined track values.
func AllTracks() []Track {
	return []Track{
		TrackCoreAnalysis,
		TrackDynamicRuntime,
		TrackAISecurity,
		TrackThreatModeling,
		TrackSupplyChain,
		TrackIntelligence,
		TrackPolicyGovernance,
		TrackIncidentReadiness,
		TrackDeveloperExperience,
		TrackAgentAssistance,
	}
}

// ValidTrack reports whether t is a recognized track value.
func ValidTrack(t Track) bool {
	for _, valid := range AllTracks() {
		if t == valid {
			return true
		}
	}
	return false
}

// TrackCharacteristics describes the operational properties of a track.
type TrackCharacteristics struct {
	RiskClass string `json:"risk_class"`          // "passive", "active", or "runtime"
	CISafe    bool   `json:"ci_safe"`             // safe to run in CI without confirmation
	Offline   bool   `json:"offline"`             // can run without network
	ReadOnly  bool   `json:"read_only"`           // never modifies workspace
}

// TrackInfo bundles a track with its display metadata and characteristics.
type TrackInfo struct {
	Track           Track                `json:"track"`
	DisplayName     string               `json:"display_name"`
	Description     string               `json:"description"`
	Characteristics TrackCharacteristics `json:"characteristics"`
}

// TrackCatalog returns metadata for all defined tracks.
func TrackCatalog() []TrackInfo {
	return []TrackInfo{
		{TrackCoreAnalysis, "Core Analysis", "Deterministic, artifact-based, CI-safe analysis", TrackCharacteristics{"passive", true, true, true}},
		{TrackDynamicRuntime, "Dynamic & Runtime", "Environment-aware, scope-bounded runtime testing", TrackCharacteristics{"active", false, false, false}},
		{TrackAISecurity, "AI Security", "Architecture-aware AI security analysis", TrackCharacteristics{"passive", true, true, true}},
		{TrackThreatModeling, "Threat Modeling & Design", "Review-focused, early design phase analysis", TrackCharacteristics{"passive", true, true, true}},
		{TrackSupplyChain, "Supply Chain & Provenance", "Artifact-centric supply chain audit", TrackCharacteristics{"passive", true, false, true}},
		{TrackIntelligence, "Intelligence & Early Warning", "Signals not exploits, defensive only", TrackCharacteristics{"passive", true, false, true}},
		{TrackPolicyGovernance, "Policy, Risk & Governance", "Org-specific, non-scanning, consumes findings", TrackCharacteristics{"passive", true, true, true}},
		{TrackIncidentReadiness, "Incident Readiness", "Process-focused, zero exploit logic", TrackCharacteristics{"passive", true, true, true}},
		{TrackDeveloperExperience, "Developer Experience", "Adapters and helpers, not detection", TrackCharacteristics{"passive", true, true, true}},
		{TrackAgentAssistance, "Agent & Assistance", "Read-only, never changes results", TrackCharacteristics{"passive", true, false, true}},
	}
}

// Source represents a registry endpoint that serves plugin indexes.
type Source struct {
	Name string `json:"name"` // e.g. "official", "enterprise"
	URL  string `json:"url"`  // e.g. "https://registry.nox-hq.dev/index.json"
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

	// Schema v2 fields — omitted in v1 indexes.
	Track       Track    `json:"track,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Maintainers []string `json:"maintainers,omitempty"`
	License     string   `json:"license,omitempty"`
	Repository  string   `json:"repository,omitempty"`
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

	// Schema v2 fields — omitted in v1 indexes.
	MinNoxVersion string `json:"minimum_nox_version,omitempty"`
	ChangelogURL  string `json:"changelog_url,omitempty"`
}

// PlatformArtifact describes a platform-specific binary for a plugin version.
type PlatformArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}
