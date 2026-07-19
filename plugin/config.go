package plugin

import (
	"errors"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the .nox.yaml configuration file.
type Config struct {
	PluginPolicy PolicyConfig `yaml:"plugin_policy"`
}

// PolicyConfig defines policy overrides loaded from configuration.
type PolicyConfig struct {
	AllowedNetworkHosts   []string `yaml:"allowed_network_hosts"`
	AllowedNetworkCIDRs   []string `yaml:"allowed_network_cidrs"`
	AllowedFilePaths      []string `yaml:"allowed_file_paths"`
	AllowedEnvVars        []string `yaml:"allowed_env_vars"`
	MaxRiskClass          string   `yaml:"max_risk_class"`
	AllowConfirmationReqd bool     `yaml:"allow_confirmation_required"`
	MaxArtifactMB         int      `yaml:"max_artifact_mb"`
	MaxConcurrency        int      `yaml:"max_concurrency"`
	ToolTimeoutSeconds    int      `yaml:"tool_timeout_seconds"`
	RequestsPerMinute     int      `yaml:"requests_per_minute"`
	BandwidthMBPerMinute  int      `yaml:"bandwidth_mb_per_minute"`

	// IgnoreTrackProfiles forces every plugin onto DefaultPolicy() regardless
	// of its registry track.
	//
	// This exists because the override semantics are one-directional: an
	// operator can widen an allowlist but cannot empty one, since a zero-length
	// list reads as "not configured". Without this flag there would be no way
	// to revoke the localhost access the dynamic-runtime profile grants — an
	// operator could only add to it. Setting this restores the pre-track
	// behaviour: passive risk class, empty allowlists, opt-in only.
	IgnoreTrackProfiles bool `yaml:"ignore_track_profiles"`
}

// LoadConfig reads a .nox.yaml configuration file. If the file does not
// exist, it returns a default Config without error. Returns an error only for
// malformed YAML or read failures.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Overrides returns a Policy holding ONLY the fields the operator explicitly
// configured, leaving everything else at its zero value.
//
// This is deliberately different from ToPolicy, which starts from
// DefaultPolicy() and overlays config on top. That resolved form cannot be
// merged with a track profile: every DefaultPolicy-derived value looks like a
// deliberate operator choice and would silently override the profile, so
// applying a profile through it would be a no-op. Merging needs to know what
// the operator actually wrote, which is what this returns.
func (c *PolicyConfig) Overrides() Policy {
	var p Policy

	p.AllowedNetworkHosts = c.AllowedNetworkHosts
	p.AllowedNetworkCIDRs = c.AllowedNetworkCIDRs
	p.AllowedFilePaths = c.AllowedFilePaths
	p.AllowedEnvVars = c.AllowedEnvVars
	if c.MaxRiskClass != "" {
		p.MaxRiskClass = RiskClass(c.MaxRiskClass)
	}
	p.AllowConfirmationReqd = c.AllowConfirmationReqd

	if c.MaxArtifactMB > 0 {
		p.MaxArtifactBytes = int64(c.MaxArtifactMB) * 1024 * 1024
	}
	if c.MaxConcurrency > 0 {
		p.MaxConcurrency = c.MaxConcurrency
	}
	if c.ToolTimeoutSeconds > 0 {
		p.ToolInvocationTimeout = time.Duration(c.ToolTimeoutSeconds) * time.Second
	}
	if c.RequestsPerMinute > 0 {
		p.RequestsPerMinute = c.RequestsPerMinute
	}
	if c.BandwidthMBPerMinute > 0 {
		p.BandwidthBytesPerMin = int64(c.BandwidthMBPerMinute) * 1024 * 1024
	}

	return p
}

// ToPolicy converts PolicyConfig to a runtime Policy, applying unit
// conversions and falling back to DefaultPolicy() values for zero fields.
func (c *PolicyConfig) ToPolicy() Policy {
	p := DefaultPolicy()

	if len(c.AllowedNetworkHosts) > 0 {
		p.AllowedNetworkHosts = c.AllowedNetworkHosts
	}
	if len(c.AllowedNetworkCIDRs) > 0 {
		p.AllowedNetworkCIDRs = c.AllowedNetworkCIDRs
	}
	if len(c.AllowedFilePaths) > 0 {
		p.AllowedFilePaths = c.AllowedFilePaths
	}
	if len(c.AllowedEnvVars) > 0 {
		p.AllowedEnvVars = c.AllowedEnvVars
	}
	if c.MaxRiskClass != "" {
		p.MaxRiskClass = RiskClass(c.MaxRiskClass)
	}
	p.AllowConfirmationReqd = c.AllowConfirmationReqd

	if c.MaxArtifactMB > 0 {
		p.MaxArtifactBytes = int64(c.MaxArtifactMB) * 1024 * 1024
	}
	if c.MaxConcurrency > 0 {
		p.MaxConcurrency = c.MaxConcurrency
	}
	if c.ToolTimeoutSeconds > 0 {
		p.ToolInvocationTimeout = time.Duration(c.ToolTimeoutSeconds) * time.Second
	}
	if c.RequestsPerMinute > 0 {
		p.RequestsPerMinute = c.RequestsPerMinute
	}
	if c.BandwidthMBPerMinute > 0 {
		p.BandwidthBytesPerMin = int64(c.BandwidthMBPerMinute) * 1024 * 1024
	}

	return p
}
