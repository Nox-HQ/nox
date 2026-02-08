package plugin

import (
	"errors"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the .nox.yaml configuration file.
type Config struct {
	PluginPolicy PluginPolicyConfig `yaml:"plugin_policy"`
}

// PluginPolicyConfig defines policy overrides loaded from configuration.
type PluginPolicyConfig struct {
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

// ToPolicy converts PluginPolicyConfig to a runtime Policy, applying unit
// conversions and falling back to DefaultPolicy() values for zero fields.
func (c *PluginPolicyConfig) ToPolicy() Policy {
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
