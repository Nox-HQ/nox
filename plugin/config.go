package plugin

import (
	"errors"
	"os"
	"time"

	"github.com/nox-hq/nox/core"

	"gopkg.in/yaml.v3"
)

// Config represents the .nox.yaml configuration file.
type Config struct {
	PluginPolicy PolicyConfig `yaml:"plugin_policy"`
}

// PolicyConfig defines policy overrides loaded from configuration.
//
// An alias, not a copy: the schema is declared in core.ScanConfig so the
// strict-config check validates this block like every other key in .nox.yaml.
// Before that, `plugin_policy` was reported as a key nox does not recognise —
// telling an operator that a sandbox override they had deliberately set was
// "not in effect" when it was.
//
// Because it is an alias to a type in another package, its behaviour is
// expressed as functions (Overrides, ToPolicy) rather than methods.
type PolicyConfig = core.PluginPolicyConfig

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
func Overrides(c *PolicyConfig) Policy {
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
func ToPolicy(c *PolicyConfig) Policy {
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
