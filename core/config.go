package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LicensePolicy defines which dependency licenses are allowed or denied.
// If Deny is specified, any package with a matching license produces a finding.
// If Allow is specified, any package with a license NOT in the list produces a finding.
type LicensePolicy struct {
	Deny  []string `yaml:"deny"`  // License IDs to deny (e.g., ["GPL-3.0", "AGPL-3.0"])
	Allow []string `yaml:"allow"` // License IDs to allow (e.g., ["MIT", "Apache-2.0", "BSD-*"])
}

// ScanConfig holds project-level configuration loaded from .nox.yaml.
type ScanConfig struct {
	Scan       ScanSettings       `yaml:"scan"`
	Output     OutputSettings     `yaml:"output"`
	Explain    ExplainSettings    `yaml:"explain"`
	Policy     PolicySettings     `yaml:"policy"`
	License    LicensePolicy      `yaml:"license"`
	Compliance ComplianceSettings `yaml:"compliance"`
}

// PolicySettings controls pass/fail thresholds and baseline behavior.
type PolicySettings struct {
	FailOn       string `yaml:"fail_on"`
	WarnOn       string `yaml:"warn_on"`
	BaselineMode string `yaml:"baseline_mode"`
	BaselinePath string `yaml:"baseline_path"`
	VEXPath      string `yaml:"vex_path"`
}

// ComplianceSettings controls compliance framework filtering.
type ComplianceSettings struct {
	Framework string `yaml:"framework"`
}

// ScanSettings controls which files are scanned and how rules behave.
type ScanSettings struct {
	Exclude  []string    `yaml:"exclude"`
	RulesDir string      `yaml:"rules_dir"`
	Rules    RulesConfig `yaml:"rules"`
	OSV      OSVConfig   `yaml:"osv"`
}

// OSVConfig controls OSV.dev vulnerability enrichment for dependency scanning.
type OSVConfig struct {
	Disabled bool `yaml:"disabled"`
}

// RulesConfig allows disabling rules or overriding their severity.
type RulesConfig struct {
	Disable          []string          `yaml:"disable"`
	SeverityOverride map[string]string `yaml:"severity_override"`
}

// OutputSettings controls default output format and directory.
type OutputSettings struct {
	Format    string `yaml:"format"`
	Directory string `yaml:"directory"`
}

// ExplainSettings controls defaults for the explain command.
type ExplainSettings struct {
	APIKeyEnv string `yaml:"api_key_env"` // env var name to read API key from (default: OPENAI_API_KEY)
	Model     string `yaml:"model"`       // LLM model name (default: gpt-4o)
	BaseURL   string `yaml:"base_url"`    // custom OpenAI-compatible API base URL
	Timeout   string `yaml:"timeout"`     // per-request timeout (e.g., "2m", "30s")
	BatchSize int    `yaml:"batch_size"`  // findings per LLM request (default: 10)
	Output    string `yaml:"output"`      // output file path (default: explanations.json)
	Enrich    string `yaml:"enrich"`      // comma-separated enrichment tool names
	PluginDir string `yaml:"plugin_dir"`  // directory containing plugin binaries
}

// LoadScanConfig reads .nox.yaml from root and returns the parsed config.
// If the file does not exist, a zero-value ScanConfig is returned with no error.
func LoadScanConfig(root string) (*ScanConfig, error) {
	path := filepath.Join(root, ".nox.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ScanConfig{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg ScanConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	return &cfg, nil
}
