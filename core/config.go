package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ScanConfig holds project-level configuration loaded from .nox.yaml.
type ScanConfig struct {
	Scan   ScanSettings   `yaml:"scan"`
	Output OutputSettings `yaml:"output"`
}

// ScanSettings controls which files are scanned and how rules behave.
type ScanSettings struct {
	Exclude []string    `yaml:"exclude"`
	Rules   RulesConfig `yaml:"rules"`
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
