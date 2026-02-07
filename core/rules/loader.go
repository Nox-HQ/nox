package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ruleFile is the top-level structure of a YAML rules file. It expects a
// single key "rules" containing an array of rule definitions.
type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// validSeverities is the set of recognised severity values.
var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

// LoadRulesFromFile reads a single YAML file and returns a validated RuleSet.
func LoadRulesFromFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %s: %w", path, err)
	}

	var rf ruleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parsing rules file %s: %w", path, err)
	}

	rs := NewRuleSet()
	for i, r := range rf.Rules {
		if err := validateRule(r); err != nil {
			return nil, fmt.Errorf("rule %d in %s: %w", i, path, err)
		}
		rs.Add(r)
	}
	return rs, nil
}

// LoadRulesFromDir reads all .yaml and .yml files in the given directory and
// merges them into a single RuleSet. Files are processed in lexicographic
// order for determinism.
func LoadRulesFromDir(dir string) (*RuleSet, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading rules directory %s: %w", dir, err)
	}

	rs := NewRuleSet()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		fileRS, err := LoadRulesFromFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		for _, r := range fileRS.Rules() {
			rs.Add(r)
		}
	}
	return rs, nil
}

// validateRule checks that a rule satisfies all mandatory constraints.
func validateRule(r Rule) error {
	if r.ID == "" {
		return fmt.Errorf("rule ID must not be empty")
	}
	if !ValidMatcherTypes[r.MatcherType] {
		return fmt.Errorf("invalid matcher_type %q for rule %s", r.MatcherType, r.ID)
	}
	if !validSeverities[string(r.Severity)] {
		return fmt.Errorf("invalid severity %q for rule %s", r.Severity, r.ID)
	}
	return nil
}
