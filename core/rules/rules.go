// Package rules implements the YAML-based declarative rule engine for the
// Nox security scanner. Rules are loaded from YAML files, matched against
// source content using pluggable matchers, and produce canonical Finding values
// from the core/findings package.
package rules

import (
	"github.com/nox-hq/nox/core/findings"
)

// ValidMatcherTypes enumerates the matcher type strings that a Rule may
// reference. Any value not in this set causes a validation error at load time.
var ValidMatcherTypes = map[string]bool{
	"regex":     true,
	"jsonpath":  true,
	"yamlpath":  true,
	"heuristic": true,
}

// Rule is a single declarative security rule loaded from YAML. It describes
// what to look for (Pattern + MatcherType), where to look (FilePatterns), and
// how to classify the result (Severity, Confidence).
type Rule struct {
	ID           string              `yaml:"id"`
	Version      string              `yaml:"version"`
	Description  string              `yaml:"description"`
	Severity     findings.Severity   `yaml:"severity"`
	Confidence   findings.Confidence `yaml:"confidence"`
	MatcherType  string              `yaml:"matcher_type"`
	Pattern      string              `yaml:"pattern"`
	FilePatterns []string            `yaml:"file_patterns"`
	Tags         []string            `yaml:"tags"`
	Metadata     map[string]string   `yaml:"metadata"`
}

// RuleSet is an ordered collection of rules with fast lookup by ID and tag.
type RuleSet struct {
	rules []Rule
	byID  map[string]int
	byTag map[string][]int
}

// NewRuleSet returns an initialised, empty RuleSet.
func NewRuleSet() *RuleSet {
	return &RuleSet{
		byID:  make(map[string]int),
		byTag: make(map[string][]int),
	}
}

// Add appends a rule to the set and updates the lookup indexes.
func (rs *RuleSet) Add(r Rule) {
	idx := len(rs.rules)
	rs.rules = append(rs.rules, r)
	rs.byID[r.ID] = idx
	for _, tag := range r.Tags {
		rs.byTag[tag] = append(rs.byTag[tag], idx)
	}
}

// Rules returns all rules in insertion order.
func (rs *RuleSet) Rules() []Rule {
	return rs.rules
}

// ByID looks up a rule by its unique identifier. The boolean return indicates
// whether a rule with the given ID exists in the set.
func (rs *RuleSet) ByID(id string) (Rule, bool) {
	idx, ok := rs.byID[id]
	if !ok {
		return Rule{}, false
	}
	return rs.rules[idx], true
}

// ByTag returns all rules that carry the given tag. If no rules match, an
// empty slice is returned.
func (rs *RuleSet) ByTag(tag string) []Rule {
	idxs, ok := rs.byTag[tag]
	if !ok {
		return nil
	}
	out := make([]Rule, 0, len(idxs))
	for _, idx := range idxs {
		out = append(out, rs.rules[idx])
	}
	return out
}
