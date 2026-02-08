// Package secrets implements pattern-based secret detection. It wraps the
// core/rules engine with a set of built-in rules that detect common secret
// patterns such as AWS keys, GitHub tokens, private key headers, and generic
// API key assignments in source files and configuration.
package secrets

import (
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer wraps a rules.Engine pre-loaded with secret detection rules.
type Analyzer struct {
	engine *rules.Engine
}

// NewAnalyzer creates an Analyzer with built-in secret detection rules loaded
// programmatically. The rules use regex matching and apply to all file types.
func NewAnalyzer() *Analyzer {
	rs := rules.NewRuleSet()

	builtinRules := []rules.Rule{
		{
			ID:          "SEC-001",
			Version:     "1.0",
			Description: "AWS Access Key ID detected",
			Severity:    findings.SeverityHigh,
			Confidence:  findings.ConfidenceHigh,
			MatcherType: "regex",
			Pattern:     `AKIA[0-9A-Z]{16}`,
			Tags:        []string{"secrets"},
		},
		{
			ID:          "SEC-002",
			Version:     "1.0",
			Description: "AWS Secret Access Key detected",
			Severity:    findings.SeverityCritical,
			Confidence:  findings.ConfidenceHigh,
			MatcherType: "regex",
			Pattern:     `(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`,
			Tags:        []string{"secrets"},
		},
		{
			ID:          "SEC-003",
			Version:     "1.0",
			Description: "GitHub token detected",
			Severity:    findings.SeverityHigh,
			Confidence:  findings.ConfidenceHigh,
			MatcherType: "regex",
			Pattern:     `gh[ps]_[A-Za-z0-9_]{36,}`,
			Tags:        []string{"secrets"},
		},
		{
			ID:          "SEC-004",
			Version:     "1.0",
			Description: "Private key header detected",
			Severity:    findings.SeverityCritical,
			Confidence:  findings.ConfidenceHigh,
			MatcherType: "regex",
			Pattern:     `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
			Tags:        []string{"secrets"},
		},
		{
			ID:          "SEC-005",
			Version:     "1.0",
			Description: "Generic API key assignment detected",
			Severity:    findings.SeverityMedium,
			Confidence:  findings.ConfidenceMedium,
			MatcherType: "regex",
			Pattern:     `(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"][A-Za-z0-9]{16,}['"]`,
			Tags:        []string{"secrets"},
		},
	}

	for _, r := range builtinRules {
		rs.Add(r)
	}

	return &Analyzer{
		engine: rules.NewEngine(rs),
	}
}

// ScanFile delegates to the underlying rules engine to scan the given file
// content and returns any secret-related findings.
func (a *Analyzer) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	return a.engine.ScanFile(path, content)
}

// ScanArtifacts reads each artifact file from disk, scans it for secrets, and
// collects all findings into a deduplicated FindingSet. If any artifact cannot
// be read, scanning stops and the error is returned.
func (a *Analyzer) ScanArtifacts(artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	for _, artifact := range artifacts {
		content, err := os.ReadFile(artifact.AbsPath)
		if err != nil {
			return nil, fmt.Errorf("reading artifact %s: %w", artifact.Path, err)
		}

		results, err := a.ScanFile(artifact.Path, content)
		if err != nil {
			return nil, fmt.Errorf("scanning artifact %s: %w", artifact.Path, err)
		}

		for _, f := range results {
			fs.Add(f)
		}
	}

	fs.Deduplicate()
	return fs, nil
}
