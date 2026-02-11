// Package iac implements Infrastructure-as-Code security scanning. It wraps
// the core/rules engine with built-in rules that detect common IaC
// misconfigurations in Dockerfiles, Terraform files, and Kubernetes manifests.
package iac

import (
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer wraps a rules.Engine pre-loaded with IaC security rules.
type Analyzer struct {
	engine *rules.Engine
}

// NewAnalyzer creates an Analyzer with built-in IaC security rules loaded
// programmatically. Rules are scoped to specific file types via FilePatterns.
func NewAnalyzer() *Analyzer {
	rs := rules.NewRuleSet()
	for _, r := range builtinIaCRules() {
		rs.Add(r)
	}
	return &Analyzer{
		engine: rules.NewEngine(rs),
	}
}

// Rules returns the analyzer's RuleSet for catalog aggregation.
func (a *Analyzer) Rules() *rules.RuleSet { return a.engine.Rules() }

// ScanFile delegates to the underlying rules engine to scan the given file
// content and returns any IaC-related findings.
func (a *Analyzer) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	return a.engine.ScanFile(path, content)
}

// ScanArtifacts reads each artifact file from disk, scans it for IaC
// misconfigurations, and collects all findings into a deduplicated FindingSet.
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
