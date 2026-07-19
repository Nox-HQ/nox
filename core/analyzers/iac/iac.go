// Package iac implements Infrastructure-as-Code security scanning. It wraps
// the core/rules engine with built-in rules that detect common IaC
// misconfigurations in Dockerfiles, Terraform files, and Kubernetes manifests.
package iac

import (
	"context"
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
	iacRules := builtinIaCRules()
	for i := range iacRules {
		rs.Add(&iacRules[i])
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
// GitHub Actions workflow findings receive a context-aware post-pass that
// downgrades well-known false positives (ephemeral test DB credentials,
// permissions paired with their justifying consumer action).
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	var collected []findings.Finding
	for _, artifact := range artifacts {
		// Honour cancellation between artifacts — see the note in the secrets
		// analyzer: nothing else in this loop consults ctx.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		content, err := os.ReadFile(artifact.AbsPath)
		if err != nil {
			return nil, fmt.Errorf("reading artifact %s: %w", artifact.Path, err)
		}

		results, err := a.ScanFile(artifact.Path, content)
		if err != nil {
			return nil, fmt.Errorf("scanning artifact %s: %w", artifact.Path, err)
		}

		collected = append(collected, results...)
	}

	// GitHub Actions context downgrades are applied by the scan pipeline across
	// EVERY analyzer's output (core/scan.go), not just IaC's. Applying them a
	// second time here was redundant, and — before finding metadata was copied
	// per-finding — the second pass re-wrote a shared map and contaminated
	// unrelated findings. The pipeline is the single place they are applied.
	for i := range collected {
		fs.Add(collected[i])
	}

	fs.Deduplicate()
	return fs, nil
}
