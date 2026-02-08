// Package core provides the shared scan pipeline for nox.
package core

import (
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// ScanResult holds the complete output of a scan pipeline run.
type ScanResult struct {
	Findings    *findings.FindingSet
	Inventory   *deps.PackageInventory
	AIInventory *ai.Inventory
}

// RunScan executes the full scan pipeline against the given target path.
// It discovers artifacts, runs all analyzers, deduplicates findings,
// and returns the combined results.
func RunScan(target string) (*ScanResult, error) {
	// Phase 1: Discover artifacts.
	walker := discovery.NewWalker(target)
	artifacts, err := walker.Walk()
	if err != nil {
		return nil, err
	}

	// Phase 2: Run analyzers.
	allFindings := findings.NewFindingSet()

	// Secrets scanner.
	secretsAnalyzer := secrets.NewAnalyzer()
	secretsFindings, err := secretsAnalyzer.ScanArtifacts(artifacts)
	if err != nil {
		return nil, err
	}
	for _, f := range secretsFindings.Findings() {
		allFindings.Add(f)
	}

	// IaC scanner.
	iacAnalyzer := iac.NewAnalyzer()
	iacFindings, err := iacAnalyzer.ScanArtifacts(artifacts)
	if err != nil {
		return nil, err
	}
	for _, f := range iacFindings.Findings() {
		allFindings.Add(f)
	}

	// AI security scanner.
	aiAnalyzer := ai.NewAnalyzer()
	aiFindings, aiInventory, err := aiAnalyzer.ScanArtifacts(artifacts)
	if err != nil {
		return nil, err
	}
	for _, f := range aiFindings.Findings() {
		allFindings.Add(f)
	}

	// Dependency scanner.
	depsAnalyzer := deps.NewAnalyzer()
	inventory, depsFindings, err := depsAnalyzer.ScanArtifacts(artifacts)
	if err != nil {
		return nil, err
	}
	for _, f := range depsFindings.Findings() {
		allFindings.Add(f)
	}

	// Phase 3: Deduplicate and sort.
	allFindings.Deduplicate()
	allFindings.SortDeterministic()

	return &ScanResult{
		Findings:    allFindings,
		Inventory:   inventory,
		AIInventory: aiInventory,
	}, nil
}
