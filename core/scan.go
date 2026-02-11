// Package core provides the shared scan pipeline for nox.
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/policy"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/suppress"
)

// ScanResult holds the complete output of a scan pipeline run.
type ScanResult struct {
	Findings     *findings.FindingSet
	Inventory    *deps.PackageInventory
	AIInventory  *ai.Inventory
	PolicyResult *policy.Result
	Rules        *rules.RuleSet
}

// RunScan executes the full scan pipeline against the given target path.
// It discovers artifacts, runs all analyzers, deduplicates findings,
// applies inline suppressions, baseline matching, and policy evaluation,
// and returns the combined results. If a .nox.yaml config file is present
// in the target directory, its scan settings are applied.
func RunScan(target string) (*ScanResult, error) {
	// Load project config.
	cfg, err := LoadScanConfig(target)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	// Phase 1: Discover artifacts.
	walker := discovery.NewWalker(target)
	walker.IgnorePatterns = append(walker.IgnorePatterns, cfg.Scan.Exclude...)
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

	// Merge all analyzer rule sets for SARIF reporting.
	allRules := rules.NewRuleSet()
	for i := range secretsAnalyzer.Rules().Rules() {
		allRules.Add(secretsAnalyzer.Rules().Rules()[i])
	}
	for i := range iacAnalyzer.Rules().Rules() {
		allRules.Add(iacAnalyzer.Rules().Rules()[i])
	}
	for i := range aiAnalyzer.Rules().Rules() {
		allRules.Add(aiAnalyzer.Rules().Rules()[i])
	}

	// Phase 3: Apply rule config.
	if len(cfg.Scan.Rules.Disable) > 0 {
		allFindings.RemoveByRuleIDs(cfg.Scan.Rules.Disable)
	}
	for ruleID, sev := range cfg.Scan.Rules.SeverityOverride {
		allFindings.OverrideSeverity(ruleID, findings.Severity(sev))
	}

	// Phase 4: Deduplicate and sort.
	allFindings.Deduplicate()
	allFindings.SortDeterministic()

	// Phase 5: Apply inline suppressions.
	applySuppressions(allFindings, target)

	// Phase 6: Apply baseline matching.
	baselinePath := cfg.Policy.BaselinePath
	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(target)
	} else if !filepath.IsAbs(baselinePath) {
		baselinePath = filepath.Join(target, baselinePath)
	}
	applyBaseline(allFindings, baselinePath)

	// Phase 7: Evaluate policy.
	var policyResult *policy.Result
	if cfg.Policy.FailOn != "" || cfg.Policy.BaselineMode != "" {
		policyCfg := policy.Config{
			FailOn:       findings.Severity(cfg.Policy.FailOn),
			WarnOn:       findings.Severity(cfg.Policy.WarnOn),
			BaselineMode: policy.BaselineMode(cfg.Policy.BaselineMode),
		}
		policyResult = policy.Evaluate(policyCfg, allFindings.Findings())
	}

	return &ScanResult{
		Findings:     allFindings,
		Inventory:    inventory,
		AIInventory:  aiInventory,
		PolicyResult: policyResult,
		Rules:        allRules,
	}, nil
}

// applySuppressions reads files that have findings and marks suppressed findings.
func applySuppressions(fs *findings.FindingSet, target string) {
	// Group findings by file.
	byFile := make(map[string][]int)
	for i, f := range fs.Findings() {
		byFile[f.Location.FilePath] = append(byFile[f.Location.FilePath], i)
	}

	for filePath, indices := range byFile {
		fullPath := filePath
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(target, fullPath)
		}

		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		suppressions := suppress.ScanForSuppressions(content, filePath)
		if len(suppressions) == 0 {
			continue
		}

		items := fs.Findings()
		for _, idx := range indices {
			f := items[idx]
			for _, s := range suppressions {
				if s.MatchesFinding(f.RuleID, f.Location.StartLine, timeNow()) {
					fs.SetStatus(idx, findings.StatusSuppressed)
					break
				}
			}
		}
	}
}

// applyBaseline loads a baseline file and marks matched findings.
func applyBaseline(fs *findings.FindingSet, baselinePath string) {
	bl, err := baseline.Load(baselinePath)
	if err != nil || bl.Len() == 0 {
		return
	}

	for i, f := range fs.Findings() {
		if f.Status != "" && f.Status != findings.StatusNew {
			continue // already suppressed
		}
		if bl.Match(f) != nil {
			fs.SetStatus(i, findings.StatusBaselined)
		}
	}
}

// timeNow returns the current time. It is a variable so tests can override it.
var timeNow = time.Now
