// Package core provides the shared scan pipeline for nox.
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/data"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/policy"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/suppress"
	"github.com/nox-hq/nox/core/vex"
)

// ScanResult holds the complete output of a scan pipeline run.
type ScanResult struct {
	Findings     *findings.FindingSet
	Inventory    *deps.PackageInventory
	AIInventory  *ai.Inventory
	PolicyResult *policy.Result
	Rules        *rules.RuleSet
}

// ScanOptions holds optional parameters for RunScanWithOptions. The zero
// value means no additional options are applied.
type ScanOptions struct {
	// CustomRulesPath is a path to a YAML file or directory containing
	// custom security rules. When set, rules are loaded and merged with
	// the built-in analyzer rules. CLI flags take precedence over
	// .nox.yaml config values.
	CustomRulesPath string

	// DisableOSV disables OSV.dev vulnerability lookups for dependency
	// scanning. When true, the scan runs fully offline with no network
	// calls.
	DisableOSV bool

	// VEXPath is a path to an OpenVEX document. When set, VEX statements
	// are applied to VULN-001 findings after baseline matching.
	VEXPath string

	// TerraformPlanPath is a path to a terraform plan JSON file. When set,
	// the plan is scanned for security issues in addition to normal scanning.
	TerraformPlanPath string
}

// RunScan executes the full scan pipeline against the given target path.
// It discovers artifacts, runs all analyzers, deduplicates findings,
// applies inline suppressions, baseline matching, and policy evaluation,
// and returns the combined results. If a .nox.yaml config file is present
// in the target directory, its scan settings are applied.
func RunScan(target string) (*ScanResult, error) {
	return RunScanWithOptions(target, ScanOptions{})
}

// RunScanWithOptions executes the full scan pipeline with the given options.
// See RunScan for a description of the pipeline stages.
func RunScanWithOptions(target string, opts ScanOptions) (*ScanResult, error) {
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

	// Data sensitivity scanner.
	dataAnalyzer := data.NewAnalyzer()
	dataFindings, err := dataAnalyzer.ScanArtifacts(artifacts)
	if err != nil {
		return nil, err
	}
	dataResults := dataFindings.Findings()
	for i := range dataResults {
		allFindings.Add(dataResults[i])
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
	var depsOpts []deps.AnalyzerOption
	if opts.DisableOSV || cfg.Scan.OSV.Disabled {
		depsOpts = append(depsOpts, deps.WithOSVDisabled())
	}
	depsAnalyzer := deps.NewAnalyzer(depsOpts...)
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
	for i := range dataAnalyzer.Rules().Rules() {
		allRules.Add(dataAnalyzer.Rules().Rules()[i])
	}
	for i := range iacAnalyzer.Rules().Rules() {
		allRules.Add(iacAnalyzer.Rules().Rules()[i])
	}
	for i := range aiAnalyzer.Rules().Rules() {
		allRules.Add(aiAnalyzer.Rules().Rules()[i])
	}
	for i := range depsAnalyzer.Rules().Rules() {
		allRules.Add(depsAnalyzer.Rules().Rules()[i])
	}

	// Phase 2b: Load and merge custom rules (CLI flag > config > none).
	customPath := opts.CustomRulesPath
	if customPath == "" {
		customPath = cfg.Scan.RulesDir
	}
	if customPath != "" {
		if !filepath.IsAbs(customPath) {
			customPath = filepath.Join(target, customPath)
		}
		customRules, err := loadCustomRules(customPath)
		if err != nil {
			return nil, fmt.Errorf("loading custom rules: %w", err)
		}
		// Check for duplicates before merging.
		for _, cr := range customRules.Rules() {
			if allRules.HasID(cr.ID) {
				return nil, fmt.Errorf("custom rule ID %q conflicts with a built-in rule", cr.ID)
			}
		}
		// Run custom rules against artifacts.
		customEngine := rules.NewEngine(customRules)
		for _, artifact := range artifacts {
			content, readErr := os.ReadFile(artifact.AbsPath)
			if readErr != nil {
				return nil, fmt.Errorf("reading artifact %s for custom rules: %w", artifact.Path, readErr)
			}
			customFindings, scanErr := customEngine.ScanFile(artifact.Path, content)
			if scanErr != nil {
				return nil, fmt.Errorf("scanning %s with custom rules: %w", artifact.Path, scanErr)
			}
			for _, f := range customFindings {
				allFindings.Add(f)
			}
		}
		// Add custom rules to the rule set for SARIF reporting.
		for _, cr := range customRules.Rules() {
			allRules.Add(cr)
		}
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

	// Phase 5b: Scan Terraform plan if provided.
	if opts.TerraformPlanPath != "" {
		tfPlanPath := opts.TerraformPlanPath
		if !filepath.IsAbs(tfPlanPath) {
			tfPlanPath = filepath.Join(target, tfPlanPath)
		}
		tfFindings, tfErr := iac.ScanTerraformPlan(tfPlanPath)
		if tfErr == nil && tfFindings != nil {
			tfItems := tfFindings.Findings()
			for i := range tfItems {
				allFindings.Add(tfItems[i])
			}
		}
	}

	// Phase 6: Apply baseline matching.
	baselinePath := cfg.Policy.BaselinePath
	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(target)
	} else if !filepath.IsAbs(baselinePath) {
		baselinePath = filepath.Join(target, baselinePath)
	}
	applyBaseline(allFindings, baselinePath)

	// Phase 6b: Apply VEX document.
	vexPath := opts.VEXPath
	if vexPath == "" {
		vexPath = cfg.Policy.VEXPath
	}
	if vexPath != "" {
		if !filepath.IsAbs(vexPath) {
			vexPath = filepath.Join(target, vexPath)
		}
		if vexDoc, vexErr := vex.LoadVEX(vexPath); vexErr == nil {
			vex.ApplyVEX(allFindings, vexDoc)
		}
	}

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

// loadCustomRules loads rules from a path, which can be a file or directory.
func loadCustomRules(path string) (*rules.RuleSet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("custom rules path %s: %w", path, err)
	}
	if info.IsDir() {
		return rules.LoadRulesFromDir(path)
	}
	return rules.LoadRulesFromFile(path)
}

// RunStagedScan executes the scan pipeline against only git-staged files. It
// reads file content from the git index (not the working tree) so that
// pre-commit hooks scan exactly what will be committed. A temporary directory
// is created with the staged content, scanned using the standard pipeline, and
// finding paths are remapped to their original repository-relative locations.
func RunStagedScan(repoRoot string) (*ScanResult, error) {
	stagedPaths, err := git.StagedFiles(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("listing staged files: %w", err)
	}

	if len(stagedPaths) == 0 {
		// Nothing staged — return clean result.
		return &ScanResult{
			Findings:    findings.NewFindingSet(),
			Inventory:   &deps.PackageInventory{},
			AIInventory: &ai.Inventory{},
			Rules:       rules.NewRuleSet(),
		}, nil
	}

	// Write staged content to a temp directory so the existing scan pipeline
	// can consume it unchanged.
	tmpDir, err := os.MkdirTemp("", "nox-staged-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, p := range stagedPaths {
		content, err := git.StagedContent(repoRoot, p)
		if err != nil {
			return nil, fmt.Errorf("reading staged content for %s: %w", p, err)
		}

		dest := filepath.Join(tmpDir, p)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return nil, fmt.Errorf("creating dir for %s: %w", p, err)
		}
		if err := os.WriteFile(dest, content, 0o644); err != nil {
			return nil, fmt.Errorf("writing staged file %s: %w", p, err)
		}
	}

	// Copy .nox.yaml config if it exists so exclusion patterns apply.
	if cfgData, err := os.ReadFile(filepath.Join(repoRoot, ".nox.yaml")); err == nil {
		_ = os.WriteFile(filepath.Join(tmpDir, ".nox.yaml"), cfgData, 0o644)
	}

	// Run the standard scan against the temp directory. Paths in findings
	// will be relative to tmpDir, which mirrors the repository-relative
	// structure, so no remapping is needed.
	result, err := RunScan(tmpDir)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// SeverityMeetsThreshold returns true if the given severity is at or above the
// threshold severity. Lower rank = more severe (critical=0, high=1, etc.).
func SeverityMeetsThreshold(severity, threshold findings.Severity) bool {
	rank := map[findings.Severity]int{
		findings.SeverityCritical: 0,
		findings.SeverityHigh:     1,
		findings.SeverityMedium:   2,
		findings.SeverityLow:      3,
		findings.SeverityInfo:     4,
	}
	sr, ok1 := rank[severity]
	tr, ok2 := rank[threshold]
	if !ok1 || !ok2 {
		return false
	}
	return sr <= tr
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
