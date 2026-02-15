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

func filterArtifactsByType(artifacts []discovery.Artifact, excludeTypes []string) []discovery.Artifact {
	if len(excludeTypes) == 0 {
		return artifacts
	}

	typeSet := make(map[discovery.ArtifactType]bool)
	for _, t := range excludeTypes {
		typeSet[discovery.ArtifactType(t)] = true
	}

	var filtered []discovery.Artifact
	for _, a := range artifacts {
		if !typeSet[a.Type] {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

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

	// Phase 1b: Filter artifacts by excluded artifact types.
	var excludeArtifactTypes []string
	for _, et := range cfg.Scan.ExcludeArtifactTypes {
		excludeArtifactTypes = append(excludeArtifactTypes, et.ArtifactTypes...)
	}
	artifacts = filterArtifactsByType(artifacts, excludeArtifactTypes)

	// Phase 2: Run analyzers.
	allFindings := findings.NewFindingSet()

	// Secrets scanner.
	secretsAnalyzer := secrets.NewAnalyzer()

	// Apply entropy config overrides from .nox.yaml.
	if ec := cfg.Scan.Entropy; ec.Threshold > 0 || ec.HexThreshold > 0 || ec.Base64Threshold > 0 || ec.RequireContext != nil {
		secretsAnalyzer.ApplyEntropyOverrides(secrets.EntropyOverrides{
			Threshold:       ec.Threshold,
			HexThreshold:    ec.HexThreshold,
			Base64Threshold: ec.Base64Threshold,
			RequireContext:  ec.RequireContext,
		})
	}

	secretsFindings, err := secretsAnalyzer.ScanArtifacts(artifacts)
	if err != nil {
		return nil, err
	}
	secretsItems := secretsFindings.Findings()
	for i := range secretsItems {
		allFindings.Add(secretsItems[i])
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
	iacItems := iacFindings.Findings()
	for i := range iacItems {
		allFindings.Add(iacItems[i])
	}

	// AI security scanner.
	aiAnalyzer := ai.NewAnalyzer()
	aiFindings, aiInventory, err := aiAnalyzer.ScanArtifacts(artifacts)
	if err != nil {
		return nil, err
	}
	aiItems := aiFindings.Findings()
	for i := range aiItems {
		allFindings.Add(aiItems[i])
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
	depsItems := depsFindings.Findings()
	for i := range depsItems {
		allFindings.Add(depsItems[i])
	}

	// Merge all analyzer rule sets for SARIF reporting.
	allRules := rules.NewRuleSet()
	for _, r := range secretsAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range dataAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range iacAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range aiAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range depsAnalyzer.Rules().Rules() {
		allRules.Add(r)
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
			for i := range customFindings {
				allFindings.Add(customFindings[i])
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

	// Phase 3b: Apply analyzer_rules (disable rules for specific paths).
	for _, ar := range cfg.Scan.AnalyzerRules {
		if ar.Action != "disable" {
			continue
		}
		if len(ar.Rules) > 0 && len(ar.Paths) > 0 {
			allFindings.RemoveByRuleIDsAndPaths(ar.Rules, ar.Paths)
		}
	}

	// Phase 3c: Apply conditional_severity (override severity based on rule + path).
	for _, cs := range cfg.Scan.ConditionalSeverity {
		if len(cs.Rules) > 0 && len(cs.Paths) > 0 {
			allFindings.OverrideSeverityByRulePatternsAndPaths(cs.Rules, cs.Paths, findings.Severity(cs.Severity))
		}
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
	return RunStagedScanWithOptions(repoRoot, ScanOptions{})
}

// RunStagedScanWithOptions executes a staged-files scan with the given options.
func RunStagedScanWithOptions(repoRoot string, opts ScanOptions) (*ScanResult, error) {
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
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			return
		}
	}()

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

// HistoryScanOptions configures git history scanning.
type HistoryScanOptions struct {
	// MaxDepth limits the number of commits to traverse. 0 means unlimited.
	MaxDepth int

	// Branch is the branch to scan. Defaults to HEAD.
	Branch string

	// Since is a bookmark commit SHA. When set, only commits after this
	// SHA are scanned (for incremental history scanning).
	Since string

	// ScanOptions are passed through to the secrets analyzer.
	ScanOptions ScanOptions
}

// RunHistoryScan traverses git history and scans each changed file for
// secrets. It uses the git history walker to enumerate commits and feeds
// file content through the secrets analyzer. Findings include commit
// metadata (SHA, author, date) in their Metadata map.
func RunHistoryScan(repoRoot string, opts *HistoryScanOptions) (*ScanResult, error) {
	allFindings := findings.NewFindingSet()
	allRules := rules.NewRuleSet()

	secretsAnalyzer := secrets.NewAnalyzer()
	for _, r := range secretsAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}

	engine := rules.NewEngine(secretsAnalyzer.Rules())

	walkOpts := git.WalkHistoryOptions{
		MaxDepth: opts.MaxDepth,
		Branch:   opts.Branch,
		Since:    opts.Since,
	}

	err := git.WalkHistory(repoRoot, walkOpts, func(diff git.HistoryDiff) error {
		matches, scanErr := engine.ScanFile(diff.FilePath, diff.Content)
		if scanErr != nil {
			return nil // skip files that fail to scan
		}

		for i := range matches {
			// Attach commit metadata.
			if matches[i].Metadata == nil {
				matches[i].Metadata = make(map[string]string)
			}
			matches[i].Metadata["commit_sha"] = diff.Commit.SHA
			matches[i].Metadata["commit_author"] = diff.Commit.Author
			matches[i].Metadata["commit_date"] = diff.Commit.Date.Format("2006-01-02T15:04:05Z")
			matches[i].Metadata["commit_message"] = diff.Commit.Message

			allFindings.Add(matches[i])
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("history scan: %w", err)
	}

	allFindings.Deduplicate()
	allFindings.SortDeterministic()

	return &ScanResult{
		Findings:    allFindings,
		Inventory:   &deps.PackageInventory{},
		AIInventory: &ai.Inventory{},
		Rules:       allRules,
	}, nil
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
	items := fs.Findings()
	for i := range items {
		byFile[items[i].Location.FilePath] = append(byFile[items[i].Location.FilePath], i)
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

	items := fs.Findings()
	for i := range items {
		f := items[i]
		if f.Status != "" && f.Status != findings.StatusNew {
			continue // already suppressed
		}
		if bl.Match(&f) != nil {
			fs.SetStatus(i, findings.StatusBaselined)
		}
	}
}

// timeNow returns the current time. It is a variable so tests can override it.
var timeNow = time.Now
