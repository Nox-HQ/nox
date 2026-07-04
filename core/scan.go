// Package core provides the shared scan pipeline for nox.
package core

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/data"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/graph"
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
	Graphs       []graph.Graph         // relationship graphs from plugins
	Enrichments  []findings.Enrichment // finding annotations from plugins
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

	// Offline is the umbrella zero-network guarantee. When true, every
	// feature that could make an outbound connection is disabled (currently
	// OSV.dev lookups — the only network path in the core scan). Use this to
	// assert that a scan never sees the network: no API, no token, no
	// telemetry. New network-capable features must honor this flag.
	Offline bool

	// VEXPath is a path to an OpenVEX document. When set, VEX statements
	// are applied to VULN-001 findings after baseline matching.
	VEXPath string

	// TerraformPlanPath is a path to a terraform plan JSON file. When set,
	// the plan is scanned for security issues in addition to normal scanning.
	TerraformPlanPath string

	// Sequential forces analyzers to run sequentially instead of in parallel.
	// Useful for debugging analyzer interactions.
	Sequential bool

	// NoCache disables the incremental scan cache, forcing a full re-scan.
	NoCache bool

	// ChangedSince limits the scan to files changed since the given git ref.
	// Only files in the diff between the ref and HEAD are analyzed.
	ChangedSince string

	// NoRespectGitignore disables .gitignore handling. When true, every
	// file under the target is walked regardless of ignore rules.
	NoRespectGitignore bool

	// TrackedOnly restricts the scan to files git tracks (`git ls-files`),
	// excluding untracked working-tree files (scratch files, build output,
	// un-added drafts) and submodule contents. Use it to scan exactly what is
	// committed — the same set a reviewer sees — for reproducible CI gates.
	// Ignored outside a git repository.
	TrackedOnly bool
}

// RunScan executes the full scan pipeline against the given target path.
// It discovers artifacts, runs all analyzers, deduplicates findings,
// applies inline suppressions, baseline matching, and policy evaluation,
// and returns the combined results. If a .nox.yaml config file is present
// in the target directory, its scan settings are applied.
func RunScan(target string) (*ScanResult, error) {
	return RunScanWithOptions(target, ScanOptions{})
}

// RunScanWithOptions executes the full scan pipeline with the given options
// using a background context. See RunScanContext for cancellation support.
//
//nolint:gocritic // ScanOptions is a public API surface; passing by value keeps callers ergonomic.
func RunScanWithOptions(target string, opts ScanOptions) (*ScanResult, error) {
	return RunScanContext(context.Background(), target, opts)
}

// RunScanContext executes the full scan pipeline with the given options,
// honoring ctx for cancellation and deadlines. The context is propagated to
// every analyzer (including OSV network lookups) and bounds parallel analyzer
// execution.
//
//nolint:gocritic // ScanOptions is a public API surface; passing by value keeps callers ergonomic.
func RunScanContext(ctx context.Context, target string, opts ScanOptions) (*ScanResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Load project config (LoadScanConfig resolves a single-file target to its
	// directory, so `nox scan path/file.py` finds the project .nox.yaml).
	cfg, err := LoadScanConfig(target)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	// Stage 1: Discover artifacts.
	artifacts, err := discoverArtifacts(target, cfg, opts)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Phase 2: Run analyzers.
	// Initialize analyzers.
	secretsAnalyzer := secrets.NewAnalyzer()
	if ec := cfg.Scan.Entropy; ec.Threshold > 0 || ec.HexThreshold > 0 || ec.Base64Threshold > 0 || ec.RequireContext != nil {
		secretsAnalyzer.ApplyEntropyOverrides(secrets.EntropyOverrides{
			Threshold:       ec.Threshold,
			HexThreshold:    ec.HexThreshold,
			Base64Threshold: ec.Base64Threshold,
			RequireContext:  ec.RequireContext,
		})
	}
	dataAnalyzer := data.NewAnalyzer()
	iacAnalyzer := iac.NewAnalyzer()
	aiAnalyzer := ai.NewAnalyzer()
	var depsOpts []deps.AnalyzerOption
	if opts.Offline || opts.DisableOSV || cfg.Scan.OSV.Disabled {
		depsOpts = append(depsOpts, deps.WithOSVDisabled())
	}
	depsAnalyzer := deps.NewAnalyzer(depsOpts...)

	// Per-analyzer result collectors.
	var (
		mu              sync.Mutex
		analyzerResults [][]findings.Finding
		aiInventory     *ai.Inventory
		inventory       *deps.PackageInventory
	)

	addFindings := func(fs *findings.FindingSet) {
		items := fs.Findings()
		if len(items) == 0 {
			return
		}
		mu.Lock()
		analyzerResults = append(analyzerResults, items)
		mu.Unlock()
	}

	// Each analyzer is wrapped as a uniform task so sequential and parallel
	// execution share one code path. The ai/deps tasks also capture their
	// inventories into the shared collectors.
	tasks := []analyzerTask{
		func(c context.Context) error {
			fs, err := secretsAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := dataAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := iacAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, inv, err := aiAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			mu.Lock()
			aiInventory = inv
			mu.Unlock()
			return nil
		},
		func(c context.Context) error {
			inv, fs, err := depsAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			mu.Lock()
			inventory = inv
			mu.Unlock()
			return nil
		},
	}
	if err := runAnalyzerTasks(ctx, tasks, opts.Sequential); err != nil {
		return nil, err
	}

	// Phase 2c: Apply GitHub Actions context-aware downgrades across all
	// analyzer outputs. Findings on .github/workflows/*.yml that match
	// well-known false-positive patterns (ephemeral test DB credentials,
	// permissions paired with a justifying consumer action) get downgraded
	// before merging.
	ghaWorkflowContent := loadGHAWorkflowContent(artifacts)
	for i, batch := range analyzerResults {
		analyzerResults[i] = iac.ApplyGHAContext(batch, ghaWorkflowContent)
	}

	// Merge per-analyzer findings into a single FindingSet.
	allFindings := findings.NewFindingSet()
	for _, batch := range analyzerResults {
		for i := range batch {
			allFindings.Add(batch[i])
		}
	}

	if aiInventory == nil {
		aiInventory = &ai.Inventory{}
	}
	if inventory == nil {
		inventory = &deps.PackageInventory{}
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

	// Phase 2c: Run configured analysis plugins (taint, SAST, …) declared in
	// .nox.yaml plugins.required and merge their findings in BEFORE refinement,
	// so plugin findings are fingerprinted and baseline-matched like any other.
	// The hook is nil unless the CLI registered it (avoids a core→plugin import
	// cycle). Plugin failures are non-fatal — the built-in scan still completes.
	var pluginEnrichments []findings.Enrichment
	var pluginGraphs []graph.Graph
	if ScanPluginHook != nil && len(cfg.Plugins.Required) > 0 {
		out, hookErr := ScanPluginHook(ctx, target, cfg.Plugins.Required)
		if hookErr != nil {
			slog.WarnContext(ctx, "analysis plugins failed; continuing with built-in findings only", "error", hookErr)
		}
		if out != nil {
			for i := range out.Findings {
				allFindings.Add(out.Findings[i])
			}
			pluginEnrichments = out.Enrichments
			pluginGraphs = out.Graphs
		}
	}

	// Stage 3: Refine findings — apply rule config, generated/noise filters,
	// conditional severity, dedup, inline suppressions, terraform plan,
	// baseline matching, and VEX.
	refineFindings(allFindings, cfg, opts, target)

	// Stage 4: Evaluate policy gates.
	policyResult := evaluatePolicy(cfg, allFindings)

	return &ScanResult{
		Findings:     allFindings,
		Enrichments:  pluginEnrichments,
		Graphs:       pluginGraphs,
		Inventory:    inventory,
		AIInventory:  aiInventory,
		PolicyResult: policyResult,
		Rules:        allRules,
	}, nil
}

// discoverArtifacts walks the target, honoring .gitignore and config excludes,
// optionally restricting to files changed since a git ref, and filtering out
// excluded artifact types. It is stage 1 of the scan pipeline.
func discoverArtifacts(target string, cfg *ScanConfig, opts ScanOptions) ([]discovery.Artifact, error) {
	// A single-file target scans exactly that file — the walker skips its own
	// root, so pointing it at a file would yield nothing. The user named the
	// file explicitly, so gitignore/scan.exclude do not apply.
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		return singleFileArtifacts(target, cfg)
	}

	walker := discovery.NewWalker(target)
	// scan.exclude is a HARD exclude (explicit "never scan this"), kept separate
	// from .gitignore so the tracked-file override does not resurrect it — a
	// tracked file the user excluded (e.g. a rule-definition file) stays
	// excluded, including under --changed-since.
	walker.ExcludePatterns = cfg.Scan.Exclude
	if opts.NoRespectGitignore {
		walker.RespectGitignore = false
	} else if tracked, err := git.TrackedFiles(target); err == nil {
		// git never ignores a tracked file, so a source committed into an
		// otherwise-ignored directory (e.g. `mobile/` in .gitignore) must still
		// be scanned. Best-effort: outside a git repo this errors and the walker
		// applies ignore rules as before.
		walker.TrackedPaths = make(map[string]bool, len(tracked))
		for _, f := range tracked {
			walker.TrackedPaths[f] = true
		}
	}

	// --tracked-only: restrict the walk to git-tracked files by seeding the
	// allow-list with `git ls-files`. Untracked working-tree files and
	// submodule contents (gitlinks, not listed) are excluded. Best-effort:
	// outside a git repo this errors and the full walk proceeds.
	if opts.TrackedOnly {
		if tracked, err := git.TrackedFiles(target); err == nil {
			walker.IncludePaths = make(map[string]bool, len(tracked))
			for _, f := range tracked {
				walker.IncludePaths[f] = true
			}
		}
	}

	// When --changed-since is set, resolve the diff and wire it into the
	// walker as an allow-list BEFORE walking. Pushing this down avoids walking
	// unchanged subtrees in large monorepos. (Changed files are a subset of
	// tracked files, so this correctly narrows a --tracked-only scan further.)
	if opts.ChangedSince != "" {
		changed, err := git.ChangedFilesSince(target, opts.ChangedSince)
		if err != nil {
			return nil, fmt.Errorf("computing changed files: %w", err)
		}
		walker.IncludePaths = make(map[string]bool, len(changed))
		for _, f := range changed {
			walker.IncludePaths[f] = true
		}
	}

	artifacts, err := walker.Walk()
	if err != nil {
		return nil, err
	}

	return filterArtifactsByType(artifacts, excludeArtifactTypes(cfg)), nil
}

// excludeArtifactTypes flattens the configured artifact-type exclusions.
func excludeArtifactTypes(cfg *ScanConfig) []string {
	var out []string
	for _, et := range cfg.Scan.ExcludeArtifactTypes {
		out = append(out, et.ArtifactTypes...)
	}
	return out
}

// singleFileArtifacts classifies one explicitly-named file into a single
// artifact for `nox scan <file>` (fast pre-commit hooks, editor integrations).
// The user named the file, so gitignore and scan.exclude do not apply; only the
// configured artifact-type exclusions do.
func singleFileArtifacts(path string, cfg *ScanConfig) ([]discovery.Artifact, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	reg := discovery.NewClassifierRegistry()
	reg.Register(&discovery.DefaultClassifier{})
	rel := filepath.Base(path)
	art := discovery.Artifact{
		Path:    filepath.ToSlash(rel),
		AbsPath: abs,
		Type:    reg.Classify(rel, info),
		Size:    info.Size(),
	}
	return filterArtifactsByType([]discovery.Artifact{art}, excludeArtifactTypes(cfg)), nil
}

// refineFindings applies all post-analysis transformations to the merged
// finding set in place: config-driven rule disabling/severity overrides,
// analyzer_rules, generated/noise-directory filtering for content rules,
// conditional severity, dedup + deterministic sort, inline suppressions,
// optional terraform-plan findings, baseline matching, and VEX. It is stage 3
// of the scan pipeline.
func refineFindings(allFindings *findings.FindingSet, cfg *ScanConfig, opts ScanOptions, target string) {
	// Config rule disabling and severity overrides.
	if len(cfg.Scan.Rules.Disable) > 0 {
		allFindings.RemoveByRuleIDs(cfg.Scan.Rules.Disable)
	}
	for ruleID, sev := range cfg.Scan.Rules.SeverityOverride {
		allFindings.OverrideSeverity(ruleID, findings.Severity(sev))
	}

	// analyzer_rules: "disable" removes the listed rules for the matching paths;
	// "skip_analyzer" removes every rule belonging to the named analyzer for the
	// matching paths (all paths when none are given).
	for _, ar := range cfg.Scan.AnalyzerRules {
		switch ar.Action {
		case "disable":
			if len(ar.Rules) > 0 && len(ar.Paths) > 0 {
				allFindings.RemoveByRuleIDsAndPaths(ar.Rules, ar.Paths)
			}
		case "skip_analyzer":
			patterns := analyzerRulePatterns(ar.Analyzer)
			if len(patterns) == 0 {
				continue
			}
			paths := ar.Paths
			if len(paths) == 0 {
				paths = []string{"*"} // all files
			}
			allFindings.RemoveByRuleIDsAndPaths(patterns, paths)
		}
	}

	// Drop content-rule findings (AI-*, MCP-*) on generated/vendored files and
	// inside test/fixture/example trees — false-positive sources. Dependency
	// scanning already ran against the same lockfiles, so no real CVE is hidden.
	if genPaths := cfg.Scan.GeneratedPaths.ResolveGeneratedPaths(); len(genPaths) > 0 {
		allFindings.RemoveByRuleIDsAndPaths([]string{"AI-*", "MCP-*"}, genPaths)
	}
	if noiseDirs := cfg.Scan.GeneratedPaths.ResolveNoiseDirs(); len(noiseDirs) > 0 {
		allFindings.RemoveByRuleIDsInDirs([]string{"AI-*", "MCP-*"}, noiseDirs)
	}

	// conditional_severity overrides based on rule + path.
	for _, cs := range cfg.Scan.ConditionalSeverity {
		if len(cs.Rules) > 0 && len(cs.Paths) > 0 {
			allFindings.OverrideSeverityByRulePatternsAndPaths(cs.Rules, cs.Paths, findings.Severity(cs.Severity))
		}
	}

	allFindings.Deduplicate()
	allFindings.SortDeterministic()

	applySuppressions(allFindings, target)

	// Scan a terraform plan if provided.
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

	// Baseline matching.
	baselinePath := cfg.Policy.BaselinePath
	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(target)
	} else if !filepath.IsAbs(baselinePath) {
		baselinePath = filepath.Join(target, baselinePath)
	}
	applyBaseline(allFindings, baselinePath)

	// VEX document.
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
}

// evaluatePolicy runs the configured fail-on / baseline policy gate over the
// refined findings. It returns nil when no policy is configured. Stage 4.
func evaluatePolicy(cfg *ScanConfig, allFindings *findings.FindingSet) *policy.Result {
	if cfg.Policy.FailOn == "" && cfg.Policy.BaselineMode == "" && len(cfg.Policy.Budget) == 0 {
		return nil
	}
	var budget map[findings.Severity]int
	if len(cfg.Policy.Budget) > 0 {
		budget = make(map[findings.Severity]int, len(cfg.Policy.Budget))
		for sev, n := range cfg.Policy.Budget {
			budget[findings.Severity(sev)] = n
		}
	}
	policyCfg := policy.Config{
		FailOn:       findings.Severity(cfg.Policy.FailOn),
		WarnOn:       findings.Severity(cfg.Policy.WarnOn),
		BaselineMode: policy.BaselineMode(cfg.Policy.BaselineMode),
		Budget:       budget,
	}
	return policy.Evaluate(policyCfg, allFindings.Findings())
}

// analyzerTask runs one analyzer against the discovered artifacts. Wrapping
// each analyzer as a uniform task lets sequential and parallel execution share
// a single runner.
type analyzerTask func(context.Context) error

// runAnalyzerTasks executes tasks sequentially (deterministic, for debugging)
// or in parallel via errgroup, returning the first error and canceling
// siblings through the group context.
func runAnalyzerTasks(ctx context.Context, tasks []analyzerTask, sequential bool) error {
	if sequential {
		for _, t := range tasks {
			if err := t(ctx); err != nil {
				return err
			}
		}
		return nil
	}
	g, gctx := errgroup.WithContext(ctx)
	for _, t := range tasks {
		t := t
		g.Go(func() error { return t(gctx) })
	}
	return g.Wait()
}

// loadGHAWorkflowContent reads the contents of every artifact under
// .github/workflows/ so that the GH Actions context-aware downgrade pass
// has the full file body available when evaluating findings.
func loadGHAWorkflowContent(artifacts []discovery.Artifact) map[string][]byte {
	out := map[string][]byte{}
	for _, a := range artifacts {
		if !strings.HasPrefix(a.Path, ".github/workflows/") {
			continue
		}
		b, err := os.ReadFile(a.AbsPath)
		if err != nil {
			continue
		}
		out[a.Path] = b
	}
	return out
}

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
//
//nolint:gocritic // ScanOptions is a public API surface; passing by value keeps callers ergonomic.
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

// ConfidenceMeetsThreshold returns true if the given confidence is at or above
// the threshold confidence. Lower rank = more certain (high=0, medium=1, low=2).
// An unknown/empty threshold accepts everything so callers can pass through.
func ConfidenceMeetsThreshold(confidence, threshold findings.Confidence) bool {
	rank := map[findings.Confidence]int{
		findings.ConfidenceHigh:   0,
		findings.ConfidenceMedium: 1,
		findings.ConfidenceLow:    2,
	}
	tr, ok := rank[threshold]
	if !ok {
		return true
	}
	cr, ok := rank[confidence]
	if !ok {
		return false
	}
	return cr <= tr
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

// analyzerRulePatterns returns the rule-ID wildcard patterns owned by a named
// analyzer, used to implement the skip_analyzer action. Unknown analyzer names
// return nil so the action is a safe no-op.
func analyzerRulePatterns(analyzer string) []string {
	switch analyzer {
	case "secrets":
		return []string{"SEC-*"}
	case "ai":
		return []string{"AI-*", "MCP-*"}
	case "iac":
		return []string{"IAC-*"}
	case "data":
		return []string{"DATA-*"}
	case "deps":
		return []string{"VULN-*", "CONT-*", "LIC-*"}
	default:
		return nil
	}
}

// timeNow returns the current time. It is a variable so tests can override it.
var timeNow = time.Now
