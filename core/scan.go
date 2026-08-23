// Package core provides the shared scan pipeline for nox.
package core

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nox-hq/nox/core/analyzers/agentflow"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/data"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/analyzers/fileperms"
	"github.com/nox-hq/nox/core/analyzers/hardening"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/memsafe"
	"github.com/nox-hq/nox/core/analyzers/provenance"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/analyzers/slop"
	"github.com/nox-hq/nox/core/analyzers/slop/feed"
	"github.com/nox-hq/nox/core/analyzers/taintflow"
	"github.com/nox-hq/nox/core/analyzers/variants"
	"github.com/nox-hq/nox/core/analyzers/weakcrypto"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/degrade"
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
	// SASTProfile records the resolved per-language SAST depth applied to this
	// scan (language name → deep|standard|off). It is the auditable answer to
	// "what depth did this scan give each language?" and is copied into the
	// report meta so the decision is visible in the artifact, not just in config.
	SASTProfile map[string]string

	// Degradations lists the parts of the scan that could not run. An empty
	// slice means every configured check completed; a non-empty one means the
	// findings are incomplete and "no findings" must not be read as "clean".
	Degradations []Degradation
}

// Degradation re-exports degrade.Degradation so callers holding a ScanResult
// need not import the leaf package. It lives in its own package because
// analyzers report degradations too, and they cannot import core.
type Degradation = degrade.Degradation

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

	// BaselinePath overrides the baseline file location for suppression
	// matching. When empty, the scan uses .nox.yaml's policy.baseline_path,
	// and if that is also empty, auto-discovers .nox/baseline.json under the
	// target. The CLI --baseline flag sets this; an explicit override always
	// takes precedence over the config value.
	BaselinePath string
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
// Analyzers check ctx between artifacts, so cancellation takes effect within
// one file rather than at the end of the walk. Discovery itself is not
// interruptible: a cancelled scan still completes the directory traversal it
// had already begun.
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

	// Fail loudly on an invalid SAST depth (e.g. a typo) instead of silently
	// defaulting — a misconfigured `off` that scanned anyway would be a silent
	// security surprise.
	if err := cfg.Scan.SAST.Validate(); err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	// Fail loudly on an invalid policy gate keyword. An unrecognized fail_on
	// silently disables the gate — a capitalized "High" or a typo turns CI
	// green on critical findings — so reject it at load rather than at exit.
	if err := (policy.Config{
		FailOn:       findings.Severity(cfg.Policy.FailOn),
		WarnOn:       findings.Severity(cfg.Policy.WarnOn),
		BaselineMode: policy.BaselineMode(cfg.Policy.BaselineMode),
		Budget:       policyBudget(cfg.Policy.Budget),
	}).Validate(); err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	// Reject an unrecognized severity in a severity override, for the same
	// reason an unrecognized fail_on is rejected above — and one sharper.
	//
	// An override is cast straight to a findings.Severity. A capitalized
	// "Critical" therefore does not RAISE the rule; it stamps the finding with a
	// severity nothing can rank, and a finding nox cannot rank used to satisfy
	// no gate at all. Evaluate now fails closed on that, but the override still
	// silently fails to do what the operator asked, so reject it at load where
	// the typo is visible.
	for ruleID, sev := range cfg.Scan.Rules.SeverityOverride {
		if !findings.Severity(sev).IsValid() {
			return nil, fmt.Errorf("loading config: scan.rules.severity_override[%s]: %q is not a severity "+
				"(want critical, high, medium, low, or info)", ruleID, sev)
		}
	}
	for i, cs := range cfg.Scan.ConditionalSeverity {
		if !findings.Severity(cs.Severity).IsValid() {
			return nil, fmt.Errorf("loading config: scan.conditional_severity[%d]: %q is not a severity "+
				"(want critical, high, medium, low, or info)", i, cs.Severity)
		}
	}

	// Stage 1: Discover artifacts.
	artifacts, err := discoverArtifacts(target, cfg, opts)
	if err != nil {
		return nil, err
	}

	// Apply the per-language SAST profile: source files of a language set to
	// "off" are dropped here, before any analyzer sees them, so they contribute
	// no findings. Non-source artifacts always pass through. This runs on the
	// discovered set (deterministic, input order preserved).
	artifacts = FilterArtifactsByLanguageProfile(artifacts, cfg.Scan.SAST)

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
	// degradations collects checks that could not complete. Analyzers write to
	// it concurrently; it is surfaced on ScanResult so "no findings" can be
	// distinguished from "did not look".
	degradations := &degrade.Degradations{}
	// The AI analyzer surfaces MCP/agent config parse failures hit while building
	// the tool permission matrix, so a broken config is a visible degradation
	// rather than a silently-empty (or all-tools-defaulted) matrix.
	aiAnalyzer := ai.NewAnalyzer(ai.WithDegradations(degradations))

	depsOpts := []deps.AnalyzerOption{deps.WithDegradations(degradations)}
	if opts.Offline || opts.DisableOSV || cfg.Scan.OSV.Disabled {
		depsOpts = append(depsOpts, deps.WithOSVDisabled())
	}
	// Wire the project's license policy through. Without this, license.deny /
	// license.allow in .nox.yaml parsed cleanly and then produced no LIC-*
	// findings at all — configured policy that silently did nothing.
	if len(cfg.License.Deny) > 0 || len(cfg.License.Allow) > 0 {
		depsOpts = append(depsOpts, deps.WithLicensePolicy(deps.LicensePolicy{
			Deny:  cfg.License.Deny,
			Allow: cfg.License.Allow,
		}))
	}
	depsAnalyzer := deps.NewAnalyzer(depsOpts...)
	// The SLOP analyzer gains a predictive dimension only when a feed is
	// configured (default: off, exact reactive behavior preserved). Loading is
	// offline: a file read plus digest/signature verification, no network. A
	// misconfigured or tampered feed fails closed — the predictive dimension
	// stays off and the failure is recorded as a visible degradation.
	var slopOpts []slop.Option
	if fp := cfg.Scan.Slop.Feed; fp != "" {
		if loaded, ferr := loadSlopFeed(ctx, target, cfg.Scan.Slop, opts.Offline); ferr != nil {
			degradations.Add(degrade.SlopFeed,
				fmt.Sprintf("predictive slopsquat feed %q could not be loaded: %v", fp, ferr),
				"the SLOP-002 predictive dimension is disabled; high-risk slopsquat targets are not being flagged from the feed")
		} else {
			slopOpts = append(slopOpts, slop.WithFeed(loaded))
		}
	}
	slopAnalyzer := slop.NewAnalyzer(slopOpts...)
	cryptoAnalyzer := weakcrypto.NewAnalyzer()
	filepermsAnalyzer := fileperms.NewAnalyzer()
	hardeningAnalyzer := hardening.NewAnalyzer()
	memsafeAnalyzer := memsafe.NewAnalyzer()
	variantsAnalyzer := variants.NewAnalyzer()
	// A signature database that fails to parse leaves every VARIANT-* rule
	// unable to match. The scan would otherwise report zero variant findings
	// and look clean.
	if err := variantsAnalyzer.LoadErr(); err != nil {
		degradations.Add(degrade.VulnData,
			fmt.Sprintf("CVE-variant signatures could not be loaded: %v", err),
			"no VARIANT-* detection ran; known CVE variants in this codebase would not be reported")
	}
	taintflowAnalyzer := taintflow.NewAnalyzer()
	agentflowAnalyzer := agentflow.NewAnalyzer()
	provenanceAnalyzer := provenance.NewAnalyzer()

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
		func(c context.Context) error {
			fs, err := cryptoAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := filepermsAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := hardeningAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := memsafeAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := slopAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := variantsAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := taintflowAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := agentflowAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
			return nil
		},
		func(c context.Context) error {
			fs, err := provenanceAnalyzer.ScanArtifacts(c, artifacts)
			if err != nil {
				return err
			}
			addFindings(fs)
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
	for _, r := range cryptoAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range filepermsAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range hardeningAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range memsafeAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range slopAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range variantsAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range taintflowAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range agentflowAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}
	for _, r := range provenanceAnalyzer.Rules().Rules() {
		allRules.Add(r)
	}

	// Phase 2b: Load and merge custom rules (CLI flag > config > none).
	customPath := opts.CustomRulesPath
	if customPath == "" {
		customPath = cfg.Scan.RulesDir
	}
	if customPath != "" {
		if !filepath.IsAbs(customPath) {
			customPath = filepath.Join(ConfigRoot(target), customPath)
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

	// Phase 2c: Run installed analysis plugins (taint, SAST, …) and merge their
	// findings in BEFORE refinement,
	// so plugin findings are fingerprinted and baseline-matched like any other.
	// The hook is nil unless the CLI registered it (avoids a core→plugin import
	// cycle). Plugin failures are non-fatal — the built-in scan still completes.
	var pluginEnrichments []findings.Enrichment
	var pluginGraphs []graph.Graph
	if ScanPluginHook != nil {
		out, hookErr := ScanPluginHook(ctx, target, cfg.Plugins.Required)
		if hookErr != nil {
			slog.WarnContext(ctx, "analysis plugins failed; continuing with built-in findings only", "error", hookErr)
			// A required detector that fails silently is the worst outcome for
			// a security scanner: the build stays green precisely because the
			// check that would have failed it never ran.
			degradations.Add(degrade.Plugin,
				fmt.Sprintf("required analysis plugins %v did not run: %v", cfg.Plugins.Required, hookErr),
				"findings these plugins would have produced are missing from this scan")
		}
		if out != nil {
			kept, dropped := filterPluginFindingsByExclude(out.Findings, target, cfg.Scan.Exclude)
			for i := range kept {
				allFindings.Add(kept[i])
			}
			if dropped > 0 {
				slog.DebugContext(ctx, "plugin findings dropped by scan.exclude",
					"dropped", dropped, "kept", len(kept))
			}
			pluginEnrichments = out.Enrichments
			pluginGraphs = out.Graphs
			for _, d := range out.Degradations {
				degradations.Add(d.Kind, d.Detail, d.Impact)
			}
		}
	}

	// Post-scan (context) plugins — e.g. reachability — need the findings the
	// scan just produced, so they run here, after the built-in analyzers and
	// the scan-tool plugins but before refinement, so their findings and
	// enrichments are deduped, suppressed, and policy-gated like any other.
	if PostScanPluginHook != nil {
		postResult := &ScanResult{Findings: allFindings, Inventory: inventory, AIInventory: aiInventory}
		if hookErr := PostScanPluginHook(ctx, postResult, target, cfg.Plugins.Required); hookErr != nil {
			slog.WarnContext(ctx, "post-scan plugins failed; continuing with findings so far", "error", hookErr)
			// Post-scan plugins annotate rather than detect — reachability
			// classification, most importantly. Their failure leaves findings
			// present but stripped of the signal operators triage on, which
			// looks like a normal scan.
			degradations.Add(degrade.Plugin,
				fmt.Sprintf("post-scan plugins %v did not run: %v", cfg.Plugins.Required, hookErr),
				"findings are missing enrichment such as reachability classification; triage priority is unreliable")
		}
		pluginEnrichments = append(pluginEnrichments, postResult.Enrichments...)
	}

	// Relational MCP pass: server/tool shadowing (MCP-023/024) and rug-pull
	// drift (MCP-015) require the full multi-config set, so they run outside the
	// per-file regex engine — like the agentflow and plugin passes — and merge
	// in before refinement, so their findings are deduped, suppressed, and
	// policy-gated like any other. Non-fatal per file.
	runMCPRelationalPass(ctx, target, artifacts, allFindings, degradations)

	// Stage 3: Refine findings — apply rule config, generated/noise filters,
	// conditional severity, dedup, inline suppressions, terraform plan,
	// baseline matching, and VEX.
	// Every file the scan looked at, so waivers in files that produced no
	// finding are still checked for deadness.
	scannedPaths := make([]string, 0, len(artifacts))
	for i := range artifacts {
		scannedPaths = append(scannedPaths, artifacts[i].Path)
	}
	if err := refineFindings(allFindings, cfg, opts, target, degradations, scannedPaths); err != nil {
		return nil, err
	}

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
		Degradations: degradations.Items(),
		SASTProfile:  cfg.Scan.SAST.ResolvedProfile(),
	}, nil
}

// loadSlopFeed resolves and verifies the predictive slopsquat feed named in the
// config. The value selects the source:
//   - "bundled"         — the feed embedded in the binary
//   - an http(s):// URL — a remotely published feed, fetched over the network,
//     verified (digest + signature), and cached locally so later scans are
//     offline and deterministic
//   - any other value   — a file path resolved relative to the scan root
//
// Verification fails closed everywhere: a digest mismatch, decode error, unmet
// signature requirement, fetch failure with no usable cache, or (offline) a
// missing cache returns an error, and the caller disables the predictive
// dimension and records a degradation rather than trusting the feed. When
// offline is set, a URL feed never touches the network — it is served from the
// verified cache or the load fails closed.
func loadSlopFeed(ctx context.Context, target string, cfg SlopConfig, offline bool) (*feed.Loaded, error) {
	opts := feed.VerifyOptions{RequireSignature: cfg.RequireSignature}
	if cfg.SignatureKeyPath != "" {
		keyPath := cfg.SignatureKeyPath
		if !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(scanRootDir(target), keyPath)
		}
		pem, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("reading signature key %s: %w", keyPath, err)
		}
		verifier, err := feed.PEMEd25519Verifier(pem)
		if err != nil {
			return nil, fmt.Errorf("parsing signature key: %w", err)
		}
		opts.Verifier = verifier
	}

	if cfg.Feed == "bundled" {
		loaded, err := feed.Bundled()
		if err != nil {
			return nil, err
		}
		// A signature requirement cannot be met by the unsigned bundled feed;
		// surface that clearly rather than silently ignoring the requirement.
		if cfg.RequireSignature {
			return nil, fmt.Errorf("the bundled feed is unsigned but require_signature is set")
		}
		return loaded, nil
	}

	if isRemoteFeed(cfg.Feed) {
		ttl := feed.DefaultRefreshInterval
		if cfg.Refresh != "" {
			parsed, err := parseFeedRefresh(cfg.Refresh)
			if err != nil {
				return nil, fmt.Errorf("parsing slop.refresh %q: %w", cfg.Refresh, err)
			}
			ttl = parsed
		}
		cacheDir := cfg.CacheDir
		if cacheDir != "" && !filepath.IsAbs(cacheDir) {
			cacheDir = filepath.Join(scanRootDir(target), cacheDir)
		}
		return feed.LoadRemote(ctx, feed.RemoteOptions{
			URL:      cfg.Feed,
			CacheDir: cacheDir,
			TTL:      ttl,
			Offline:  offline,
			Verify:   opts,
		})
	}

	path := cfg.Feed
	if !filepath.IsAbs(path) {
		path = filepath.Join(scanRootDir(target), path)
	}
	return feed.Load(path, opts)
}

// isRemoteFeed reports whether a feed value names a remotely fetched feed rather
// than a local path or the bundled feed.
func isRemoteFeed(v string) bool {
	return strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://")
}

// parseFeedRefresh parses a refresh interval: a standard Go duration, or a
// bare "<n>d" days form (which time.ParseDuration does not accept). It matches
// the "7d"/"24h" style used elsewhere in .nox.yaml.
func parseFeedRefresh(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil {
			return 0, fmt.Errorf("invalid days value %q", s)
		}
		if days < 0 {
			return 0, fmt.Errorf("negative refresh interval %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// scanRootDir returns the directory a relative config path is resolved against:
// the target itself when it is a directory, or its parent when it is a file.
func scanRootDir(target string) string {
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		return filepath.Dir(target)
	}
	return target
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
	// submodule contents (gitlinks, not listed) are excluded.
	//
	// A git failure here is a hard error, not a fallback. The previous
	// best-effort skip left the allow-list empty, which the walker treats as
	// "no restriction" — so --tracked-only silently INVERTED to scanning the
	// entire working tree, including the untracked and generated files the flag
	// exists to keep out. An operator using it to bound a CI or pre-commit scan
	// got the opposite of what they asked for, with no signal. As with --vex and
	// --terraform-plan, an explicit request that cannot be honoured must fail.
	if opts.TrackedOnly {
		tracked, err := git.TrackedFiles(target)
		if err != nil {
			return nil, fmt.Errorf("--tracked-only requires a git repository: %w", err)
		}
		walker.IncludePaths = make(map[string]bool, len(tracked))
		for _, f := range tracked {
			walker.IncludePaths[f] = true
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
func refineFindings(allFindings *findings.FindingSet, cfg *ScanConfig, opts ScanOptions, target string, deg *degrade.Degradations, scanned []string) error {
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

	// Context-gated SAST severity: downgrade code-pattern findings located in
	// non-production trees (tests, examples, docs, vendored/generated/minified
	// code) by one level. The deterministic, path-based analogue of Snyk's
	// reachability gating — the same finding is far less actionable in throwaway
	// code than in shipping source. Scoped to code-pattern families only (never
	// SEC-*/VULN-*/CONT-*/LIC-, see ContextDowngradeRulePatterns) and gated by
	// scan.context_downgrade (default on). Runs before dedup/sort; it changes
	// only Severity + audit Metadata, never fingerprints or ordering, so byte
	// output stays stable apart from the intended severity change. It also runs
	// AFTER user conditional_severity so an explicit override is the source of
	// truth and is never silently re-downgraded (that override wins).
	if cfg.Scan.ContextDowngradeEnabled() {
		globs := NonProductionPathGlobs()
		allFindings.DowngradeByRulePatternsAndPath(
			ContextDowngradeRulePatterns(),
			func(p string) bool { return MatchesNonProductionPath(p, globs) },
			"non-production",
		)
	}

	// Collapse one dataflow reported from both ends. The built-in taint model
	// anchors a flow at its sink; the taint-analysis plugin anchors the same
	// flow at its source. Neither the fingerprint nor the location matches, so
	// one vulnerability survives as two findings and two baseline entries.
	// Runs before the class suppression below, which is location-keyed and
	// would otherwise be comparing against the wrong end of the flow.
	allFindings.DeduplicateFlows()

	// Drop a taint finding when another analyzer already reports the same vuln
	// class at the same location — e.g. the taint engine's TAINT-003 SSTI sink
	// firing on a render_template_string call that a variants CVE signature
	// (VARIANT-005) already covers. Keeps the more specific signature; reports
	// the vulnerability once instead of twice.
	allFindings.SuppressDuplicateVulnClass("TAINT-")

	allFindings.Deduplicate()
	allFindings.SortDeterministic()

	applySuppressions(allFindings, target, deg, scanned)

	// Scan a terraform plan if provided. A plan path is only ever set because
	// the operator asked for it, so a plan that cannot be read or parsed is an
	// error: silently scanning nothing while reporting success would let a
	// typo'd path masquerade as a clean infrastructure review.
	if opts.TerraformPlanPath != "" {
		tfPlanPath := opts.TerraformPlanPath
		if !filepath.IsAbs(tfPlanPath) {
			tfPlanPath = filepath.Join(ConfigRoot(target), tfPlanPath)
		}
		tfFindings, tfErr := iac.ScanTerraformPlan(tfPlanPath)
		if tfErr != nil {
			return fmt.Errorf("scanning terraform plan %s: %w", opts.TerraformPlanPath, tfErr)
		}
		if tfFindings != nil {
			tfItems := tfFindings.Findings()
			for i := range tfItems {
				allFindings.Add(tfItems[i])
			}
		}
	}

	// Baseline matching. An explicit --baseline override (opts.BaselinePath)
	// wins over .nox.yaml's policy.baseline_path; when neither is set the
	// baseline is auto-discovered at .nox/baseline.json under the target.
	baselinePath := opts.BaselinePath
	if baselinePath == "" {
		baselinePath = cfg.Policy.BaselinePath
	}
	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(ConfigRoot(target))
	} else if !filepath.IsAbs(baselinePath) {
		baselinePath = filepath.Join(ConfigRoot(target), baselinePath)
	}
	applyBaseline(allFindings, baselinePath, deg)

	// VEX document.
	vexPath := opts.VEXPath
	if vexPath == "" {
		vexPath = cfg.Policy.VEXPath
	}
	// As with the terraform plan, the path is explicit — from a flag or from
	// .nox.yaml — so failing to load it is an error rather than a silent no-op
	// that would leave every waiver unapplied.
	if vexPath != "" {
		if !filepath.IsAbs(vexPath) {
			vexPath = filepath.Join(ConfigRoot(target), vexPath)
		}
		vexDoc, vexErr := vex.LoadVEX(vexPath)
		if vexErr != nil {
			return fmt.Errorf("loading VEX document %s: %w", vexPath, vexErr)
		}
		vex.ApplyVEX(allFindings, vexDoc)
	}

	return nil
}

// evaluatePolicy runs the configured fail-on / baseline policy gate over the
// refined findings. It returns nil when no policy is configured. Stage 4.
func evaluatePolicy(cfg *ScanConfig, allFindings *findings.FindingSet) *policy.Result {
	if cfg.Policy.FailOn == "" && cfg.Policy.BaselineMode == "" && len(cfg.Policy.Budget) == 0 {
		return nil
	}
	policyCfg := policy.Config{
		FailOn:       findings.Severity(cfg.Policy.FailOn),
		WarnOn:       findings.Severity(cfg.Policy.WarnOn),
		BaselineMode: policy.BaselineMode(cfg.Policy.BaselineMode),
		Budget:       policyBudget(cfg.Policy.Budget),
	}
	return policy.Evaluate(policyCfg, allFindings.Findings())
}

// policyBudget converts the string-keyed budget from config into the
// severity-keyed map the policy package expects.
func policyBudget(in map[string]int) map[findings.Severity]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[findings.Severity]int, len(in))
	for sev, n := range in {
		out[findings.Severity(sev)] = n
	}
	return out
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
	// opts is threaded through deliberately: this previously called
	// RunScan(tmpDir) and dropped every option, so --rules, --offline, --vex and
	// friends were silently ignored whenever --staged was used.
	//
	// ChangedSince is cleared because the temp directory is not a git
	// repository — a staged scan already IS a changed-files scan, and leaving
	// the ref set would make discovery fail.
	//
	// TrackedOnly is cleared for the same reason, and it costs nothing: the
	// staged set is by definition a subset of the tracked set, so the flag's
	// guarantee already holds. Leaving it set would make --staged --tracked-only
	// fail with "requires a git repository", which is true of the temp directory
	// and false of what the operator asked for.
	stagedOpts := opts
	stagedOpts.ChangedSince = ""
	stagedOpts.TrackedOnly = false

	result, err := RunScanWithOptions(tmpDir, stagedOpts)
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
	scanRules := secretsAnalyzer.Rules()
	for _, r := range scanRules.Rules() {
		allRules.Add(r)
	}

	// Honour --rules here too. HistoryScanOptions carried a ScanOptions field
	// that nothing ever read, so custom rules were silently dropped for
	// --history scans — the flag appeared to work and quietly did nothing.
	if path := opts.ScanOptions.CustomRulesPath; path != "" {
		if !filepath.IsAbs(path) {
			path = filepath.Join(repoRoot, path)
		}
		customRules, err := loadCustomRules(path)
		if err != nil {
			return nil, fmt.Errorf("loading custom rules: %w", err)
		}
		for _, r := range customRules.Rules() {
			if scanRules.HasID(r.ID) {
				return nil, fmt.Errorf("custom rule %s conflicts with a built-in rule ID", r.ID)
			}
			scanRules.Add(r)
			allRules.Add(r)
		}
	}

	engine := rules.NewEngine(scanRules)

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

// filterPluginFindingsByExclude drops plugin findings whose path matches the
// scan's `scan.exclude` patterns, returning the survivors and the drop count.
//
// A plugin's `scan` tool walks the workspace root itself and is handed only
// workspace_root, so it never sees `scan.exclude`. That made any required
// analysis plugin re-surface exactly the files the operator excluded: on nox's
// own repo, requiring the code-analysis plugins took a clean grade-A self-scan
// (3 findings) to grade F (47), and 38 of those 47 were on excluded paths —
// principally the intentionally-vulnerable fixture corpora
// (testdata/precision-suite, testdata/metamorphic-corpus) that exist to be
// found by the precision and metamorphic harnesses, not by the self-scan.
//
// The boundary is enforced here, host-side, rather than by passing the patterns
// down: a plugin is third-party code and cannot be relied on to honour an
// exclusion it is merely told about. Filtering through the same
// discovery.IsIgnored matcher the walker uses means "excluded" means the same
// thing no matter which analyzer produced the finding.
//
// Paths are made relative to the scan root before matching, since patterns like
// "testdata/" are written relative to the repository while plugins commonly
// report absolute paths. A finding with no path is repository-scoped and is
// never excluded — there is no path for a pattern to match.
func filterPluginFindingsByExclude(in []findings.Finding, target string, patterns []string) (kept []findings.Finding, dropped int) {
	if len(in) == 0 {
		return in, 0
	}

	// The root must be absolute to be comparable: plugins report absolute
	// paths (they are handed an absolute workspace_root), while the target is
	// commonly ".". filepath.Rel refuses to relate a relative base to an
	// absolute path, so a relative root left every plugin path absolute and no
	// root-relative pattern could ever match it.
	root := ConfigRoot(target)
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	kept = make([]findings.Finding, 0, len(in))
	for i := range in {
		p := in[i].Location.FilePath
		if p == "" {
			kept = append(kept, in[i])
			continue
		}
		rel := p
		if filepath.IsAbs(rel) {
			if r, err := filepath.Rel(root, rel); err == nil {
				rel = r
			}
		}
		rel = filepath.ToSlash(rel)
		// The finding names the scan root itself: it is repository-scoped, not
		// located in a file (nox/depconfusion's DEPCONF-002, "no private
		// registry config for this ecosystem", is a property of the repo). The
		// empty path is the canonical spelling for that — the suppression pass
		// already reads it as "repository-scoped rather than located" — and it
		// keeps the absolute machine path out of the v2 fingerprint, which
		// otherwise made such a finding unbaselineable anywhere but the machine
		// that produced it.
		if rel == "." {
			f := in[i]
			f.Location.FilePath = ""
			kept = append(kept, f)
			continue
		}
		// A path outside the scan root cannot be described by a root-relative
		// pattern, and is not ours to rewrite; keep it as reported.
		if strings.HasPrefix(rel, "../") {
			kept = append(kept, in[i])
			continue
		}
		if len(patterns) > 0 && discovery.IsIgnored(rel, patterns) {
			dropped++
			continue
		}
		// Record the finding against the same root-relative path convention
		// core findings use. Left absolute, the same physical file appeared
		// under two spellings: the unused-waiver check (which groups by path)
		// then tested every waiver in the file against only one group's
		// findings and reported live waivers as dead, and the v2 fingerprint
		// hashed a machine-specific absolute path so no baseline could match
		// across machines.
		f := in[i]
		f.Location.FilePath = rel
		kept = append(kept, f)
	}
	return kept, dropped
}

// ConfigRoot returns the directory that paths relative to a scan target
// resolve against — the baseline, the VEX document, custom rules, a Terraform
// plan, and the source files findings point at.
//
// A target may be a single file (`nox scan main.go`), and joining a relative
// path onto a file path yields main.go/.nox/baseline.json, which cannot exist.
// Every such lookup then failed: the baseline was reported unloadable, and the
// file could not be re-read to apply its nox:ignore comments — so a single-file
// scan silently reported findings the operator had waived. Resolving against
// the file's directory is both what the operator means and what the rest of the
// scan already assumes: for a file target, finding paths are recorded relative
// to that same directory.
//
// A target that cannot be stat'd is returned unchanged, leaving the caller's
// existing error handling to report it rather than guessing here.
func ConfigRoot(target string) string {
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		return filepath.Dir(target)
	}
	return target
}

// sweepWaiversInCleanFiles reports waivers in files that produced no finding.
//
// The unused-waiver check is driven by findings grouped by path, so it only
// ever examined files that already had one. A waiver in an otherwise-clean
// file was invisible — and that is exactly where a dead waiver is most likely
// to hide, since the usual way one dies is the finding it covered getting
// fixed. The gap surfaced by accident: enabling analysis plugins spread
// findings across many more files and five dead waivers in nox's own source
// appeared at once, purely because those files now had some unrelated finding.
// Whether a waiver is reported must not depend on whether something else in
// the same file happened to fire.
//
// Every waiver found here is by definition unused: the file produced no
// finding for it to suppress. Expired and doc-example directives are excluded
// on the same grounds as the main path.
func sweepWaiversInCleanFiles(byFile map[string][]int, target string, deg *degrade.Degradations, scanned []string) {
	if len(scanned) == 0 {
		return
	}
	root := ConfigRoot(target)
	for _, rel := range scanned {
		if _, hasFindings := byFile[rel]; hasFindings {
			continue // already evaluated against its own findings
		}
		fullPath := rel
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(root, fullPath)
		}
		content, err := os.ReadFile(fullPath)
		if err != nil {
			// A file the scan just read that cannot be read now is not worth a
			// degradation of its own: it produced no findings, so no waiver of
			// the operator's is going unapplied.
			continue
		}
		// Cheap reject before parsing: the directive keyword must appear at all.
		if !bytes.Contains(content, []byte("nox:")) {
			continue
		}
		for _, s := range suppress.ScanForSuppressions(content, rel) {
			if s.DocExample || s.InvalidExpiry != "" {
				continue
			}
			if s.Expires != nil && timeNow().After(*s.Expires) {
				continue
			}
			deg.Add(degrade.Suppression,
				fmt.Sprintf("%s:%d waives %s but matched no finding",
					rel, s.Line, strings.Join(s.RuleIDs, ",")),
				"this waiver is not suppressing anything — the finding it covered may have been fixed, "+
					"in which case remove the waiver; otherwise check the rule ID and that a dedicated "+
					"nox:ignore comment sits on the line directly above the code")
		}
	}
}

// suppressionCovers reports whether an inline directive waives a finding,
// under the finding's own rule ID or under a retired ID it inherited.
//
// The retired-ID leg is what keeps `# nox:ignore IAC-310` working after
// IAC-310 was retired into IAC-018: the comment names an ID the scanner no
// longer emits, and without this the waived finding would come back reported
// under the surviving ID. See findings.Finding.RetiredRuleIDs.
func suppressionCovers(s suppress.Suppression, f *findings.Finding) bool {
	now := timeNow()
	if s.MatchesFinding(f.RuleID, f.Location.StartLine, now) {
		return true
	}
	for _, id := range f.RetiredRuleIDs {
		if s.MatchesFinding(id, f.Location.StartLine, now) {
			return true
		}
	}
	return false
}

// applySuppressions reads files that have findings and marks suppressed
// findings. scanned lists every file the scan looked at, so waivers in files
// that produced no finding are still checked — see sweepWaiversInCleanFiles.
func applySuppressions(fs *findings.FindingSet, target string, deg *degrade.Degradations, scanned []string) {
	// Group findings by file.
	byFile := make(map[string][]int)
	items := fs.Findings()
	for i := range items {
		byFile[items[i].Location.FilePath] = append(byFile[items[i].Location.FilePath], i)
	}

	defer sweepWaiversInCleanFiles(byFile, target, deg, scanned)

	for filePath, indices := range byFile {
		// A finding with no file path has no file to read suppressions from —
		// dependency and plugin findings are often repository-scoped rather
		// than located. Joining "" to the target yields the target directory,
		// whose read fails, which then reported a degradation on a perfectly
		// healthy scan. Nothing was missed here, so nothing is reported.
		if filePath == "" {
			continue
		}

		fullPath := filePath
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(ConfigRoot(target), fullPath)
		}

		// The same reasoning as the empty path above, one step further: a
		// repository-scoped finding may name the workspace root itself rather
		// than a file. nox/depconfusion's DEPCONF-002 ("no private registry
		// config for the npm ecosystem") is a property of the repository, not
		// of any one file, so it reports the root — and reading a directory
		// failed, degrading a perfectly healthy scan. A directory holds no
		// nox:ignore comments, so nothing was missed and nothing is reported.
		if fi, statErr := os.Stat(fullPath); statErr == nil && fi.IsDir() {
			continue
		}

		content, err := os.ReadFile(fullPath)
		if err != nil {
			// Fails safe — findings stay reported rather than being wrongly
			// suppressed — but the operator's nox:ignore comments in this file
			// are not being honoured, which is surprising enough to surface.
			deg.Add(degrade.Suppression,
				fmt.Sprintf("%s could not be re-read to apply inline suppressions: %v", filePath, err),
				"nox:ignore comments in this file were not applied; its findings may be reported despite being waived")
			continue
		}

		suppressions := suppress.ScanForSuppressions(content, filePath)

		// A waiver whose expiry date will not parse is not applied — see
		// Suppression.InvalidExpiry. Say so, or the operator sees an
		// unexplained finding they believe they waived.
		for i := range suppressions {
			if suppressions[i].InvalidExpiry == "" {
				continue
			}
			deg.Add(degrade.Suppression,
				fmt.Sprintf("%s:%d has an unparseable expiry date %q (expected YYYY-MM-DD)",
					filePath, suppressions[i].Line, suppressions[i].InvalidExpiry),
				"this waiver was NOT applied and its findings are reported; fix the date to restore it")
		}
		if len(suppressions) == 0 {
			continue
		}

		items := fs.Findings()
		// Every matching suppression is marked used, not just the first: two
		// waivers may legitimately cover the same finding, and breaking early
		// would report the second as unused below.
		used := make([]bool, len(suppressions))
		for _, idx := range indices {
			f := items[idx]
			suppressed := false
			for si := range suppressions {
				if suppressionCovers(suppressions[si], &f) {
					used[si] = true
					suppressed = true
				}
			}
			if suppressed {
				fs.SetStatus(idx, findings.StatusSuppressed)
			}
		}

		// A waiver that suppressed nothing is reported. The operator believes a
		// finding is waived when it is not, and nothing else says otherwise.
		//
		// The common cause is a dedicated directive whose reason wrapped onto a
		// second comment line: the directive applies to the next non-blank line,
		// so it lands on the continuation comment and the code below stays
		// reported. A mistyped rule ID and a waiver left behind after the finding
		// was fixed produce the same silence.
		//
		// An unparseable expiry is already reported above; do not say it twice.
		// A correctly-parsed EXPIRED waiver is also excluded: it is meant to stop
		// applying, so its findings returning is the feature working, not a
		// mistake to warn about.
		for si := range suppressions {
			if used[si] || suppressions[si].InvalidExpiry != "" {
				continue
			}
			if suppressions[si].Expires != nil && timeNow().After(*suppressions[si].Expires) {
				continue
			}
			// A directive inside a fenced code block in markdown is documentation
			// showing the syntax, not a waiver anyone expects to apply — reporting
			// it as unused is pure noise. nox's own README trips this.
			if suppressions[si].DocExample {
				continue
			}
			deg.Add(degrade.Suppression,
				fmt.Sprintf("%s:%d waives %s but matched no finding",
					filePath, suppressions[si].Line, strings.Join(suppressions[si].RuleIDs, ",")),
				"this waiver is not suppressing anything — check the rule ID, whether the finding moved, "+
					"and that a dedicated nox:ignore comment sits on the line directly above the code (a reason "+
					"wrapped onto a second comment line takes the waiver with it)")
		}
	}
}

// applyBaseline loads a baseline file and marks matched findings.
func applyBaseline(fs *findings.FindingSet, baselinePath string, deg *degrade.Degradations) {
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		// No baseline is the normal state before the first `nox baseline write`,
		// so absence is silent. A baseline that exists but will not load is
		// different: under baseline_mode it changes what the gate enforces, so
		// it must not pass unnoticed.
		if !os.IsNotExist(err) {
			deg.Add(degrade.Baseline,
				fmt.Sprintf("%s could not be loaded: %v", baselinePath, err),
				"findings are not being classified against the baseline; known-vs-new status is unreliable")
		}
		return
	}
	if bl.Len() == 0 {
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
	case "slop":
		return []string{"SLOP-*"}
	case "variants":
		return []string{"VARIANT-*"}
	case "taintflow":
		return []string{"TAINT-*"}
	case "agentflow":
		return []string{"AGENTFLOW-*"}
	case "provenance":
		return []string{"PROV-*"}
	default:
		return nil
	}
}

// timeNow returns the current time. It is a variable so tests can override it.
var timeNow = time.Now
