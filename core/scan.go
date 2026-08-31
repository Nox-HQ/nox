// Package core provides the shared scan pipeline for nox.
package core

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox-core/vulnsource"
	osvsource "github.com/nox-hq/nox-core/vulnsource/osv"
	"github.com/nox-hq/nox/core/adjudicate"
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
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/graph"
	"github.com/nox-hq/nox/core/intel"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/policy"
	"github.com/nox-hq/nox/core/reach"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/replay"
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

	// Capabilities is what this installation can establish at all, and
	// Coverage is what each capability actually concluded about each subject.
	//
	// Both are populated on every scan, including one that did not record
	// reasoning, because "what could nox not tell you?" is answerable without
	// any evidence being collected and is worth answering unconditionally. A
	// capability nothing provides is a limit; one that is provided and said
	// nothing is a gap; and neither is a clearance.
	Capabilities *capability.Registry
	Coverage     *capability.Coverage

	// Reasoning holds the claims for and against each candidate this scan
	// considered: why a finding was reported, and why a dropped one was not.
	//
	// It is nil unless ScanOptions.RecordReasoning was set, and it is held
	// beside the findings rather than on them. Both facts come from
	// docs/benchmarks/2026-Q3/ledger-budget.md: a three-claim ledger carried
	// inline on every Finding projects to 6.62 GiB against 3.48 GiB bare on the
	// largest project nox has scanned, which is past what an ordinary CI runner
	// has. A nil store is free, so a scan that did not ask for reasoning pays
	// nothing for the option existing.
	//
	// A finding's subject is derived from the finding, not stored on it — see
	// SubjectForFinding — so the reference costs zero bytes per finding.
	Reasoning *reasoning.Store

	// Divergences lists the findings whose analyzer-authored confidence
	// disagrees with what their evidence supports. Empty unless the scan
	// recorded reasoning.
	//
	// This is the measurement C5 needs before analyzer-authored confidence can
	// be retired. Retiring it because evidence "should" be better is a bet;
	// retiring it having counted where the two disagree, and in which
	// direction, is a decision.
	Divergences []adjudicate.Divergence

	// Conflicts lists the findings whose evidence contradicts itself at equal
	// strength. Empty unless the scan recorded reasoning.
	//
	// Reported, never resolved. Picking a winner silently is the behaviour the
	// evidence spine exists to replace, so a disagreement between two producers
	// about one subject is surfaced for a person to look at.
	//
	// Empty on every committed corpus today, and structurally so rather than by
	// luck — see adjudicate.Conflict for why, and for what makes it reachable.
	Conflicts []adjudicate.Conflict
}

// EvidenceArtifact assembles the replayable record of what this scan
// established: input identity, capability state, claims and their provenance,
// relationships, and the adjudicated verdicts.
//
// It is built on request rather than always. A scan that did not ask pays
// nothing, which is the same reasoning that put the ledger out-of-band in the
// first place — see ScanResult.Reasoning.
//
// A scan that did not record reasoning still produces a valid artifact: it has
// capability state and findings, and no evidence. Replay then reports that
// nothing was checked, rather than that everything reproduced.
func (r *ScanResult) EvidenceArtifact(in replay.Inputs) *replay.Artifact {
	if in.FingerprintVersion == 0 {
		in.FingerprintVersion = int(findings.GetFingerprintVersion())
	}
	var fs []findings.Finding
	if r.Findings != nil {
		fs = r.Findings.Findings()
	}
	return replay.Build(in, r.Reasoning, r.Coverage, r.Capabilities, fs, SubjectForFinding)
}

// SubjectForFinding returns the evidence subject a finding's claims are filed
// against.
//
// It is computed rather than stored, which is what keeps the out-of-band ledger
// free at the Finding's expense: no field, no pointer, no allocation. It also
// means a candidate that was REFUTED and one that survived resolve to the same
// subject, so the claims for and against one match land in one ledger instead
// of two that nothing relates.
func SubjectForFinding(f findings.Finding) evidence.Subject {
	return reasoning.Candidate(f.RuleID, f.Location.FilePath,
		f.Location.StartLine, f.Location.StartColumn)
}

// Degradation re-exports degrade.Degradation so callers holding a ScanResult
// need not import the leaf package. It lives in its own package because
// analyzers report degradations too, and they cannot import core.
type Degradation = degrade.Degradation

// ScanOptions holds optional parameters for RunScanWithOptions. The zero
// value means no additional options are applied.
type ScanOptions struct {
	// ContributeObservations permits this scan to send observations to a
	// configured intelligence service.
	//
	// Deriving observations is pure computation; transmitting them is not, and
	// a transmission that happens as a side effect of "run a scan" is one that
	// happens in places nobody intended. It fired from `nox intel preview` —
	// the command whose entire purpose is to show what WOULD be sent without
	// sending it — and would have fired from `nox diff`, which scans a target
	// twice.
	//
	// So the default for every caller is silence, and the one command a user
	// invokes to scan-and-contribute opts in explicitly. The config gate is a
	// second, independent condition: both must be set.
	ContributeObservations bool

	// ToolVersion identifies the build performing the scan. It is recorded on
	// contributed observations so a claim can be traced back to the code that
	// made it. Empty is acceptable — the field is optional on the wire — but an
	// unattributable claim is worth less to whoever has to assess it.
	ToolVersion string

	// CustomRulesPath is a path to a YAML file or directory containing
	// custom security rules. When set, rules are loaded and merged with
	// the built-in analyzer rules. CLI flags take precedence over
	// .nox.yaml config values.
	CustomRulesPath string

	// DisableOSV disables OSV.dev vulnerability lookups for dependency
	// scanning. When true, the scan runs fully offline with no network
	// calls.
	DisableOSV bool

	// RecordReasoning collects the claims for and against every candidate the
	// scan considers, into ScanResult.Reasoning.
	//
	// It is opt-in because it is not free at scale and because nothing in the
	// default output depends on it: a scan with it off produces byte-identical
	// results to one with it on. Track C consumes it; until then it is how the
	// refinements that DROP findings become auditable at all, which they were
	// not — every one of them used to discard the finding and the reason for
	// dropping it in the same statement.
	RecordReasoning bool

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
	if err := policyConfigFrom(cfg).Validate(); err != nil {
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
	//
	// The reasoning store is created before them so refiners inside the
	// analyzers can file refutations as they drop candidates. It stays nil
	// unless asked for, and every recording call is nil-safe, so nothing below
	// branches on whether it exists.
	var reasons *reasoning.Store
	if opts.RecordReasoning {
		reasons = reasoning.New()
	}

	// The capability registry is built unconditionally. It costs one small map
	// and it answers a question every scan should be able to answer — what this
	// installation cannot tell you — whether or not anybody asked for evidence.
	capabilities := capability.DefaultRegistry()
	coverage := capability.NewCoverage(capabilities)

	// Initialize analyzers.
	secretsAnalyzer := secrets.NewAnalyzer()
	secretsAnalyzer.RecordReasoningTo(reasons)
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
	iacAnalyzer.RecordReasoningTo(reasons)
	// degradations collects checks that could not complete. Analyzers write to
	// it concurrently; it is surfaced on ScanResult so "no findings" can be
	// distinguished from "did not look".
	degradations := &degrade.Degradations{}
	// Config nox parses but does not act on is a coverage question, so it rides
	// the same channel as every other "did not look" signal. Reported here in
	// core rather than printed by one adapter: an agent scanning over MCP has no
	// other way to learn that the policy it configured is not in force.
	recordConfigDegradations(degradations, target)
	// The AI analyzer surfaces MCP/agent config parse failures hit while building
	// the tool permission matrix, so a broken config is a visible degradation
	// rather than a silently-empty (or all-tools-defaulted) matrix.
	aiAnalyzer := ai.NewAnalyzer(ai.WithDegradations(degradations))
	aiAnalyzer.RecordReasoningTo(reasons)

	// Whether dependency scanning may reach the network at all. Named once and
	// used by both the disable switch and the intelligence wiring below, so the
	// two cannot drift into disagreeing about what "offline" means.
	vulnLookupEnabled := !opts.Offline && !opts.DisableOSV && !cfg.Scan.OSV.Disabled

	depsOpts := []deps.AnalyzerOption{deps.WithDegradations(degradations)}
	if !vulnLookupEnabled {
		depsOpts = append(depsOpts, deps.WithOSVDisabled())
	}

	// The advisory cache holds hydrated advisory documents between scans, keyed
	// on the publisher's own `modified` stamp. It is a pure speed win with no
	// staleness window: the batch query stays live, so a newly published CVE is
	// never hidden, and a revised advisory misses its cache entry the moment
	// upstream changes it.
	var advisoryCache osvsource.AdvisoryCache
	if vulnLookupEnabled && !cfg.Scan.OSV.CacheDisabled {
		advisoryCache = osvsource.NewFileCache(cfg.Scan.OSV.CacheDir)
		depsOpts = append(depsOpts, deps.WithAdvisoryCache(advisoryCache))
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
	// An intelligence endpoint replaces OSV.dev as the source dependency
	// scanning asks. It is off unless configured, so the default path is
	// unchanged.
	//
	// When verification is on (the default), the intelligence source is checked
	// against OSV on every lookup and any record it withheld is restored from
	// OSV and reported as a degradation. That is what keeps "superset" a
	// property rather than a promise: a source that starts dropping advisories
	// costs its operator trust, immediately and visibly, but never costs the
	// scan a finding.
	if endpoint := cfg.Scan.Intelligence.Endpoint; endpoint != "" && vulnLookupEnabled {
		intel := osvsource.NewNamed("nox-intelligence", endpoint, intelHTTPClient(), degradations).
			WithCache(advisoryCache)

		var src vulnsource.Source = intel
		if cfg.Scan.Intelligence.VerificationEnabled() {
			src = vulnsource.NewVerifying(intel, func(refDeg *degrade.Degradations) vulnsource.Source {
				return osvsource.New(osvsource.DefaultBaseURL, intelHTTPClient(), refDeg).
					WithCache(advisoryCache)
			}, degradations)
		}
		depsOpts = append(depsOpts, deps.WithSource(src))
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
			kept, dropped := filterPluginFindingsByScope(out.Findings, target, cfg.Scan.Exclude, cfg.Scan.Include)
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
	if err := refineFindings(allFindings, cfg, opts, target, degradations, scannedPaths, reasons); err != nil {
		return nil, err
	}

	// Stage 3c: adjudicate. Shadow mode — the verdict is written onto the
	// finding and into ScanResult, and nothing reads it. SARIF, the policy
	// gate and the exit code are untouched, so a build cannot pass or fail
	// differently because of anything here.
	//
	// Stage 3b: record the supporting claim behind every finding that survived.
	//
	// It runs after refinement, over the findings the scan will actually
	// report, so the ledger describes the output rather than an intermediate
	// state. That leaves a known gap: refinement's own drops — suppression,
	// baseline matching, VEX, dedup — are still silent, and each is a
	// refutation that ought to be recorded the way the analyzers' are. They are
	// a larger change than this one and are left to the E track.
	recordObservations(reasons, allFindings)
	recordCapabilityCoverage(coverage, allFindings)
	recordAnalysisLimitations(allFindings, target, reasons)
	divergences, conflicts := adjudicateFindings(reasons, allFindings)

	// Stage 4: Evaluate policy gates.
	policyResult := evaluatePolicy(cfg, allFindings, capabilities, coverage)

	// Stage 5: Contribute observations, if this installation opted in. Runs
	// last, over the refined findings, so what is shared is what the scan
	// actually concluded rather than an intermediate state.
	contributeObservations(ctx, cfg, opts, allFindings.Findings(), degradations)

	return &ScanResult{
		Capabilities: capabilities,
		Coverage:     coverage,
		Reasoning:    reasons,
		Divergences:  divergences,
		Conflicts:    conflicts,
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

// recordConfigDegradations reports .nox.yaml keys nox does not act on.
//
// Two kinds, and from where the operator sits they are the same failure: a key
// nox cannot parse, and a key nox parses and then ignores. Either way the
// policy they wrote is not the policy in force. Only the first used to be
// reported, and only by the CLI.
// contributeObservations shares security facts about dependencies with a
// configured intelligence service.
//
// Querying an endpoint and contributing to it are two decisions, and this is
// the second one. A lookup already transmits (ecosystem, package, version) for
// every dependency, so if querying implied contributing then "contribute:
// false" would be a lie for anyone with an endpoint configured. Both are off by
// default and both must be set explicitly.
//
// Failure is recorded, never propagated. A scan that failed because an upload
// did would make opting in actively hostile, and would give operators a reason
// to switch off the thing that makes corroboration possible at all.
func contributeObservations(ctx context.Context, cfg *ScanConfig, opts ScanOptions, fs []findings.Finding, deg *degrade.Degradations) {
	ic := cfg.Scan.Intelligence
	if !opts.ContributeObservations || !ic.Contribute || ic.Endpoint == "" {
		return
	}

	reporterID, err := intel.ReporterID(ic.ReporterSaltPath)
	if err != nil {
		// Without a stable identifier the observations would be unattributed
		// and could never corroborate, so sending them anyway would add volume
		// without adding evidence.
		deg.Add(degrade.IntelContribution,
			fmt.Sprintf("reporter identity unavailable: %v", err),
			"no observations were contributed; this scan added nothing to the "+
				"intelligence network, and nothing left this environment")
		return
	}

	obs := intel.Derive(fs, intel.DeriveOptions{
		ReporterID:  reporterID,
		ObservedAt:  time.Now().UTC().Format(time.RFC3339),
		ToolVersion: opts.ToolVersion,
	})
	if len(obs) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	res := intel.NewClient(ic.Endpoint, intelHTTPClient()).Contribute(ctx, obs)
	if res.FirstError != nil {
		deg.Add(degrade.IntelContribution,
			fmt.Sprintf("%d of %d observations were not accepted: %v",
				res.Rejected, res.Submitted, res.FirstError),
			"this scan contributed less than it intended; the scan's own findings "+
				"are unaffected")
	}
}

// intelHTTPClient returns the client used for vulnerability lookups. The
// timeout matches the analyzer's own default; a lookup that hangs is a scan
// that hangs.
func intelHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func recordConfigDegradations(deg *degrade.Degradations, target string) {
	if unknown := UnknownConfigKeys(target); len(unknown) > 0 {
		deg.Add(degrade.Config,
			fmt.Sprintf(".nox.yaml has %d key(s) nox does not recognise: %s",
				len(unknown), strings.Join(unknown, ", ")),
			"they are ignored, so whatever they were meant to configure is not in effect; "+
				"check for a typo against the documented keys")
	}
	for _, k := range IneffectiveConfigKeys(target) {
		deg.Add(degrade.Config,
			fmt.Sprintf(".nox.yaml sets %s, which nox accepts but does not act on", k.Key),
			k.Reason)
	}
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
	walker.IncludePatterns = cfg.Scan.Include
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
func refineFindings(allFindings *findings.FindingSet, cfg *ScanConfig, opts ScanOptions, target string, deg *degrade.Degradations, scanned []string, reasons *reasoning.Store) error {
	// Every config-driven removal below is wrapped so the candidate it deleted
	// leaves a trail. Without it an operator cannot tell "nox found nothing
	// here" from "nox found it and my config removed it", and those are very
	// different states to be in.
	//
	// The wrapper is a no-op on a nil store, so a scan that did not ask for
	// reasoning does not pay for the snapshots.
	withheld := func(reason string, remove func()) {
		recordWithheld(reasons, allFindings, reason, remove)
	}

	// Config rule disabling and severity overrides.
	if len(cfg.Scan.Rules.Disable) > 0 {
		withheld("removed by scan.rules.disable in .nox.yaml", func() {
			allFindings.RemoveByRuleIDs(cfg.Scan.Rules.Disable)
		})
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
				withheld("removed by scan.analyzer_rules disable in .nox.yaml", func() {
					allFindings.RemoveByRuleIDsAndPaths(ar.Rules, ar.Paths)
				})
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
			withheld("removed by scan.analyzer_rules skip_analyzer "+ar.Analyzer+" in .nox.yaml", func() {
				allFindings.RemoveByRuleIDsAndPaths(patterns, paths)
			})
		}
	}

	// Drop content-rule findings (AI-*, MCP-*) on generated/vendored files and
	// inside test/fixture/example trees — false-positive sources. Dependency
	// scanning already ran against the same lockfiles, so no real CVE is hidden.
	if genPaths := cfg.Scan.GeneratedPaths.ResolveGeneratedPaths(); len(genPaths) > 0 {
		withheld("content rule dropped on a generated or vendored path", func() {
			allFindings.RemoveByRuleIDsAndPaths([]string{"AI-*", "MCP-*"}, genPaths)
		})
	}
	if noiseDirs := cfg.Scan.GeneratedPaths.ResolveNoiseDirs(); len(noiseDirs) > 0 {
		withheld("content rule dropped inside a test, fixture or example tree", func() {
			allFindings.RemoveByRuleIDsInDirs([]string{"AI-*", "MCP-*"}, noiseDirs)
		})
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

	// Name the dataflows BEFORE collapsing them, because collapsing is what
	// destroys the evidence that there was ever more than one candidate.
	//
	// Dedup already knows that two findings describe one flow — that knowledge
	// is the whole basis on which it deletes one of them — and then throws it
	// away. Recording the relation first turns "two findings became one" into
	// something a reader can see and check, rather than a count that silently
	// went down.
	recordFlowIdentity(reasons, allFindings)

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
func evaluatePolicy(cfg *ScanConfig, allFindings *findings.FindingSet, caps *capability.Registry,
	cov *capability.Coverage) *policy.Result {
	// A project that declares a capability requirement has configured a policy,
	// even with no severity threshold set. Leaving it out of this condition
	// would accept the setting and never evaluate it — a gate that looks
	// configured and is not, which is the exact defect Config.Validate exists
	// to prevent for fail_on.
	if cfg.Policy.FailOn == "" && cfg.Policy.BaselineMode == "" &&
		len(cfg.Policy.Budget) == 0 && len(cfg.Policy.RequireCapabilities) == 0 {
		return nil
	}
	policyCfg := policyConfigFrom(cfg)
	result := policy.Evaluate(policyCfg, allFindings.Findings())
	return policy.EvaluateCapabilities(policyCfg, caps, cov, result)
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

// filterPluginFindingsByScope drops plugin findings outside the scan's
// configured scope, returning the survivors and the drop count.
//
// Scope is `scan.exclude` and `scan.include` together, with exclude winning —
// the same precedence the walker applies to core findings. include was wired
// into the walker alone at first, which made one setting mean two things: an
// operator narrowing a scan to src/** still got plugin findings from vendor/.
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
func filterPluginFindingsByScope(in []findings.Finding, target string, patterns, include []string) (kept []findings.Finding, dropped int) {
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
		// The include allow-list, applied through the same matcher the walker
		// uses, so "in scope" means one thing regardless of which analyzer
		// produced the finding.
		if len(include) > 0 && !discovery.MatchesInclude(rel, include) {
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

// recordObservations files one supporting claim per reported finding, so every
// finding the scan emits has a recorded reason for existing and not only the
// refuted ones have a recorded reason for not.
//
// This is the shadow half of Track C: the claims are written and nothing reads
// them. Analyzers keep authoring Confidence exactly as before and it keeps
// driving everything it drove — the synthesised claim carries that label as an
// attribute rather than acting on it, which is what lets a later stage compare
// the two and find where an analyzer's own confidence and the evidence disagree.
// Folding the label into the claim's kind now would destroy that comparison
// before it could be made.
func recordObservations(store *reasoning.Store, fs *findings.FindingSet) {
	if store == nil || fs == nil {
		return
	}
	all := fs.Findings()
	for i := range all {
		store.Observed(SubjectForFinding(all[i]), all[i].RuleID,
			string(all[i].Confidence), "scan")
	}
}

// adjudicateFindings derives a verdict for every reported finding from its
// evidence, writes the state onto the finding, and returns the cases where the
// analyzer's own confidence disagreed with what the evidence supports.
//
// Shadow mode: the verdict is recorded and nothing acts on it. The policy gate
// still reads Severity and analyzer Confidence exactly as before, so no build
// changes colour because of this. What it produces is the count C5 needs —
// where, how often, and in which direction the two disagree — measured on real
// scans instead of argued from first principles.
func adjudicateFindings(store *reasoning.Store, fs *findings.FindingSet) ([]adjudicate.Divergence, []adjudicate.Conflict) {
	if store == nil || fs == nil {
		return nil, nil
	}
	all := fs.Findings()
	var out []adjudicate.Divergence
	var conflicts []adjudicate.Conflict
	for i := range all {
		subject := SubjectForFinding(all[i])
		ledger := store.About(subject)
		verdict := adjudicate.Adjudicate(ledger, subject)
		fs.SetExploitability(i, string(verdict.Exploitability))
		fs.SetEvidenceConfidence(i, string(verdict.Confidence))

		// Verdict.Conflicted used to be computed here and dropped on the floor.
		// It costs nothing today because nothing conflicts, which is exactly
		// the condition under which a discarded value is impossible to notice.
		if verdict.Conflicted {
			if c, ok := adjudicate.ConflictFor(ledger, subject); ok {
				c.Fingerprint = all[i].Fingerprint
				c.RuleID = all[i].RuleID
				conflicts = append(conflicts, c)
			}
		}

		diverged, overclaimed := adjudicate.Diverged(string(all[i].Confidence), verdict.Confidence)
		if !diverged {
			continue
		}
		out = append(out, adjudicate.Divergence{
			Fingerprint: all[i].Fingerprint,
			RuleID:      all[i].RuleID,
			Analyzer:    adjudicate.ConfidenceFrom(string(all[i].Confidence)),
			Adjudicated: verdict.Confidence,
			Overclaimed: overclaimed,
		})
	}
	return out, conflicts
}

// recordCapabilityCoverage records, per reported finding, what the analyses
// that ran actually concluded about it.
//
// It records only what is TRUE of a scan, which is a much shorter list than it
// looks. A finding exists because a rule matched, so lexical context was
// consulted wherever a lexer exists for the language — that is Positive. Taint
// concluded about a finding the taint engine produced, and about nothing else.
// Everything not recorded here resolves through the registry: provided but
// silent is NotEvaluated, unprovided is Unsupported.
//
// Dynamic verification is the case worth being explicit about. `nox scan`
// executes nothing, ever, so it is never conclusive here — which is exactly why
// every scan finding adjudicates to POTENTIAL, and why an operator reading a
// clean scan should be able to see that nox did not try.
func recordCapabilityCoverage(cov *capability.Coverage, fs *findings.FindingSet) {
	if cov == nil || fs == nil {
		return
	}
	for _, f := range fs.Findings() {
		subject := SubjectForFinding(f)

		// A rule fired on this location, so the lexer either classified the
		// file or could not. LangUnknown means no lexer exists for it, which is
		// a limit rather than a gap.
		if lexctx.LangFromPath(f.Location.FilePath) == lexctx.LangUnknown {
			cov.Record(subject, capability.LexicalContext, capability.Unsupported)
		} else {
			cov.Record(subject, capability.LexicalContext, capability.Positive)
		}

		// The taint engine concluded about the findings it produced, and said
		// nothing about the rest — which stays NotEvaluated rather than being
		// asserted as anything.
		if strings.HasPrefix(f.RuleID, "TAINT-") {
			cov.Record(subject, capability.Taint, capability.Positive)
			cov.Record(subject, capability.SymbolResolution, capability.Positive)
		}

		// The dependency analyzer answers at the level it can, and coverage is
		// recorded against THAT level's capability rather than a stronger one.
		//
		// This used to read meta["reachable"] and record capability.Reachability.
		// What `go list -deps` establishes is that an affected import is in the
		// linked set — reach.SymbolReferenced — so a project asking whether
		// REACHABILITY had been answered was told yes on the strength of a
		// weaker question. Evidence for an earlier proposition establishing a
		// later one is the invariant core/reach exists to hold, and this was
		// the place it was broken.
		//
		// Reachability stays unrecorded here on purpose. Nothing in nox builds
		// a call graph, so call_path_exists is unevaluated for every finding,
		// and saying nothing is what makes `nox why` and the capability gate
		// report it as unevaluated rather than as answered.
		switch reach.Outcome(f.Metadata["reach_outcome"]) {
		case reach.Established:
			cov.Record(subject, capability.SymbolResolution, capability.Positive)
		case reach.Refuted:
			cov.Record(subject, capability.SymbolResolution, capability.Negative)
		case reach.Undetermined:
			cov.Record(subject, capability.SymbolResolution, capability.Unknown)
		}
	}
}

// recordAnalysisLimitations annotates findings whose file contains a construct
// that defeats static analysis, so "nothing else was found here" reads as what
// it is.
//
// This is Milestone C's second half. The first gave nox a vocabulary for
// incompleteness; this is the first thing that speaks it. It does not know
// WHICH flow a reflective call defeated — that needs the taint engine to know
// it was defeated, and the engine has no such notion — but it can say the file
// contains a call whose target is a string at runtime, which is enough for a
// reader to know that silence about the rest of the file is a statement about
// what was visible.
//
// Only findings are annotated, which is a real limit and worth naming: a file
// with no finding at all gets no annotation, so the four-of-five silence on the
// hard corpus is only partly addressed. Attaching limitations to files rather
// than findings would need a per-file record the scan result does not have, and
// that is a larger change than this one.
func recordAnalysisLimitations(fs *findings.FindingSet, target string, store *reasoning.Store) {
	if fs == nil {
		return
	}
	byFile := map[string][]int{}
	items := fs.Findings()
	for i := range items {
		if p := items[i].Location.FilePath; p != "" {
			byFile[p] = append(byFile[p], i)
		}
	}

	for filePath, idx := range byFile {
		full := filePath
		if !filepath.IsAbs(full) {
			full = filepath.Join(ConfigRoot(target), full)
		}
		if fi, err := os.Stat(full); err != nil || fi.IsDir() {
			continue
		}
		content, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		limits := reach.Detect(content)
		if len(limits) == 0 {
			continue
		}
		names := make([]string, 0, len(limits))
		for _, l := range limits {
			names = append(names, string(l))
		}
		joined := strings.Join(names, ",")
		for _, i := range idx {
			fs.SetMetadata(i, "analysis_limitations", joined)
		}
		// Withheld, not refuting: a construct the analysis cannot follow is not
		// an argument against any finding. It is a statement that the search
		// behind any negative here was incomplete.
		for _, i := range idx {
			store.Withheld(SubjectForFinding(items[i]), "nox-scan", "scan",
				"the analysis of this file is incomplete: "+limits[0].Describe())
		}
	}
}

// recordWithheld runs a removal and records which candidates it deleted.
//
// The removal functions on FindingSet do not report what they took, and giving
// each of them a reporting variant would be a wide change to a much-used API
// for one caller's benefit. Diffing around the call gets the same answer at the
// one place that needs it.
//
// It is a no-op on a nil store, and that guard is what keeps the cost honest:
// the snapshot is O(findings) per removal step, which is not something to pay
// on a six-million-finding scan that never asked for the trail.
func recordWithheld(store *reasoning.Store, fs *findings.FindingSet, reason string, remove func()) {
	if store == nil {
		remove()
		return
	}

	before := make(map[evidence.Subject]findings.Finding, len(fs.Findings()))
	for _, f := range fs.Findings() {
		before[SubjectForFinding(f)] = f
	}

	remove()

	for _, f := range fs.Findings() {
		delete(before, SubjectForFinding(f))
	}
	for subject, f := range before {
		store.Withheld(subject, "nox-scan", "config",
			fmt.Sprintf("%s (%s at %s:%d)", reason, f.RuleID,
				f.Location.FilePath, f.Location.StartLine))
	}
}

// policyConfigFrom builds the policy configuration from .nox.yaml.
//
// It exists because there are two callers — the loader, which validates, and
// the gate, which evaluates — and they were separate literals. Adding a field
// to one and not the other produced exactly the defect the validation is FOR:
// `uncertainty: Fail` was accepted and silently resolved to the permissive
// default, because the value never reached the function that would have
// rejected it. A validator that cannot see a field validates nothing about it,
// and nothing about the shape of two literals made that visible.
//
// One constructor, so the two cannot drift again.
func policyConfigFrom(cfg *ScanConfig) policy.Config {
	return policy.Config{
		FailOn:              findings.Severity(cfg.Policy.FailOn),
		WarnOn:              findings.Severity(cfg.Policy.WarnOn),
		BaselineMode:        policy.BaselineMode(cfg.Policy.BaselineMode),
		Budget:              policyBudget(cfg.Policy.Budget),
		Uncertainty:         policy.Uncertainty(cfg.Policy.Uncertainty),
		RequireCapabilities: cfg.Policy.RequireCapabilities,
	}
}

// recordFlowIdentity relates every candidate that describes a dataflow to the
// flow itself.
//
// It runs before dedup, and that ordering is the point. Afterwards the
// duplicates are gone and nothing is left to relate — the merge would be
// invisible in exactly the way this whole programme exists to prevent, and
// invisible in the direction that looks like progress, because the finding
// count went down.
//
// A relation is an assertion and carries its own evidence, so the edge is not
// asserted on nox's authority alone: the claim names the source variable, the
// line its value came from, and the sink it reached, which is what a reader
// needs to check the merge rather than take it.
func recordFlowIdentity(store *reasoning.Store, fs *findings.FindingSet) {
	if store == nil || fs == nil {
		return
	}
	for _, f := range fs.Findings() {
		id, ok := findings.FlowID(&f)
		if !ok {
			continue
		}
		candidate := SubjectForFinding(f)
		flow := reasoning.Flow(id)

		var ledger evidence.Ledger
		ledger.Add(evidence.Claim{
			Kind: evidence.KindStatic,
			Statement: fmt.Sprintf("%s reports %s reaching a sink from line %s",
				f.RuleID, f.Metadata["source_var"], f.Metadata["source_line"]),
			Subject:    flow,
			Provenance: evidence.Provenance{Source: "nox-scan", Tool: "taint"},
		})

		store.Relate(evidence.Relation{
			From: candidate, Kind: evidence.RelConcerns, To: flow, Ledger: ledger,
		})
	}
}
