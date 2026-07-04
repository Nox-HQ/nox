package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LicensePolicy defines which dependency licenses are allowed or denied.
// If Deny is specified, any package with a matching license produces a finding.
// If Allow is specified, any package with a license NOT in the list produces a finding.
type LicensePolicy struct {
	Deny  []string `yaml:"deny"`  // License IDs to deny (e.g., ["GPL-3.0", "AGPL-3.0"])
	Allow []string `yaml:"allow"` // License IDs to allow (e.g., ["MIT", "Apache-2.0", "BSD-*"])
}

// CacheSettings controls the incremental scan cache.
type CacheSettings struct {
	Disabled bool   `yaml:"disabled"`
	TTL      string `yaml:"ttl"` // duration string, e.g. "7d", "24h"
	Dir      string `yaml:"dir"` // custom cache directory
}

// ScanConfig holds project-level configuration loaded from .nox.yaml.
type ScanConfig struct {
	Scan       ScanSettings       `yaml:"scan"`
	Output     OutputSettings     `yaml:"output"`
	Explain    ExplainSettings    `yaml:"explain"`
	Policy     PolicySettings     `yaml:"policy"`
	License    LicensePolicy      `yaml:"license"`
	Compliance ComplianceSettings `yaml:"compliance"`
	Cache      CacheSettings      `yaml:"cache"`
	Plugins    PluginsConfig      `yaml:"plugins"`
}

// PluginsConfig declares the plugins a project requires plus any
// non-default registries to consult when resolving them. Modeled on
// package.json / Gemfile dependency manifests: `nox install` reads the
// block and installs missing entries; `nox scan` checks the block and
// auto-installs unless --no-auto-install is set.
type PluginsConfig struct {
	// Required lists plugin specifiers — `name@constraint` or bare name.
	// Examples: "nox/reachability@>=0.5", "nox/ai-eval", "nox/grc@0.5.0".
	Required []string `yaml:"required"`
	// Registries are extra registry index URLs to consult on top of the
	// official source. Each entry is a URL or `name=url` pair.
	Registries []string `yaml:"registries"`
	// AutoInstall, when true (default), lets `nox scan` install missing
	// required plugins automatically. Set false to fail loudly instead.
	AutoInstall *bool `yaml:"auto_install"`
	// TrustPolicy controls signature enforcement on install. Values:
	//   "permissive"  — accept unverified plugins (default until ecosystem
	//                   pipelines stamp signatures consistently)
	//   "default"     — require valid signature, any signer (community or
	//                   verified)
	//   "enterprise"  — require signature from a key in the local keyring
	//
	// Empty defaults to "permissive". CLI flags override.
	TrustPolicy string `yaml:"trust_policy"`
}

// AutoInstallEnabled returns whether the project consents to scan-time
// auto-install. Defaults to true for parity with package.json semantics
// but operators can opt out via `auto_install: false`.
func (p PluginsConfig) AutoInstallEnabled() bool {
	if p.AutoInstall == nil {
		return true
	}
	return *p.AutoInstall
}

// PolicySettings controls pass/fail thresholds and baseline behavior.
type PolicySettings struct {
	FailOn       string `yaml:"fail_on"`
	WarnOn       string `yaml:"warn_on"`
	BaselineMode string `yaml:"baseline_mode"`
	BaselinePath string `yaml:"baseline_path"`
	VEXPath      string `yaml:"vex_path"`
	// Budget is a per-severity allowance for NEW findings: the gate tolerates
	// up to Budget[severity] new findings of that severity before failing. It
	// refines fail_on — a severity at/above the fail threshold with a budget of
	// N fails only on the N+1th new finding; severities without an entry default
	// to 0 (fail on the first, the pre-budget behaviour). Lets a team accept a
	// bounded amount of debt ("up to 5 new mediums, zero new highs") without
	// baselining every finding. Keys are severity names (critical/high/medium/
	// low/info).
	Budget map[string]int `yaml:"budget"`
}

// ComplianceSettings controls compliance framework filtering.
type ComplianceSettings struct {
	Framework string `yaml:"framework"`
}

// ArtifactTypeExclusion defines exclusions by artifact type.
type ArtifactTypeExclusion struct {
	ArtifactTypes []string `yaml:"artifact_types"` // e.g., ["lockfile", "container"]
	Paths         []string `yaml:"paths"`          // optional: limit to specific paths
}

// AnalyzerRuleConfig defines rules that apply to specific analyzers and paths.
type AnalyzerRuleConfig struct {
	Analyzer string   `yaml:"analyzer"` // analyzer name (deps, secrets, iac, ai, data)
	Rules    []string `yaml:"rules"`    // rule IDs or wildcards (e.g., ["VULN-*", "SEC-001"])
	Paths    []string `yaml:"paths"`    // glob patterns to match
	Action   string   `yaml:"action"`   // "disable" or "skip_analyzer"
}

// ConditionalSeverity defines severity overrides based on path patterns.
type ConditionalSeverity struct {
	Rules    []string `yaml:"rules"`    // rule IDs or wildcards
	Paths    []string `yaml:"paths"`    // glob patterns
	Severity string   `yaml:"severity"` // critical, high, medium, low, info
}

// ScanSettings controls which files are scanned and how rules behave.
type ScanSettings struct {
	Exclude              []string                `yaml:"exclude"`
	ExcludeArtifactTypes []ArtifactTypeExclusion `yaml:"exclude_artifact_types"`
	Include              []string                `yaml:"include"`
	RulesDir             string                  `yaml:"rules_dir"`
	Rules                RulesConfig             `yaml:"rules"`
	AnalyzerRules        []AnalyzerRuleConfig    `yaml:"analyzer_rules"`
	ConditionalSeverity  []ConditionalSeverity   `yaml:"conditional_severity"`
	OSV                  OSVConfig               `yaml:"osv"`
	Entropy              EntropyConfig           `yaml:"entropy"`
	GeneratedPaths       GeneratedPathsConfig    `yaml:"generated_paths"`
}

// GeneratedPathsConfig controls the built-in noise filter that stops the
// content rule families (AI-*, MCP-*) from firing on generated and vendored
// files — lockfiles, minified bundles, generated type definitions, etc. These
// files are not human-authored and produce only false positives for prose and
// AI-security rules. Dependency scanning is unaffected: the deps analyzer still
// reads lockfiles directly, so this filter never hides a real CVE.
type GeneratedPathsConfig struct {
	// Disabled turns the filter off entirely. Default false (filter on).
	Disabled bool `yaml:"disabled"`
	// Extend adds glob patterns to the built-in generated-path set.
	Extend []string `yaml:"extend"`
	// Override replaces the built-in set with exactly these globs (advanced;
	// when non-empty, Extend is ignored).
	Override []string `yaml:"override"`
	// ExtendDirs adds directory-name segments to the built-in noise-dir set
	// (test/example/fixture trees the content rules skip).
	ExtendDirs []string `yaml:"extend_dirs"`
	// OverrideDirs replaces the built-in noise-dir segment set entirely.
	OverrideDirs []string `yaml:"override_dirs"`
}

// DefaultNoiseDirs is the built-in set of directory-name segments whose
// contents are excluded from the content rule families (AI-*, MCP-*). Code
// under these trees is test scaffolding, fixtures, mocks, or runnable examples
// — it produces only false positives for prose / AI-security rules (security
// tests carry deliberate attack strings; examples log demo output).
func DefaultNoiseDirs() []string {
	return []string{
		"test", "tests", "__tests__", "spec", "specs", "e2e",
		"fixtures", "testdata", "mocks", "mock", "samples", "example", "examples",
	}
}

// ResolveNoiseDirs returns the effective noise-dir segment set: nil when
// disabled, OverrideDirs when set, otherwise the defaults plus ExtendDirs.
func (g GeneratedPathsConfig) ResolveNoiseDirs() []string {
	if g.Disabled {
		return nil
	}
	if len(g.OverrideDirs) > 0 {
		return g.OverrideDirs
	}
	return append(DefaultNoiseDirs(), g.ExtendDirs...)
}

// DefaultGeneratedPaths is the built-in set of generated/vendored file globs
// excluded from the content rule families. Globs are matched against both the
// full path and the base name.
func DefaultGeneratedPaths() []string {
	return []string{
		// Dependency lockfiles (still read by the deps analyzer).
		"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "npm-shrinkwrap.json",
		"Cargo.lock", "poetry.lock", "Gemfile.lock", "composer.lock", "go.sum",
		"*-lock.json", "*-lock.yaml",
		// Minified / bundled assets.
		"*.min.js", "*.min.css", "*.bundle.js",
		// Generated type definitions and protobuf/codegen output.
		"worker-configuration.d.ts", "*.pb.go", "*_pb2.py", "*_pb2.pyi",
		"*.generated.go", "*.generated.ts", "*.gen.go",
	}
}

// ResolveGeneratedPaths returns the effective generated-path glob set for the
// config: nil when disabled, Override when set, otherwise the default set plus
// Extend.
func (g GeneratedPathsConfig) ResolveGeneratedPaths() []string {
	if g.Disabled {
		return nil
	}
	if len(g.Override) > 0 {
		return g.Override
	}
	return append(DefaultGeneratedPaths(), g.Extend...)
}

// EntropyConfig allows overriding entropy-based secret detection thresholds
// from .nox.yaml. Zero values mean "use the rule defaults".
type EntropyConfig struct {
	// Threshold overrides the default entropy threshold for SEC-161.
	Threshold float64 `yaml:"threshold"`
	// HexThreshold overrides the entropy threshold for SEC-163 (hex detection).
	HexThreshold float64 `yaml:"hex_threshold"`
	// Base64Threshold overrides the entropy threshold for SEC-162 (base64 detection).
	Base64Threshold float64 `yaml:"base64_threshold"`
	// RequireContext when true forces SEC-162/SEC-163 to only fire when a
	// secret-suggestive keyword appears on the same line. Default is true
	// (set in rule metadata); setting this to false disables that check.
	RequireContext *bool `yaml:"require_context"`
}

// OSVConfig controls OSV.dev vulnerability enrichment for dependency scanning.
type OSVConfig struct {
	Disabled bool `yaml:"disabled"`
}

// RulesConfig allows disabling rules or overriding their severity.
type RulesConfig struct {
	Disable          []string          `yaml:"disable"`
	SeverityOverride map[string]string `yaml:"severity_override"`
}

// OutputSettings controls default output format and directory.
type OutputSettings struct {
	Format    string `yaml:"format"`
	Directory string `yaml:"directory"`
}

// ExplainSettings controls defaults for the explain command.
type ExplainSettings struct {
	APIKeyEnv string `yaml:"api_key_env"` // env var name to read API key from (default: OPENAI_API_KEY)
	Model     string `yaml:"model"`       // LLM model name (default: gpt-4o)
	BaseURL   string `yaml:"base_url"`    // custom OpenAI-compatible API base URL
	Timeout   string `yaml:"timeout"`     // per-request timeout (e.g., "2m", "30s")
	BatchSize int    `yaml:"batch_size"`  // findings per LLM request (default: 10)
	Output    string `yaml:"output"`      // output file path (default: explanations.json)
	Enrich    string `yaml:"enrich"`      // comma-separated enrichment tool names
	PluginDir string `yaml:"plugin_dir"`  // directory containing plugin binaries
}

// LoadScanConfig reads .nox.yaml from root and returns the parsed config.
// If the file does not exist, a zero-value ScanConfig is returned with no error.
func LoadScanConfig(root string) (*ScanConfig, error) {
	// A single-file target loads config from the file's directory, so
	// `nox scan path/to/file.py` finds the project .nox.yaml instead of
	// looking for `file.py/.nox.yaml`.
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		root = filepath.Dir(root)
	}
	path := filepath.Join(root, ".nox.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ScanConfig{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg ScanConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	return &cfg, nil
}
