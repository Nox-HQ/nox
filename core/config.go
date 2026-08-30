package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	// Uncertainty says what to do about what the scan did not establish:
	// "warn" (default), "fail", or "ignore". It reads the axis the gate never
	// has — not how bad a finding would be if true, but how much nox actually
	// determined.
	Uncertainty string `yaml:"uncertainty"`

	// RequireCapabilities names the analysis capabilities this project's triage
	// depends on ("reachability", "taint", …; see `nox analysis-capabilities`).
	//
	// Empty for every existing repository, and empty changes nothing. Listing
	// one asserts that this project relies on that question being answered —
	// so that uninstalling the plugin which answers it can no longer make the
	// build quietly greener, which is the whole failure this setting exists to
	// close.
	RequireCapabilities []string `yaml:"require_capabilities"`
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
	Intelligence         IntelligenceConfig      `yaml:"intelligence"`
	Slop                 SlopConfig              `yaml:"slop"`
	Entropy              EntropyConfig           `yaml:"entropy"`
	GeneratedPaths       GeneratedPathsConfig    `yaml:"generated_paths"`
	SAST                 SASTConfig              `yaml:"sast"`
	// ContextDowngrade gates the context-gated SAST severity refinement: a
	// code-pattern finding (AI-*, MCP-*, AGENT-*, IAC-*, TAINT-*, SLOP-*,
	// VARIANT-*) located in a non-production tree (tests, examples, docs,
	// vendored/generated/minified code) is dropped one severity level, since
	// the same pattern in throwaway code is far less actionable than in
	// shipping source. It is a *bool so the absent/zero case can default to
	// enabled (parity with auto_install): nil ⇒ on, set false ⇒ off.
	ContextDowngrade *bool `yaml:"context_downgrade"`
}

// SASTConfig declares the per-language SAST depth strategy. nox targets ~15
// languages but shouldn't invest equal analysis depth everywhere: Python and
// JS/TS — where AI apps and the worst false positives concentrate — earn deep
// analysis; the rest get standard pattern coverage; a repo can turn a language
// off entirely.
//
// Languages maps a canonical language name (see LanguageForExtension) to a
// depth level: "deep" | "standard" | "off". Unlisted languages fall back to
// DefaultLanguageDepth. See docs/sast-language-strategy.md for the rationale
// and how each depth maps to behavior today and in future.
type SASTConfig struct {
	Languages map[string]string `yaml:"languages"`
}

// ContextDowngradeEnabled reports whether context-gated severity downgrading is
// active. It defaults to true when unset in .nox.yaml so noise reduction is on
// out of the box; `scan.context_downgrade: false` opts out.
func (s *ScanSettings) ContextDowngradeEnabled() bool {
	if s.ContextDowngrade == nil {
		return true
	}
	return *s.ContextDowngrade
}

// NonProductionPathGlobs is the built-in set of path globs that mark a file as
// non-production context for the context-gated severity downgrade. Matching is
// case-insensitive on path segments (see MatchesNonProductionPath); `**` spans
// zero or more path segments so a tree matches at any depth. The set covers the
// four classic "not shipping source" buckets: test code, examples, docs, and
// vendored/generated/minified/build output.
func NonProductionPathGlobs() []string {
	return []string{
		"**/test/**", "**/tests/**", "*_test.*",
		"**/testdata/**",
		"**/example/**", "**/examples/**",
		"**/docs/**",
		"**/vendor/**", "**/node_modules/**",
		"**/*.min.js",
		"**/dist/**", "**/build/**",
		"**/generated/**", "**/__mocks__/**",
	}
}

// ContextDowngradeRulePatterns is the set of rule-ID families the context
// downgrade applies to — the *code-pattern* families whose actionability
// genuinely depends on where the code ships:
//
//   - AI-*, MCP-*, AGENT-* — AI/agent/tool-wiring patterns
//   - IAC-*                — infrastructure-as-code misconfigurations
//   - TAINT-*              — dataflow/taint findings
//   - SLOP-*               — AI-generated-code smells
//   - VARIANT-*            — variant/anti-pattern matches
//
// It deliberately EXCLUDES:
//
//   - SEC-*                — a secret in a test file is frequently a real,
//     committed credential (test fixtures leak prod keys); downgrading it
//     would bury genuine exposure. Secrets are graded by the secret itself,
//     not by the file it sits in.
//   - VULN-*, CONT-*, LIC- — dependency/container/license facts. A vulnerable
//     or wrongly-licensed dependency is exploitable/non-compliant regardless
//     of whether the manifest importing it lives under tests/ or examples/;
//     the risk is a property of the package, not the call site.
func ContextDowngradeRulePatterns() []string {
	return []string{
		"AI-*", "MCP-*", "AGENT-*", "IAC-*", "TAINT-*", "SLOP-*", "VARIANT-*",
	}
}

// MatchesNonProductionPath reports whether path matches any of the given globs
// under the context-downgrade matching rules. It is a robust, filepath-style
// matcher: paths are normalized to forward slashes, matching is
// case-insensitive on every segment, and a `**` glob segment spans zero or more
// path segments so `**/test/**` matches `test/a.py`, `src/test/a.py`, and
// `a/b/test/c/d.py` alike. A single `*` matches within one segment via
// filepath.Match (so `*_test.*` and `**/*.min.js` work). Returns false for an
// empty path or empty glob set.
func MatchesNonProductionPath(path string, globs []string) bool {
	if path == "" || len(globs) == 0 {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	segs := strings.Split(lower, "/")
	base := segs[len(segs)-1]
	for _, g := range globs {
		lg := strings.ToLower(g)
		gsegs := strings.Split(lg, "/")
		if matchGlobSegments(segs, gsegs) {
			return true
		}
		// A single-segment glob with no `**` (e.g. `*_test.*`, `*.min.js`) is a
		// basename pattern: match it against the final path segment at any depth,
		// mirroring the base-name fallback used elsewhere in the pipeline.
		if len(gsegs) == 1 && !strings.Contains(lg, "**") {
			if ok, _ := filepath.Match(lg, base); ok {
				return true
			}
		}
	}
	return false
}

// matchGlobSegments matches pre-split, lower-cased path segments against
// pre-split glob segments, treating `**` as "zero or more segments" and
// delegating single-segment matching (including `*`) to filepath.Match. It runs
// a small recursive backtracking match — glob depth is tiny (a handful of
// segments) so this is effectively linear in path length.
func matchGlobSegments(path, glob []string) bool {
	// Both exhausted ⇒ match; a trailing `**` still matches the empty tail.
	if len(glob) == 0 {
		return len(path) == 0
	}
	if glob[0] == "**" {
		// `**` consumes zero segments (skip it) or one segment (advance path).
		if matchGlobSegments(path, glob[1:]) {
			return true
		}
		if len(path) > 0 {
			return matchGlobSegments(path[1:], glob[1:]) || matchGlobSegments(path[1:], glob)
		}
		return false
	}
	if len(path) == 0 {
		return false
	}
	if ok, _ := filepath.Match(glob[0], path[0]); !ok {
		return false
	}
	return matchGlobSegments(path[1:], glob[1:])
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

	// CacheDisabled turns off the advisory cache. Default is enabled.
	//
	// Only advisory *documents* are ever cached, keyed on the publisher's own
	// `modified` stamp. The batch query — which advisories match this package
	// version — is always live, so disabling the cache cannot make a scan find
	// anything it would otherwise miss. It only makes it slower: a scan of a
	// modest corpus issues one batch query and a hundred-odd detail fetches,
	// and repeats every one of them on the next run.
	CacheDisabled bool `yaml:"cache_disabled"`

	// CacheDir overrides where cached advisories are stored. Empty defaults to
	// $HOME/.nox/cache/advisories.
	CacheDir string `yaml:"cache_dir"`
}

// IntelligenceConfig points dependency scanning at a NOX Intelligence service
// instead of OSV.dev directly.
//
// Off by default. Enabling it is an explicit act, and it changes who answers
// "is this package vulnerable?" — which is a trust decision, not a tuning knob.
type IntelligenceConfig struct {
	// Endpoint is the intelligence service base URL. Empty (default) means
	// dependency scanning queries OSV.dev exactly as before.
	Endpoint string `yaml:"endpoint"`

	// VerifyAgainstOSV checks every lookup against OSV.dev and reports any
	// record the intelligence service withheld. Default true.
	//
	// It is a *bool rather than a bool because the zero value must mean "on".
	// A verification that silently defaults to off would make the strongest
	// safeguard the one an operator is least likely to have enabled, and the
	// resulting scans would look identical to verified ones.
	VerifyAgainstOSV *bool `yaml:"verify_against_osv"`

	// Contribute controls whether this installation sends observations. It is
	// deliberately separate from querying: a lookup already transmits
	// (ecosystem, package, version), so if querying implied contributing then
	// "contribute: false" would be a lie for anyone with an endpoint set.
	// Querying and contributing are two decisions, and both are off by default.
	Contribute bool `yaml:"contribute"`

	// ReporterSaltPath overrides where the private reporter salt is kept.
	// Empty defaults to $HOME/.nox/reporter-salt. The salt never leaves the
	// machine; only an HMAC derived from it does.
	ReporterSaltPath string `yaml:"reporter_salt_path"`
}

// VerificationEnabled reports whether lookups are checked against OSV,
// defaulting to true when unset.
func (c IntelligenceConfig) VerificationEnabled() bool {
	return c.VerifyAgainstOSV == nil || *c.VerifyAgainstOSV
}

// SlopConfig enables the SLOP analyzer's predictive slopsquat dimension
// (SLOP-002). It is off by default: with no Feed configured the analyzer keeps
// exactly its reactive SLOP-001 behavior and adds no findings. The feed is a
// versioned, content-addressed, offline data file — no network is touched at
// scan time (only the out-of-band generator queries registries). See
// docs/slopsquat-feed.md.
type SlopConfig struct {
	// Feed selects the predictive blocklist. Empty (default) disables the
	// predictive dimension entirely. Accepted values:
	//   - "bundled"          — the feed shipped in the nox binary
	//   - an http(s):// URL  — a remotely published, signature-verified feed
	//                          (fetched, verified, and cached locally; offline
	//                          after the first successful fetch)
	//   - any other value    — a path to a feed JSON file (relative to the scan
	//                          root or absolute)
	Feed string `yaml:"feed"`
	// CacheDir overrides where a remote feed's verified bytes are cached. Empty
	// defaults to $HOME/.nox/cache/slopfeed. Only used for http(s) feeds.
	CacheDir string `yaml:"cache_dir"`
	// Refresh sets how long a cached remote feed is treated as fresh before a
	// refetch is attempted (a Go duration such as "24h" or "7d"). Within it, no
	// network call is made. Empty defaults to 24h. Only used for http(s) feeds.
	Refresh string `yaml:"refresh"`
	// RequireSignature, when true, rejects a feed that is unsigned or whose
	// signature does not verify — the predictive dimension then stays off rather
	// than trusting an unverified feed. Digest integrity is always enforced
	// regardless of this setting. Verifying a signature requires a configured
	// public key (SignatureKeyPath); without one, a required signature fails
	// closed.
	RequireSignature bool `yaml:"require_signature"`
	// SignatureKeyPath points at a PEM-encoded Ed25519 public key used to verify
	// the feed signature. Optional; when set, a present signature is verified
	// against it (and a bad signature is always a hard failure).
	SignatureKeyPath string `yaml:"signature_key_path"`
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
			cfg := &ScanConfig{}
			applyRequiredPluginsEnv(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg ScanConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	applyRequiredPluginsEnv(&cfg)
	return &cfg, nil
}

// RequirePluginsEnv names the environment variable that adds to
// plugins.required, comma-separated.
const RequirePluginsEnv = "NOX_REQUIRE_PLUGINS"

// applyRequiredPluginsEnv merges NOX_REQUIRE_PLUGINS into plugins.required.
//
// A plugin only contributes findings when it is declared, and declaration lives
// in a per-repository .nox.yaml. That is the wrong place for a fleet: a shared
// CI workflow installs the same analysis plugin for every repository it runs
// on, pins its version centrally, and then cannot say the one thing that makes
// it take effect — so every repository without its own .nox.yaml silently gets
// reduced coverage (#403).
//
// This lets the workflow declare it once, in the same file the version is
// pinned in. It ADDS to whatever the repository declared rather than replacing
// it: a repo that lists its own plugins keeps them, and duplicates collapse, so
// setting the variable can only widen coverage.
func applyRequiredPluginsEnv(cfg *ScanConfig) {
	raw := strings.TrimSpace(os.Getenv(RequirePluginsEnv))
	if raw == "" || cfg == nil {
		return
	}
	seen := make(map[string]bool, len(cfg.Plugins.Required))
	for _, p := range cfg.Plugins.Required {
		seen[p] = true
	}
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		cfg.Plugins.Required = append(cfg.Plugins.Required, name)
	}
}
