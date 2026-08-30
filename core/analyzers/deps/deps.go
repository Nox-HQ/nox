// Package deps implements dependency manifest scanning and OSV lookup.
//
// The analyzer parses lockfiles from multiple ecosystems (Go, npm, PyPI,
// RubyGems, Cargo, Maven, Gradle, NuGet), builds a PackageInventory, and
// produces a FindingSet for any known vulnerabilities. Lockfile format
// detection is driven by the filename so callers can feed arbitrary paths
// without configuration.
package deps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
	osvsource "github.com/nox-hq/nox-core/vulnsource/osv"
	"github.com/nox-hq/nox/core/applicability"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reach"
	"github.com/nox-hq/nox/core/rules"
)

// redundantLockfiles names files that carry no dependency information nox
// cannot already get from a file it does parse. Only these are exempt from
// degradation reporting when they go unparsed.
//
// go.sum is the sole member: it hashes the whole module graph, while go.mod
// carries the versions Minimal Version Selection actually chose, so parsing
// go.mod loses nothing. Do not add a lockfile here merely because nox lacks a
// parser for it — that is exactly the blind spot this list exists to avoid
// hiding.
var redundantLockfiles = map[string]bool{
	"go.sum": true,
}

// knownUnparsed names lockfiles nox classifies but cannot yet parse.
//
// Empty, and meant to stay that way: every lockfile discovery classifies now
// has a parser. Unlike redundantLockfiles, an entry here is a real blind spot —
// a project using that ecosystem gets no dependency inventory and no
// vulnerability matching. Entries are permitted only so the gap is a recorded,
// testable decision rather than an accident, and each still produces a
// degradation at scan time so operators are told. Writing a parser and removing
// the entry is the fix; the entry is not the fix. The coverage invariant is
// enforced by the deps package tests.
var knownUnparsed = map[string]string{}

// isRedundantLockfile reports whether an unparsed lockfile is safe to ignore
// silently. Only genuine redundancy qualifies — a missing parser does not,
// because the operator needs to know their dependencies went unscanned.
func isRedundantLockfile(path string) bool {
	return redundantLockfiles[filepath.Base(path)]
}

// ErrUnsupportedLockfile marks a file whose name matches no known lockfile
// parser. It is deliberately distinguishable from a parse failure: the former
// means nox never intended to read the file, the latter means it tried and
// failed, which leaves a real blind spot worth reporting.
var ErrUnsupportedLockfile = errors.New("unsupported lockfile type")

// Package represents a single dependency extracted from a lockfile.
type Package struct {
	Name      string
	Version   string
	Ecosystem string // "npm", "go", "pypi", "rubygems", "cargo", "maven", "gradle", "nuget"
	License   string // SPDX identifier (e.g., "MIT", "Apache-2.0", "GPL-3.0")
}

// Vulnerability describes a known security issue for a package.
type Vulnerability struct {
	ID               string
	Summary          string
	Severity         findings.Severity
	AffectedVersions string
	Aliases          []string
	Details          string
}

// PackageInventory is a thread-safe, ordered collection of discovered packages.
type PackageInventory struct {
	mu    sync.Mutex
	pkgs  []Package
	vulns map[int][]Vulnerability
}

// Add appends a package to the inventory.
func (pi *PackageInventory) Add(p Package) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	pi.pkgs = append(pi.pkgs, p)
}

// Packages returns all packages in the inventory. The caller must not modify
// the returned slice.
func (pi *PackageInventory) Packages() []Package {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	out := make([]Package, len(pi.pkgs))
	copy(out, pi.pkgs)
	return out
}

// ByEcosystem returns only the packages matching the given ecosystem string.
func (pi *PackageInventory) ByEcosystem(eco string) []Package {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	var result []Package
	for _, p := range pi.pkgs {
		if p.Ecosystem == eco {
			result = append(result, p)
		}
	}
	return result
}

// SetLicense updates the license for the package at the given index.
func (pi *PackageInventory) SetLicense(pkgIdx int, license string) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	if pkgIdx >= 0 && pkgIdx < len(pi.pkgs) && pi.pkgs[pkgIdx].License == "" {
		pi.pkgs[pkgIdx].License = license
	}
}

// SetVulnerabilities stores vulnerability data for the package at the given index.
func (pi *PackageInventory) SetVulnerabilities(pkgIdx int, vulns []Vulnerability) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	if pi.vulns == nil {
		pi.vulns = make(map[int][]Vulnerability)
	}
	pi.vulns[pkgIdx] = vulns
}

// Vulnerabilities returns the vulnerability data for the package at the given index.
func (pi *PackageInventory) Vulnerabilities(pkgIdx int) []Vulnerability {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	if pi.vulns == nil {
		return nil
	}
	return pi.vulns[pkgIdx]
}

// AllVulnerabilities returns vulnerability data for all packages, keyed by index.
func (pi *PackageInventory) AllVulnerabilities() map[int][]Vulnerability {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	if pi.vulns == nil {
		return nil
	}
	out := make(map[int][]Vulnerability, len(pi.vulns))
	for k, v := range pi.vulns {
		out[k] = v
	}
	return out
}

// LicensePolicy defines which dependency licenses are allowed or denied.
type LicensePolicy struct {
	Deny  []string
	Allow []string
}

// AnalyzerOption configures the dependency Analyzer.
type AnalyzerOption func(*Analyzer)

// WithOSVDisabled disables OSV.dev vulnerability lookups. Use this for
// offline scans or deterministic testing.
func WithOSVDisabled() AnalyzerOption {
	return func(a *Analyzer) { a.osvEnabled = false }
}

// WithHTTPClient sets a custom HTTP client for OSV API requests.
func WithHTTPClient(c *http.Client) AnalyzerOption {
	return func(a *Analyzer) { a.httpClient = c }
}

// WithOSVBaseURL overrides the default OSV API base URL. It has no effect when
// WithSource supplies an explicit source, which brings its own endpoint.
func WithOSVBaseURL(url string) AnalyzerOption {
	return func(a *Analyzer) { a.OSVBaseURL = url }
}

// WithAdvisoryCache gives the default OSV source a cache for advisory
// documents. It has no effect when WithSource supplies an explicit source,
// which brings its own caching arrangement.
//
// It lives here rather than being wired at the call site so the cache is
// applied to whatever endpoint OSVBaseURL names at scan time, instead of a
// second construction site having to remember to read that field.
func WithAdvisoryCache(c osvsource.AdvisoryCache) AnalyzerOption {
	return func(a *Analyzer) { a.advisoryCache = c }
}

// WithSource replaces the vulnerability source the analyzer queries. Without
// one the analyzer builds an OSV.dev source from OSVBaseURL and the configured
// HTTP client, which is the behaviour every existing caller gets.
//
// This is the seam a richer source plugs into. Anything it returns still passes
// through the same severity mapping, fix selection, and reachability scoping as
// an OSV record, so a source cannot quietly acquire different treatment by
// being a different source.
func WithSource(s vulnsource.Source) AnalyzerOption {
	return func(a *Analyzer) { a.source = s }
}

// WithLicensePolicy sets the license compliance policy for the analyzer.
// When set, the analyzer will detect licenses from manifest files and
// evaluate them against the policy, producing findings for violations.
func WithLicensePolicy(policy LicensePolicy) AnalyzerOption {
	return func(a *Analyzer) { a.licensePolicy = &policy }
}

// Analyzer scans lockfile artifacts, extracts dependency information, and
// queries the OSV database for known vulnerabilities.
type Analyzer struct {
	// OSVBaseURL is the base URL for the OSV vulnerability database API. It is
	// used to build the default source; an explicit source set by WithSource
	// ignores it.
	OSVBaseURL    string
	httpClient    *http.Client
	osvEnabled    bool
	licensePolicy *LicensePolicy

	// source resolves packages to known vulnerabilities. Nil means "build the
	// default OSV source at scan time" — deferred rather than built in
	// NewAnalyzer because OSVBaseURL is exported and callers set it directly.
	source vulnsource.Source

	// advisoryCache is applied to the default OSV source when one is built.
	advisoryCache osvsource.AdvisoryCache

	// degradations collects the checks this analyzer could not complete. It is
	// optional: a nil collector discards records, so library callers that do
	// not supply one behave exactly as before.
	degradations *degrade.Degradations
}

// WithDegradations gives the analyzer a collector to report incomplete checks
// to. Without one, a failed OSV lookup or an unparseable lockfile is
// indistinguishable from a clean result.
func WithDegradations(d *degrade.Degradations) AnalyzerOption {
	return func(a *Analyzer) { a.degradations = d }
}

// NewAnalyzer returns an Analyzer with the default OSV API endpoint.
func NewAnalyzer(opts ...AnalyzerOption) *Analyzer {
	a := &Analyzer{
		OSVBaseURL: "https://api.osv.dev",
		httpClient: &http.Client{Timeout: 30 * time.Second},
		osvEnabled: true,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// vulnSource returns the configured source, or an OSV.dev source built from the
// analyzer's current endpoint and HTTP client.
func (a *Analyzer) vulnSource() vulnsource.Source {
	if a.source != nil {
		return a.source
	}
	return osvsource.New(a.OSVBaseURL, a.httpClient, a.degradations).
		WithCache(a.advisoryCache)
}

// Rules returns the rule set for the dependency vulnerability analyzer.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          "VULN-001",
		Version:     "1.0",
		Description: "Known vulnerability in dependency",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceHigh,
		Tags:        []string{"dependency", "vulnerability", "sca"},
		Remediation: "Check the advisory for the minimum fixed version. Update the dependency in your package manager (Go: go get -u <module>@<fixed-version>, npm: npm install <package>@<fixed-version>, pip: pip install <package>>=<fixed-version>). Run your test suite to verify compatibility. If a major version bump is required, review the changelog for breaking changes. Update lockfiles (go mod tidy / npm install / pip freeze).",
		References:  []string{"https://osv.dev"},
		Metadata:    map[string]string{"cwe": "CWE-1395"},
	})
	rs.Add(&rules.Rule{
		ID:          "VULN-002",
		Version:     "1.0",
		Description: "Typosquatting: package name suspiciously similar to popular package",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceLow,
		Tags:        []string{"dependency", "typosquatting", "supply-chain"},
		Remediation: "Verify the package name is correct. The name is suspiciously similar to a popular package, which may indicate a typosquatting attack.",
		References:  []string{"https://snyk.io/blog/typosquatting-attacks/"},
		Metadata:    map[string]string{"cwe": "CWE-1357"},
	})
	rs.Add(&rules.Rule{
		ID:          "VULN-003",
		Version:     "1.0",
		Description: "Known malicious package detected",
		Severity:    findings.SeverityCritical,
		Confidence:  findings.ConfidenceHigh,
		Tags:        []string{"dependency", "malicious", "supply-chain"},
		Remediation: "Remove this package immediately. It has been identified as malicious and may contain backdoors, data exfiltration, or other harmful code.",
		References:  []string{"https://osv.dev"},
		Metadata:    map[string]string{"cwe": "CWE-506"},
	})
	rs.Add(&rules.Rule{
		ID:          "LIC-001",
		Version:     "1.0",
		Description: "Dependency uses a restricted license",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceHigh,
		Tags:        []string{"dependency", "license", "compliance"},
		Remediation: "Identify the exact license restriction (copyleft, non-commercial, etc.). Search for alternative packages with permissive licenses (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC). If no alternative exists, consult legal counsel for compliance. Document the decision in your project's NOTICE or LICENSE-THIRD-PARTY file. Use license-checker or go-licenses to audit transitive dependencies.",
		References:  []string{"https://spdx.org/licenses/"},
		Metadata:    map[string]string{"cwe": "CWE-1357"},
	})
	rs.Add(&rules.Rule{
		ID:          "CONT-001",
		Version:     "1.0",
		Description: "Container base image not pinned to specific digest",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		Tags:        []string{"container", "supply-chain", "pinning"},
		Remediation: "Pin the base image to a specific digest (e.g., FROM ubuntu@sha256:abc123) to ensure reproducible builds.",
		References:  []string{"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"},
		Metadata:    map[string]string{"cwe": "CWE-829"},
	})
	rs.Add(&rules.Rule{
		ID:          "CONT-002",
		Version:     "1.0",
		Description: "Container base image uses 'latest' tag or no tag",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceHigh,
		Tags:        []string{"container", "supply-chain", "pinning"},
		Remediation: "Specify an explicit version tag for the base image instead of relying on 'latest' (e.g., FROM node:18-alpine).",
		References:  []string{"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"},
		Metadata:    map[string]string{"cwe": "CWE-829"},
	})
	return rs
}

// supportedLockfiles maps well-known lockfile basenames to their parser
// functions.
var supportedLockfiles = map[string]func([]byte) ([]Package, error){
	// Go resolves from go.mod, deliberately NOT go.sum: go.sum hashes the
	// entire module graph, so it yields versions the build never selects
	// (~99% false positives in practice). See parseGoMod.
	"go.mod":             parseGoMod,
	"package-lock.json":  parsePackageLockJSON,
	"requirements.txt":   parseRequirementsTxt,
	"Gemfile.lock":       parseGemfileLock,
	"Cargo.lock":         parseCargoLock,
	"pom.xml":            parsePomXML,
	"build.gradle":       parseBuildGradle,
	"build.gradle.kts":   parseBuildGradle,
	"yarn.lock":          parseYarnLock,
	"pnpm-lock.yaml":     parsePnpmLock,
	"poetry.lock":        parsePoetryLock,
	"packages.lock.json": parseNuGetPackagesLock,
	"composer.lock":      parseComposerLock,
	"bom.json":           parseCycloneDXContent,
	"sbom.json":          parseSPDXContent,
}

// ParseLockfile detects the lockfile format from its filename and delegates
// to the appropriate parser. It returns an error if the filename is not
// recognised as a supported lockfile type.
func (a *Analyzer) ParseLockfile(path string, content []byte) ([]Package, error) {
	base := filepath.Base(path)
	parser, ok := supportedLockfiles[base]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedLockfile, base)
	}
	return parser(content)
}

// ScanArtifacts processes the provided artifacts, filters for Lockfile types,
// parses each one, queries OSV for known vulnerabilities, and returns a
// PackageInventory plus a FindingSet with vulnerability findings.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*PackageInventory, *findings.FindingSet, error) {
	inventory := &PackageInventory{}
	fs := findings.NewFindingSet()

	// Track which lockfile each package came from for finding locations.
	type pkgSource struct {
		lockfilePath string
	}
	var sources []pkgSource

	// Module root of the Go module under scan, used to enumerate the packages
	// the build actually links so advisories can be scoped by import path.
	var goModDir string

	for _, art := range artifacts {
		if art.Type != discovery.Lockfile {
			continue
		}

		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("reading lockfile %s: %w", art.Path, err)
		}

		var pkgs []Package
		if filepath.Base(art.AbsPath) == "go.mod" {
			goModDir = filepath.Dir(art.AbsPath)
			// Go needs both files: go.mod for the selected versions, go.sum to
			// recover transitives that module graph pruning left unnamed. A
			// missing or unreadable go.sum is fine — go.mod alone still resolves.
			goSum, _ := os.ReadFile(filepath.Join(filepath.Dir(art.AbsPath), "go.sum"))
			pkgs, err = resolveGoPackages(content, goSum)
		} else {
			pkgs, err = a.ParseLockfile(art.AbsPath, content)
		}
		if err != nil {
			// Two different situations reach here, and conflating them is how
			// yarn, pnpm, poetry and gradle projects came to get a silently
			// empty dependency scan.
			//
			// A file whose contents are redundant with one we DO parse (go.sum
			// against go.mod) is genuinely nothing to report; saying so on every
			// Go repository would train operators to ignore this channel.
			//
			// Anything else — a lockfile nox recognises well enough to classify
			// but has no parser for, or one that failed to parse — is a real
			// blind spot. Every dependency it declares is absent from
			// vulnerability matching, and the operator has no way to know.
			if !isRedundantLockfile(art.Path) {
				a.degradations.Add(degrade.Lockfile,
					fmt.Sprintf("%s was not parsed: %v", art.Path, err),
					"dependencies declared in this file were NOT scanned for vulnerabilities")
			}
			continue
		}

		for _, p := range pkgs {
			inventory.Add(p)
			sources = append(sources, pkgSource{lockfilePath: art.Path})
		}
	}

	// Scan Dockerfiles for base image references and container findings.
	for _, art := range artifacts {
		if art.Type != discovery.Container && !isDockerfile(art.Path) {
			continue
		}
		if !isDockerfile(art.Path) {
			continue
		}

		// Same class of blind spot as an unparsed lockfile: without the base
		// image nox has no container inventory and no base-image findings for
		// this file, and reported success either way.
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			a.degradations.Add(degrade.Lockfile,
				fmt.Sprintf("%s could not be read: %v", art.Path, err),
				"base images declared in this Dockerfile were NOT inventoried or scanned")
			continue
		}

		images, err := ParseDockerfile(content)
		if err != nil {
			a.degradations.Add(degrade.Lockfile,
				fmt.Sprintf("%s could not be parsed: %v", art.Path, err),
				"base images declared in this Dockerfile were NOT inventoried or scanned")
			continue
		}

		// Determine line numbers for each FROM instruction for precise locations.
		fromLines := dockerfileFromLines(content)

		for i, img := range images {
			inventory.Add(img)
			sources = append(sources, pkgSource{lockfilePath: art.Path})

			line := 1
			if i < len(fromLines) {
				line = fromLines[i]
			}

			// CONT-002: image uses "latest" tag (explicit or implicit).
			if imageUsesLatestTag(img.Version) {
				fs.Add(findings.Finding{
					RuleID:     "CONT-002",
					Severity:   findings.SeverityHigh,
					Confidence: findings.ConfidenceHigh,
					Location: findings.Location{
						FilePath:  art.Path,
						StartLine: line,
					},
					Message: fmt.Sprintf("Container base image %s uses 'latest' tag or no tag", img.Name),
					Metadata: map[string]string{
						"image":     img.Name,
						"version":   img.Version,
						"ecosystem": "docker",
					},
				})
			}

			// CONT-001: image not pinned to digest.
			if !imageIsPinnedToDigest(img.Version) {
				fs.Add(findings.Finding{
					RuleID:     "CONT-001",
					Severity:   findings.SeverityMedium,
					Confidence: findings.ConfidenceHigh,
					Location: findings.Location{
						FilePath:  art.Path,
						StartLine: line,
					},
					Message: fmt.Sprintf("Container base image %s:%s not pinned to specific digest", img.Name, img.Version),
					Metadata: map[string]string{
						"image":     img.Name,
						"version":   img.Version,
						"ecosystem": "docker",
					},
				})
			}
		}
	}

	// Detect licenses from manifest files alongside lockfiles.
	// This is best-effort: failures are silently ignored.
	for _, art := range artifacts {
		if art.Type != discovery.Lockfile {
			continue
		}
		basePath := filepath.Dir(art.AbsPath)
		DetectLicenses(basePath, inventory)
	}

	// Evaluate license policy if configured.
	if a.licensePolicy != nil {
		licFindings := CheckLicenses(inventory, a.licensePolicy.Deny, a.licensePolicy.Allow)
		for i := range licFindings {
			fs.Add(licFindings[i])
		}
	}

	// Malicious package detection: check for known malicious packages and
	// typosquatting before making any network calls. This runs entirely
	// offline using embedded data.
	{
		pkgs := inventory.Packages()
		// Report any embedded dataset that failed to load. Both checks below
		// silently return "not malicious" / "not a typosquat" when their data
		// is missing, so without this a supply-chain scan that never loaded its
		// attack data is indistinguishable from one that found nothing.
		for _, failure := range dataLoadFailures() {
			a.degradations.Add(degrade.VulnData, failure,
				"malicious-package and typosquatting detection did not run against this dataset")
		}

		for i, pkg := range pkgs {
			lockfilePath := ""
			if i < len(sources) {
				lockfilePath = sources[i].lockfilePath
			}

			// VULN-003: known malicious package.
			if IsKnownMalicious(pkg.Name, pkg.Ecosystem) {
				fs.Add(findings.Finding{
					RuleID:     "VULN-003",
					Severity:   findings.SeverityCritical,
					Confidence: findings.ConfidenceHigh,
					Location: findings.Location{
						FilePath:  lockfilePath,
						StartLine: 1,
					},
					Message: fmt.Sprintf("Known malicious package detected: %s@%s (%s)", pkg.Name, pkg.Version, pkg.Ecosystem),
					Metadata: map[string]string{
						"package":   pkg.Name,
						"version":   pkg.Version,
						"ecosystem": pkg.Ecosystem,
					},
				})
			}

			// VULN-002: typosquatting detection. A distance-1 (single-character)
			// match is the high-precision signal; distance 2 collides with too
			// many legitimate packages that merely resemble a popular name
			// (regex/redux, parse5/parcel, h3/d3, …). This is a heuristic
			// SUSPICION — not a confirmed malicious package (that is VULN-003) —
			// so it is medium severity / low confidence, not a CI-blocking
			// critical.
			if popularName, typosquat := DetectTyposquatting(pkg.Name, pkg.Ecosystem, 1); typosquat {
				fs.Add(findings.Finding{
					RuleID:     "VULN-002",
					Severity:   findings.SeverityMedium,
					Confidence: findings.ConfidenceLow,
					Location: findings.Location{
						FilePath:  lockfilePath,
						StartLine: 1,
					},
					Message: fmt.Sprintf("Possible typosquatting: %s is suspiciously similar to popular package %s", pkg.Name, popularName),
					Metadata: map[string]string{
						"package":         pkg.Name,
						"version":         pkg.Version,
						"ecosystem":       pkg.Ecosystem,
						"similar_package": popularName,
					},
				})
			}
		}
	}

	// Query OSV for vulnerabilities if enabled.
	if a.osvEnabled {
		pkgs := inventory.Packages()
		if len(pkgs) > 0 {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()

			src := a.vulnSource()
			queries := make([]vulnsource.Query, len(pkgs))
			for i, p := range pkgs {
				queries[i] = vulnsource.Query{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version}
			}

			vulnMap, err := src.Lookup(ctx, queries)
			if err != nil {
				return nil, nil, fmt.Errorf("querying %s: %w", src.Name(), err)
			}

			// Enumerate the packages this build links, once, so Go advisories
			// can be scoped to the import paths they actually affect. Best
			// effort: when it cannot be determined, every finding is reported
			// exactly as before.
			var (
				linkedGoPkgs  map[string]struct{}
				linkedGoKnown bool
			)
			if goModDir != "" {
				linkedGoPkgs, linkedGoKnown = goImportedPackages(ctx, goModDir)
			}

			for pkgIdx, osvVulns := range vulnMap {
				pkg := pkgs[pkgIdx]
				var domainVulns []Vulnerability

				for _, ov := range osvVulns {
					sev := mapOSVSeverity(ov.Severity, ov.DatabaseSpecific)
					domainVulns = append(domainVulns, Vulnerability{
						ID:       ov.ID,
						Summary:  ov.Summary,
						Severity: sev,
						Aliases:  ov.Aliases,
						Details:  ov.Details,
					})

					lockfilePath := ""
					if pkgIdx < len(sources) {
						lockfilePath = sources[pkgIdx].lockfilePath
					}

					aliases := strings.Join(ov.Aliases, ",")
					meta := map[string]string{
						"vuln_id":   ov.ID,
						"package":   pkg.Name,
						"version":   pkg.Version,
						"ecosystem": pkg.Ecosystem,
						"aliases":   aliases,
					}
					// Epistemic status travels with the finding. A published
					// advisory and an undisclosed candidate are not the same
					// claim, and rendering them identically is how a projection
					// gets read as an observation.
					status := ov.Status()
					meta["vuln_status"] = string(status)
					if intel := ov.Intelligence; intel != nil {
						if intel.SourceName != "" {
							meta["intel_source"] = intel.SourceName
						}
						if intel.Corroboration > 0 {
							// Distinct reporters, never observation count.
							meta["intel_corroboration"] = strconv.Itoa(intel.Corroboration)
						}
						if intel.Evidence != nil {
							meta["intel_confidence"] = string(intel.Evidence.Confidence())
						}
					}
					if fix := fixedVersion(&ov, pkg.Name, pkg.Ecosystem, pkg.Version); fix != "" {
						meta["fixed_in"] = fix
						meta["remediation_action"] = "upgrade"
						meta["remediation_command"] = upgradeCommand(pkg.Ecosystem, pkg.Name, fix)
					}
					// OSV scopes Go advisories to import paths. When the affected
					// packages are provably not linked, the finding is recorded
					// but demoted out of gating severity rather than dropped: a
					// silent disappearance is indistinguishable from a scanner
					// that simply missed it.
					message := fmt.Sprintf("Known vulnerability %s in %s@%s: %s", ov.ID, pkg.Name, pkg.Version, ov.Summary)

					// A record with no published advisory is a projection, and
					// says so wherever it is rendered. It is also demoted out of
					// gating severity: an uncorroborated candidate that fails a
					// build the way a CVE does burns the feature on its first
					// false positive, and an operator who starts ignoring
					// candidate findings is worse off than one who never saw
					// them. Demoted, not dropped — a silent disappearance is
					// indistinguishable from a scanner that missed it. This is
					// the same treatment an unreachable Go advisory gets below.
					if !status.Gating() {
						sev = findings.SeverityInfo
						message = fmt.Sprintf("THEORETICAL %s in %s@%s: %s",
							strings.ToLower(string(status)), pkg.Name, pkg.Version, ov.Summary)
						if ov.Theoretical() {
							meta["theoretical"] = "true"
						}
					}
					// Applicability: how far the argument from "this advisory
					// exists" to "an attacker can use it here" actually got, and
					// why it stopped. Recorded on every dependency finding,
					// including — especially — the ones where it got nowhere,
					// because "we could not tell" and "we did not look" are the
					// answers a reader most needs and least often gets.
					verdict := applicabilityFor(pkg, &ov, linkedGoPkgs, linkedGoKnown)
					meta["applicability"] = string(verdict.Outcome)
					meta["applicability_reached"] = string(verdict.Reached)
					if verdict.StoppedAt != "" {
						meta["applicability_stopped_at"] = string(verdict.StoppedAt)
						meta["applicability_because"] = string(verdict.Because)
					}

					if pkg.Ecosystem == "go" {
						affected := goAffectedImports(&ov, pkg.Name)
						if r, ok := goSymbolReferenced(affected, linkedGoPkgs, linkedGoKnown); ok {
							meta["affected_imports"] = strings.Join(affected, ",")
							// The LEVEL, named. `go list -deps` establishes that
							// the affected import is in the linked set, which is
							// symbol_referenced and nothing above it. This used to
							// be written as meta["reachable"], a name that reads as
							// call_reachable, and the capability matrix then counted
							// it as the reachability capability — evidence for one
							// proposition establishing a later one, which is the
							// invariant this vocabulary exists to hold.
							meta["reach_level"] = string(r.Level)
							meta["reach_outcome"] = string(r.Outcome)
							meta["reach_scope"] = r.Scope.Describe()
							if r.Outcome == reach.Refuted {
								// Refuted at symbol_referenced only: the build links
								// no affected package. Severity drops because there
								// is nothing here to call, not because the
								// application was shown to be unaffected.
								sev = findings.SeverityInfo
							}
						}
					}

					// The message says what was established rather than only
					// what was not. "not reachable" alone invites the reader to
					// supply the more comfortable reading; the ladder says how
					// far nox got and where it stopped.
					message += " — " + verdict.Describe()

					fs.Add(findings.Finding{
						RuleID:     "VULN-001",
						Severity:   sev,
						Confidence: findings.ConfidenceHigh,
						Location: findings.Location{
							FilePath:  lockfilePath,
							StartLine: 1,
						},
						Message:  message,
						Metadata: meta,
					})
				}

				inventory.SetVulnerabilities(pkgIdx, domainVulns)
			}
		}
	}

	return inventory, fs, nil
}

// applicabilityFor climbs the applicability ladder as far as the evidence
// actually supports, and records where it stopped.
//
// Every rung above SymbolUsed is currently out of reach: nox has no call-graph
// analysis, so CallReachable cannot be established for anything. Saying so is
// the point. A scanner that stops climbing and stays silent leaves the reader
// to assume it stopped because there was nothing above; this says it stopped
// because nobody has built the thing that would look.
func applicabilityFor(pkg Package, ov *osvVuln, linked map[string]struct{}, linkedKnown bool) applicability.Verdict {
	// Present and AffectedVersion are established by the fact of the finding:
	// the package is in the lockfile, and OSV matched its version.
	const reached = applicability.AffectedVersion

	if pkg.Ecosystem != "go" {
		// Dependency reachability is implemented for Go only. An npm package is
		// not unreachable; it is unexamined, and nothing here could examine it.
		return applicability.Undeterminable(reached, applicability.SymbolUsed, capability.Unsupported)
	}

	affected := goAffectedImports(ov, pkg.Name)
	reachable, determined := goVulnReachable(affected, linked, linkedKnown)
	if !determined {
		// The advisory named no import paths, or the linked set is unknown.
		// Either way nothing was established, and the rung stays unclimbed.
		return applicability.Undeterminable(reached, applicability.SymbolUsed, capability.Unknown)
	}
	if !reachable {
		return applicability.Refuted(reached, applicability.SymbolUsed, capability.Negative,
			[]string{"the build links no package under " + strings.Join(affected, ", ")})
	}

	// The affected package IS linked. That is SymbolUsed established — and the
	// next rung, whether anything calls it, is one nox cannot climb at all.
	return applicability.Undeterminable(applicability.SymbolUsed,
		applicability.CallReachable, capability.Unsupported)
}
