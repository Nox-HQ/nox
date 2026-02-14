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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

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

// WithOSVBaseURL overrides the default OSV API base URL.
func WithOSVBaseURL(url string) AnalyzerOption {
	return func(a *Analyzer) { a.OSVBaseURL = url }
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
	// OSVBaseURL is the base URL for the OSV vulnerability database API.
	OSVBaseURL    string
	httpClient    *http.Client
	osvEnabled    bool
	licensePolicy *LicensePolicy
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
		Remediation: "Update the affected dependency to a patched version. Check the advisory for details on which versions contain the fix.",
		References:  []string{"https://osv.dev"},
		Metadata:    map[string]string{"cwe": "CWE-1395"},
	})
	rs.Add(&rules.Rule{
		ID:          "VULN-002",
		Version:     "1.0",
		Description: "Typosquatting: package name suspiciously similar to popular package",
		Severity:    findings.SeverityCritical,
		Confidence:  findings.ConfidenceMedium,
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
		Remediation: "Review the license terms of this dependency. Consider replacing it with an alternative that uses a compatible license.",
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
	"go.sum":             parseGoSum,
	"package-lock.json":  parsePackageLockJSON,
	"requirements.txt":   parseRequirementsTxt,
	"Gemfile.lock":       parseGemfileLock,
	"Cargo.lock":         parseCargoLock,
	"pom.xml":            parsePomXML,
	"build.gradle":       parseBuildGradle,
	"build.gradle.kts":   parseBuildGradle,
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
		return nil, fmt.Errorf("unsupported lockfile type: %s", base)
	}
	return parser(content)
}

// ScanArtifacts processes the provided artifacts, filters for Lockfile types,
// parses each one, queries OSV for known vulnerabilities, and returns a
// PackageInventory plus a FindingSet with vulnerability findings.
func (a *Analyzer) ScanArtifacts(artifacts []discovery.Artifact) (*PackageInventory, *findings.FindingSet, error) {
	inventory := &PackageInventory{}
	fs := findings.NewFindingSet()

	// Track which lockfile each package came from for finding locations.
	type pkgSource struct {
		lockfilePath string
	}
	var sources []pkgSource

	for _, art := range artifacts {
		if art.Type != discovery.Lockfile {
			continue
		}

		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("reading lockfile %s: %w", art.Path, err)
		}

		pkgs, err := a.ParseLockfile(art.AbsPath, content)
		if err != nil {
			// Skip lockfiles we cannot parse (e.g. yarn.lock)
			// rather than failing the entire scan.
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

		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			continue // best-effort: skip unreadable files
		}

		images, err := ParseDockerfile(content)
		if err != nil {
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

			// VULN-002: typosquatting detection.
			if popularName, typosquat := DetectTyposquatting(pkg.Name, pkg.Ecosystem, 2); typosquat {
				fs.Add(findings.Finding{
					RuleID:     "VULN-002",
					Severity:   findings.SeverityCritical,
					Confidence: findings.ConfidenceMedium,
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
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			vulnMap, err := queryOSV(ctx, a.httpClient, a.OSVBaseURL, pkgs)
			if err != nil {
				return nil, nil, fmt.Errorf("querying OSV: %w", err)
			}

			for pkgIdx, osvVulns := range vulnMap {
				pkg := pkgs[pkgIdx]
				var domainVulns []Vulnerability

				for _, ov := range osvVulns {
					sev := mapOSVSeverity(ov.Severity)
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
					fs.Add(findings.Finding{
						RuleID:     "VULN-001",
						Severity:   sev,
						Confidence: findings.ConfidenceHigh,
						Location: findings.Location{
							FilePath:  lockfilePath,
							StartLine: 1,
						},
						Message: fmt.Sprintf("Known vulnerability %s in %s@%s: %s", ov.ID, pkg.Name, pkg.Version, ov.Summary),
						Metadata: map[string]string{
							"vuln_id":   ov.ID,
							"package":   pkg.Name,
							"version":   pkg.Version,
							"ecosystem": pkg.Ecosystem,
							"aliases":   aliases,
						},
					})
				}

				inventory.SetVulnerabilities(pkgIdx, domainVulns)
			}
		}
	}

	return inventory, fs, nil
}
