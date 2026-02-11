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

// Analyzer scans lockfile artifacts, extracts dependency information, and
// queries the OSV database for known vulnerabilities.
type Analyzer struct {
	// OSVBaseURL is the base URL for the OSV vulnerability database API.
	OSVBaseURL string
	httpClient *http.Client
	osvEnabled bool
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
	rs.Add(rules.Rule{
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
