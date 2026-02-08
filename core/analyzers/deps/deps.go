// Package deps implements dependency manifest scanning and OSV lookup.
//
// The analyzer parses lockfiles from multiple ecosystems (Go, npm, PyPI,
// RubyGems, Cargo), builds a PackageInventory, and produces a FindingSet
// for any known vulnerabilities. Lockfile format detection is driven by
// the filename so callers can feed arbitrary paths without configuration.
package deps

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// Package represents a single dependency extracted from a lockfile.
type Package struct {
	Name      string
	Version   string
	Ecosystem string // "npm", "go", "pypi", "rubygems", "cargo"
}

// Vulnerability describes a known security issue for a package.
type Vulnerability struct {
	ID               string
	Summary          string
	Severity         findings.Severity
	AffectedVersions string
}

// PackageInventory is a thread-safe, ordered collection of discovered packages.
type PackageInventory struct {
	mu   sync.Mutex
	pkgs []Package
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

// Analyzer scans lockfile artifacts, extracts dependency information, and
// (in the future) queries the OSV database for known vulnerabilities.
type Analyzer struct {
	// OSVBaseURL is the base URL for the OSV vulnerability database API.
	OSVBaseURL string
}

// NewAnalyzer returns an Analyzer with the default OSV API endpoint.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		OSVBaseURL: "https://api.osv.dev",
	}
}

// supportedLockfiles maps well-known lockfile basenames to their parser
// functions.
var supportedLockfiles = map[string]func([]byte) ([]Package, error){
	"go.sum":            parseGoSum,
	"package-lock.json": parsePackageLockJSON,
	"requirements.txt":  parseRequirementsTxt,
	"Gemfile.lock":      parseGemfileLock,
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
// parses each one, and returns a PackageInventory plus an (initially empty)
// FindingSet. OSV vulnerability lookups will be added in a follow-up.
func (a *Analyzer) ScanArtifacts(artifacts []discovery.Artifact) (*PackageInventory, *findings.FindingSet, error) {
	inventory := &PackageInventory{}
	fs := findings.NewFindingSet()

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
			// Skip lockfiles we cannot parse (e.g. yarn.lock, Cargo.lock)
			// rather than failing the entire scan.
			continue
		}

		for _, p := range pkgs {
			inventory.Add(p)
		}
	}

	return inventory, fs, nil
}
