package main

import "strings"

// VulnInfo holds the relevant fields from a VULN finding.
type VulnInfo struct {
	Fingerprint string
	Package     string
	Ecosystem   string
	VulnID      string
}

// ReachStatus classifies the reachability of a vulnerable package.
type ReachStatus int

const (
	ReachUnreachable  ReachStatus = iota // Not imported
	ReachReachable                       // Imported in workspace
	ReachUndetermined                    // Unsupported ecosystem
)

// Result holds the reachability analysis outcome for a single VULN finding.
type Result struct {
	Vuln   VulnInfo
	Status ReachStatus
	RuleID string
}

// supportedEcosystems lists ecosystems we can perform import analysis on.
// Precision class per language is documented per extractor:
//   - Go: AST-based (parser.ParseFile); precision class A
//   - PyPI: top-level module regex + PEP 503 distribution-name normalisation; class B
//   - npm: import/require regex + scoped-package handling; class B
//   - crates.io: `use foo::...` regex with std exclusion; class B
//   - Maven: import-statement regex collapsed to top-three segments; class C (over-reports)
//   - RubyGems: require/require_relative regex; class B
//   - NuGet: using-statement regex collapsed to top-two segments; class C (over-reports)
//
// "Over-reports" means false-positives on reachability are possible,
// which is the safer direction (we never silently miss an exploited
// vulnerability path).
var supportedEcosystems = map[string]bool{
	"Go":        true,
	"PyPI":      true,
	"npm":       true,
	"crates.io": true,
	"Maven":     true,
	"RubyGems":  true,
	"NuGet":     true,
}

// Analyze cross-references VULN findings against workspace imports and
// produces a Result for each.
func Analyze(vulns []VulnInfo, imports *ImportSet) []Result {
	results := make([]Result, 0, len(vulns))

	for _, v := range vulns {
		imported, supported := isImported(v.Package, v.Ecosystem, imports)

		var r Result
		r.Vuln = v

		switch {
		case !supported:
			r.Status = ReachUndetermined
			r.RuleID = "REACH-003"
		case imported:
			r.Status = ReachReachable
			r.RuleID = "REACH-002"
		default:
			r.Status = ReachUnreachable
			r.RuleID = "REACH-001"
		}

		results = append(results, r)
	}

	return results
}

// isImported checks whether pkg is imported in the workspace for the given
// ecosystem. Returns (imported, supported).
func isImported(pkg, ecosystem string, imports *ImportSet) (imported, supported bool) {
	if !supportedEcosystems[ecosystem] {
		return false, false
	}

	name := normalizePackageName(pkg, ecosystem)
	return imports.Contains(ecosystem, name), true
}

// normalizePackageName maps a dependency name to the form used in source imports.
func normalizePackageName(pkg, ecosystem string) string {
	switch ecosystem {
	case "Go":
		// Go imports use the full module path as-is.
		return pkg
	case "PyPI":
		return PyPIToImportName(pkg)
	case "npm":
		// npm package names match import specifiers directly.
		return pkg
	case "crates.io":
		// Cargo crate names use hyphens but `use` paths use underscores
		// after the crate root. We index extractors on the crate root
		// segment which preserves underscores.
		return strings.ReplaceAll(strings.ToLower(pkg), "-", "_")
	case "Maven":
		// Maven coordinates are `group:artifact`; reachability indexes
		// on `group.artifact-leading-segments`. Take the group portion
		// when present, else the bare name.
		if idx := strings.IndexByte(pkg, ':'); idx > 0 {
			return pkg[:idx]
		}
		return pkg
	case "RubyGems":
		return strings.ToLower(pkg)
	case "NuGet":
		return pkg
	default:
		return strings.ToLower(pkg)
	}
}
