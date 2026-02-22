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
var supportedEcosystems = map[string]bool{
	"Go":   true,
	"PyPI": true,
	"npm":  true,
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
	default:
		return strings.ToLower(pkg)
	}
}
