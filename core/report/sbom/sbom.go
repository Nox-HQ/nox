// Package sbom generates CycloneDX and SPDX SBOM documents from a dependency
// package inventory. Both generators produce deterministic JSON output suitable
// for ingestion by vulnerability scanners and compliance tools.
package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/report"
)

// ---------------------------------------------------------------------------
// CycloneDX 1.5 JSON
// ---------------------------------------------------------------------------

// CDXReport is the top-level CycloneDX BOM structure.
type CDXReport struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        CDXMetadata        `json:"metadata"`
	Components      []CDXComponent     `json:"components"`
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities,omitempty"`
}

// CDXMetadata holds tool and timestamp information.
type CDXMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []CDXTool `json:"tools"`
}

// CDXTool identifies the tool that generated the BOM.
type CDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CDXLicense represents a license in CycloneDX format.
type CDXLicense struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CDXLicenseWrapper wraps a CDXLicense for the CycloneDX licenses array.
type CDXLicenseWrapper struct {
	License CDXLicense `json:"license"`
}

// CDXComponent represents a single dependency.
type CDXComponent struct {
	Type     string              `json:"type"`
	BOMRef   string              `json:"bom-ref"`
	Name     string              `json:"name"`
	Version  string              `json:"version"`
	PURL     string              `json:"purl"`
	Licenses []CDXLicenseWrapper `json:"licenses,omitempty"`
}

// CDXVulnerability represents a known vulnerability in the CycloneDX format.
type CDXVulnerability struct {
	ID          string      `json:"id"`
	Source      CDXSource   `json:"source"`
	Ratings     []CDXRating `json:"ratings,omitempty"`
	Description string      `json:"description,omitempty"`
	Affects     []CDXAffect `json:"affects"`
}

// CDXSource identifies the vulnerability database source.
type CDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// CDXRating holds a severity rating for a vulnerability.
type CDXRating struct {
	Severity string `json:"severity"`
}

// CDXAffect identifies a component affected by a vulnerability.
type CDXAffect struct {
	Ref string `json:"ref"`
}

// CycloneDXReporter generates CycloneDX 1.5 JSON SBOMs.
type CycloneDXReporter struct {
	ToolVersion string
}

// NewCycloneDXReporter returns a reporter configured with the given tool version.
func NewCycloneDXReporter(version string) *CycloneDXReporter {
	return &CycloneDXReporter{ToolVersion: version}
}

// Generate produces a CycloneDX JSON byte slice from the package inventory.
func (r *CycloneDXReporter) Generate(inventory *deps.PackageInventory) ([]byte, error) {
	pkgs := inventory.Packages()

	// Build a map from original index to package for vulnerability lookup.
	// We need to track original indices through sorting.
	type indexedPkg struct {
		pkg     deps.Package
		origIdx int
	}
	indexed := make([]indexedPkg, len(pkgs))
	for i, p := range pkgs {
		indexed[i] = indexedPkg{pkg: p, origIdx: i}
	}

	// Sort deterministically by ecosystem, then name, then version.
	sort.Slice(indexed, func(i, j int) bool {
		a, b := indexed[i].pkg, indexed[j].pkg
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})

	components := make([]CDXComponent, 0, len(indexed))
	bomRefs := make(map[int]string) // origIdx -> bom-ref
	for i, ip := range indexed {
		bomRef := fmt.Sprintf("pkg:%d", i)
		bomRefs[ip.origIdx] = bomRef
		comp := CDXComponent{
			Type:    "library",
			BOMRef:  bomRef,
			Name:    ip.pkg.Name,
			Version: ip.pkg.Version,
			PURL:    buildPURL(ip.pkg),
		}
		if ip.pkg.License != "" {
			comp.Licenses = []CDXLicenseWrapper{{License: cdxLicenseFor(ip.pkg.License)}}
		}
		components = append(components, comp)
	}

	// Build vulnerability entries from inventory.
	allVulns := inventory.AllVulnerabilities()
	var cdxVulns []CDXVulnerability
	if allVulns != nil {
		// Collect and sort for deterministic output.
		type vulnEntry struct {
			origIdx int
			vuln    deps.Vulnerability
		}
		var entries []vulnEntry
		for idx, vulns := range allVulns {
			for _, v := range vulns {
				entries = append(entries, vulnEntry{origIdx: idx, vuln: v})
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			// Sort by vuln.ID first, then by the package's original index as a
			// deterministic tie-breaker. Entries are collected by ranging a map
			// (randomized order in Go), so when one CVE affects several packages
			// its entries share an equal vuln.ID; without this tie-breaker their
			// relative order would vary run to run, breaking nox's byte-identical
			// output guarantee.
			if entries[i].vuln.ID != entries[j].vuln.ID {
				return entries[i].vuln.ID < entries[j].vuln.ID
			}
			return entries[i].origIdx < entries[j].origIdx
		})

		for _, e := range entries {
			ref, ok := bomRefs[e.origIdx]
			if !ok {
				continue
			}
			cdxVuln := CDXVulnerability{
				ID: e.vuln.ID,
				Source: CDXSource{
					Name: "OSV",
					URL:  "https://osv.dev/vulnerability/" + e.vuln.ID,
				},
				Description: e.vuln.Summary,
				Affects:     []CDXAffect{{Ref: ref}},
			}
			if e.vuln.Severity != "" {
				cdxVuln.Ratings = []CDXRating{{Severity: string(e.vuln.Severity)}}
			}
			cdxVulns = append(cdxVulns, cdxVuln)
		}
	}

	doc := CDXReport{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: deterministicSerialURN(components),
		Version:      1,
		Metadata: CDXMetadata{
			Timestamp: report.GeneratedAt(),
			Tools: []CDXTool{
				{
					Vendor:  "nox",
					Name:    "nox",
					Version: r.ToolVersion,
				},
			},
		},
		Components:      components,
		Vulnerabilities: cdxVulns,
	}

	return json.MarshalIndent(doc, "", "  ")
}

// WriteToFile generates the CycloneDX report and writes it to the given path.
func (r *CycloneDXReporter) WriteToFile(inventory *deps.PackageInventory, path string) error {
	data, err := r.Generate(inventory)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ---------------------------------------------------------------------------
// SPDX 2.3 JSON
// ---------------------------------------------------------------------------

// SPDXDocument is the top-level SPDX document structure.
type SPDXDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo   `json:"creationInfo"`
	Packages          []SPDXPackage      `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships"`
}

// SPDXCreationInfo contains creation metadata.
type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDXPackage represents a single package in the SPDX document.
type SPDXPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DeclaredLicense  string            `json:"licenseDeclared"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
}

// SPDXExternalRef is a reference to an external resource.
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXRelationship describes a relationship between SPDX elements.
type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// SPDXReporter generates SPDX 2.3 JSON SBOMs.
type SPDXReporter struct {
	ToolVersion string
}

// NewSPDXReporter returns a reporter configured with the given tool version.
func NewSPDXReporter(version string) *SPDXReporter {
	return &SPDXReporter{ToolVersion: version}
}

// Generate produces an SPDX 2.3 JSON byte slice from the package inventory.
func (r *SPDXReporter) Generate(inventory *deps.PackageInventory) ([]byte, error) {
	pkgs := inventory.Packages()

	// Build a map from original index to package for vulnerability lookup.
	type indexedPkg struct {
		pkg     deps.Package
		origIdx int
	}
	indexed := make([]indexedPkg, len(pkgs))
	for i, p := range pkgs {
		indexed[i] = indexedPkg{pkg: p, origIdx: i}
	}

	// Sort deterministically.
	sort.Slice(indexed, func(i, j int) bool {
		a, b := indexed[i].pkg, indexed[j].pkg
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})

	allVulns := inventory.AllVulnerabilities()

	spdxPkgs := make([]SPDXPackage, 0, len(indexed))
	relationships := make([]SPDXRelationship, 0, len(indexed))

	for i, ip := range indexed {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i)
		purl := buildPURL(ip.pkg)

		// SPDX 2.3 requires licenseDeclared to be a valid SPDX license
		// expression, NOASSERTION, or NONE. Free-text like "Apache 2.0" (with a
		// space) or "see LICENSE file" would produce a spec-invalid document, so
		// only emit the license when it is a recognized SPDX identifier and fall
		// back to NOASSERTION otherwise. This mirrors the CycloneDX path's use of
		// the spdxLicenseIDs whitelist.
		declaredLicense := "NOASSERTION"
		if spdxLicenseIDs[ip.pkg.License] {
			declaredLicense = ip.pkg.License
		}

		pkg := SPDXPackage{
			SPDXID:           spdxID,
			Name:             ip.pkg.Name,
			VersionInfo:      ip.pkg.Version,
			DeclaredLicense:  declaredLicense,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		}

		var refs []SPDXExternalRef
		if purl != "" {
			refs = append(refs, SPDXExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			})
		}

		// Add SECURITY external refs for known vulnerabilities.
		if allVulns != nil {
			vulns := allVulns[ip.origIdx]
			// Sort vuln IDs for deterministic output.
			sortedVulns := make([]deps.Vulnerability, len(vulns))
			copy(sortedVulns, vulns)
			sort.Slice(sortedVulns, func(a, b int) bool {
				return sortedVulns[a].ID < sortedVulns[b].ID
			})
			for _, v := range sortedVulns {
				refs = append(refs, SPDXExternalRef{
					ReferenceCategory: "SECURITY",
					ReferenceType:     "advisory",
					ReferenceLocator:  "https://osv.dev/vulnerability/" + v.ID,
				})
			}
		}

		if len(refs) > 0 {
			pkg.ExternalRefs = refs
		}

		spdxPkgs = append(spdxPkgs, pkg)

		relationships = append(relationships, SPDXRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: spdxID,
		})
	}

	doc := SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "nox-scan",
		DocumentNamespace: "https://github.com/nox-hq/nox/scans",
		CreationInfo: SPDXCreationInfo{
			Created:  report.GeneratedAt(),
			Creators: []string{fmt.Sprintf("Tool: nox-%s", r.ToolVersion)},
		},
		Packages:      spdxPkgs,
		Relationships: relationships,
	}

	return json.MarshalIndent(doc, "", "  ")
}

// WriteToFile generates the SPDX report and writes it to the given path.
func (r *SPDXReporter) WriteToFile(inventory *deps.PackageInventory, path string) error {
	data, err := r.Generate(inventory)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// purlEcosystems maps internal ecosystem names to PURL type prefixes.
var purlEcosystems = map[string]string{
	"go":       "golang",
	"npm":      "npm",
	"pypi":     "pypi",
	"rubygems": "gem",
	"cargo":    "cargo",
	"maven":    "maven",
	"gradle":   "maven",
	"nuget":    "nuget",
}

// buildPURL constructs a Package URL (purl) for the given package.
// See https://github.com/package-url/purl-spec for the format.
func buildPURL(p deps.Package) string {
	purlType, ok := purlEcosystems[p.Ecosystem]
	if !ok {
		return ""
	}
	// Maven PURLs use namespace/name format for groupId:artifactId.
	if (p.Ecosystem == "maven" || p.Ecosystem == "gradle") && strings.Contains(p.Name, ":") {
		parts := strings.SplitN(p.Name, ":", 2)
		return fmt.Sprintf("pkg:%s/%s/%s@%s", purlType, parts[0], parts[1], p.Version)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", purlType, p.Name, p.Version)
}

// deterministicSerialURN returns a valid RFC-4122 UUID URN derived from the
// component set. CycloneDX constrains serialNumber to the UUID URN grammar, so
// the previous constant "urn:uuid:nox-scan" failed schema validation on every
// document. Deriving it from a content hash keeps nox's reproducible-output
// guarantee — identical input yields an identical serial — while remaining a
// well-formed, per-scan-unique UUID.
func deterministicSerialURN(components []CDXComponent) string {
	h := sha256.New()
	for i := range components {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\n", components[i].Name, components[i].Version, components[i].PURL)
	}
	sum := h.Sum(nil)
	// Format 16 bytes as a UUID, stamping the version (4) and variant (RFC 4122)
	// nibbles so the result is a syntactically valid UUID.
	var u [16]byte
	copy(u[:], sum)
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// spdxLicenseIDs is the set of SPDX identifiers common in real dependency
// metadata. CycloneDX validates license.id against the SPDX enumeration, so an
// arbitrary string there (e.g. "Apache 2.0" with a space, or proprietary text)
// fails the schema. Anything not confirmed here goes into license.name, which
// accepts free text — always schema-valid, if less precise.
var spdxLicenseIDs = map[string]bool{
	"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
	"ISC": true, "MPL-2.0": true, "LGPL-2.1": true, "LGPL-2.1-only": true,
	"LGPL-3.0": true, "LGPL-3.0-only": true, "GPL-2.0": true, "GPL-2.0-only": true,
	"GPL-3.0": true, "GPL-3.0-only": true, "GPL-3.0-or-later": true,
	"AGPL-3.0": true, "AGPL-3.0-only": true, "Unlicense": true, "0BSD": true,
	"CC0-1.0": true, "CC-BY-4.0": true, "BSL-1.0": true, "Zlib": true,
	"Artistic-2.0": true, "EPL-2.0": true, "WTFPL": true, "Python-2.0": true,
}

// cdxLicenseFor routes a license string to license.id (valid SPDX IDs only) or
// license.name (everything else), keeping the CycloneDX document schema-valid.
func cdxLicenseFor(license string) CDXLicense {
	if spdxLicenseIDs[license] {
		return CDXLicense{ID: license}
	}
	return CDXLicense{Name: license}
}
