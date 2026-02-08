// Package sbom generates CycloneDX and SPDX SBOM documents from a dependency
// package inventory. Both generators produce deterministic JSON output suitable
// for ingestion by vulnerability scanners and compliance tools.
package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/nox-hq/nox/core/analyzers/deps"
)

// ---------------------------------------------------------------------------
// CycloneDX 1.5 JSON
// ---------------------------------------------------------------------------

// CDXReport is the top-level CycloneDX BOM structure.
type CDXReport struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     CDXMetadata    `json:"metadata"`
	Components   []CDXComponent `json:"components"`
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

// CDXComponent represents a single dependency.
type CDXComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
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

	// Sort deterministically by ecosystem, then name, then version.
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})

	components := make([]CDXComponent, 0, len(pkgs))
	for _, p := range pkgs {
		components = append(components, CDXComponent{
			Type:    "library",
			Name:    p.Name,
			Version: p.Version,
			PURL:    buildPURL(p),
		})
	}

	report := CDXReport{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:nox-scan",
		Version:      1,
		Metadata: CDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CDXTool{
				{
					Vendor:  "nox",
					Name:    "nox",
					Version: r.ToolVersion,
				},
			},
		},
		Components: components,
	}

	return json.MarshalIndent(report, "", "  ")
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

	// Sort deterministically.
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})

	spdxPkgs := make([]SPDXPackage, 0, len(pkgs))
	relationships := make([]SPDXRelationship, 0, len(pkgs))

	for i, p := range pkgs {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i)
		purl := buildPURL(p)

		pkg := SPDXPackage{
			SPDXID:           spdxID,
			Name:             p.Name,
			VersionInfo:      p.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		}

		if purl != "" {
			pkg.ExternalRefs = []SPDXExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  purl,
				},
			}
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
			Created:  time.Now().UTC().Format(time.RFC3339),
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
}

// buildPURL constructs a Package URL (purl) for the given package.
// See https://github.com/package-url/purl-spec for the format.
func buildPURL(p deps.Package) string {
	purlType, ok := purlEcosystems[p.Ecosystem]
	if !ok {
		return ""
	}
	return fmt.Sprintf("pkg:%s/%s@%s", purlType, p.Name, p.Version)
}
