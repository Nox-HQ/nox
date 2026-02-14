package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/deps"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func testInventory() *deps.PackageInventory {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"})
	inv.Add(deps.Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"})
	inv.Add(deps.Package{Name: "golang.org/x/text", Version: "v0.14.0", Ecosystem: "go"})
	inv.Add(deps.Package{Name: "flask", Version: "3.0.0", Ecosystem: "pypi"})
	inv.Add(deps.Package{Name: "rails", Version: "7.1.2", Ecosystem: "rubygems"})
	return inv
}

// ---------------------------------------------------------------------------
// CycloneDX: schema validation
// ---------------------------------------------------------------------------

func TestCycloneDX_SchemaFields(t *testing.T) {
	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(testInventory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if report.BOMFormat != "CycloneDX" {
		t.Fatalf("expected bomFormat 'CycloneDX', got %q", report.BOMFormat)
	}
	if report.SpecVersion != "1.5" {
		t.Fatalf("expected specVersion '1.5', got %q", report.SpecVersion)
	}
	if report.Version != 1 {
		t.Fatalf("expected version 1, got %d", report.Version)
	}
}

func TestCycloneDX_ToolMetadata(t *testing.T) {
	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(testInventory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if len(report.Metadata.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(report.Metadata.Tools))
	}
	tool := report.Metadata.Tools[0]
	if tool.Name != "nox" {
		t.Fatalf("expected tool name 'nox', got %q", tool.Name)
	}
	if tool.Version != "0.1.0" {
		t.Fatalf("expected tool version '0.1.0', got %q", tool.Version)
	}
}

// ---------------------------------------------------------------------------
// CycloneDX: components
// ---------------------------------------------------------------------------

func TestCycloneDX_ComponentCount(t *testing.T) {
	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(testInventory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if len(report.Components) != 5 {
		t.Fatalf("expected 5 components, got %d", len(report.Components))
	}
}

func TestCycloneDX_PURLGeneration(t *testing.T) {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"})

	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(inv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if len(report.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(report.Components))
	}

	c := report.Components[0]
	if c.PURL != "pkg:npm/express@4.18.2" {
		t.Fatalf("expected purl 'pkg:npm/express@4.18.2', got %q", c.PURL)
	}
	if c.Type != "library" {
		t.Fatalf("expected type 'library', got %q", c.Type)
	}
}

func TestCycloneDX_DeterministicOrder(t *testing.T) {
	r := NewCycloneDXReporter("0.1.0")
	data1, _ := r.Generate(testInventory())
	data2, _ := r.Generate(testInventory())

	// Parse and compare components (ignoring timestamp).
	var r1, r2 CDXReport
	if err := json.Unmarshal(data1, &r1); err != nil {
		t.Fatalf("unmarshal data1: %v", err)
	}
	if err := json.Unmarshal(data2, &r2); err != nil {
		t.Fatalf("unmarshal data2: %v", err)
	}

	if len(r1.Components) != len(r2.Components) {
		t.Fatal("component counts differ between runs")
	}
	for i := range r1.Components {
		if r1.Components[i].Name != r2.Components[i].Name {
			t.Fatalf("component order differs at index %d: %q vs %q",
				i, r1.Components[i].Name, r2.Components[i].Name)
		}
	}
}

func TestCycloneDX_EmptyInventory(t *testing.T) {
	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(&deps.PackageInventory{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if len(report.Components) != 0 {
		t.Fatalf("expected 0 components for empty inventory, got %d", len(report.Components))
	}
}

func TestCycloneDX_WriteToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.cdx.json")

	r := NewCycloneDXReporter("0.1.0")
	if err := r.WriteToFile(testInventory(), path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse written file: %v", err)
	}
	if report.BOMFormat != "CycloneDX" {
		t.Fatalf("expected bomFormat 'CycloneDX' in written file, got %q", report.BOMFormat)
	}
}

// ---------------------------------------------------------------------------
// SPDX: schema validation
// ---------------------------------------------------------------------------

func TestSPDX_SchemaFields(t *testing.T) {
	r := NewSPDXReporter("0.1.0")
	data, err := r.Generate(testInventory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Fatalf("expected spdxVersion 'SPDX-2.3', got %q", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Fatalf("expected dataLicense 'CC0-1.0', got %q", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Fatalf("expected SPDXID 'SPDXRef-DOCUMENT', got %q", doc.SPDXID)
	}
}

func TestSPDX_CreatorInfo(t *testing.T) {
	r := NewSPDXReporter("0.1.0")
	data, err := r.Generate(testInventory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}

	if len(doc.CreationInfo.Creators) != 1 {
		t.Fatalf("expected 1 creator, got %d", len(doc.CreationInfo.Creators))
	}
	if doc.CreationInfo.Creators[0] != "Tool: nox-0.1.0" {
		t.Fatalf("expected creator 'Tool: nox-0.1.0', got %q", doc.CreationInfo.Creators[0])
	}
}

// ---------------------------------------------------------------------------
// SPDX: packages
// ---------------------------------------------------------------------------

func TestSPDX_PackageCount(t *testing.T) {
	r := NewSPDXReporter("0.1.0")
	data, err := r.Generate(testInventory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}

	if len(doc.Packages) != 5 {
		t.Fatalf("expected 5 packages, got %d", len(doc.Packages))
	}
}

func TestSPDX_PURLExternalRef(t *testing.T) {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "flask", Version: "3.0.0", Ecosystem: "pypi"})

	r := NewSPDXReporter("0.1.0")
	data, err := r.Generate(inv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}

	if len(doc.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(doc.Packages))
	}

	pkg := doc.Packages[0]
	if len(pkg.ExternalRefs) != 1 {
		t.Fatalf("expected 1 external ref, got %d", len(pkg.ExternalRefs))
	}
	ref := pkg.ExternalRefs[0]
	if ref.ReferenceLocator != "pkg:pypi/flask@3.0.0" {
		t.Fatalf("expected purl 'pkg:pypi/flask@3.0.0', got %q", ref.ReferenceLocator)
	}
	if ref.ReferenceType != "purl" {
		t.Fatalf("expected referenceType 'purl', got %q", ref.ReferenceType)
	}
}

func TestSPDX_Relationships(t *testing.T) {
	r := NewSPDXReporter("0.1.0")
	data, err := r.Generate(testInventory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}

	// One DESCRIBES relationship per package.
	if len(doc.Relationships) != 5 {
		t.Fatalf("expected 5 relationships, got %d", len(doc.Relationships))
	}

	for _, rel := range doc.Relationships {
		if rel.SPDXElementID != "SPDXRef-DOCUMENT" {
			t.Fatalf("expected spdxElementId 'SPDXRef-DOCUMENT', got %q", rel.SPDXElementID)
		}
		if rel.RelationshipType != "DESCRIBES" {
			t.Fatalf("expected relationshipType 'DESCRIBES', got %q", rel.RelationshipType)
		}
	}
}

func TestSPDX_EmptyInventory(t *testing.T) {
	r := NewSPDXReporter("0.1.0")
	data, err := r.Generate(&deps.PackageInventory{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}

	if len(doc.Packages) != 0 {
		t.Fatalf("expected 0 packages for empty inventory, got %d", len(doc.Packages))
	}
}

func TestSPDX_DeterministicOrder(t *testing.T) {
	r := NewSPDXReporter("0.1.0")
	data1, _ := r.Generate(testInventory())
	data2, _ := r.Generate(testInventory())

	var d1, d2 SPDXDocument
	if err := json.Unmarshal(data1, &d1); err != nil {
		t.Fatalf("unmarshal data1: %v", err)
	}
	if err := json.Unmarshal(data2, &d2); err != nil {
		t.Fatalf("unmarshal data2: %v", err)
	}

	for i := range d1.Packages {
		if d1.Packages[i].Name != d2.Packages[i].Name {
			t.Fatalf("package order differs at index %d", i)
		}
	}
}

func TestSPDX_WriteToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.spdx.json")

	r := NewSPDXReporter("0.1.0")
	if err := r.WriteToFile(testInventory(), path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse written file: %v", err)
	}
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Fatalf("expected spdxVersion 'SPDX-2.3' in written file, got %q", doc.SPDXVersion)
	}
}

// ---------------------------------------------------------------------------
// PURL generation
// ---------------------------------------------------------------------------

func TestBuildPURL_AllEcosystems(t *testing.T) {
	tests := []struct {
		pkg      deps.Package
		expected string
	}{
		{deps.Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"}, "pkg:npm/express@4.18.2"},
		{deps.Package{Name: "golang.org/x/text", Version: "v0.14.0", Ecosystem: "go"}, "pkg:golang/golang.org/x/text@v0.14.0"},
		{deps.Package{Name: "flask", Version: "3.0.0", Ecosystem: "pypi"}, "pkg:pypi/flask@3.0.0"},
		{deps.Package{Name: "rails", Version: "7.1.2", Ecosystem: "rubygems"}, "pkg:gem/rails@7.1.2"},
		{deps.Package{Name: "tokio", Version: "1.35.0", Ecosystem: "cargo"}, "pkg:cargo/tokio@1.35.0"},
		{deps.Package{Name: "org.springframework:spring-core", Version: "6.1.0", Ecosystem: "maven"}, "pkg:maven/org.springframework/spring-core@6.1.0"},
		{deps.Package{Name: "io.netty:netty-all", Version: "4.1.100", Ecosystem: "gradle"}, "pkg:maven/io.netty/netty-all@4.1.100"},
		{deps.Package{Name: "Newtonsoft.Json", Version: "13.0.3", Ecosystem: "nuget"}, "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{deps.Package{Name: "unknown", Version: "1.0", Ecosystem: "unknown"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.pkg.Ecosystem+"/"+tt.pkg.Name, func(t *testing.T) {
			result := buildPURL(tt.pkg)
			if result != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CycloneDX: vulnerability enrichment
// ---------------------------------------------------------------------------

func testInventoryWithVulns() *deps.PackageInventory {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "express", Version: "4.17.1", Ecosystem: "npm"})
	inv.Add(deps.Package{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"})

	inv.SetVulnerabilities(1, []deps.Vulnerability{
		{
			ID:       "GHSA-1234-5678-9012",
			Summary:  "Prototype pollution in lodash",
			Severity: "high",
		},
		{
			ID:       "GHSA-abcd-efgh-ijkl",
			Summary:  "ReDoS in lodash",
			Severity: "medium",
		},
	})
	return inv
}

func TestCycloneDX_Vulnerabilities(t *testing.T) {
	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(testInventoryWithVulns())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if len(report.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(report.Vulnerabilities))
	}

	// Sorted by ID.
	if report.Vulnerabilities[0].ID != "GHSA-1234-5678-9012" {
		t.Errorf("expected first vuln GHSA-1234-5678-9012, got %s", report.Vulnerabilities[0].ID)
	}
	if report.Vulnerabilities[1].ID != "GHSA-abcd-efgh-ijkl" {
		t.Errorf("expected second vuln GHSA-abcd-efgh-ijkl, got %s", report.Vulnerabilities[1].ID)
	}

	// Check source.
	if report.Vulnerabilities[0].Source.Name != "OSV" {
		t.Errorf("expected source name OSV, got %s", report.Vulnerabilities[0].Source.Name)
	}
	if report.Vulnerabilities[0].Source.URL != "https://osv.dev/vulnerability/GHSA-1234-5678-9012" {
		t.Errorf("unexpected source URL: %s", report.Vulnerabilities[0].Source.URL)
	}

	// Check ratings.
	if len(report.Vulnerabilities[0].Ratings) != 1 {
		t.Fatalf("expected 1 rating, got %d", len(report.Vulnerabilities[0].Ratings))
	}
	if report.Vulnerabilities[0].Ratings[0].Severity != "high" {
		t.Errorf("expected severity high, got %s", report.Vulnerabilities[0].Ratings[0].Severity)
	}

	// Check affects reference.
	if len(report.Vulnerabilities[0].Affects) != 1 {
		t.Fatalf("expected 1 affect, got %d", len(report.Vulnerabilities[0].Affects))
	}
	// The affect ref should point to lodash's bom-ref.
	ref := report.Vulnerabilities[0].Affects[0].Ref
	if ref == "" {
		t.Error("expected non-empty affect ref")
	}
}

func TestCycloneDX_NoVulnerabilities(t *testing.T) {
	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(testInventory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if len(report.Vulnerabilities) != 0 {
		t.Fatalf("expected 0 vulnerabilities, got %d", len(report.Vulnerabilities))
	}
}

func TestCycloneDX_BOMRef(t *testing.T) {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"})

	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(inv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if len(report.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(report.Components))
	}
	if report.Components[0].BOMRef == "" {
		t.Error("expected non-empty bom-ref")
	}
}

// ---------------------------------------------------------------------------
// SPDX: vulnerability enrichment
// ---------------------------------------------------------------------------

func TestSPDX_SecurityExternalRefs(t *testing.T) {
	r := NewSPDXReporter("0.1.0")
	data, err := r.Generate(testInventoryWithVulns())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}

	// Find lodash package (sorted: express at 0, lodash at 1).
	if len(doc.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(doc.Packages))
	}

	var lodashPkg SPDXPackage
	for _, p := range doc.Packages {
		if p.Name == "lodash" {
			lodashPkg = p
			break
		}
	}

	// lodash should have PURL ref + 2 SECURITY refs = 3 total.
	if len(lodashPkg.ExternalRefs) != 3 {
		t.Fatalf("expected 3 external refs for lodash (1 purl + 2 security), got %d", len(lodashPkg.ExternalRefs))
	}

	// Count security refs.
	var securityRefs int
	for _, ref := range lodashPkg.ExternalRefs {
		if ref.ReferenceCategory == "SECURITY" {
			securityRefs++
			if ref.ReferenceType != "advisory" {
				t.Errorf("expected referenceType advisory, got %s", ref.ReferenceType)
			}
		}
	}
	if securityRefs != 2 {
		t.Fatalf("expected 2 security refs, got %d", securityRefs)
	}

	// Express should have only PURL ref (no vulns).
	var expressPkg SPDXPackage
	for _, p := range doc.Packages {
		if p.Name == "express" {
			expressPkg = p
			break
		}
	}
	if len(expressPkg.ExternalRefs) != 1 {
		t.Fatalf("expected 1 external ref for express (purl only), got %d", len(expressPkg.ExternalRefs))
	}
}

func TestSPDX_NoVulnerabilities(t *testing.T) {
	r := NewSPDXReporter("0.1.0")
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"})

	data, err := r.Generate(inv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}

	// Only PURL ref, no security refs.
	if len(doc.Packages[0].ExternalRefs) != 1 {
		t.Fatalf("expected 1 external ref (purl only), got %d", len(doc.Packages[0].ExternalRefs))
	}
	if doc.Packages[0].ExternalRefs[0].ReferenceCategory != "PACKAGE-MANAGER" {
		t.Errorf("expected PACKAGE-MANAGER, got %s", doc.Packages[0].ExternalRefs[0].ReferenceCategory)
	}
}

// ---------------------------------------------------------------------------
// CycloneDX: license field on component
// ---------------------------------------------------------------------------

func TestCycloneDX_LicenseField(t *testing.T) {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "express", Version: "4.18.2", Ecosystem: "npm", License: "MIT"})
	inv.Add(deps.Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"}) // no license

	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(inv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if len(report.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(report.Components))
	}

	// Find by name since sorting is deterministic.
	var expressComp, lodashComp CDXComponent
	for _, c := range report.Components {
		switch c.Name {
		case "express":
			expressComp = c
		case "lodash":
			lodashComp = c
		}
	}

	if len(expressComp.Licenses) != 1 {
		t.Fatalf("expected 1 license for express, got %d", len(expressComp.Licenses))
	}
	if expressComp.Licenses[0].License.ID != "MIT" {
		t.Errorf("expected license MIT, got %s", expressComp.Licenses[0].License.ID)
	}

	if len(lodashComp.Licenses) != 0 {
		t.Errorf("expected 0 licenses for lodash (no license), got %d", len(lodashComp.Licenses))
	}
}

// ---------------------------------------------------------------------------
// CycloneDX: vulnerability with empty severity → no Ratings
// ---------------------------------------------------------------------------

func TestCycloneDX_VulnerabilityEmptySeverity(t *testing.T) {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "express", Version: "4.17.1", Ecosystem: "npm"})

	inv.SetVulnerabilities(0, []deps.Vulnerability{
		{
			ID:       "GHSA-empty-sev",
			Summary:  "Some vulnerability with no severity",
			Severity: "", // empty severity
		},
	})

	r := NewCycloneDXReporter("0.1.0")
	data, err := r.Generate(inv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if len(report.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(report.Vulnerabilities))
	}

	// Empty severity → Ratings should be nil/empty.
	if len(report.Vulnerabilities[0].Ratings) != 0 {
		t.Errorf("expected 0 ratings for empty severity, got %d", len(report.Vulnerabilities[0].Ratings))
	}
}

// ---------------------------------------------------------------------------
// SPDX: declaredLicense field
// ---------------------------------------------------------------------------

func TestSPDX_DeclaredLicense(t *testing.T) {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "express", Version: "4.18.2", Ecosystem: "npm", License: "MIT"})
	inv.Add(deps.Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"}) // no license

	r := NewSPDXReporter("0.1.0")
	data, err := r.Generate(inv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}

	if len(doc.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(doc.Packages))
	}

	var expressPkg, lodashPkg SPDXPackage
	for _, p := range doc.Packages {
		switch p.Name {
		case "express":
			expressPkg = p
		case "lodash":
			lodashPkg = p
		}
	}

	if expressPkg.DeclaredLicense != "MIT" {
		t.Errorf("expected declaredLicense MIT for express, got %q", expressPkg.DeclaredLicense)
	}
	if lodashPkg.DeclaredLicense != "NOASSERTION" {
		t.Errorf("expected declaredLicense NOASSERTION for lodash, got %q", lodashPkg.DeclaredLicense)
	}
}

// ---------------------------------------------------------------------------
// CycloneDX & SPDX: WriteToFile error path
// ---------------------------------------------------------------------------

func TestCycloneDX_WriteToFile_ErrorOnInvalidPath(t *testing.T) {
	r := NewCycloneDXReporter("0.1.0")
	inv := testInventory()

	err := r.WriteToFile(inv, "/nonexistent/dir/sbom.cdx.json")
	if err == nil {
		t.Fatal("expected error writing to invalid path, got nil")
	}
}

func TestSPDX_WriteToFile_ErrorOnInvalidPath(t *testing.T) {
	r := NewSPDXReporter("0.1.0")
	inv := testInventory()

	err := r.WriteToFile(inv, "/nonexistent/dir/sbom.spdx.json")
	if err == nil {
		t.Fatal("expected error writing to invalid path, got nil")
	}
}
