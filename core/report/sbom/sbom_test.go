package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/felixgeelhaar/hardline/core/analyzers/deps"
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
	if tool.Name != "hardline" {
		t.Fatalf("expected tool name 'hardline', got %q", tool.Name)
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
	if doc.CreationInfo.Creators[0] != "Tool: hardline-0.1.0" {
		t.Fatalf("expected creator 'Tool: hardline-0.1.0', got %q", doc.CreationInfo.Creators[0])
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
