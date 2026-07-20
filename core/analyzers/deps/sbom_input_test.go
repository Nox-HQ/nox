package deps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCycloneDXContent(t *testing.T) {
	content := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{
				"type": "library",
				"name": "express",
				"version": "4.18.2",
				"purl": "pkg:npm/express@4.18.2"
			},
			{
				"type": "library",
				"group": "org.apache",
				"name": "commons-lang3",
				"version": "3.12.0",
				"purl": "pkg:maven/org.apache/commons-lang3@3.12.0"
			},
			{
				"type": "library",
				"name": "",
				"version": "1.0.0"
			}
		]
	}`)

	pkgs, err := parseCycloneDXContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	if pkgs[0].Name != "express" || pkgs[0].Version != "4.18.2" || pkgs[0].Ecosystem != "npm" {
		t.Errorf("unexpected first package: %+v", pkgs[0])
	}

	if pkgs[1].Name != "org.apache/commons-lang3" || pkgs[1].Ecosystem != "maven" {
		t.Errorf("unexpected second package: %+v", pkgs[1])
	}
}

func TestParseSPDXContent(t *testing.T) {
	content := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"name": "lodash",
				"versionInfo": "4.17.21",
				"externalRefs": [
					{
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/lodash@4.17.21"
					}
				]
			},
			{
				"name": "requests",
				"versionInfo": "2.31.0",
				"externalRefs": [
					{
						"referenceType": "purl",
						"referenceLocator": "pkg:pypi/requests@2.31.0"
					}
				]
			}
		]
	}`)

	pkgs, err := parseSPDXContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	if pkgs[0].Name != "lodash" || pkgs[0].Ecosystem != "npm" {
		t.Errorf("unexpected first package: %+v", pkgs[0])
	}

	if pkgs[1].Name != "requests" || pkgs[1].Ecosystem != "pypi" {
		t.Errorf("unexpected second package: %+v", pkgs[1])
	}
}

func TestEcosystemFromPurl(t *testing.T) {
	tests := []struct {
		purl string
		want string
	}{
		{"pkg:npm/express@4.18.2", "npm"},
		{"pkg:maven/org.apache/commons@3.0", "maven"},
		{"pkg:pypi/requests@2.31.0", "pypi"},
		// purl types differ from nox's ecosystem names for Go and Ruby; they
		// must be normalized or OSV never queries these components.
		{"pkg:golang/github.com/foo/bar@1.0", "go"},
		{"pkg:gem/rails@7.0.0", "rubygems"},
		{"", "unknown"},
		{"invalid", "unknown"},
	}

	for _, tc := range tests {
		got := ecosystemFromPurl(tc.purl)
		if got != tc.want {
			t.Errorf("ecosystemFromPurl(%q) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

func TestParseCycloneDXInput_ReadError(t *testing.T) {
	_, err := ParseCycloneDXInput("/path/does/not/exist.json")
	if err == nil {
		t.Fatal("expected error for missing CycloneDX file")
	}
	if !strings.Contains(err.Error(), "reading CycloneDX BOM") {
		t.Fatalf("expected read error, got: %v", err)
	}
}

func TestParseCycloneDXInput_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := ParseCycloneDXInput(path)
	if err == nil {
		t.Fatal("expected error for invalid CycloneDX JSON")
	}
	if !strings.Contains(err.Error(), "parsing CycloneDX BOM") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestParseCycloneDXInput_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.json")
	content := []byte(`{"components":[{"type":"library","name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2"}]}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	inv, err := ParseCycloneDXInput(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pkgs := inv.Packages()
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "express" || pkgs[0].Version != "4.18.2" || pkgs[0].Ecosystem != "npm" {
		t.Fatalf("unexpected package: %+v", pkgs[0])
	}
}

func TestParseSPDXInput_ReadError(t *testing.T) {
	_, err := ParseSPDXInput("/path/does/not/exist.json")
	if err == nil {
		t.Fatal("expected error for missing SPDX file")
	}
	if !strings.Contains(err.Error(), "reading SPDX document") {
		t.Fatalf("expected read error, got: %v", err)
	}
}

func TestParseSPDXInput_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spdx.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := ParseSPDXInput(path)
	if err == nil {
		t.Fatal("expected error for invalid SPDX JSON")
	}
	if !strings.Contains(err.Error(), "parsing SPDX document") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestParseSPDXInput_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spdx.json")
	content := []byte(`{"packages":[{"name":"lodash","versionInfo":"4.17.21","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.21"}]}]}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	inv, err := ParseSPDXInput(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pkgs := inv.Packages()
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "lodash" || pkgs[0].Version != "4.17.21" || pkgs[0].Ecosystem != "npm" {
		t.Fatalf("unexpected package: %+v", pkgs[0])
	}
}

// TestPurlEcosystemReachesOSV is the security assertion behind the
// normalization: a Go or Ruby component parsed from an SBOM must map to an
// ecosystem OSV.dev recognizes, or osvEcosystem returns false and the component
// is silently dropped from the vulnerability batch — a clean bill of health for
// the whole ecosystem. Before normalization, "golang"/"gem" failed this.
func TestPurlEcosystemReachesOSV(t *testing.T) {
	for _, purl := range []string{
		"pkg:golang/github.com/foo/bar@1.0",
		"pkg:gem/rails@7.0.0",
		"pkg:npm/express@4.18.2",
		"pkg:pypi/requests@2.31.0",
	} {
		eco := ecosystemFromPurl(purl)
		if _, ok := osvEcosystem(eco); !ok {
			t.Errorf("%s -> ecosystem %q not OSV-queryable; component would be dropped from scanning", purl, eco)
		}
	}
}
