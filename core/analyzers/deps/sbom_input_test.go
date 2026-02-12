package deps

import (
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
		{"pkg:golang/github.com/foo/bar@1.0", "golang"},
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
