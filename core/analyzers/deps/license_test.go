package deps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// CheckLicenses: deny list
// ---------------------------------------------------------------------------

func TestCheckLicenses_DenyList_Match(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "gpl-lib", Version: "1.0.0", Ecosystem: "npm", License: "GPL-3.0"})
	inv.Add(Package{Name: "mit-lib", Version: "2.0.0", Ecosystem: "npm", License: "MIT"})

	fs := CheckLicenses(inv, []string{"GPL-3.0"}, nil)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].RuleID != "LIC-001" {
		t.Errorf("expected rule ID LIC-001, got %s", fs[0].RuleID)
	}
	if fs[0].Severity != findings.SeverityHigh {
		t.Errorf("expected severity high, got %s", fs[0].Severity)
	}
	if fs[0].Metadata["package"] != "gpl-lib" {
		t.Errorf("expected package gpl-lib, got %s", fs[0].Metadata["package"])
	}
	if fs[0].Metadata["license"] != "GPL-3.0" {
		t.Errorf("expected license GPL-3.0, got %s", fs[0].Metadata["license"])
	}
}

func TestCheckLicenses_DenyList_MultipleDenied(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "gpl-lib", Version: "1.0.0", Ecosystem: "npm", License: "GPL-3.0"})
	inv.Add(Package{Name: "agpl-lib", Version: "1.0.0", Ecosystem: "npm", License: "AGPL-3.0"})
	inv.Add(Package{Name: "mit-lib", Version: "2.0.0", Ecosystem: "npm", License: "MIT"})

	fs := CheckLicenses(inv, []string{"GPL-3.0", "AGPL-3.0"}, nil)
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// CheckLicenses: allow list
// ---------------------------------------------------------------------------

func TestCheckLicenses_AllowList_NotAllowed(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "mit-lib", Version: "1.0.0", Ecosystem: "npm", License: "MIT"})
	inv.Add(Package{Name: "bsd-lib", Version: "1.0.0", Ecosystem: "npm", License: "BSD-3-Clause"})

	fs := CheckLicenses(inv, nil, []string{"MIT", "Apache-2.0"})
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding (BSD not in allow list), got %d", len(fs))
	}
	if fs[0].Metadata["package"] != "bsd-lib" {
		t.Errorf("expected package bsd-lib, got %s", fs[0].Metadata["package"])
	}
}

func TestCheckLicenses_AllowList_AllAllowed(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "mit-lib", Version: "1.0.0", Ecosystem: "npm", License: "MIT"})
	inv.Add(Package{Name: "apache-lib", Version: "1.0.0", Ecosystem: "npm", License: "Apache-2.0"})

	fs := CheckLicenses(inv, nil, []string{"MIT", "Apache-2.0"})
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings when all licenses are allowed, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// CheckLicenses: empty policy
// ---------------------------------------------------------------------------

func TestCheckLicenses_EmptyPolicy_NoFindings(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "some-lib", Version: "1.0.0", Ecosystem: "npm", License: "GPL-3.0"})

	fs := CheckLicenses(inv, nil, nil)
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings with empty policy, got %d", len(fs))
	}
}

func TestCheckLicenses_EmptyDenyAndAllow_NoFindings(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "some-lib", Version: "1.0.0", Ecosystem: "npm", License: "GPL-3.0"})

	fs := CheckLicenses(inv, []string{}, []string{})
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings with empty lists, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// CheckLicenses: packages without licenses are skipped
// ---------------------------------------------------------------------------

func TestCheckLicenses_NoLicense_Skipped(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "unknown-lib", Version: "1.0.0", Ecosystem: "npm"})
	inv.Add(Package{Name: "gpl-lib", Version: "1.0.0", Ecosystem: "npm", License: "GPL-3.0"})

	// Deny GPL, but the unknown package should be skipped.
	fs := CheckLicenses(inv, []string{"GPL-3.0"}, nil)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding (unknown skipped), got %d", len(fs))
	}
	if fs[0].Metadata["package"] != "gpl-lib" {
		t.Errorf("expected gpl-lib finding, got %s", fs[0].Metadata["package"])
	}
}

func TestCheckLicenses_AllNoLicense_Skipped(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "lib-a", Version: "1.0.0", Ecosystem: "npm"})
	inv.Add(Package{Name: "lib-b", Version: "2.0.0", Ecosystem: "pypi"})

	fs := CheckLicenses(inv, []string{"GPL-3.0"}, nil)
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings when no packages have licenses, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// CheckLicenses: case-insensitive matching
// ---------------------------------------------------------------------------

func TestCheckLicenses_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name      string
		license   string
		denyEntry string
		wantMatch bool
	}{
		{name: "exact case", license: "GPL-3.0", denyEntry: "GPL-3.0", wantMatch: true},
		{name: "lower license", license: "gpl-3.0", denyEntry: "GPL-3.0", wantMatch: true},
		{name: "lower deny", license: "GPL-3.0", denyEntry: "gpl-3.0", wantMatch: true},
		{name: "mixed case", license: "Gpl-3.0", denyEntry: "gPL-3.0", wantMatch: true},
		{name: "no match", license: "MIT", denyEntry: "GPL-3.0", wantMatch: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := &PackageInventory{}
			inv.Add(Package{Name: "lib", Version: "1.0", Ecosystem: "npm", License: tt.license})

			fs := CheckLicenses(inv, []string{tt.denyEntry}, nil)
			if tt.wantMatch && len(fs) != 1 {
				t.Errorf("expected 1 finding for match, got %d", len(fs))
			}
			if !tt.wantMatch && len(fs) != 0 {
				t.Errorf("expected 0 findings for no match, got %d", len(fs))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckLicenses: prefix matching
// ---------------------------------------------------------------------------

func TestCheckLicenses_PrefixMatching(t *testing.T) {
	tests := []struct {
		name      string
		license   string
		denyEntry string
		wantMatch bool
	}{
		{name: "GPL prefix matches GPL-2.0", license: "GPL-2.0", denyEntry: "GPL", wantMatch: true},
		{name: "GPL prefix matches GPL-3.0", license: "GPL-3.0", denyEntry: "GPL", wantMatch: true},
		{name: "GPL prefix matches GPL-3.0-only", license: "GPL-3.0-only", denyEntry: "GPL", wantMatch: true},
		{name: "AGPL not matched by GPL prefix", license: "AGPL-3.0", denyEntry: "GPL", wantMatch: false},
		{name: "MIT not matched by GPL prefix", license: "MIT", denyEntry: "GPL", wantMatch: false},
		{name: "BSD prefix matches BSD-2-Clause", license: "BSD-2-Clause", denyEntry: "BSD", wantMatch: true},
		{name: "BSD prefix matches BSD-3-Clause", license: "BSD-3-Clause", denyEntry: "BSD", wantMatch: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := &PackageInventory{}
			inv.Add(Package{Name: "lib", Version: "1.0", Ecosystem: "npm", License: tt.license})

			fs := CheckLicenses(inv, []string{tt.denyEntry}, nil)
			if tt.wantMatch && len(fs) != 1 {
				t.Errorf("expected 1 finding, got %d", len(fs))
			}
			if !tt.wantMatch && len(fs) != 0 {
				t.Errorf("expected 0 findings, got %d", len(fs))
			}
		})
	}
}

func TestCheckLicenses_AllowList_PrefixMatching(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "lib", Version: "1.0", Ecosystem: "npm", License: "BSD-3-Clause"})

	// Allow "BSD" prefix should match "BSD-3-Clause".
	fs := CheckLicenses(inv, nil, []string{"BSD"})
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings (BSD prefix should match BSD-3-Clause), got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// matchesLicenseList unit tests
// ---------------------------------------------------------------------------

func TestMatchesLicenseList(t *testing.T) {
	tests := []struct {
		license string
		list    []string
		want    bool
	}{
		{"MIT", []string{"MIT"}, true},
		{"MIT", []string{"Apache-2.0"}, false},
		{"GPL-3.0", []string{"GPL"}, true},
		{"AGPL-3.0", []string{"GPL"}, false},
		{"gpl-3.0", []string{"GPL"}, true},
		{"MIT", []string{"MIT", "Apache-2.0"}, true},
		{"ISC", []string{"MIT", "Apache-2.0"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			got := matchesLicenseList(tt.license, tt.list)
			if got != tt.want {
				t.Errorf("matchesLicenseList(%q, %v) = %v, want %v", tt.license, tt.list, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DetectLicenses: npm
// ---------------------------------------------------------------------------

func TestDetectLicenses_NPM_PackageJSON(t *testing.T) {
	dir := t.TempDir()

	// Write package.json with license.
	packageJSON := []byte(`{
		"name": "my-app",
		"version": "1.0.0",
		"license": "MIT"
	}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), packageJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "my-app", Version: "1.0.0", Ecosystem: "npm"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "MIT" {
		t.Errorf("expected license MIT, got %q", pkgs[0].License)
	}
}

func TestDetectLicenses_NPM_ObjectLicense(t *testing.T) {
	dir := t.TempDir()

	packageJSON := []byte(`{
		"name": "my-app",
		"version": "1.0.0",
		"license": {"type": "Apache-2.0", "url": "http://example.com"}
	}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), packageJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "my-app", Version: "1.0.0", Ecosystem: "npm"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "Apache-2.0" {
		t.Errorf("expected license Apache-2.0, got %q", pkgs[0].License)
	}
}

func TestDetectLicenses_NPM_NodeModules(t *testing.T) {
	dir := t.TempDir()

	// Root package.json.
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"root","license":"MIT"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// node_modules/express/package.json.
	expressDir := filepath.Join(dir, "node_modules", "express")
	if err := os.MkdirAll(expressDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(expressDir, "package.json"), []byte(`{"name":"express","license":"MIT"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// node_modules/lodash/package.json.
	lodashDir := filepath.Join(dir, "node_modules", "lodash")
	if err := os.MkdirAll(lodashDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lodashDir, "package.json"), []byte(`{"name":"lodash","license":"MIT"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"})
	inv.Add(Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	for _, pkg := range pkgs {
		if pkg.License != "MIT" {
			t.Errorf("expected license MIT for %s, got %q", pkg.Name, pkg.License)
		}
	}
}

// ---------------------------------------------------------------------------
// DetectLicenses: Cargo
// ---------------------------------------------------------------------------

func TestDetectLicenses_Cargo(t *testing.T) {
	dir := t.TempDir()

	cargoToml := []byte(`[package]
name = "my-crate"
version = "0.1.0"
license = "MIT OR Apache-2.0"
`)
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), cargoToml, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "my-crate", Version: "0.1.0", Ecosystem: "cargo"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "MIT OR Apache-2.0" {
		t.Errorf("expected license 'MIT OR Apache-2.0', got %q", pkgs[0].License)
	}
}

// ---------------------------------------------------------------------------
// DetectLicenses: Maven
// ---------------------------------------------------------------------------

func TestDetectLicenses_Maven(t *testing.T) {
	dir := t.TempDir()

	pomXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>mylib</artifactId>
  <version>1.0.0</version>
  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
      <url>http://www.apache.org/licenses/LICENSE-2.0</url>
    </license>
  </licenses>
</project>`)
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), pomXML, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "com.example:mylib", Version: "1.0.0", Ecosystem: "maven"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "Apache-2.0" {
		t.Errorf("expected license Apache-2.0, got %q", pkgs[0].License)
	}
}

// ---------------------------------------------------------------------------
// DetectLicenses: PyPI
// ---------------------------------------------------------------------------

func TestDetectLicenses_PyPI_PyprojectToml(t *testing.T) {
	dir := t.TempDir()

	pyprojectToml := []byte(`[project]
name = "mypackage"
version = "1.0.0"
license = "MIT"
`)
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), pyprojectToml, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "mypackage", Version: "1.0.0", Ecosystem: "pypi"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "MIT" {
		t.Errorf("expected license MIT, got %q", pkgs[0].License)
	}
}

func TestDetectLicenses_PyPI_SetupCfg(t *testing.T) {
	dir := t.TempDir()

	setupCfg := []byte(`[metadata]
name = mypackage
license = BSD-3-Clause
`)
	if err := os.WriteFile(filepath.Join(dir, "setup.cfg"), setupCfg, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "mypackage", Version: "1.0.0", Ecosystem: "pypi"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "BSD-3-Clause" {
		t.Errorf("expected license BSD-3-Clause, got %q", pkgs[0].License)
	}
}

// ---------------------------------------------------------------------------
// DetectLicenses: Go
// ---------------------------------------------------------------------------

func TestDetectLicenses_Go_LICENSEFile(t *testing.T) {
	dir := t.TempDir()

	mitLicense := []byte(`MIT License

Copyright (c) 2024 Test

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
`)
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), mitLicense, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "example.com/module", Version: "v1.0.0", Ecosystem: "go"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "MIT" {
		t.Errorf("expected license MIT, got %q", pkgs[0].License)
	}
}

func TestDetectLicenses_Go_ApacheLicense(t *testing.T) {
	dir := t.TempDir()

	apacheLicense := []byte(`
                                Apache License
                          Version 2.0, January 2004
                       http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
`)
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), apacheLicense, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "example.com/module", Version: "v1.0.0", Ecosystem: "go"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "Apache-2.0" {
		t.Errorf("expected license Apache-2.0, got %q", pkgs[0].License)
	}
}

// ---------------------------------------------------------------------------
// DetectLicenses: Ruby
// ---------------------------------------------------------------------------

func TestDetectLicenses_Ruby_Gemspec(t *testing.T) {
	dir := t.TempDir()

	gemspec := []byte(`Gem::Specification.new do |spec|
  spec.name          = "mygem"
  spec.version       = "1.0.0"
  spec.license       = "MIT"
end
`)
	if err := os.WriteFile(filepath.Join(dir, "mygem.gemspec"), gemspec, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "mygem", Version: "1.0.0", Ecosystem: "rubygems"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "MIT" {
		t.Errorf("expected license MIT, got %q", pkgs[0].License)
	}
}

func TestDetectLicenses_Ruby_GemspecLicensesArray(t *testing.T) {
	dir := t.TempDir()

	gemspec := []byte(`Gem::Specification.new do |s|
  s.name          = "mygem"
  s.version       = "1.0.0"
  s.licenses      = ["Apache-2.0"]
end
`)
	if err := os.WriteFile(filepath.Join(dir, "mygem.gemspec"), gemspec, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "mygem", Version: "1.0.0", Ecosystem: "rubygems"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "Apache-2.0" {
		t.Errorf("expected license Apache-2.0, got %q", pkgs[0].License)
	}
}

// ---------------------------------------------------------------------------
// DetectLicenses: no manifest files (no-op)
// ---------------------------------------------------------------------------

func TestDetectLicenses_NoManifest_NoChange(t *testing.T) {
	dir := t.TempDir()

	inv := &PackageInventory{}
	inv.Add(Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "" {
		t.Errorf("expected empty license when no manifests exist, got %q", pkgs[0].License)
	}
}

// ---------------------------------------------------------------------------
// DetectLicenses: does not overwrite existing license
// ---------------------------------------------------------------------------

func TestDetectLicenses_DoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()

	packageJSON := []byte(`{"name":"express","license":"Apache-2.0"}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), packageJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	inv := &PackageInventory{}
	inv.Add(Package{Name: "express", Version: "4.18.2", Ecosystem: "npm", License: "MIT"})

	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if pkgs[0].License != "MIT" {
		t.Errorf("expected license to stay MIT (not overwritten), got %q", pkgs[0].License)
	}
}

// ---------------------------------------------------------------------------
// SetLicense
// ---------------------------------------------------------------------------

func TestSetLicense(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "lib", Version: "1.0", Ecosystem: "npm"})

	inv.SetLicense(0, "MIT")
	pkgs := inv.Packages()
	if pkgs[0].License != "MIT" {
		t.Errorf("expected MIT, got %q", pkgs[0].License)
	}
}

func TestSetLicense_DoesNotOverwrite(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "lib", Version: "1.0", Ecosystem: "npm", License: "Apache-2.0"})

	inv.SetLicense(0, "MIT")
	pkgs := inv.Packages()
	if pkgs[0].License != "Apache-2.0" {
		t.Errorf("expected Apache-2.0 (not overwritten), got %q", pkgs[0].License)
	}
}

func TestSetLicense_OutOfBounds(t *testing.T) {
	inv := &PackageInventory{}
	inv.Add(Package{Name: "lib", Version: "1.0", Ecosystem: "npm"})

	// Should not panic.
	inv.SetLicense(-1, "MIT")
	inv.SetLicense(5, "MIT")

	pkgs := inv.Packages()
	if pkgs[0].License != "" {
		t.Errorf("expected empty license after out-of-bounds set, got %q", pkgs[0].License)
	}
}

// ---------------------------------------------------------------------------
// identifyLicenseFromContent
// ---------------------------------------------------------------------------

func TestIdentifyLicenseFromContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "MIT",
			content: "MIT License\n\nCopyright (c) 2024\n\nPermission is hereby granted, free of charge...",
			want:    "MIT",
		},
		{
			name:    "Apache 2.0",
			content: "Apache License\nVersion 2.0, January 2004",
			want:    "Apache-2.0",
		},
		{
			name:    "GPL 3.0",
			content: "GNU General Public License\nVersion 3, 29 June 2007",
			want:    "GPL-3.0",
		},
		{
			name:    "GPL 2.0",
			content: "GNU General Public License\nVersion 2, June 1991",
			want:    "GPL-2.0",
		},
		{
			name:    "ISC",
			content: "ISC License\n\nCopyright (c) 2024",
			want:    "ISC",
		},
		{
			name:    "Unlicense",
			content: "This is free and unencumbered software released into the public domain.\n\nThe Unlicense",
			want:    "Unlicense",
		},
		{
			name:    "unknown",
			content: "Some custom license text that doesn't match anything",
			want:    "",
		},
		{
			name:    "empty",
			content: "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identifyLicenseFromContent(tt.content)
			if got != tt.want {
				t.Errorf("identifyLicenseFromContent() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalizeLicenseName
// ---------------------------------------------------------------------------

func TestNormalizeLicenseName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"MIT", "MIT"},
		{"mit", "MIT"},
		{"MIT License", "MIT"},
		{"Apache License, Version 2.0", "Apache-2.0"},
		{"Apache-2.0", "Apache-2.0"},
		{"GPL-3.0", "GPL-3.0"},
		{"GPL v2", "GPL-2.0"},
		{"BSD-3-Clause", "BSD-3-Clause"},
		{"ISC", "ISC"},
		{"Custom License", "Custom License"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeLicenseName(tt.input)
			if got != tt.want {
				t.Errorf("normalizeLicenseName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseCargoTOMLLicense
// ---------------------------------------------------------------------------

func TestParseCargoTOMLLicense(t *testing.T) {
	data := []byte(`[package]
name = "my-crate"
version = "0.1.0"
license = "MIT"

[dependencies]
serde = "1.0"
`)

	name, license := parseCargoTOMLLicense(data)
	if name != "my-crate" {
		t.Errorf("expected name my-crate, got %q", name)
	}
	if license != "MIT" {
		t.Errorf("expected license MIT, got %q", license)
	}
}

func TestParseCargoTOMLLicense_LicenseFile(t *testing.T) {
	// license-file should not be confused with license.
	data := []byte(`[package]
name = "my-crate"
version = "0.1.0"
license-file = "LICENSE"
`)

	_, license := parseCargoTOMLLicense(data)
	if license != "" {
		t.Errorf("expected empty license (license-file is not license), got %q", license)
	}
}

// ---------------------------------------------------------------------------
// extractJSONLicense
// ---------------------------------------------------------------------------

func TestExtractJSONLicense(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"string", `"MIT"`, "MIT"},
		{"object", `{"type":"Apache-2.0","url":"http://example.com"}`, "Apache-2.0"},
		{"empty", ``, ""},
		{"null", `null`, ""},
		{"number", `42`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSONLicense([]byte(tt.input))
			if got != tt.want {
				t.Errorf("extractJSONLicense(%s) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// WithLicensePolicy integration
// ---------------------------------------------------------------------------

func TestWithLicensePolicy(t *testing.T) {
	a := NewAnalyzer(
		WithOSVDisabled(),
		WithLicensePolicy(LicensePolicy{
			Deny: []string{"GPL-3.0"},
		}),
	)

	if a.licensePolicy == nil {
		t.Fatal("expected license policy to be set")
	}
	if len(a.licensePolicy.Deny) != 1 {
		t.Errorf("expected 1 deny entry, got %d", len(a.licensePolicy.Deny))
	}
}

// ---------------------------------------------------------------------------
// LIC-001 rule registration
// ---------------------------------------------------------------------------

func TestRules_ContainsLIC001(t *testing.T) {
	a := NewAnalyzer(WithOSVDisabled())
	rs := a.Rules()

	rule, ok := rs.ByID("LIC-001")
	if !ok {
		t.Fatal("expected LIC-001 rule to be registered")
	}
	if rule.Description != "Dependency uses a restricted license" {
		t.Errorf("unexpected description: %s", rule.Description)
	}
	if rule.Severity != findings.SeverityHigh {
		t.Errorf("expected severity high, got %s", rule.Severity)
	}
}

// ---------------------------------------------------------------------------
// parseGemspec
// ---------------------------------------------------------------------------

func TestParseGemspec(t *testing.T) {
	dir := t.TempDir()
	gemspec := []byte(`Gem::Specification.new do |spec|
  spec.name          = "rails"
  spec.version       = "7.1.0"
  spec.license       = "MIT"
  spec.summary       = "Full-stack web framework"
end
`)
	path := filepath.Join(dir, "rails.gemspec")
	if err := os.WriteFile(path, gemspec, 0o644); err != nil {
		t.Fatal(err)
	}

	name, license := parseGemspec(path)
	if name != "rails" {
		t.Errorf("expected name rails, got %q", name)
	}
	if license != "MIT" {
		t.Errorf("expected license MIT, got %q", license)
	}
}

// ---------------------------------------------------------------------------
// parsePyprojectTOML
// ---------------------------------------------------------------------------

func TestParsePyprojectTOML(t *testing.T) {
	dir := t.TempDir()
	toml := []byte(`[build-system]
requires = ["setuptools"]

[project]
name = "flask"
version = "3.0.0"
license = "BSD-3-Clause"
`)
	path := filepath.Join(dir, "pyproject.toml")
	if err := os.WriteFile(path, toml, 0o644); err != nil {
		t.Fatal(err)
	}

	name, license := parsePyprojectTOML(path)
	if name != "flask" {
		t.Errorf("expected name flask, got %q", name)
	}
	if license != "BSD-3-Clause" {
		t.Errorf("expected license BSD-3-Clause, got %q", license)
	}
}

// ---------------------------------------------------------------------------
// parseSetupCfg
// ---------------------------------------------------------------------------

func TestParseSetupCfg(t *testing.T) {
	dir := t.TempDir()
	cfg := []byte(`[metadata]
name = mypackage
license = Apache-2.0
`)
	path := filepath.Join(dir, "setup.cfg")
	if err := os.WriteFile(path, cfg, 0o644); err != nil {
		t.Fatal(err)
	}

	name, license := parseSetupCfg(path)
	if name != "mypackage" {
		t.Errorf("expected name mypackage, got %q", name)
	}
	if license != "Apache-2.0" {
		t.Errorf("expected license Apache-2.0, got %q", license)
	}
}

// ---------------------------------------------------------------------------
// Empty inventory
// ---------------------------------------------------------------------------

func TestCheckLicenses_EmptyInventory(t *testing.T) {
	inv := &PackageInventory{}
	fs := CheckLicenses(inv, []string{"GPL"}, nil)
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings for empty inventory, got %d", len(fs))
	}
}

func TestDetectLicenses_EmptyInventory(t *testing.T) {
	dir := t.TempDir()
	inv := &PackageInventory{}

	// Should not panic.
	DetectLicenses(dir, inv)

	pkgs := inv.Packages()
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(pkgs))
	}
}
