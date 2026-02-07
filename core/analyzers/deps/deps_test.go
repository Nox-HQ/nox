package deps

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/felixgeelhaar/hardline/core/discovery"
)

func TestParseGoSum(t *testing.T) {
	content := []byte(`golang.org/x/text v0.3.7 h1:aRYxNxv6iGQlyVaZmk6ZgYEDa+Jg18DxelFNyGJFnOg=
golang.org/x/text v0.3.7/go.mod h1:u+2+/6zg+i71rQMx5EYifcz6MCKuco9NR6JIITiCfzQ=
golang.org/x/net v0.0.0-20220225172249-27dd8689420f h1:oA4XRj0qtSt8Yo1Zms0CUlsT3KG69V2UGQWPBxujDmc=
golang.org/x/net v0.0.0-20220225172249-27dd8689420f/go.mod h1:CfG3xpIq0wQ8r1q4Su4UZFWDARRcnwPjda9FqA0JpMk=
github.com/stretchr/testify v1.8.0 h1:pSgiaMZlXftHpm5L7V1+rVB+AZJz+IJ80/gly7ch0e0=
github.com/stretchr/testify v1.8.0/go.mod h1:yNjHg4UonilssWZ8iaSj1OCr/vHnekPRkoO+kdMU+MU=
`)

	pkgs, err := parseGoSum(content)
	if err != nil {
		t.Fatalf("parseGoSum returned error: %v", err)
	}

	// Three unique modules (each appears twice: source + /go.mod).
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	// Sort for deterministic assertions.
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name < pkgs[j].Name
	})

	expected := []Package{
		{Name: "github.com/stretchr/testify", Version: "v1.8.0", Ecosystem: "go"},
		{Name: "golang.org/x/net", Version: "v0.0.0-20220225172249-27dd8689420f", Ecosystem: "go"},
		{Name: "golang.org/x/text", Version: "v0.3.7", Ecosystem: "go"},
	}

	for i, exp := range expected {
		if pkgs[i] != exp {
			t.Errorf("package[%d]: got %+v, want %+v", i, pkgs[i], exp)
		}
	}
}

func TestParseGoSum_EmptyInput(t *testing.T) {
	pkgs, err := parseGoSum([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestParsePackageLockJSON(t *testing.T) {
	content := []byte(`{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0"
    },
    "node_modules/express": {
      "version": "4.18.2"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    },
    "node_modules/express/node_modules/debug": {
      "version": "2.6.9"
    },
    "node_modules/@types/node": {
      "version": "18.11.9"
    }
  }
}`)

	pkgs, err := parsePackageLockJSON(content)
	if err != nil {
		t.Fatalf("parsePackageLockJSON returned error: %v", err)
	}

	// 4 packages (root "" is skipped).
	if len(pkgs) != 4 {
		t.Fatalf("expected 4 packages, got %d", len(pkgs))
	}

	// Sort for deterministic assertions.
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name < pkgs[j].Name
	})

	expected := []Package{
		{Name: "@types/node", Version: "18.11.9", Ecosystem: "npm"},
		{Name: "debug", Version: "2.6.9", Ecosystem: "npm"},
		{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	}

	for i, exp := range expected {
		if pkgs[i] != exp {
			t.Errorf("package[%d]: got %+v, want %+v", i, pkgs[i], exp)
		}
	}
}

func TestParsePackageLockJSON_InvalidJSON(t *testing.T) {
	_, err := parsePackageLockJSON([]byte(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	content := []byte(`# This is a comment
Django==4.2.1
requests>=2.28.0
Flask~=2.3.0
numpy!=1.24.0
pandas<=1.5.3

# Another comment
-e git+https://github.com/user/project.git#egg=project
boto3==1.26.137  # inline comment
cryptography==40.0.2 ; python_version >= "3.7"
Pillow[jpeg]==9.5.0
`)

	pkgs, err := parseRequirementsTxt(content)
	if err != nil {
		t.Fatalf("parseRequirementsTxt returned error: %v", err)
	}

	// Sort for deterministic assertions.
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name < pkgs[j].Name
	})

	expected := []Package{
		{Name: "Django", Version: "4.2.1", Ecosystem: "pypi"},
		{Name: "Flask", Version: "2.3.0", Ecosystem: "pypi"},
		{Name: "Pillow", Version: "9.5.0", Ecosystem: "pypi"},
		{Name: "boto3", Version: "1.26.137", Ecosystem: "pypi"},
		{Name: "cryptography", Version: "40.0.2", Ecosystem: "pypi"},
		{Name: "numpy", Version: "1.24.0", Ecosystem: "pypi"},
		{Name: "pandas", Version: "1.5.3", Ecosystem: "pypi"},
		{Name: "requests", Version: "2.28.0", Ecosystem: "pypi"},
	}

	if len(pkgs) != len(expected) {
		t.Fatalf("expected %d packages, got %d: %+v", len(expected), len(pkgs), pkgs)
	}

	for i, exp := range expected {
		if pkgs[i] != exp {
			t.Errorf("package[%d]: got %+v, want %+v", i, pkgs[i], exp)
		}
	}
}

func TestParseRequirementsTxt_EmptyInput(t *testing.T) {
	pkgs, err := parseRequirementsTxt([]byte("# only comments\n\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestParseGemfileLock(t *testing.T) {
	content := []byte(`GIT
  remote: https://github.com/user/repo.git
  revision: abc123
  specs:
    custom_gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.4)
      actionpack (= 7.0.4)
      nio4r (~> 2.0)
    actionmailer (7.0.4)
      actionpack (= 7.0.4)
    rails (7.0.4)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  rails (~> 7.0)

BUNDLED WITH
   2.4.2
`)

	pkgs, err := parseGemfileLock(content)
	if err != nil {
		t.Fatalf("parseGemfileLock returned error: %v", err)
	}

	// Sort for deterministic assertions.
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name < pkgs[j].Name
	})

	// Only gems under GEM/specs at 4-space indent: actioncable, actionmailer, rails.
	expected := []Package{
		{Name: "actioncable", Version: "7.0.4", Ecosystem: "rubygems"},
		{Name: "actionmailer", Version: "7.0.4", Ecosystem: "rubygems"},
		{Name: "rails", Version: "7.0.4", Ecosystem: "rubygems"},
	}

	if len(pkgs) != len(expected) {
		t.Fatalf("expected %d packages, got %d: %+v", len(expected), len(pkgs), pkgs)
	}

	for i, exp := range expected {
		if pkgs[i] != exp {
			t.Errorf("package[%d]: got %+v, want %+v", i, pkgs[i], exp)
		}
	}
}

func TestParseGemfileLock_EmptyInput(t *testing.T) {
	pkgs, err := parseGemfileLock([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestParseLockfile_Dispatch(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		filename  string
		content   []byte
		ecosystem string
	}{
		{
			filename:  "/project/go.sum",
			content:   []byte("golang.org/x/text v0.3.7 h1:abc=\n"),
			ecosystem: "go",
		},
		{
			filename:  "/project/package-lock.json",
			content:   []byte(`{"packages":{"node_modules/express":{"version":"4.18.2"}}}`),
			ecosystem: "npm",
		},
		{
			filename:  "/project/requirements.txt",
			content:   []byte("Django==4.2.1\n"),
			ecosystem: "pypi",
		},
		{
			filename:  "/project/Gemfile.lock",
			content:   []byte("GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n\nPLATFORMS\n  ruby\n"),
			ecosystem: "rubygems",
		},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			pkgs, err := analyzer.ParseLockfile(tt.filename, tt.content)
			if err != nil {
				t.Fatalf("ParseLockfile(%s) returned error: %v", tt.filename, err)
			}
			if len(pkgs) == 0 {
				t.Fatal("expected at least one package")
			}
			if pkgs[0].Ecosystem != tt.ecosystem {
				t.Errorf("expected ecosystem %q, got %q", tt.ecosystem, pkgs[0].Ecosystem)
			}
		})
	}
}

func TestParseLockfile_UnknownType(t *testing.T) {
	analyzer := NewAnalyzer()

	_, err := analyzer.ParseLockfile("/project/unknown.lock", []byte("data"))
	if err == nil {
		t.Fatal("expected error for unknown lockfile type, got nil")
	}

	want := "unsupported lockfile type: unknown.lock"
	if err.Error() != want {
		t.Errorf("error message: got %q, want %q", err.Error(), want)
	}
}

func TestPackageInventory_AddAndPackages(t *testing.T) {
	inv := &PackageInventory{}

	inv.Add(Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"})
	inv.Add(Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"})
	inv.Add(Package{Name: "Django", Version: "4.2.1", Ecosystem: "pypi"})

	pkgs := inv.Packages()
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	// Verify order is preserved.
	if pkgs[0].Name != "express" {
		t.Errorf("expected first package to be express, got %s", pkgs[0].Name)
	}
	if pkgs[2].Name != "Django" {
		t.Errorf("expected third package to be Django, got %s", pkgs[2].Name)
	}
}

func TestPackageInventory_ByEcosystem(t *testing.T) {
	inv := &PackageInventory{}

	inv.Add(Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"})
	inv.Add(Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"})
	inv.Add(Package{Name: "Django", Version: "4.2.1", Ecosystem: "pypi"})
	inv.Add(Package{Name: "rails", Version: "7.0.4", Ecosystem: "rubygems"})

	npmPkgs := inv.ByEcosystem("npm")
	if len(npmPkgs) != 2 {
		t.Fatalf("expected 2 npm packages, got %d", len(npmPkgs))
	}

	pypiPkgs := inv.ByEcosystem("pypi")
	if len(pypiPkgs) != 1 {
		t.Fatalf("expected 1 pypi package, got %d", len(pypiPkgs))
	}

	goPkgs := inv.ByEcosystem("go")
	if len(goPkgs) != 0 {
		t.Fatalf("expected 0 go packages, got %d", len(goPkgs))
	}
}

func TestPackageInventory_Empty(t *testing.T) {
	inv := &PackageInventory{}

	pkgs := inv.Packages()
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages from empty inventory, got %d", len(pkgs))
	}

	eco := inv.ByEcosystem("npm")
	if len(eco) != 0 {
		t.Fatalf("expected 0 packages by ecosystem from empty inventory, got %d", len(eco))
	}
}

func TestScanArtifacts(t *testing.T) {
	// Create a temporary directory with lockfiles.
	tmpDir := t.TempDir()

	// Write a go.sum file.
	goSumContent := []byte("golang.org/x/text v0.3.7 h1:abc=\ngolang.org/x/text v0.3.7/go.mod h1:def=\n")
	goSumPath := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSumPath, goSumContent, 0644); err != nil {
		t.Fatalf("writing go.sum: %v", err)
	}

	// Write a requirements.txt file.
	reqContent := []byte("Django==4.2.1\nrequests==2.28.0\n")
	reqPath := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(reqPath, reqContent, 0644); err != nil {
		t.Fatalf("writing requirements.txt: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "go.sum",
			AbsPath: goSumPath,
			Type:    discovery.Lockfile,
			Size:    int64(len(goSumContent)),
		},
		{
			Path:    "requirements.txt",
			AbsPath: reqPath,
			Type:    discovery.Lockfile,
			Size:    int64(len(reqContent)),
		},
		{
			Path:    "main.go",
			AbsPath: filepath.Join(tmpDir, "main.go"),
			Type:    discovery.Source,
			Size:    100,
		},
	}

	analyzer := NewAnalyzer()
	inventory, fs, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	// Should have 3 packages: 1 from go.sum (deduplicated) + 2 from requirements.txt.
	pkgs := inventory.Packages()
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d: %+v", len(pkgs), pkgs)
	}

	// FindingSet should be empty (no OSV lookups yet).
	if len(fs.Findings()) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs.Findings()))
	}

	// Check ecosystem filtering.
	goPkgs := inventory.ByEcosystem("go")
	if len(goPkgs) != 1 {
		t.Fatalf("expected 1 go package, got %d", len(goPkgs))
	}

	pypiPkgs := inventory.ByEcosystem("pypi")
	if len(pypiPkgs) != 2 {
		t.Fatalf("expected 2 pypi packages, got %d", len(pypiPkgs))
	}
}

func TestScanArtifacts_SkipsUnsupportedLockfiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a yarn.lock file (not currently supported by parsers).
	yarnPath := filepath.Join(tmpDir, "yarn.lock")
	if err := os.WriteFile(yarnPath, []byte("# yarn lockfile v1\n"), 0644); err != nil {
		t.Fatalf("writing yarn.lock: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "yarn.lock",
			AbsPath: yarnPath,
			Type:    discovery.Lockfile,
			Size:    20,
		},
	}

	analyzer := NewAnalyzer()
	inventory, _, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts should not error on unsupported lockfiles: %v", err)
	}

	pkgs := inventory.Packages()
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages for unsupported lockfile, got %d", len(pkgs))
	}
}

func TestScanArtifacts_EmptyInput(t *testing.T) {
	analyzer := NewAnalyzer()
	inventory, fs, err := analyzer.ScanArtifacts(nil)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error on nil input: %v", err)
	}

	if len(inventory.Packages()) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(inventory.Packages()))
	}
	if len(fs.Findings()) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs.Findings()))
	}
}

func TestNewAnalyzer(t *testing.T) {
	a := NewAnalyzer()
	if a.OSVBaseURL != "https://api.osv.dev" {
		t.Errorf("expected OSVBaseURL %q, got %q", "https://api.osv.dev", a.OSVBaseURL)
	}
}
