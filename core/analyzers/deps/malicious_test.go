package deps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "ab", 1},
		{"ab", "abc", 1},
		{"kitten", "sitting", 3},
		{"lodash", "lodas", 1},
		{"lodash", "lodassh", 1},
		{"", "abc", 3},
		{"abc", "", 3},
		{"flaw", "lawn", 2},
		{"express", "expresss", 1}, //nolint:misspell // intentional typosquatting test data
		{"react", "react", 0},
		{"numpy", "numppy", 1},
		{"requests", "reqests", 1},
		{"requests", "reqeusts", 2},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := LevenshteinDistance(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("LevenshteinDistance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestLevenshteinDistance_Symmetric(t *testing.T) {
	pairs := [][2]string{
		{"kitten", "sitting"},
		{"lodash", "lodassh"},
		{"abc", "def"},
		{"react", "raect"},
	}

	for _, pair := range pairs {
		ab := LevenshteinDistance(pair[0], pair[1])
		ba := LevenshteinDistance(pair[1], pair[0])
		if ab != ba {
			t.Errorf("LevenshteinDistance(%q, %q) = %d, but LevenshteinDistance(%q, %q) = %d — should be symmetric",
				pair[0], pair[1], ab, pair[1], pair[0], ba)
		}
	}
}

func TestDetectTyposquatting(t *testing.T) {
	tests := []struct {
		name      string
		pkgName   string
		ecosystem string
		threshold int
		wantMatch string
		wantFound bool
	}{
		{
			name:      "exact match returns false (npm)",
			pkgName:   "lodash",
			ecosystem: "npm",
			threshold: 2,
			wantMatch: "",
			wantFound: false,
		},
		{
			name:      "exact match returns false (pypi)",
			pkgName:   "requests",
			ecosystem: "pypi",
			threshold: 2,
			wantMatch: "",
			wantFound: false,
		},
		{
			name:      "typosquat lodassh -> lodash",
			pkgName:   "lodassh",
			ecosystem: "npm",
			threshold: 2,
			wantMatch: "lodash",
			wantFound: true,
		},
		{
			name:      "typosquat reqests -> requests",
			pkgName:   "reqests",
			ecosystem: "pypi",
			threshold: 2,
			wantMatch: "requests",
			wantFound: true,
		},
		{
			name:      "completely different package",
			pkgName:   "completely-different-package",
			ecosystem: "npm",
			threshold: 2,
			wantMatch: "",
			wantFound: false,
		},
		{
			name:      "unsupported ecosystem returns false",
			pkgName:   "lodassh",
			ecosystem: "cargo",
			threshold: 2,
			wantMatch: "",
			wantFound: false,
		},
		{
			name:      "typosquat expresss -> express", //nolint:misspell // intentional typosquatting test data
			pkgName:   "expresss",                      //nolint:misspell // intentional typosquatting test data
			ecosystem: "npm",
			threshold: 2,
			wantMatch: "express",
			wantFound: true,
		},
		{
			name:      "typosquat numppy -> numpy",
			pkgName:   "numppy",
			ecosystem: "pypi",
			threshold: 2,
			wantMatch: "numpy",
			wantFound: true,
		},
		{
			name:      "threshold 1 rejects distance 2",
			pkgName:   "reqeusts",
			ecosystem: "pypi",
			threshold: 1,
			wantMatch: "",
			wantFound: false,
		},
		{
			name:      "case insensitive exact match",
			pkgName:   "Express",
			ecosystem: "npm",
			threshold: 2,
			wantMatch: "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotFound := DetectTyposquatting(tt.pkgName, tt.ecosystem, tt.threshold)
			if gotFound != tt.wantFound {
				t.Errorf("DetectTyposquatting(%q, %q, %d) found=%v, want found=%v",
					tt.pkgName, tt.ecosystem, tt.threshold, gotFound, tt.wantFound)
			}
			if gotMatch != tt.wantMatch {
				t.Errorf("DetectTyposquatting(%q, %q, %d) match=%q, want match=%q",
					tt.pkgName, tt.ecosystem, tt.threshold, gotMatch, tt.wantMatch)
			}
		})
	}
}

func TestIsKnownMalicious(t *testing.T) {
	tests := []struct {
		name      string
		pkgName   string
		ecosystem string
		want      bool
	}{
		{
			name:      "known malicious npm package",
			pkgName:   "crossenv",
			ecosystem: "npm",
			want:      true,
		},
		{
			name:      "known malicious pypi package",
			pkgName:   "colourama",
			ecosystem: "pypi",
			want:      true,
		},
		{
			name:      "legitimate npm package",
			pkgName:   "react",
			ecosystem: "npm",
			want:      false,
		},
		{
			name:      "legitimate pypi package",
			pkgName:   "requests",
			ecosystem: "pypi",
			want:      false,
		},
		{
			name:      "unknown ecosystem",
			pkgName:   "crossenv",
			ecosystem: "cargo",
			want:      false,
		},
		{
			name:      "case insensitive malicious check",
			pkgName:   "CrossEnv",
			ecosystem: "npm",
			want:      true,
		},
		{
			name:      "flatmap-stream malicious",
			pkgName:   "flatmap-stream",
			ecosystem: "npm",
			want:      true,
		},
		{
			name:      "dajngo malicious pypi",
			pkgName:   "dajngo",
			ecosystem: "pypi",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsKnownMalicious(tt.pkgName, tt.ecosystem)
			if got != tt.want {
				t.Errorf("IsKnownMalicious(%q, %q) = %v, want %v",
					tt.pkgName, tt.ecosystem, got, tt.want)
			}
		})
	}
}

func TestRulesContainVULN002AndVULN003(t *testing.T) {
	a := NewAnalyzer(WithOSVDisabled())
	rs := a.Rules()

	if !rs.HasID("VULN-002") {
		t.Error("Rules() does not contain VULN-002")
	}
	if !rs.HasID("VULN-003") {
		t.Error("Rules() does not contain VULN-003")
	}

	vuln002, _ := rs.ByID("VULN-002")
	if vuln002.Description != "Typosquatting: package name suspiciously similar to popular package" {
		t.Errorf("VULN-002 description: got %q", vuln002.Description)
	}

	vuln003, _ := rs.ByID("VULN-003")
	if vuln003.Description != "Known malicious package detected" {
		t.Errorf("VULN-003 description: got %q", vuln003.Description)
	}

	// Verify supply-chain tags.
	scRules := rs.ByTag("supply-chain")
	if len(scRules) < 2 {
		t.Errorf("expected at least 2 supply-chain rules, got %d", len(scRules))
	}
}

func TestScanArtifacts_MaliciousPackageDetection(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a package-lock.json with a known malicious package.
	content := []byte(`{
  "packages": {
    "node_modules/crossenv": {
      "version": "1.0.0"
    },
    "node_modules/express": {
      "version": "4.18.2"
    }
  }
}`)
	lockPath := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockPath, content, 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "package-lock.json",
			AbsPath: lockPath,
			Type:    discovery.Lockfile,
			Size:    int64(len(content)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	_, fs, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	// Should have at least one VULN-003 finding for crossenv.
	var foundVULN003 bool
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-003" {
			foundVULN003 = true
			if f.Metadata["package"] != "crossenv" {
				t.Errorf("VULN-003 finding package: got %q, want %q", f.Metadata["package"], "crossenv")
			}
		}
	}
	if !foundVULN003 {
		t.Error("expected a VULN-003 finding for known malicious package crossenv")
	}
}

func TestScanArtifacts_TyposquattingDetection(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a requirements.txt with a typosquatted package name.
	content := []byte("reqests==2.28.0\n")
	lockPath := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(lockPath, content, 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "requirements.txt",
			AbsPath: lockPath,
			Type:    discovery.Lockfile,
			Size:    int64(len(content)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	_, fs, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	// Should have at least one VULN-002 finding for reqests -> requests.
	var foundVULN002 bool
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-002" {
			foundVULN002 = true
			if f.Metadata["package"] != "reqests" {
				t.Errorf("VULN-002 finding package: got %q, want %q", f.Metadata["package"], "reqests")
			}
			if f.Metadata["similar_package"] != "requests" {
				t.Errorf("VULN-002 finding similar_package: got %q, want %q", f.Metadata["similar_package"], "requests")
			}
		}
	}
	if !foundVULN002 {
		t.Error("expected a VULN-002 finding for typosquatted package reqests")
	}
}

func TestScanArtifacts_LegitimatePackagesNoFindings(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a package-lock.json with only legitimate packages.
	content := []byte(`{
  "packages": {
    "node_modules/express": {
      "version": "4.18.2"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`)
	lockPath := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockPath, content, 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "package-lock.json",
			AbsPath: lockPath,
			Type:    discovery.Lockfile,
			Size:    int64(len(content)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	_, fs, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	// Legitimate packages should produce no VULN-002 or VULN-003 findings.
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-002" || f.RuleID == "VULN-003" {
			t.Errorf("unexpected finding %s for legitimate package: %s", f.RuleID, f.Message)
		}
	}
}

func TestPopularPackagesLoaded(t *testing.T) {
	// Force-load popular packages and verify they are non-empty.
	popularOnce.Do(loadPopular)

	npmPkgs, ok := popularPkgs["npm"]
	if !ok || len(npmPkgs) == 0 {
		t.Fatal("expected non-empty npm popular packages list")
	}
	if len(npmPkgs) < 200 {
		t.Errorf("expected at least 200 npm popular packages, got %d", len(npmPkgs))
	}

	pypiPkgs, ok := popularPkgs["pypi"]
	if !ok || len(pypiPkgs) == 0 {
		t.Fatal("expected non-empty pypi popular packages list")
	}
	if len(pypiPkgs) < 200 {
		t.Errorf("expected at least 200 pypi popular packages, got %d", len(pypiPkgs))
	}
}

func TestMaliciousPackagesLoaded(t *testing.T) {
	// Force-load malicious packages and verify they are non-empty.
	maliciousOnce.Do(loadMalicious)

	npmMal, ok := maliciousPkgs["npm"]
	if !ok || len(npmMal) == 0 {
		t.Fatal("expected non-empty npm malicious packages list")
	}

	pypiMal, ok := maliciousPkgs["pypi"]
	if !ok || len(pypiMal) == 0 {
		t.Fatal("expected non-empty pypi malicious packages list")
	}
}
