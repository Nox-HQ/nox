package deps

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
)

// lockfileCase is one table row shared by the five parsers below.
type lockfileCase struct {
	name    string
	input   string
	want    []Package
	wantErr bool
}

func runLockfileCases(t *testing.T, parse func([]byte) ([]Package, error), cases []lockfileCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parse([]byte(tc.input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// Formats: https://github.com/swiftlang/swift-package-manager (Package.resolved
// v1 under "object", v2/v3 flat with "identity" and "location").
func TestParsePackageResolved(t *testing.T) {
	runLockfileCases(t, parsePackageResolved, []lockfileCase{
		{name: "v1", input: `{
  "object": {
    "pins": [
      {"package": "Alamofire", "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
       "state": {"branch": null, "revision": "f82c23a8", "version": "5.6.1"}},
      {"package": "Branchy", "repositoryURL": "https://github.com/x/Branchy.git",
       "state": {"branch": "main", "revision": "abc", "version": null}}
    ]
  },
  "version": 1
}`, want: []Package{{Name: "https://github.com/Alamofire/Alamofire.git", Version: "5.6.1", Ecosystem: "swift"}}},
		{name: "v2", input: `{
  "pins" : [
    {"identity" : "swift-nio", "kind" : "remoteSourceControl",
     "location" : "https://github.com/apple/swift-nio.git",
     "state" : {"revision" : "1", "version" : "2.40.0"}},
    {"identity" : "vapor", "kind" : "remoteSourceControl",
     "location" : "https://github.com/vapor/vapor.git",
     "state" : {"branch" : "main", "revision" : "2"}}
  ],
  "version" : 2
}`, want: []Package{{Name: "https://github.com/apple/swift-nio.git", Version: "2.40.0", Ecosystem: "swift"}}},
		{name: "v3 with originHash", input: `{"originHash":"abc","pins":[{"identity":"a","kind":"remoteSourceControl","location":"https://github.com/o/a","state":{"revision":"r","version":"1.0.0"}}],"version":3}`,
			want: []Package{{Name: "https://github.com/o/a", Version: "1.0.0", Ecosystem: "swift"}}},
		{name: "no pins", input: `{"pins":[],"version":2}`},
		{name: "empty", input: ``},
		{name: "malformed", input: `{"pins": [`, wantErr: true},
		{name: "not an object", input: `[1,2]`, wantErr: true},
	})
}

// Format: https://hexdocs.pm/mix/Mix.Tasks.Deps.html (mix.lock is an Elixir map
// literal, one `"name": {:hex, :name, "version", ...}` entry per line).
func TestParseMixLock(t *testing.T) {
	runLockfileCases(t, parseMixLock, []lockfileCase{
		{name: "hex and git", input: `%{
  "cowboy": {:hex, :cowboy, "2.9.0", "2c4f5c1b", [:make, :rebar3], [{:cowlib, "2.11.0", [hex: :cowlib, repo: "hexpm", optional: false]}], "hexpm", "aa3f"},
  "gitdep": {:git, "https://github.com/x/gitdep.git", "abc123", [branch: "main"]},
  "plug": {:hex, :plug, "1.11.0", "f17217525597628298998bc3baed9f8ea1fa3f1160aa9871aee6df47a6e4d38e", [:mix], [{:mime, "~> 1.0", [hex: :mime, repo: "hexpm", optional: false]}], "hexpm", "2d9c633f0499f9dc5c2fd069161af4e2e7756890b81adcbb2ceaa074e8308876"},
  "renamed": {:hex, :real_name, "0.1.0", "aa", [:mix], [], "hexpm", "bb"},
}
`, want: []Package{
			{Name: "cowboy", Version: "2.9.0", Ecosystem: "hex"},
			{Name: "plug", Version: "1.11.0", Ecosystem: "hex"},
			{Name: "real_name", Version: "0.1.0", Ecosystem: "hex"},
		}},
		{name: "empty map", input: "%{\n}\n"},
		{name: "empty", input: ``},
		{name: "truncated", input: "%{\n  \"plug\": {:hex, :plug, \"1.11.0\",", wantErr: true},
		{name: "not a map", input: "hello world", wantErr: true},
		{name: "hex entry without version", input: "%{\n  \"plug\": {:hex, :plug},\n}\n", wantErr: true},
	})
}

// Format: https://docs.gradle.org/current/userguide/dependency_locking.html
func TestParseGradleLockfile(t *testing.T) {
	runLockfileCases(t, parseGradleLockfile, []lockfileCase{
		{name: "standard", input: `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
org.apache.logging.log4j:log4j-api:2.14.1=compileClasspath,runtimeClasspath
org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath
org.apache.logging.log4j:log4j-core:2.14.1=testCompileClasspath
com.google.guava:guava:31.0.1-jre=compileClasspath
empty=annotationProcessor,testAnnotationProcessor
`, want: []Package{
			{Name: "org.apache.logging.log4j:log4j-api", Version: "2.14.1", Ecosystem: "gradle"},
			{Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Ecosystem: "gradle"},
			{Name: "com.google.guava:guava", Version: "31.0.1-jre", Ecosystem: "gradle"},
		}},
		{name: "only empty", input: "# header\nempty=annotationProcessor\n"},
		{name: "empty", input: ``},
		{name: "garbage line", input: "org.x:y:1.0=compileClasspath\nthis is not a lockfile\n", wantErr: true},
		{name: "missing version", input: "org.x:y=compileClasspath\n", wantErr: true},
	})
}

// Format: https://guides.cocoapods.org/using/the-podfile.html (Podfile.lock).
func TestParsePodfileLock(t *testing.T) {
	runLockfileCases(t, parsePodfileLock, []lockfileCase{
		{name: "pods with subspecs", input: `PODS:
  - AFNetworking (4.0.1):
    - AFNetworking/NSURLSession (= 4.0.1)
    - AFNetworking/Reachability (= 4.0.1)
  - AFNetworking/NSURLSession (4.0.1)
  - AFNetworking/Reachability (4.0.1)
  - "Firebase/Core (8.0.0)":
    - FirebaseAnalytics (= 8.0.0)
  - FirebaseAnalytics (8.0.0)
  - Local (from ` + "`../Local`" + `)

DEPENDENCIES:
  - AFNetworking (~> 4.0)

SPEC REPOS:
  trunk:
    - AFNetworking

SPEC CHECKSUMS:
  AFNetworking: 7864c38297c79aaca1500c33288e429c3451fdce

PODFILE CHECKSUM: 4f7e0e5d7ac3c2a1a3c5

COCOAPODS: 1.11.3
`, want: []Package{
			{Name: "AFNetworking", Version: "4.0.1", Ecosystem: "cocoapods"},
			{Name: "Firebase", Version: "8.0.0", Ecosystem: "cocoapods"},
			{Name: "FirebaseAnalytics", Version: "8.0.0", Ecosystem: "cocoapods"},
		}},
		{name: "empty pods", input: "PODS: []\n\nCOCOAPODS: 1.11.3\n"},
		{name: "empty", input: ``},
		{name: "no PODS section", input: "COCOAPODS: 1.11.3\n", wantErr: true},
		{name: "malformed pod", input: "PODS:\n  - NoVersionHere\n", wantErr: true},
	})
}

// Format: https://docs.conan.io/2/tutorial/versioning/lockfiles.html (2.x,
// "version": "0.5") and Conan 1.x graph_lock files.
func TestParseConanLock(t *testing.T) {
	runLockfileCases(t, parseConanLock, []lockfileCase{
		{name: "v0.5", input: `{
  "version": "0.5",
  "requires": [
    "zlib/1.2.11#f1fadf0d3b196dc0332750354ad8ab7b%1646157360.2",
    "openssl/1.1.1q#e4c8ab4b%1665000000.1"
  ],
  "build_requires": ["cmake/3.22.0#aaaa%1"],
  "python_requires": ["tools/1.0"]
}`, want: []Package{
			{Name: "cmake", Version: "3.22.0", Ecosystem: "conan"},
			{Name: "openssl", Version: "1.1.1q", Ecosystem: "conan"},
			{Name: "zlib", Version: "1.2.11", Ecosystem: "conan"},
		}},
		{name: "graph_lock", input: `{
  "graph_lock": {
    "nodes": {
      "0": {"ref": "conanfile.txt", "requires": ["1"]},
      "1": {"ref": "zlib/1.2.11@_/_#abc", "package_id": "x", "prev": "y", "context": "host"},
      "2": {"pref": "bzip2/1.0.8@user/stable#rev:pkgid#prev", "context": "build"}
    },
    "revisions_enabled": true
  },
  "version": "0.4"
}`, want: []Package{
			{Name: "bzip2", Version: "1.0.8", Ecosystem: "conan"},
			{Name: "zlib", Version: "1.2.11", Ecosystem: "conan"},
		}},
		{name: "no requires", input: `{"version":"0.5","requires":[]}`},
		{name: "empty", input: ``},
		{name: "malformed", input: `{"requires": [`, wantErr: true},
		{name: "ref without version", input: `{"requires":["zlib"]}`, wantErr: true},
		{name: "unrecognised shape", input: `{"hello":"world"}`, wantErr: true},
	})
}

func TestNewLockfiles_AreDiscoveredAndGovernManifests(t *testing.T) {
	for lockfile, manifest := range map[string]string{
		"Package.resolved": "Package.swift",
		"mix.lock":         "mix.exs",
		"gradle.lockfile":  "libs.versions.toml",
		"Podfile.lock":     "Podfile",
		"conan.lock":       "conanfile.txt",
	} {
		if _, ok := supportedLockfiles[lockfile]; !ok {
			t.Errorf("%s has no parser", lockfile)
		}
		if !lockfileTypes[lockfile] {
			t.Errorf("discovery does not classify %s as a lockfile", lockfile)
		}
		if got := lockfileEcosystems[lockfile]; got == "" || got != manifestTable[manifest].Ecosystem {
			t.Errorf("%s governs ecosystem %q, want %q", lockfile, got, manifestTable[manifest].Ecosystem)
		}
	}
	if !contains(manifestTable["conanfile.py"].Lockfiles, "conan.lock") {
		t.Error("conanfile.py does not name conan.lock")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// A lockfile that governs a manifest replaces the "no reader" degradation, and
// its packages reach the inventory.
func TestScanArtifacts_NewLockfilesFeedInventoryAndGovernManifest(t *testing.T) {
	arts := writeTree(t, map[string]string{
		"mix.exs":  "defmodule X.MixProject do\nend\n",
		"mix.lock": "%{\n  \"plug\": {:hex, :plug, \"1.11.0\", \"aa\", [:mix], [], \"hexpm\", \"bb\"},\n}\n",
	})
	inv, d := scanOffline(t, arts)
	pkgs := inv.Packages()
	if len(pkgs) != 1 || pkgs[0].Name != "plug" || pkgs[0].Ecosystem != "hex" {
		t.Fatalf("inventory = %+v", pkgs)
	}
	for _, e := range d.Items() {
		t.Errorf("unexpected degradation: %+v", e)
	}
}

// A malformed lockfile is a degradation, never a clean scan.
func TestScanArtifacts_MalformedNewLockfileIsADegradation(t *testing.T) {
	arts := writeTree(t, map[string]string{"Package.resolved": `{"pins": [`})
	_, d := scanOffline(t, arts)
	if len(d.Items()) == 0 {
		t.Fatal("malformed Package.resolved produced no degradation")
	}
}

// OSV cannot be asked about Swift, CocoaPods or Conan through the advisory
// pipeline: those packages are inventoried and the gap is named.
func TestScanArtifacts_UnqueryableEcosystemIsDegradedNotSilent(t *testing.T) {
	arts := writeTree(t, map[string]string{
		"Podfile.lock": "PODS:\n  - AFNetworking (4.0.1)\n",
		"mix.lock":     "%{\n  \"plug\": {:hex, :plug, \"1.11.0\", \"aa\", [:mix], [], \"hexpm\", \"bb\"},\n}\n",
	})
	d := &degrade.Degradations{}
	a := NewAnalyzer(WithDegradations(d), WithSource(&stubSource{name: "stub"}))
	inv, _, err := a.ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Packages()) != 2 {
		t.Fatalf("inventory = %+v", inv.Packages())
	}
	var found int
	for _, e := range d.Items() {
		if strings.Contains(e.Detail, "cocoapods") {
			found++
		}
		if strings.Contains(e.Detail, "hex") {
			t.Errorf("hex is queryable but was reported: %+v", e)
		}
	}
	if found != 1 {
		t.Errorf("want exactly one cocoapods degradation, got %d: %+v", found, d.Items())
	}
}
