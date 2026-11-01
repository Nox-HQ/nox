package deps

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/discovery"
)

type manifestReaderCase struct {
	name       string
	content    string
	want       []Package
	unresolved []string // "name" of each expected unresolved spec
}

func runReaderCases(t *testing.T, read manifestReader, cases []manifestReaderCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgs, unresolved, err := read([]byte(tc.content))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(pkgs, tc.want) {
				t.Errorf("packages = %+v\nwant       %+v", pkgs, tc.want)
			}
			var got []string
			for _, u := range unresolved {
				got = append(got, u.Name)
			}
			if !reflect.DeepEqual(got, tc.unresolved) {
				t.Errorf("unresolved = %v, want %v (%+v)", got, tc.unresolved, unresolved)
			}
		})
	}
}

func TestParsePyprojectManifest(t *testing.T) {
	runReaderCases(t, parsePyprojectManifest, []manifestReaderCase{
		{
			name: "pep 621",
			content: `[project]
name = "x"
dependencies = [
  "django==2.2.0",
  "requests>=2.0,<3",
  "flask[async]~=2.0.1",
  "pkg @ https://example.com/pkg.whl",
  "numpy; python_version < '3.9'",
  "pyyaml (==5.4)",
]
[project.optional-dependencies]
dev = ["pytest==7.0.0"]
`,
			want: []Package{
				{Name: "django", Version: "2.2.0", Ecosystem: "pypi"},
				{Name: "flask", Version: "2.0.1", Ecosystem: "pypi", Spec: "~=2.0.1"},
				{Name: "pytest", Version: "7.0.0", Ecosystem: "pypi"},
				{Name: "pyyaml", Version: "5.4", Ecosystem: "pypi"},
				{Name: "requests", Version: "2.0", Ecosystem: "pypi", Spec: ">=2.0,<3"},
			},
			unresolved: []string{"numpy", "pkg"},
		},
		{
			name: "poetry",
			content: `[tool.poetry.dependencies]
python = "^3.9"
urllib3 = "1.26.4"
pyyaml = {version = "^5.3", extras = ["x"]}
lib = {git = "https://example.com/lib.git"}
star = "*"
[tool.poetry.group.dev.dependencies]
black = ">=22.1.0,<23"
`,
			want: []Package{
				{Name: "black", Version: "22.1.0", Ecosystem: "pypi", Spec: ">=22.1.0,<23"},
				{Name: "pyyaml", Version: "5.3.0", Ecosystem: "pypi", Spec: "^5.3"},
				{Name: "urllib3", Version: "1.26.4", Ecosystem: "pypi"},
			},
			unresolved: []string{"lib", "star"},
		},
		{name: "tool config only", content: "[tool.ruff]\nline-length = 100\n", want: nil},
	})
	if _, _, err := parsePyprojectManifest([]byte("[project\n")); err == nil {
		t.Error("malformed pyproject.toml parsed without error")
	}
}

func TestParseCargoManifest(t *testing.T) {
	runReaderCases(t, parseCargoManifest, []manifestReaderCase{{
		name: "all shapes",
		content: `[package]
name = "x"
[dependencies]
smallvec = "=1.6.0"
serde = "1.0.100"
tokio = { version = "1", features = ["full"] }
local = { path = "../local" }
fork = { git = "https://example.com/fork" }
shared = { workspace = true }
star = "*"
renamed = { package = "real-name", version = "0.3.1" }
[dev-dependencies]
rand = "~0.8.0"
[dependencies.regex]
version = "1.5.4"
[target.'cfg(unix)'.dependencies]
libc = ">=0.2.100, <0.3"
[workspace.dependencies]
anyhow = "=1.0.40"
`,
		want: []Package{
			{Name: "anyhow", Version: "1.0.40", Ecosystem: "cargo"},
			{Name: "libc", Version: "0.2.100", Ecosystem: "cargo", Spec: ">=0.2.100, <0.3"},
			{Name: "rand", Version: "0.8.0", Ecosystem: "cargo", Spec: "~0.8.0"},
			{Name: "real-name", Version: "0.3.1", Ecosystem: "cargo", Spec: "0.3.1"},
			{Name: "regex", Version: "1.5.4", Ecosystem: "cargo", Spec: "1.5.4"},
			{Name: "serde", Version: "1.0.100", Ecosystem: "cargo", Spec: "1.0.100"},
			{Name: "smallvec", Version: "1.6.0", Ecosystem: "cargo"},
			{Name: "tokio", Version: "1.0.0", Ecosystem: "cargo", Spec: "1"},
		},
		unresolved: []string{"fork", "local", "shared", "star"},
	}})
	if _, _, err := parseCargoManifest([]byte("[dependencies\n")); err == nil {
		t.Error("malformed Cargo.toml parsed without error")
	}
}

func TestParseCsprojManifest(t *testing.T) {
	runReaderCases(t, parseCsprojManifest, []manifestReaderCase{{
		name: "package references",
		content: `<Project Sdk="Microsoft.NET.Sdk" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Serilog"><Version>2.10.0</Version></PackageReference>
    <PackageReference Include="Ranged" Version="[1.0,2.0)" />
    <PackageReference Include="Central" />
    <PackageReference Include="Prop" Version="$(PropVersion)" />
    <PackageVersion Include="Props.Central" Version="3.1.4" />
  </ItemGroup>
</Project>`,
		want: []Package{
			{Name: "Newtonsoft.Json", Version: "12.0.1", Ecosystem: "nuget"},
			{Name: "Props.Central", Version: "3.1.4", Ecosystem: "nuget"},
			{Name: "Ranged", Version: "1.0", Ecosystem: "nuget", Spec: "[1.0,2.0)"},
			{Name: "Serilog", Version: "2.10.0", Ecosystem: "nuget"},
		},
		unresolved: []string{"Central", "Prop"},
	}})
	if _, _, err := parseCsprojManifest([]byte("<Project><ItemGroup>")); err == nil {
		t.Error("malformed csproj parsed without error")
	}
}

func TestParseComposerManifest(t *testing.T) {
	runReaderCases(t, parseComposerManifest, []manifestReaderCase{{
		name: "require and require-dev",
		content: `{"require":{"php":">=7.4","ext-json":"*","monolog/monolog":"1.25.0",
		  "guzzlehttp/guzzle":"^6.3","a/b":"dev-master","c/d":"~2.1 || ^3.0","e/f":"2.*"},
		  "require-dev":{"phpunit/phpunit":"^9.0 | ^10.0","monolog/monolog":"2.0.0"}}`,
		want: []Package{
			{Name: "c/d", Version: "2.1.0", Ecosystem: "composer", Spec: "~2.1 || ^3.0"},
			{Name: "e/f", Version: "2.0.0", Ecosystem: "composer", Spec: "2.*"},
			{Name: "guzzlehttp/guzzle", Version: "6.3.0", Ecosystem: "composer", Spec: "^6.3"},
			{Name: "monolog/monolog", Version: "1.25.0", Ecosystem: "composer"},
			{Name: "phpunit/phpunit", Version: "9.0.0", Ecosystem: "composer", Spec: "^9.0 | ^10.0"},
		},
		unresolved: []string{"a/b"},
	}})
	if _, _, err := parseComposerManifest([]byte(`{"require":`)); err == nil {
		t.Error("malformed composer.json parsed without error")
	}
}

func TestParseGemfileManifest(t *testing.T) {
	runReaderCases(t, parseGemfileManifest, []manifestReaderCase{{
		name: "gems",
		content: `source 'https://rubygems.org'
gem 'rails'
gem 'nokogiri', '1.8.0'
gem "rack", "~> 2.0.1"
gem 'devise', '>= 4.0', '< 5'
gem 'foo', git: 'https://example.com/foo.git'
gem 'bar', '1.0', require: false
gem 'baz', path: '../baz'
# gem 'commented', '1.0.0'
group :test do
  gem 'rspec', '3.9.0'
end
`,
		want: []Package{
			{Name: "bar", Version: "1.0", Ecosystem: "rubygems"},
			{Name: "devise", Version: "4.0", Ecosystem: "rubygems", Spec: ">= 4.0, < 5"},
			{Name: "nokogiri", Version: "1.8.0", Ecosystem: "rubygems"},
			{Name: "rack", Version: "2.0.1", Ecosystem: "rubygems", Spec: "~> 2.0.1"},
			{Name: "rspec", Version: "3.9.0", Ecosystem: "rubygems"},
		},
		unresolved: []string{"baz", "foo", "rails"},
	}})
}

func TestParsePubspecManifest(t *testing.T) {
	runReaderCases(t, parsePubspecManifest, []manifestReaderCase{{
		name: "dependencies",
		content: `name: app
dependencies:
  flutter:
    sdk: flutter
  http: ^0.13.0
  intl: 0.17.0
  path: any
  fork:
    git: https://example.com/fork.git
  bar:
    hosted: {name: bar, url: "https://pub.example.com"}
    version: ^1.0.0
dev_dependencies:
  test: ">=1.16.0 <2.0.0"
`,
		want: []Package{
			{Name: "bar", Version: "1.0.0", Ecosystem: "pub", Spec: "^1.0.0"},
			{Name: "http", Version: "0.13.0", Ecosystem: "pub", Spec: "^0.13.0"},
			{Name: "intl", Version: "0.17.0", Ecosystem: "pub"},
			{Name: "test", Version: "1.16.0", Ecosystem: "pub", Spec: ">=1.16.0 <2.0.0"},
		},
		unresolved: []string{"fork", "path"},
	}})
	if _, _, err := parsePubspecManifest([]byte("dependencies: [")); err == nil {
		t.Error("malformed pubspec.yaml parsed without error")
	}
}

// The table is the single place that names a manifest, its ecosystem and the
// lockfiles that govern it. Every lockfile it names must be one nox parses, or
// the claim "a lockfile is committed beside it" would be a claim nothing read.
func TestManifestTable_LockfilesAreParsed(t *testing.T) {
	for name, spec := range manifestTable {
		for _, lf := range spec.Lockfiles {
			if _, ok := supportedLockfiles[lf]; !ok {
				t.Errorf("%s names lockfile %s, which nox does not parse", name, lf)
			}
		}
		if spec.Read == nil && len(spec.Lockfiles) != 0 {
			t.Errorf("%s has lockfiles but no reader: its lockfiles cannot govern what nox cannot read", name)
		}
	}
	for _, name := range []string{"Cargo.toml", "pyproject.toml", "composer.json", "Gemfile", "pubspec.yaml", "Package.swift",
		"mix.exs", "build.sbt", "conanfile.txt", "conanfile.py", "Podfile", "App.csproj", "App.fsproj", "Directory.Packages.props"} {
		if _, ok := lookupManifest(name); !ok {
			t.Errorf("%s is not recognised as a dependency manifest", name)
		}
	}
	for _, name := range []string{"main.go", "README.md", "pom.xml", "build.gradle"} {
		if _, ok := lookupManifest(name); ok {
			t.Errorf("%s should not be in the manifest table (it is parsed as a lockfile already)", name)
		}
	}
}

func scanManifestTree(t *testing.T, files map[string]string, opts ...AnalyzerOption) (*PackageInventory, *degrade.Degradations, []string) {
	t.Helper()
	arts := writeTree(t, files)
	d := &degrade.Degradations{}
	a := NewAnalyzer(append([]AnalyzerOption{WithDegradations(d)}, opts...)...)
	inv, fs, err := a.ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	var vulns []string
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-001" {
			vulns = append(vulns, f.Metadata["package"]+"@"+f.Metadata["version"])
		}
	}
	return inv, d, vulns
}

// The reproduced defect: a Cargo.toml pinning smallvec 1.6.0 and nothing else
// declared produced "0 dependencies" and no degradation.
func TestScanArtifacts_CargoManifestOnlyYieldsVulnerability(t *testing.T) {
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{
		"smallvec": {{ID: "RUSTSEC-2021-0003", Summary: "Buffer overflow in SmallVec::insert_many"}},
	}}
	inv, d, vulns := scanManifestTree(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"x\"\n[dependencies]\nsmallvec = \"=1.6.0\"\n",
	}, WithSource(src))
	if got := inv.Packages(); len(got) != 1 || got[0].Name != "smallvec" || got[0].Version != "1.6.0" || got[0].Ecosystem != "cargo" {
		t.Fatalf("inventory = %+v", got)
	}
	if !reflect.DeepEqual(vulns, []string{"smallvec@1.6.0"}) {
		t.Errorf("VULN-001 = %v, want smallvec@1.6.0", vulns)
	}
	items := d.Items()
	if len(items) != 1 || !strings.Contains(items[0].Detail, "Cargo.toml") ||
		!strings.Contains(items[0].Detail, "Cargo.lock") || !strings.Contains(items[0].Impact, "manifest") {
		t.Errorf("degradations = %+v, want one naming Cargo.toml and Cargo.lock", items)
	}
}

func TestScanArtifacts_LockfileGovernsItsEcosystemManifest(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"cargo", map[string]string{
			"Cargo.toml": "[dependencies]\nsmallvec = \"=1.6.0\"\n",
			"Cargo.lock": "[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\n",
		}},
		{"poetry", map[string]string{
			"pyproject.toml": "[tool.poetry.dependencies]\ndjango = \"2.2.0\"\n",
			"poetry.lock":    "[[package]]\nname = \"django\"\nversion = \"2.2.0\"\n",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv, d, _ := scanManifestTree(t, tc.files, WithOSVDisabled())
			if n := len(inv.Packages()); n != 1 {
				t.Errorf("packages = %+v, want the lockfile's one (not double counted)", inv.Packages())
			}
			if items := d.Items(); len(items) != 0 {
				t.Errorf("degradations = %+v, want none: a lockfile is beside the manifest", items)
			}
		})
	}
}

// A lockfile for a DIFFERENT ecosystem must not govern: Cargo.toml beside a
// package-lock.json is still ungoverned.
func TestScanArtifacts_ForeignLockfileDoesNotGovern(t *testing.T) {
	_, d, _ := scanManifestTree(t, map[string]string{
		"Cargo.toml":        "[dependencies]\nsmallvec = \"=1.6.0\"\n",
		"package-lock.json": `{"lockfileVersion":3,"packages":{}}`,
	}, WithOSVDisabled())
	if items := d.Items(); len(items) != 1 || !strings.Contains(items[0].Detail, "Cargo.toml") {
		t.Errorf("degradations = %+v", items)
	}
}

// Every manifest nox cannot turn into dependencies says so, by name.
func TestScanArtifacts_UnreadableManifestIsADegradationNotSilence(t *testing.T) {
	for _, name := range []string{"Package.swift", "mix.exs", "build.sbt", "conanfile.txt", "conanfile.py", "Podfile", "libs.versions.toml"} {
		t.Run(name, func(t *testing.T) {
			_, d, _ := scanManifestTree(t, map[string]string{name: "// dependencies live here\n"}, WithOSVDisabled())
			items := d.Items()
			if len(items) != 1 {
				t.Fatalf("degradations = %+v, want exactly one", items)
			}
			if !strings.Contains(items[0].Detail, name) || !strings.Contains(items[0].Impact, "NOT scanned") {
				t.Errorf("degradation does not name %s and what was not checked: %+v", name, items[0])
			}
			if items[0].Kind != degrade.Lockfile {
				t.Errorf("kind = %s, want %s", items[0].Kind, degrade.Lockfile)
			}
		})
	}
}

func TestScanArtifacts_MalformedManifestIsADegradationNotSilence(t *testing.T) {
	for name, body := range map[string]string{
		"Cargo.toml":     "[dependencies\n",
		"pyproject.toml": "[project\n",
		"composer.json":  `{"require":`,
		"pubspec.yaml":   "dependencies: [",
		"App.csproj":     "<Project><ItemGroup>",
	} {
		t.Run(name, func(t *testing.T) {
			_, d, _ := scanManifestTree(t, map[string]string{name: body}, WithOSVDisabled())
			items := d.Items()
			if len(items) != 1 || !strings.Contains(items[0].Detail, name) || !strings.Contains(items[0].Impact, "NOT scanned") {
				t.Errorf("degradations = %+v", items)
			}
		})
	}
}

func TestScanArtifacts_ManifestDeclaringNothingIsNotADegradation(t *testing.T) {
	_, d, _ := scanManifestTree(t, map[string]string{
		"pyproject.toml": "[tool.ruff]\nline-length = 100\n",
		"Cargo.toml":     "[workspace]\nmembers = [\"a\"]\n",
	}, WithOSVDisabled())
	if items := d.Items(); len(items) != 0 {
		t.Errorf("degradations = %+v, want none", items)
	}
}

// The per-ecosystem readers all go through the pipeline the CLI uses.
func TestScanArtifacts_EveryReaderFeedsTheInventory(t *testing.T) {
	cases := map[string]struct{ file, body, name string }{
		"pypi":     {"pyproject.toml", "[project]\ndependencies = [\"django==2.2.0\"]\n", "django"},
		"nuget":    {"App.csproj", `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1"/></ItemGroup></Project>`, "Newtonsoft.Json"},
		"composer": {"composer.json", `{"require":{"monolog/monolog":"1.25.0"}}`, "monolog/monolog"},
		"gems":     {"Gemfile", "gem 'nokogiri', '1.8.0'\n", "nokogiri"},
		"pub":      {"pubspec.yaml", "dependencies:\n  http: 0.13.0\n", "http"},
	}
	for eco, tc := range cases {
		t.Run(eco, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, tc.file)
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			d := &degrade.Degradations{}
			a := NewAnalyzer(WithOSVDisabled(), WithDegradations(d))
			inv, _, err := a.ScanArtifacts(context.Background(), []discovery.Artifact{{Path: tc.file, AbsPath: p, Type: discovery.Config}})
			if err != nil {
				t.Fatal(err)
			}
			if got := inv.Packages(); len(got) != 1 || got[0].Name != tc.name {
				t.Errorf("inventory = %+v, want %s", got, tc.name)
			}
			if len(d.Items()) != 1 {
				t.Errorf("want the versions-from-manifest degradation, got %+v", d.Items())
			}
		})
	}
}
