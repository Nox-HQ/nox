package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/fix"
)

// Currency needs two things per ecosystem that vulnerability scanning does not:
//
//  1. Which dependencies are DIRECT. deps.Package comes from lockfiles, which
//     are flat and include the whole transitive closure. Upgrading a transitive
//     package writes an explicit requirement for something the project does not
//     import — churn the operator has to unpick. Directness lives in the
//     manifest, not the lockfile.
//  2. What the latest published version is, which only a registry can answer.
//
// These tests cover both, per ecosystem, against stub registries.

func writeManifest(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestDirectDeps_NPM(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "package.json", `{
	  "name": "app",
	  "dependencies":    { "express": "^4.18.0", "@scope/thing": "1.2.3" },
	  "devDependencies": { "jest": "~29.0.0" }
	}`)
	// The lockfile carries the resolved versions AND the transitive closure.
	writeManifest(t, dir, "package-lock.json", `{
	  "lockfileVersion": 3,
	  "packages": {
	    "node_modules/express":      { "version": "4.18.2" },
	    "node_modules/@scope/thing": { "version": "1.2.3" },
	    "node_modules/jest":         { "version": "29.0.1" },
	    "node_modules/body-parser":  { "version": "1.20.0" }
	  }
	}`)

	got := directDeps(dir)
	byName := map[string]string{}
	for _, d := range got {
		if d.eco == "npm" {
			byName[d.name] = d.version
		}
	}

	for name, want := range map[string]string{
		"express":      "4.18.2",
		"@scope/thing": "1.2.3",
		"jest":         "29.0.1", // devDependencies count: they run in CI
	} {
		if byName[name] != want {
			t.Errorf("npm %s = %q, want %q (resolved version must come from the lockfile, not the range)", name, byName[name], want)
		}
	}
	// The whole point: a transitive package must not appear.
	if v, ok := byName["body-parser"]; ok {
		t.Errorf("body-parser is transitive but was reported as direct (version %q)", v)
	}
}

func TestDirectDeps_Cargo(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "Cargo.toml", `
[package]
name = "app"

[dependencies]
serde = "1.0.100"
tokio = { version = "1.20", features = ["full"] }

[dev-dependencies]
proptest = "1.0"
`)
	writeManifest(t, dir, "Cargo.lock", `
[[package]]
name = "serde"
version = "1.0.150"

[[package]]
name = "tokio"
version = "1.28.0"

[[package]]
name = "proptest"
version = "1.2.0"

[[package]]
name = "libc"
version = "0.2.140"
`)

	byName := map[string]string{}
	for _, d := range directDeps(dir) {
		if d.eco == "cargo" {
			byName[d.name] = d.version
		}
	}
	// `tokio` is declared in table form; parsing only bare strings would miss it.
	for name, want := range map[string]string{"serde": "1.0.150", "tokio": "1.28.0", "proptest": "1.2.0"} {
		if byName[name] != want {
			t.Errorf("cargo %s = %q, want %q", name, byName[name], want)
		}
	}
	if _, ok := byName["libc"]; ok {
		t.Error("libc is transitive but was reported as direct")
	}
}

func TestDirectDeps_PyPI(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "requirements.txt", `
# comment
requests==2.28.1
flask>=2.0,<3.0
urllib3 == 1.26.12   # inline comment
-e .
`)

	byName := map[string]string{}
	for _, d := range directDeps(dir) {
		if d.eco == "pypi" {
			byName[d.name] = d.version
		}
	}
	if byName["requests"] != "2.28.1" {
		t.Errorf("requests = %q, want 2.28.1", byName["requests"])
	}
	if byName["urllib3"] != "1.26.12" {
		t.Errorf("urllib3 = %q, want 1.26.12 (whitespace around == must not defeat parsing)", byName["urllib3"])
	}
	// A range pin has no single current version; reporting one would invent a
	// fact. It is listed with an empty version and skipped by the planner.
	if v := byName["flask"]; v != "" {
		t.Errorf("flask = %q, want empty — a range gives no exact current version", v)
	}
	if _, ok := byName["-e ."]; ok {
		t.Error("an editable install was parsed as a package name")
	}
}

// Each registry answers "what is latest" in its own shape. A wrong field means
// silently proposing the wrong upgrade, so each is pinned by a test.
func TestRegistryResolvers(t *testing.T) {
	cases := []struct {
		eco, path, body, want string
	}{
		{"npm", "/express", `{"dist-tags":{"latest":"4.19.2","next":"5.0.0-beta"}}`, "4.19.2"},
		{"pypi", "/pypi/requests/json", `{"info":{"version":"2.31.0"}}`, "2.31.0"},
		{"cargo", "/api/v1/crates/serde", `{"crate":{"max_stable_version":"1.0.197","max_version":"1.1.0-alpha"}}`, "1.0.197"},
	}
	for _, tc := range cases {
		t.Run(tc.eco, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			got, err := resolveLatest(tc.eco, pkgNameForPath(tc.path, tc.eco), srv.URL)
			if err != nil {
				t.Fatalf("resolveLatest: %v", err)
			}
			if got != tc.want {
				t.Errorf("latest = %q, want %q", got, tc.want)
			}
		})
	}
}

// Prerelease channels must never win. npm's `next`, cargo's `max_version` and
// PyPI's yanked-but-present releases are all traps: an operator running a
// currency pass wants the current stable, not a beta.
func TestRegistryResolvers_IgnorePrereleaseChannels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"crate":{"max_stable_version":"1.0.197","max_version":"2.0.0-rc.1"}}`))
	}))
	defer srv.Close()

	got, err := resolveLatest("cargo", "serde", srv.URL)
	if err != nil {
		t.Fatalf("resolveLatest: %v", err)
	}
	if got != "1.0.197" {
		t.Errorf("cargo latest = %q — max_version is a prerelease and must not be chosen", got)
	}
}

// A registry that is down, rate-limiting, or does not know the package must
// produce an error rather than an empty string that reads as "no update".
func TestRegistryResolvers_ErrorsRatherThanReportingCurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	if got, err := resolveLatest("npm", "express", srv.URL); err == nil {
		t.Errorf("a 429 produced no error (returned %q); the package would look up to date", got)
	}
}

// npm's full packument for a popular package is enormous — typescript and
// @types/node both exceed 8 MB — which truncated the response body and surfaced
// as "unexpected end of JSON input" against the real registry. Every dependency
// in the VS Code extension reported as un-checkable.
//
// The fix is to ask for the abbreviated document rather than to keep raising a
// size ceiling, so this asserts the header is actually sent. Found only by
// running against the live registry; no stub was ever big enough to catch it.
func TestNpmResolver_RequestsTheAbbreviatedPackument(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"1.0.0"}}`))
	}))
	defer srv.Close()

	if _, err := resolveLatest("npm", "typescript", srv.URL); err != nil {
		t.Fatalf("resolveLatest: %v", err)
	}
	if gotAccept != "application/vnd.npm.install-v1+json" {
		t.Errorf("Accept = %q, want the abbreviated-packument media type; "+
			"the full document is large enough to truncate", gotAccept)
	}
}

// Second batch of ecosystems. Each registry answers "latest" in a different
// shape, and two of the three actively invite picking a prerelease.
func TestRegistryResolvers_SecondBatch(t *testing.T) {
	cases := []struct {
		name, eco, path, body, want string
	}{
		{
			// RubyGems is the easy one: .version is already the latest stable.
			name: "rubygems", eco: "rubygems", path: "/api/v1/gems/rails.json",
			body: `{"name":"rails","version":"8.1.3"}`, want: "8.1.3",
		},
		{
			// Packagist returns versions NEWEST-FIRST, mixed with branch
			// aliases (dev-master) and prereleases. Taking [0] blindly can
			// yield "dev-main".
			name: "packagist", eco: "composer", path: "/p2/monolog/monolog.json",
			body: `{"packages":{"monolog/monolog":[
				{"version":"dev-main"},
				{"version":"3.11.0-RC1"},
				{"version":"3.10.0"},
				{"version":"3.9.0"}]}}`,
			want: "3.10.0",
		},
		{
			// NuGet returns ASCENDING versions INCLUDING prereleases, so the
			// last element is frequently a beta. Verified against the live API:
			// newtonsoft.json ends 13.0.4, 13.0.5-beta1 — versions[-1] is the
			// beta and 13.0.4 is the answer.
			name: "nuget", eco: "nuget", path: "/v3-flatcontainer/newtonsoft.json/index.json",
			body: `{"versions":["13.0.3-beta1","13.0.3","13.0.4-beta1","13.0.4","13.0.5-beta1"]}`,
			want: "13.0.4",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("requested %q, want %q", r.URL.Path, tc.path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			got, err := resolveLatest(tc.eco, pkgNameForPath(tc.path, tc.eco), srv.URL)
			if err != nil {
				t.Fatalf("resolveLatest: %v", err)
			}
			if got != tc.want {
				t.Errorf("latest = %q, want %q", got, tc.want)
			}
		})
	}
}

// NuGet ids are case-insensitive but the flat-container path must be lowercase,
// so a manifest saying `Newtonsoft.Json` has to become `newtonsoft.json` or the
// request 404s and the package reports as un-checkable.
func TestNugetResolver_LowercasesThePackageID(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"versions":["13.0.4"]}`))
	}))
	defer srv.Close()

	if _, err := resolveLatest("nuget", "Newtonsoft.Json", srv.URL); err != nil {
		t.Fatalf("resolveLatest: %v", err)
	}
	if gotPath != "/v3-flatcontainer/newtonsoft.json/index.json" {
		t.Errorf("path = %q; the NuGet id must be lowercased", gotPath)
	}
}

// A package with only prereleases published has no stable version. Returning
// the prerelease anyway would push a beta into someone's manifest; returning
// nothing is the honest answer and the planner treats it as "no update".
func TestRegistryResolvers_NoStableRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"versions":["1.0.0-alpha","1.0.0-beta"]}`))
	}))
	defer srv.Close()

	got, err := resolveLatest("nuget", "somepkg", srv.URL)
	if err != nil {
		t.Fatalf("resolveLatest: %v", err)
	}
	if got != "" {
		t.Errorf("latest = %q — no stable release exists, so there is nothing to propose", got)
	}
}

func TestDirectDeps_RubyGems(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "Gemfile", `
source "https://rubygems.org"
gem "rails", "~> 8.1"
gem 'puma'
gem "rspec", require: false
`)
	writeManifest(t, dir, "Gemfile.lock", `
GEM
  remote: https://rubygems.org/
  specs:
    rails (8.1.3)
    puma (6.4.2)
    rspec (3.13.0)
    concurrent-ruby (1.2.3)
`)

	byName := map[string]string{}
	for _, d := range directDeps(dir) {
		if d.eco == "rubygems" {
			byName[d.name] = d.version
		}
	}
	for name, want := range map[string]string{"rails": "8.1.3", "puma": "6.4.2", "rspec": "3.13.0"} {
		if byName[name] != want {
			t.Errorf("rubygems %s = %q, want %q", name, byName[name], want)
		}
	}
	if _, ok := byName["concurrent-ruby"]; ok {
		t.Error("concurrent-ruby is transitive but was reported as direct")
	}
}

func TestDirectDeps_Composer(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "composer.json", `{
	  "require":     { "monolog/monolog": "^3.0", "php": ">=8.1" },
	  "require-dev": { "phpunit/phpunit": "^10.0" }
	}`)
	writeManifest(t, dir, "composer.lock", `{
	  "packages":     [{"name":"monolog/monolog","version":"3.10.0"},
	                   {"name":"psr/log","version":"3.0.0"}],
	  "packages-dev": [{"name":"phpunit/phpunit","version":"10.5.0"}]
	}`)

	byName := map[string]string{}
	for _, d := range directDeps(dir) {
		if d.eco == "composer" {
			byName[d.name] = d.version
		}
	}
	if byName["monolog/monolog"] != "3.10.0" {
		t.Errorf("monolog = %q, want 3.10.0", byName["monolog/monolog"])
	}
	if byName["phpunit/phpunit"] != "10.5.0" {
		t.Errorf("phpunit = %q, want 10.5.0", byName["phpunit/phpunit"])
	}
	// "php" is a platform requirement, not a package — Packagist has no such
	// entry and querying it would produce a spurious degraded line.
	if _, ok := byName["php"]; ok {
		t.Error("the php platform requirement was treated as a package")
	}
	if _, ok := byName["psr/log"]; ok {
		t.Error("psr/log is transitive but was reported as direct")
	}
}

// A resolver without an applier plans an upgrade nox cannot perform: the plan
// prints, the operator agrees, and applyUpgrade then fails with "ecosystem not
// supported". Worse, planRegistryCurrency reads the command name out of
// supportedFixEcosystems, so a missing entry renders a plan line with an empty
// command.
//
// This is the same declared-but-dead shape as the fail-on-degraded action input
// and the GITHUB_TOKEN that action.yml never mapped: two halves that must agree
// and nothing connecting them. Fail the build instead.
func TestEveryCurrencyEcosystemCanAlsoApply(t *testing.T) {
	for eco := range registryBase {
		if _, ok := fix.SupportedEcosystem(eco); !ok {
			t.Errorf("ecosystem %q has a currency resolver but no entry in "+
				"supportedFixEcosystems, so --outdated would plan an upgrade it cannot apply", eco)
		}
	}
	// Go resolves through the toolchain rather than a registry, so it is absent
	// from registryBase but must still be appliable.
	if _, ok := fix.SupportedEcosystem("go"); !ok {
		t.Error("go lost its applier")
	}
}

// NuGet declares direct dependencies as <PackageReference> in the project file,
// and there is no lockfile in a default project — the Include/Version pair IS
// the resolved version, so unlike npm or Cargo there is no second file to read.
func TestDirectDeps_NuGet(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "App.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="3.1.1" />
    <ProjectReference Include="../Other/Other.csproj" />
  </ItemGroup>
</Project>`)

	byName := map[string]string{}
	for _, d := range directDeps(dir) {
		if d.eco == "nuget" {
			byName[d.name] = d.version
		}
	}
	if byName["Newtonsoft.Json"] != "13.0.3" {
		t.Errorf("Newtonsoft.Json = %q, want 13.0.3", byName["Newtonsoft.Json"])
	}
	if byName["Serilog"] != "3.1.1" {
		t.Errorf("Serilog = %q, want 3.1.1", byName["Serilog"])
	}
	// A ProjectReference is a sibling project, not a package.
	if _, ok := byName["../Other/Other.csproj"]; ok {
		t.Error("a ProjectReference was treated as a NuGet package")
	}
}

// crates.io answers HTTP 403 to requests without a descriptive User-Agent, and
// Go's http.Client sends none by default. Every cargo lookup failed against the
// live registry while passing against every stub here — the second bug in this
// file that only a real request could surface.
func TestResolvers_SendAUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`{"crate":{"max_stable_version":"1.0.0"}}`))
	}))
	defer srv.Close()

	if _, err := resolveLatest("cargo", "serde", srv.URL); err != nil {
		t.Fatalf("resolveLatest: %v", err)
	}
	if !strings.Contains(gotUA, "nox") {
		t.Errorf("User-Agent = %q; crates.io 403s anonymous clients", gotUA)
	}
}

// "all direct dependencies are current" on a tree with no manifests is the
// exact failure this project keeps finding elsewhere: a reassuring message
// where nothing was actually checked. There is a real difference between
// "checked seven ecosystems, everything current" and "found nothing to check".
func TestDirectDeps_ReportsWhenNoManifestExists(t *testing.T) {
	_, notes := directDepsWithNotes(t.TempDir())
	if len(notes) == 0 {
		t.Fatal("an empty directory produced no note; --outdated would report it as all-current")
	}
	joined := strings.Join(notes, " ")
	if !strings.Contains(joined, "no supported manifest") {
		t.Errorf("note does not say a manifest was missing: %q", joined)
	}
}

// A manifest that exists but cannot be parsed must be reported, not skipped.
// Silently dropping it means the ecosystem disappears from the run while the
// summary still reads as a clean result.
func TestDirectDeps_ReportsUnparseableManifest(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "package.json", `{ this is not json`)
	// A valid second ecosystem, to prove one broken manifest does not stop the
	// others being checked.
	writeManifest(t, dir, "Cargo.toml", "[package]\nname=\"x\"\n\n[dependencies]\nserde = \"1.0.100\"\n")
	writeManifest(t, dir, "Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\n")

	deps, notes := directDepsWithNotes(dir)

	var sawCargo bool
	for _, d := range deps {
		if d.eco == "cargo" && d.name == "serde" {
			sawCargo = true
		}
	}
	if !sawCargo {
		t.Error("a broken package.json stopped Cargo from being checked")
	}

	joined := strings.Join(notes, " ")
	if !strings.Contains(joined, "package.json") {
		t.Errorf("the unparseable package.json was dropped silently: %q", joined)
	}
}
