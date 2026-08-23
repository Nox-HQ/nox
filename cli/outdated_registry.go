package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/fix"
)

// Multi-ecosystem support for `nox fix --outdated`.
//
// Currency needs two things that vulnerability scanning does not, which is why
// it cannot simply reuse the deps analyzer:
//
//  1. WHICH DEPENDENCIES ARE DIRECT. deps.Package is parsed from lockfiles,
//     which are flat and contain the entire transitive closure. Upgrading a
//     transitive package writes an explicit requirement for something the
//     project never imports — churn the operator then has to unpick. Directness
//     is declared in the MANIFEST (package.json, Cargo.toml, requirements.txt),
//     so both files are read: names from the manifest, resolved versions from
//     the lockfile.
//
//  2. WHAT THE LATEST VERSION IS, which only a registry can answer. Go gets
//     this from `go list -m -u`; every other ecosystem needs an HTTP call.
//
// Registries are queried directly rather than shelling out to npm/pip/cargo,
// so planning needs no toolchain and behaves the same everywhere. Applying an
// upgrade still uses the native command, which is where a toolchain genuinely
// belongs.

// directDep is one direct dependency with its currently-resolved version.
// An empty version means the manifest pins a range and no lockfile entry
// resolved it; the planner skips those rather than inventing a current version.
type directDep struct {
	eco     string
	name    string
	version string
}

// registryBase maps an ecosystem to its default registry root. Overridable per
// call so tests can point at a stub.
var registryBase = map[string]string{
	"npm":      "https://registry.npmjs.org",
	"pypi":     "https://pypi.org",
	"cargo":    "https://crates.io",
	"rubygems": "https://rubygems.org",
	"composer": "https://repo.packagist.org",
	"nuget":    "https://api.nuget.org",
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

// resolveLatest asks an ecosystem's registry for the latest STABLE version.
//
// Each registry expresses that differently, and picking the wrong field means
// silently proposing a prerelease: npm publishes channels under dist-tags where
// only `latest` is stable, and crates.io reports both max_version (which
// includes prereleases) and max_stable_version.
func resolveLatest(eco, pkg, base string) (string, error) {
	if base == "" {
		base = registryBase[eco]
	}
	if base == "" {
		return "", fmt.Errorf("no registry configured for ecosystem %q", eco)
	}

	var url string
	switch eco {
	case "npm":
		url = base + "/" + pkg
	case "pypi":
		url = base + "/pypi/" + pkg + "/json"
	case "cargo":
		url = base + "/api/v1/crates/" + pkg
	case "rubygems":
		url = base + "/api/v1/gems/" + pkg + ".json"
	case "composer":
		url = base + "/p2/" + pkg + ".json"
	case "nuget":
		// NuGet ids are case-insensitive, but the flat-container path is not:
		// `Newtonsoft.Json` 404s where `newtonsoft.json` succeeds, and a 404
		// here would report a perfectly ordinary package as un-checkable.
		url = base + "/v3-flatcontainer/" + strings.ToLower(pkg) + "/index.json"
	default:
		return "", fmt.Errorf("ecosystem %q has no currency resolver yet", eco)
	}

	req, err := http.NewRequest(http.MethodGet, url, http.NoBody) //nolint:noctx // short-lived CLI call with a client timeout
	if err != nil {
		return "", fmt.Errorf("%s registry: %w", eco, err)
	}
	// crates.io rejects requests without a descriptive User-Agent with HTTP 403
	// — Go's client sends none by default, so every cargo lookup failed against
	// the live registry while passing against stubs. Sent to all registries:
	// identifying the client is expected etiquette and some others rate-limit
	// anonymous traffic harder.
	req.Header.Set("User-Agent", "nox (+https://github.com/nox-hq/nox)")
	if eco == "npm" {
		// The full packument for a popular package is enormous — typescript and
		// @types/node both exceed 8 MB, which silently truncated the read and
		// surfaced as "unexpected end of JSON input". The abbreviated document
		// carries dist-tags and is orders of magnitude smaller.
		req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s registry: %w", eco, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Anything but 200 is an error, never an empty result. A silent "" would be
	// indistinguishable from "already current", so a rate-limited or unreachable
	// registry would quietly report the whole project as up to date.
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s registry returned HTTP %d for %s", eco, resp.StatusCode, pkg)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", fmt.Errorf("reading %s registry response: %w", eco, err)
	}

	switch eco {
	case "npm":
		var doc struct {
			DistTags map[string]string `json:"dist-tags"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("parsing npm response for %s: %w", pkg, err)
		}
		return doc.DistTags["latest"], nil
	case "pypi":
		var doc struct {
			Info struct {
				Version string `json:"version"`
			} `json:"info"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("parsing pypi response for %s: %w", pkg, err)
		}
		return doc.Info.Version, nil
	case "cargo":
		var doc struct {
			Crate struct {
				MaxStable string `json:"max_stable_version"`
				Max       string `json:"max_version"`
			} `json:"crate"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("parsing crates.io response for %s: %w", pkg, err)
		}
		// max_version includes prereleases; max_stable_version is the one a
		// currency pass wants. Fall back only when no stable release exists.
		if doc.Crate.MaxStable != "" {
			return doc.Crate.MaxStable, nil
		}
		return doc.Crate.Max, nil
	case "rubygems":
		var doc struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("parsing rubygems response for %s: %w", pkg, err)
		}
		return doc.Version, nil
	case "composer":
		var doc struct {
			Packages map[string][]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("parsing packagist response for %s: %w", pkg, err)
		}
		// Newest first, but mixed with branch aliases (dev-main) and
		// prereleases, so the first entry is often not a released version.
		for _, v := range doc.Packages[pkg] {
			if isStableVersion(v.Version) {
				return v.Version, nil
			}
		}
		return "", nil
	case "nuget":
		var doc struct {
			Versions []string `json:"versions"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("parsing nuget response for %s: %w", pkg, err)
		}
		// ASCENDING and including prereleases, so the last element is
		// frequently a beta — verified against the live API, where
		// newtonsoft.json ends 13.0.4, 13.0.5-beta1. Walk backwards to the
		// highest stable rather than taking the tail.
		for i := len(doc.Versions) - 1; i >= 0; i-- {
			if isStableVersion(doc.Versions[i]) {
				return doc.Versions[i], nil
			}
		}
		return "", nil
	}
	return "", fmt.Errorf("unreachable resolver for %q", eco)
}

// isStableVersion reports whether a version string is a plain release rather
// than a prerelease or a branch alias. SemVer puts prerelease data after a
// hyphen; Packagist additionally publishes `dev-<branch>` pseudo-versions, and
// NuGet mixes `-beta`/`-rc` straight into its ascending version list.
//
// Returning a prerelease from a currency pass would push a beta into someone's
// manifest, which is the one thing an unattended upgrade must never do.
func isStableVersion(v string) bool {
	if v == "" || strings.HasPrefix(v, "dev-") {
		return false
	}
	return !strings.Contains(v, "-")
}

// pkgNameForPath recovers the package name from a stub registry path. Test
// helper kept beside the resolver so the two stay in step.
func pkgNameForPath(path, eco string) string {
	switch eco {
	case "npm":
		return strings.TrimPrefix(path, "/")
	case "pypi":
		return strings.TrimSuffix(strings.TrimPrefix(path, "/pypi/"), "/json")
	case "cargo":
		return strings.TrimPrefix(path, "/api/v1/crates/")
	case "rubygems":
		return strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/gems/"), ".json")
	case "composer":
		return strings.TrimSuffix(strings.TrimPrefix(path, "/p2/"), ".json")
	case "nuget":
		return strings.TrimSuffix(strings.TrimPrefix(path, "/v3-flatcontainer/"), "/index.json")
	}
	return path
}

// directDeps enumerates direct dependencies across every ecosystem whose
// manifest is present in root. Missing or malformed manifests are skipped
// rather than failing: a repo with a broken package.json should still get its
// Cargo dependencies checked.
func directDeps(root string) []directDep {
	deps, _ := directDepsWithNotes(root)
	return deps
}

// manifestForEco names the file that declares direct dependencies for each
// registry-resolved ecosystem, so their presence can be reported on.
var manifestForEco = map[string]string{
	"npm":      "package.json",
	"cargo":    "Cargo.toml",
	"pypi":     "requirements.txt",
	"rubygems": "Gemfile",
	"composer": "composer.json",
}

// directDepsWithNotes enumerates direct dependencies and returns notes about
// anything it could NOT check.
//
// Both notes matter for the same reason. A manifest that exists but does not
// parse drops its whole ecosystem from the run, and a tree with no manifests at
// all was never checked in the first place — reporting either as "all
// dependencies are current" is the reassuring-but-empty result this project has
// had to dig out of CI repeatedly. "Report what you could not check" is the
// scan degradations contract; it applies here too.
func directDepsWithNotes(root string) (deps []directDep, notes []string) {
	deps = append(deps, npmDirectDeps(root)...)
	deps = append(deps, cargoDirectDeps(root)...)
	deps = append(deps, pypiDirectDeps(root)...)
	deps = append(deps, rubygemsDirectDeps(root)...)
	deps = append(deps, composerDirectDeps(root)...)
	deps = append(deps, nugetDirectDeps(root)...)

	// A manifest on disk that yielded nothing is either empty or unparseable.
	// Either way the operator should hear about it rather than lose the
	// ecosystem silently.
	found := 0
	for eco, file := range manifestForEco {
		if readIfPresent(filepath.Join(root, file)) == nil {
			continue
		}
		found++
		sawEco := false
		for _, d := range deps {
			if d.eco == eco {
				sawEco = true
				break
			}
		}
		if !sawEco {
			notes = append(notes, fmt.Sprintf("%s exists but no dependencies could be read from it", file))
		}
	}
	if hasGoMod(root) || hasProjectFile(root) {
		found++
	}
	if found == 0 {
		notes = append(notes, fmt.Sprintf("no supported manifest found in %s — nothing was checked", root))
	}
	return deps, notes
}

func hasGoMod(root string) bool {
	_, err := os.Stat(filepath.Join(root, "go.mod"))
	return err == nil
}

// hasProjectFile reports whether a .NET project file is present. NuGet has no
// single canonical manifest name, so it is detected by extension.
func hasProjectFile(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && (strings.HasSuffix(n, ".csproj") || strings.HasSuffix(n, ".fsproj") || strings.HasSuffix(n, ".vbproj")) {
			return true
		}
	}
	return false
}

func readIfPresent(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// npmDirectDeps reads names from package.json (dependencies AND
// devDependencies — a dev dependency still runs in CI and still carries
// vulnerabilities) and resolved versions from package-lock.json.
func npmDirectDeps(root string) []directDep {
	raw := readIfPresent(filepath.Join(root, "package.json"))
	if raw == nil {
		return nil
	}
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil
	}

	resolved := map[string]string{}
	if lock := readIfPresent(filepath.Join(root, "package-lock.json")); lock != nil {
		var doc struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(lock, &doc); err == nil {
			for path, e := range doc.Packages {
				// Keys look like "node_modules/express" or
				// "node_modules/@scope/thing"; the root package has key "".
				if name, ok := strings.CutPrefix(path, "node_modules/"); ok {
					resolved[name] = e.Version
				}
			}
		}
	}

	var out []directDep
	for _, set := range []map[string]string{manifest.Dependencies, manifest.DevDependencies} {
		for name := range set {
			out = append(out, directDep{eco: "npm", name: name, version: resolved[name]})
		}
	}
	return out
}

var cargoDepLine = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=`)

// cargoDirectDeps reads the [dependencies] and [dev-dependencies] tables of
// Cargo.toml for names, and Cargo.lock for resolved versions. Only the key is
// taken from the manifest, so both `serde = "1"` and the table form
// `tokio = { version = "1.20" }` are handled.
func cargoDirectDeps(root string) []directDep {
	raw := readIfPresent(filepath.Join(root, "Cargo.toml"))
	if raw == nil {
		return nil
	}

	names := map[string]bool{}
	inDeps := false
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			inDeps = t == "[dependencies]" || t == "[dev-dependencies]" || t == "[build-dependencies]"
			continue
		}
		if !inDeps || t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if m := cargoDepLine.FindStringSubmatch(line); m != nil {
			names[m[1]] = true
		}
	}

	resolved := map[string]string{}
	if lock := readIfPresent(filepath.Join(root, "Cargo.lock")); lock != nil {
		var name string
		for _, line := range strings.Split(string(lock), "\n") {
			t := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(t, "name = "):
				name = strings.Trim(strings.TrimPrefix(t, "name = "), `"`)
			case strings.HasPrefix(t, "version = ") && name != "":
				resolved[name] = strings.Trim(strings.TrimPrefix(t, "version = "), `"`)
				name = ""
			}
		}
	}

	var out []directDep
	for name := range names {
		out = append(out, directDep{eco: "cargo", name: name, version: resolved[name]})
	}
	return out
}

// pypiExactPin matches only `name == version`. A range (`>=2.0,<3.0`) has no
// single current version, so it is recorded with an empty version and skipped
// by the planner rather than being assigned a version it does not have.
var pypiExactPin = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)`)
var pypiAnyReq = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~]|$)`)

func pypiDirectDeps(root string) []directDep {
	raw := readIfPresent(filepath.Join(root, "requirements.txt"))
	if raw == nil {
		return nil
	}
	var out []directDep
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		// Strip inline comments before matching, so `urllib3 == 1.26.12  # x`
		// does not carry the comment into the version.
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		// Skip blanks, editable installs, options and requirement includes.
		if t == "" || strings.HasPrefix(t, "-") {
			continue
		}
		if m := pypiExactPin.FindStringSubmatch(t); m != nil {
			out = append(out, directDep{eco: "pypi", name: m[1], version: m[2]})
			continue
		}
		if m := pypiAnyReq.FindStringSubmatch(t); m != nil {
			out = append(out, directDep{eco: "pypi", name: m[1]})
		}
	}
	return out
}

// planRegistryCurrency plans upgrades for every non-Go ecosystem found in root.
//
// Failures are reported, never swallowed: a registry that is unreachable or
// rate-limiting must not make a project look up to date. Each is returned as a
// degradation string so the caller can print them, matching nox's "report what
// you could not check" model.
func planRegistryCurrency(root string, includeMajor bool, base map[string]string) (plan upgradePlan, degraded []string) {
	deps, notes := directDepsWithNotes(root)
	degraded = append(degraded, notes...)
	for _, d := range deps {
		if d.version == "" {
			// A range pin with no lockfile entry: there is no single current
			// version to compare, so there is nothing honest to say.
			plan.skipped++
			continue
		}
		latest, err := resolveLatest(d.eco, d.name, base[d.eco])
		if err != nil {
			degraded = append(degraded, fmt.Sprintf("could not determine the latest version of %s %s: %v", d.eco, d.name, err))
			continue
		}
		if latest == "" || !versionLess(d.version, latest) {
			continue
		}
		if !includeMajor && fix.IsMajorBump(d.version, latest) {
			plan.majorSkipped++
			continue
		}
		plan.actions = append(plan.actions, upgradeAction{
			ruleID:    "OUTDATED",
			pkg:       d.name,
			fromVer:   d.version,
			toVersion: latest,
			ecosystem: d.eco,
			action:    ecoBase(d.eco),
		})
	}
	return plan, degraded
}

var gemfileLine = regexp.MustCompile(`^\s*gem\s+["']([^"']+)["']`)
var gemfileLockSpec = regexp.MustCompile(`^\s{4}([A-Za-z0-9._-]+) \(([^)]+)\)`)

// rubygemsDirectDeps takes names from the Gemfile's `gem "name"` lines and
// resolved versions from Gemfile.lock.
//
// Gemfile.lock indents direct and transitive specs differently: entries under
// `specs:` are indented four spaces, their dependencies six. Matching on the
// four-space form alone would still include transitive gems that happen to be
// top-level specs, which is why names come from the Gemfile.
func rubygemsDirectDeps(root string) []directDep {
	raw := readIfPresent(filepath.Join(root, "Gemfile"))
	if raw == nil {
		return nil
	}
	names := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if m := gemfileLine.FindStringSubmatch(line); m != nil {
			names[m[1]] = true
		}
	}

	resolved := map[string]string{}
	if lock := readIfPresent(filepath.Join(root, "Gemfile.lock")); lock != nil {
		for _, line := range strings.Split(string(lock), "\n") {
			if m := gemfileLockSpec.FindStringSubmatch(line); m != nil {
				resolved[m[1]] = m[2]
			}
		}
	}

	var out []directDep
	for name := range names {
		out = append(out, directDep{eco: "rubygems", name: name, version: resolved[name]})
	}
	return out
}

// composerDirectDeps reads require/require-dev from composer.json and resolved
// versions from composer.lock.
//
// Platform requirements (php, ext-*, lib-*, composer-*) are dropped: they are
// constraints on the runtime, not packages, and Packagist has no entry for
// them — querying one would produce a spurious "could not determine" line for
// something that was never a dependency.
func composerDirectDeps(root string) []directDep {
	raw := readIfPresent(filepath.Join(root, "composer.json"))
	if raw == nil {
		return nil
	}
	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil
	}

	resolved := map[string]string{}
	if lock := readIfPresent(filepath.Join(root, "composer.lock")); lock != nil {
		var doc struct {
			Packages    []struct{ Name, Version string } `json:"packages"`
			PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
		}
		if err := json.Unmarshal(lock, &doc); err == nil {
			for _, set := range [][]struct{ Name, Version string }{doc.Packages, doc.PackagesDev} {
				for _, p := range set {
					resolved[p.Name] = strings.TrimPrefix(p.Version, "v")
				}
			}
		}
	}

	var out []directDep
	for _, set := range []map[string]string{manifest.Require, manifest.RequireDev} {
		for name := range set {
			if isComposerPlatformRequirement(name) {
				continue
			}
			out = append(out, directDep{eco: "composer", name: name, version: resolved[name]})
		}
	}
	return out
}

// isComposerPlatformRequirement reports whether a composer `require` key names
// the runtime rather than a package. A real package is always `vendor/name`.
func isComposerPlatformRequirement(name string) bool {
	if !strings.Contains(name, "/") {
		return true // "php", "hhvm"
	}
	for _, p := range []string{"ext-", "lib-", "composer-"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var packageRefRe = regexp.MustCompile(`<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"`)

// nugetDirectDeps reads <PackageReference> entries from every project file in
// root. Unlike npm or Cargo there is no lockfile in a default project: the
// Include/Version pair in the .csproj IS the resolved version.
//
// <ProjectReference> is deliberately not matched — it names a sibling project
// on disk, not a package, and Packagist-style lookups for it would 404.
func nugetDirectDeps(root string) []directDep {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []directDep
	seen := map[string]bool{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || (!strings.HasSuffix(n, ".csproj") && !strings.HasSuffix(n, ".fsproj") && !strings.HasSuffix(n, ".vbproj")) {
			continue
		}
		raw := readIfPresent(filepath.Join(root, n))
		for _, m := range packageRefRe.FindAllStringSubmatch(string(raw), -1) {
			if seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			out = append(out, directDep{eco: "nuget", name: m[1], version: m[2]})
		}
	}
	return out
}

// ecoBase returns the base upgrade command for an ecosystem, or "" if nox fix
// cannot drive it — from the shared core/fix registry so the CLI and the
// planner agree on what is supported.
func ecoBase(eco string) string { c, _ := fix.SupportedEcosystem(eco); return c }
