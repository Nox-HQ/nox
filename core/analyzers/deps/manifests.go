package deps

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/discovery"
)

// manifestReader turns a dependency manifest into the packages it declares at a
// usable version and, separately, the declarations it could not resolve. It
// never guesses: see parsePackageJSONManifest for the version conventions every
// reader shares.
type manifestReader func(content []byte) (pkgs []Package, unresolved []unresolvedSpec, err error)

// manifestSpec says what a recognised dependency manifest is.
type manifestSpec struct {
	// Ecosystem is the Package.Ecosystem its dependencies carry, and the
	// ecosystem of the lockfiles that govern it.
	Ecosystem string
	// Label names the ecosystem for a reader of a degradation.
	Label string
	// Lockfiles are the lockfiles which, committed beside the manifest, make its
	// versions authoritative. Every name must be one supportedLockfiles parses:
	// a lockfile nox cannot read governs nothing.
	Lockfiles []string
	// Read is nil when nox has no reader for the manifest. Such a manifest is
	// always reported, because nothing was checked from it.
	Read manifestReader
}

// manifestTable is the one place that names a dependency manifest, its
// ecosystem and the lockfiles that govern it. A manifest that is already parsed
// as a lockfile (pom.xml, build.gradle, build.gradle.kts, go.mod) is NOT here:
// it is read directly and reports its own failure.
//
// Keyed by exact basename; manifestSuffixes covers names that vary.
var manifestTable = map[string]manifestSpec{
	"package.json": {"npm", "npm", []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}, parsePackageJSONManifest},

	"pyproject.toml": {"pypi", "Python", []string{"poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt"}, parsePyprojectManifest},
	"Pipfile":        {"pypi", "Python (Pipenv)", []string{"Pipfile.lock"}, nil},

	"Cargo.toml":    {"cargo", "Rust", []string{"Cargo.lock"}, parseCargoManifest},
	"composer.json": {"composer", "PHP", []string{"composer.lock"}, parseComposerManifest},
	"Gemfile":       {"rubygems", "Ruby", []string{"Gemfile.lock"}, parseGemfileManifest},
	"pubspec.yaml":  {"pub", "Dart", []string{"pubspec.lock"}, parsePubspecManifest},

	"Directory.Packages.props": {"nuget", ".NET", []string{"packages.lock.json"}, parseCsprojManifest},

	// No reader. Each of these is recognised so that a project built on it is
	// never reported as having no dependencies.
	"Package.swift":      {"swift", "Swift Package Manager", nil, nil},
	"mix.exs":            {"hex", "Elixir (Mix)", nil, nil},
	"build.sbt":          {"sbt", "Scala (sbt)", nil, nil},
	"conanfile.txt":      {"conan", "C/C++ (Conan)", nil, nil},
	"conanfile.py":       {"conan", "C/C++ (Conan)", nil, nil},
	"vcpkg.json":         {"vcpkg", "C/C++ (vcpkg)", nil, nil},
	"Podfile":            {"cocoapods", "CocoaPods", nil, nil},
	"Cartfile":           {"carthage", "Carthage", nil, nil},
	"libs.versions.toml": {"gradle", "Gradle version catalog", nil, nil},
	"rebar.config":       {"hex", "Erlang (rebar3)", nil, nil},
	"stack.yaml":         {"hackage", "Haskell (Stack)", nil, nil},
	"cabal.project":      {"hackage", "Haskell (Cabal)", nil, nil},
	"Project.toml":       {"julia", "Julia", nil, nil},
	"DESCRIPTION":        {"cran", "R", nil, nil},
	"cpanfile":           {"cpan", "Perl", nil, nil},
}

// manifestSuffixes are manifests recognised by extension. .NET project files
// carry the project's name.
var manifestSuffixes = map[string]manifestSpec{
	".csproj": {"nuget", ".NET", []string{"packages.lock.json"}, parseCsprojManifest},
	".fsproj": {"nuget", ".NET", []string{"packages.lock.json"}, parseCsprojManifest},
	".vbproj": {"nuget", ".NET", []string{"packages.lock.json"}, parseCsprojManifest},
}

// lookupManifest reports whether base names a dependency manifest.
func lookupManifest(base string) (manifestSpec, bool) {
	if spec, ok := manifestTable[base]; ok {
		return spec, true
	}
	spec, ok := manifestSuffixes[strings.ToLower(filepath.Ext(base))]
	return spec, ok
}

// lockfileEcosystems maps a lockfile basename to the ecosystem it governs,
// derived from manifestTable so the two cannot disagree.
var lockfileEcosystems = func() map[string]string {
	out := map[string]string{}
	add := func(spec manifestSpec) {
		for _, lf := range spec.Lockfiles {
			out[lf] = spec.Ecosystem
		}
	}
	for _, spec := range manifestTable {
		add(spec)
	}
	for _, spec := range manifestSuffixes {
		add(spec)
	}
	return out
}()

// manifestDedupe tracks the lockfiles seen during a scan, by ecosystem and
// directory, so a manifest can defer to the lockfile that governs it.
type manifestDedupe struct {
	// names maps ecosystem, then lockfile directory, to the package names that
	// lockfile resolved.
	names map[string]map[string]map[string]struct{}
}

func newManifestDedupe() *manifestDedupe {
	return &manifestDedupe{names: map[string]map[string]map[string]struct{}{}}
}

// nameKey normalises a package name for comparison: PyPI names are
// case-insensitive and treat "-", "_" and "." alike.
func nameKey(ecosystem, name string) string {
	if ecosystem != "pypi" {
		return name
	}
	r := strings.NewReplacer("_", "-", ".", "-")
	return r.Replace(strings.ToLower(name))
}

// record notes that the lockfile in dir resolved these packages. A lockfile
// that failed to parse is still recorded, with no names: it exists, so the
// manifest is not "without a lockfile", but it resolved nothing, so the manifest
// still fills in.
func (d *manifestDedupe) record(ecosystem, dir string, pkgs []Package) {
	dirs := d.names[ecosystem]
	if dirs == nil {
		dirs = map[string]map[string]struct{}{}
		d.names[ecosystem] = dirs
	}
	set := dirs[dir]
	if set == nil {
		set = map[string]struct{}{}
		dirs[dir] = set
	}
	for _, p := range pkgs {
		if p.Ecosystem == ecosystem {
			set[nameKey(ecosystem, p.Name)] = struct{}{}
		}
	}
}

// governing returns the names resolved by the lockfiles of ecosystem that
// govern a manifest in dir (its own directory or any ancestor, which is how a
// workspace root's lockfile covers member packages), and whether any exists.
func (d *manifestDedupe) governing(ecosystem, dir string) (map[string]struct{}, bool) {
	names := map[string]struct{}{}
	found := false
	for lockDir, set := range d.names[ecosystem] {
		if lockDir != "." && dir != lockDir && !strings.HasPrefix(dir, lockDir+"/") {
			continue
		}
		found = true
		for n := range set {
			names[n] = struct{}{}
		}
	}
	return names, found
}

// manifestPackages are the packages read from one manifest.
type manifestPackages struct {
	Path string
	Pkgs []Package
}

// readManifests reads every recognised dependency manifest among artifacts and
// reports, as a degradation, each one whose dependencies were not all turned
// into checked packages. This is the language-agnostic guarantee: a manifest nox
// recognised and did not fully read never passes as "no dependencies".
//
// A lockfile stays authoritative: a manifest contributes only the names its
// lockfile does not resolve, and everything when there is no lockfile at all.
func (a *Analyzer) readManifests(artifacts []discovery.Artifact, locks *manifestDedupe) []manifestPackages {
	var out []manifestPackages
	for _, art := range artifacts {
		spec, ok := lookupManifest(filepath.Base(art.Path))
		if !ok || isInstalledDependencyPath(art.Path) {
			continue
		}
		if spec.Read == nil {
			// A lockfile is read on its own: Pipfile beside Pipfile.lock was
			// scanned, though nox cannot read the Pipfile itself.
			if _, governed := locks.governing(spec.Ecosystem, pathDir(art.Path)); governed {
				continue
			}
			a.degradations.AddAdvisory(degrade.Lockfile,
				fmt.Sprintf("%s is a dependency manifest (%s) and nox has no reader for it", art.Path, spec.Label),
				"dependencies declared in this file were NOT scanned for vulnerabilities")
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			a.degradations.AddAdvisory(degrade.Lockfile,
				fmt.Sprintf("%s could not be read: %v", art.Path, err),
				"dependencies declared in this file were NOT scanned for vulnerabilities")
			continue
		}
		mpkgs, unresolved, err := spec.Read(content)
		if err != nil {
			a.degradations.AddAdvisory(degrade.Lockfile,
				fmt.Sprintf("%s was not parsed: %v", art.Path, err),
				"dependencies declared in this file were NOT scanned for vulnerabilities")
			continue
		}
		locked, governed := locks.governing(spec.Ecosystem, pathDir(art.Path))
		var fresh []Package
		for _, p := range mpkgs {
			if _, ok := locked[nameKey(spec.Ecosystem, p.Name)]; !ok {
				fresh = append(fresh, p)
			}
		}
		out = append(out, manifestPackages{Path: art.Path, Pkgs: fresh})
		if !governed && len(mpkgs)+len(unresolved) > 0 {
			detail, impact := manifestDegradation(art.Path, spec, len(mpkgs), unresolved)
			a.degradations.AddAdvisory(degrade.Lockfile, detail, impact)
		}
	}
	return out
}

// manifestAccumulator collects the declarations of one manifest. The first
// section to declare a name wins, so callers add sections in precedence order.
type manifestAccumulator struct {
	ecosystem  string
	seen       map[string]struct{}
	pkgs       []Package
	unresolved []unresolvedSpec
}

func newManifestAccumulator(ecosystem string) *manifestAccumulator {
	return &manifestAccumulator{ecosystem: ecosystem, seen: map[string]struct{}{}}
}

// resolveFunc turns one declaration into (registry name, version). A non-empty
// reason means no version could be determined.
type resolveFunc func(declared, spec string) (name, version string, isRange bool, reason string)

func (m *manifestAccumulator) add(declared, spec string, resolve resolveFunc) {
	key := nameKey(m.ecosystem, declared)
	if _, dup := m.seen[key]; dup {
		return
	}
	m.seen[key] = struct{}{}
	spec = strings.TrimSpace(spec)
	name, ver, isRange, reason := resolve(declared, spec)
	if reason != "" {
		m.unresolved = append(m.unresolved, unresolvedSpec{Name: declared, Spec: spec, Reason: reason})
		return
	}
	p := Package{Name: name, Version: ver, Ecosystem: m.ecosystem}
	if isRange {
		p.Spec = spec
	}
	m.pkgs = append(m.pkgs, p)
}

func (m *manifestAccumulator) result() ([]Package, []unresolvedSpec) {
	sort.SliceStable(m.pkgs, func(i, j int) bool { return m.pkgs[i].Name < m.pkgs[j].Name })
	sort.SliceStable(m.unresolved, func(i, j int) bool { return m.unresolved[i].Name < m.unresolved[j].Name })
	return m.pkgs, m.unresolved
}

// joinOr renders ["a","b","c"] as "a, b or c".
func joinOr(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
}

// manifestDegradation words the advisory for a manifest with no governing
// lockfile: what was read, and what that leaves unchecked.
func manifestDegradation(path string, spec manifestSpec, checked int, unresolved []unresolvedSpec) (detail, impact string) {
	detail = fmt.Sprintf("%s declares %d dependencies and no lockfile (%s) is committed beside it",
		path, checked+len(unresolved), joinOr(spec.Lockfiles))
	impact = fmt.Sprintf("versions come from the manifest, not a resolved install: %d checked as declared (exact pins as written, ranges at their lower bound)", checked)
	if len(unresolved) > 0 {
		const shown = 5
		var parts []string
		for i, u := range unresolved {
			if i == shown {
				parts = append(parts, fmt.Sprintf("and %d more", len(unresolved)-shown))
				break
			}
			parts = append(parts, u.String())
		}
		impact += fmt.Sprintf("; %d NOT checked because no version could be determined (%s)", len(unresolved), strings.Join(parts, ", "))
	}
	impact += "; commit a lockfile for an exact answer"
	return detail, impact
}
