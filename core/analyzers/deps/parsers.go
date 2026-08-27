package deps

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/vulnsource"
)

// parseGoMod extracts the module versions a Go build actually selects, from
// go.mod content.
//
// go.mod is the authoritative source of selected versions, and the distinction
// from go.sum matters: go.sum is a hash manifest for the entire module graph,
// not a lockfile. It records every version the resolver ever considered, so
// scanning it directly reports vulnerabilities against code that is never
// compiled — measured at ~99% false positives on real repositories (e.g. x/net
// flagged at a 2019 pseudo-version while the build selects v0.56.0). go.mod
// carries the versions Minimal Version Selection actually chose. See
// https://go.dev/ref/mod#go-sum-files and https://go.dev/ref/mod#minimal-version-selection.
//
// Callers should use resolveGoPackages rather than this function directly: Go
// 1.17+ module graph pruning means go.mod names only the modules providing
// imported packages, so resolveGoPackages consults go.sum to recover deeper
// transitives that are linked but unnamed here.
//
// replace directives are applied, because the replacement is what gets built.
// A replacement pointing at a local filesystem path is dropped: it is not a
// fetched module and has no upstream version to match against advisories.
func parseGoMod(content []byte) ([]Package, error) {
	type modVer struct{ mod, ver string }

	var requires []modVer
	// Keyed by module, or module@version for a version-specific replace.
	replaces := make(map[string]modVer)

	inRequireBlock := false
	inReplaceBlock := false

	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Strip line comments ("// indirect" and friends) before parsing.
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "require ("):
			inRequireBlock = true
			continue
		case strings.HasPrefix(line, "replace ("):
			inReplaceBlock = true
			continue
		case line == ")":
			inRequireBlock, inReplaceBlock = false, false
			continue
		}

		// Single-line forms carry the directive as a prefix.
		body := line
		isRequire := inRequireBlock
		isReplace := inReplaceBlock
		if after, ok := strings.CutPrefix(line, "require "); ok && !inRequireBlock && !inReplaceBlock {
			body, isRequire = strings.TrimSpace(after), true
		} else if after, ok := strings.CutPrefix(line, "replace "); ok && !inRequireBlock && !inReplaceBlock {
			body, isReplace = strings.TrimSpace(after), true
		}

		switch {
		case isReplace:
			// old [version] => new [version]
			left, right, found := strings.Cut(body, "=>")
			if !found {
				continue
			}
			lf, rf := strings.Fields(left), strings.Fields(right)
			if len(lf) == 0 || len(rf) == 0 {
				continue
			}
			key := lf[0]
			if len(lf) > 1 {
				key = lf[0] + "@" + lf[1]
			}
			if len(rf) < 2 {
				// A filesystem path replacement has no version; drop the module.
				replaces[key] = modVer{}
				continue
			}
			replaces[key] = modVer{mod: rf[0], ver: rf[1]}

		case isRequire:
			f := strings.Fields(body)
			if len(f) < 2 || !strings.HasPrefix(f[1], "v") {
				continue
			}
			requires = append(requires, modVer{mod: f[0], ver: f[1]})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning go.mod: %w", err)
	}

	var pkgs []Package
	for _, r := range requires {
		// A version-specific replace wins over a module-wide one.
		if rep, ok := replaces[r.mod+"@"+r.ver]; ok {
			if rep.mod == "" {
				continue
			}
			r = rep
		} else if rep, ok := replaces[r.mod]; ok {
			if rep.mod == "" {
				continue
			}
			r = rep
		}
		pkgs = append(pkgs, Package{Name: r.mod, Version: r.ver, Ecosystem: "go"})
	}

	return pkgs, nil
}

// resolveGoPackages determines the module versions a Go build links, given
// go.mod and (optionally) go.sum.
//
// Neither file answers the question alone:
//
//   - go.mod carries the versions MVS selected, but Go 1.17+ module graph
//     pruning means it only names modules providing imported packages. A module
//     reached deeper in the graph is still linked but absent here.
//   - go.sum names every module ever in the graph, but records each at every
//     version considered — so it reports code that is not built.
//
// So go.mod is authoritative for the modules it names, and go.sum is consulted
// only for modules go.mod omits — and then only for entries carrying a source
// hash (see goSumSourceModules), since a metadata-only entry means the code was
// never downloaded. For those recovered modules MVS selects the maximum
// required version, making the highest version in go.sum the best estimate.
//
// Measured against the true linked set (`go list -deps`) on two large
// repositories: false positives fell from 358 to 1 and from 148 to 0, with
// every true positive retained.
//
// A module dropped by a local filesystem replace is never resurrected from
// go.sum: it is not fetched and has no upstream version to match advisories
// against.
func resolveGoPackages(goMod, goSum []byte) ([]Package, error) {
	pkgs, err := parseGoMod(goMod)
	if err != nil {
		return nil, err
	}
	if len(goSum) == 0 {
		return pkgs, nil
	}

	// Every module go.mod spoke about — including ones it deliberately
	// dropped — so go.sum cannot contradict it.
	declared := make(map[string]struct{})
	for _, m := range goModDeclaredModules(goMod) {
		declared[m] = struct{}{}
	}
	for _, p := range pkgs {
		declared[p.Name] = struct{}{}
	}

	sumPkgs, err := goSumSourceModules(goSum)
	if err != nil {
		return nil, err
	}

	highest := make(map[string]string)
	for _, p := range sumPkgs {
		if _, ok := declared[p.Name]; ok {
			continue
		}
		if cur, ok := highest[p.Name]; !ok || compareGoVersions(p.Version, cur) > 0 {
			highest[p.Name] = p.Version
		}
	}

	names := make([]string, 0, len(highest))
	for n := range highest {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		pkgs = append(pkgs, Package{Name: n, Version: highest[n], Ecosystem: "go"})
	}

	return pkgs, nil
}

// goSumSourceModules returns the module/version pairs whose *source* is hashed
// in go.sum, i.e. lines without the "/go.mod" version suffix.
//
// go.sum records two kinds of entry. A "/go.mod" line hashes only the module's
// go.mod file, which Go fetches to compute the module graph; a plain line
// hashes the module zip, which Go fetches only when it actually needs the
// code. A module appearing solely under "/go.mod" was therefore never
// downloaded and cannot contribute a single line to the build, so reporting a
// vulnerability against it is always a false positive.
func goSumSourceModules(content []byte) ([]Package, error) {
	type key struct{ mod, ver string }
	seen := make(map[key]struct{})
	var pkgs []Package

	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mod, ver := fields[0], fields[1]
		if strings.HasSuffix(ver, "/go.mod") {
			continue // metadata-only: the module's code is not in the build
		}
		k := key{mod, ver}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		pkgs = append(pkgs, Package{Name: mod, Version: ver, Ecosystem: "go"})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning go.sum: %w", err)
	}
	return pkgs, nil
}

// goModDeclaredModules lists every module named on the left-hand side of a
// require or replace directive, whether or not it survives resolution.
func goModDeclaredModules(content []byte) []string {
	var out []string
	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		line = strings.TrimPrefix(line, "require ")
		line = strings.TrimPrefix(line, "replace ")
		if before, _, found := strings.Cut(line, "=>"); found {
			line = strings.TrimSpace(before)
		}
		f := strings.Fields(line)
		if len(f) == 0 || strings.ContainsAny(f[0], "()") || !strings.Contains(f[0], ".") {
			continue
		}
		out = append(out, f[0])
	}
	return out
}

// compareGoVersions orders two Go module versions, returning -1, 0 or 1.
//
// It implements the subset of semver ordering that module versions use: the
// numeric MAJOR.MINOR.PATCH triple first, then prerelease, where a release
// outranks any prerelease of the same triple. Pseudo-versions
// (v0.0.0-<timestamp>-<hash>) fall out correctly because their timestamp sorts
// lexically within the prerelease segment.
// compareGoVersions orders two semver-shaped versions. Delegated to
// core/vulnsource so the comparison a client performs and the one a mirror
// performs are the same code.
func compareGoVersions(a, b string) int { return vulnsource.CompareVersions(a, b) }

// parseGoSum extracts unique module/version pairs from go.sum content.
//
// Not used directly for Go dependency scanning — go.sum describes the module
// graph, not the build. resolveGoPackages consults it only for modules that
// go.mod omits. See parseGoMod.
//
// Each line has the format:
//
//	module version hash
//
// A module may appear twice: once for the module source and once for the
// go.mod file (with a "/go.mod" suffix on the version). We deduplicate by
// stripping the /go.mod suffix and keeping only unique module+version pairs.
func parseGoSum(content []byte) ([]Package, error) {
	type key struct{ mod, ver string }
	seen := make(map[key]struct{})
	var pkgs []Package

	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		mod := fields[0]
		ver := fields[1]

		// Strip /go.mod suffix from version so both entries resolve to the
		// same module+version pair.
		ver = strings.TrimSuffix(ver, "/go.mod")

		k := key{mod, ver}
		if _, exists := seen[k]; exists {
			continue
		}
		seen[k] = struct{}{}

		pkgs = append(pkgs, Package{
			Name:      mod,
			Version:   ver,
			Ecosystem: "go",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning go.sum: %w", err)
	}

	return pkgs, nil
}

// packageLockJSON is the minimal structure needed to extract packages from
// npm package-lock.json v2/v3. The "packages" map is keyed by path; the root
// package uses the empty string "" as its key.
type packageLockJSON struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

// parsePackageLockJSON extracts dependencies from an npm package-lock.json
// v2/v3 file. The root entry (key "") is skipped because it represents the
// project itself rather than a dependency.
func parsePackageLockJSON(content []byte) ([]Package, error) {
	var lock packageLockJSON
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	var pkgs []Package
	for path, info := range lock.Packages {
		// Skip the root package entry.
		if path == "" {
			continue
		}

		// The key is a path like "node_modules/express" or
		// "node_modules/express/node_modules/debug". Extract the package
		// name from the last node_modules/ segment.
		name := extractNpmPackageName(path)
		if name == "" || info.Version == "" {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   info.Version,
			Ecosystem: "npm",
		})
	}

	return pkgs, nil
}

// extractNpmPackageName extracts the npm package name from a
// package-lock.json path key. Paths follow the pattern
// "node_modules/@scope/name" or "node_modules/name", potentially nested.
func extractNpmPackageName(path string) string {
	const prefix = "node_modules/"

	// Find the last occurrence of node_modules/ to handle nested deps.
	idx := strings.LastIndex(path, prefix)
	if idx == -1 {
		return ""
	}

	name := path[idx+len(prefix):]
	return name
}

// parseRequirementsTxt extracts pinned packages from a Python requirements.txt
// file. It supports the == operator for exact pinning and also extracts the
// version from >=, <=, ~=, !=, < and > specifiers (taking the version after the
// leftmost operator). Lines without a version specifier are skipped.
func parseRequirementsTxt(content []byte) ([]Package, error) {
	var pkgs []Package

	// All PEP 508 comparison operators, including the bare strict bounds
	// "<" and ">". The two-character operators are listed before the
	// single-character ones so that on an equal index (e.g. ">=" and ">"
	// both start at the same position) the longer operator is preferred.
	operators := []string{"==", ">=", "<=", "~=", "!=", "<", ">"}

	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, and option lines.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Strip inline comments.
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip environment markers (e.g. ; python_version >= "3.6").
		if idx := strings.Index(line, ";"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip extras (e.g. package[extra]==1.0).
		if idx := strings.Index(line, "["); idx != -1 {
			bracket := strings.Index(line, "]")
			if bracket != -1 && bracket > idx {
				line = line[:idx] + line[bracket+1:]
			}
		}

		// Select the operator at the leftmost position in the line, not the
		// first operator in the list. Compound specifiers such as
		// "urllib3<1.27,>=1.21.1" must split on the "<" that precedes the
		// name/version boundary; splitting on ">=" (which appears earlier in
		// the operator list but later in the string) would corrupt the name.
		// On an index tie the longer operator wins because two-character
		// operators are ordered ahead of their single-character prefixes.
		bestIdx := -1
		var bestOp string
		for _, op := range operators {
			idx := strings.Index(line, op)
			if idx == -1 {
				continue
			}
			if bestIdx == -1 || idx < bestIdx {
				bestIdx = idx
				bestOp = op
			}
		}

		var name, version string
		found := false
		if bestIdx != -1 {
			name = strings.TrimSpace(line[:bestIdx])
			// Take only the first version (before any comma for
			// compound specifiers like >=1.0,<2.0).
			ver := strings.TrimSpace(line[bestIdx+len(bestOp):])
			if comma := strings.Index(ver, ","); comma != -1 {
				ver = strings.TrimSpace(ver[:comma])
			}
			version = ver
			found = true
		}

		if !found || name == "" || version == "" {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   version,
			Ecosystem: "pypi",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning requirements.txt: %w", err)
	}

	return pkgs, nil
}

// parseGemfileLock extracts gem names and versions from a Gemfile.lock file.
//
// The relevant section has the following structure:
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    actioncable (7.0.4)
//	    actionmailer (7.0.4)
//	      actionpack (= 7.0.4)
//
// We parse lines under GEM/specs that match the 4-space-indented pattern
// "    name (version)" but not the 6-space sub-dependency lines.
func parseGemfileLock(content []byte) ([]Package, error) {
	var pkgs []Package
	inGEM := false
	inSpecs := false

	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()

		// Detect section boundaries.
		trimmed := strings.TrimSpace(line)
		if trimmed == "GEM" {
			inGEM = true
			inSpecs = false
			continue
		}

		// A new top-level section resets the GEM context.
		if line != "" && line[0] != ' ' && trimmed != "" {
			inGEM = false
			inSpecs = false
			continue
		}

		if inGEM && trimmed == "specs:" {
			inSpecs = true
			continue
		}

		if !inGEM || !inSpecs {
			continue
		}

		// Gem entries are indented with exactly 4 spaces.
		// Sub-dependencies are indented with 6+ spaces.
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}

		entry := strings.TrimSpace(line)
		if entry == "" {
			continue
		}

		// Expected format: "name (version)"
		parenOpen := strings.Index(entry, "(")
		parenClose := strings.Index(entry, ")")
		if parenOpen == -1 || parenClose == -1 || parenClose <= parenOpen {
			continue
		}

		name := strings.TrimSpace(entry[:parenOpen])
		version := strings.TrimSpace(entry[parenOpen+1 : parenClose])

		if name == "" || version == "" {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   version,
			Ecosystem: "rubygems",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning Gemfile.lock: %w", err)
	}

	return pkgs, nil
}

// parseCargoLock extracts crate names and versions from a Cargo.lock file.
//
// Cargo.lock uses a TOML-like format with [[package]] blocks:
//
//	[[package]]
//	name = "serde"
//	version = "1.0.193"
func parseCargoLock(content []byte) ([]Package, error) {
	var pkgs []Package
	var name, version string

	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			// Emit previous package if complete.
			if name != "" && version != "" {
				pkgs = append(pkgs, Package{
					Name:      name,
					Version:   version,
					Ecosystem: "cargo",
				})
			}
			name = ""
			version = ""
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			name = unquoteTOML(strings.TrimPrefix(line, "name = "))
		} else if strings.HasPrefix(line, "version = ") {
			version = unquoteTOML(strings.TrimPrefix(line, "version = "))
		}
	}

	// Emit the last package.
	if name != "" && version != "" {
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   version,
			Ecosystem: "cargo",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning Cargo.lock: %w", err)
	}

	return pkgs, nil
}

// unquoteTOML strips surrounding double quotes from a TOML value.
func unquoteTOML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// pomXML is the minimal structure needed to extract dependencies from a Maven
// pom.xml file.
type pomXML struct {
	Dependencies struct {
		Dependency []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
		} `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []struct {
				GroupID    string `xml:"groupId"`
				ArtifactID string `xml:"artifactId"`
				Version    string `xml:"version"`
			} `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

// parsePomXML extracts dependencies from a Maven pom.xml file.
// Dependencies are named as "groupId:artifactId".
func parsePomXML(content []byte) ([]Package, error) {
	var pom pomXML
	if err := xml.Unmarshal(content, &pom); err != nil {
		return nil, fmt.Errorf("parsing pom.xml: %w", err)
	}

	type key struct{ name, ver string }
	seen := make(map[key]struct{})
	var pkgs []Package

	addDeps := func(deps []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	}) {
		for _, d := range deps {
			if d.GroupID == "" || d.ArtifactID == "" || d.Version == "" {
				continue
			}
			// Skip Maven property references like ${project.version}.
			if strings.HasPrefix(d.Version, "${") {
				continue
			}
			name := d.GroupID + ":" + d.ArtifactID
			k := key{name, d.Version}
			if _, exists := seen[k]; exists {
				continue
			}
			seen[k] = struct{}{}
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   d.Version,
				Ecosystem: "maven",
			})
		}
	}

	addDeps(pom.Dependencies.Dependency)
	addDeps(pom.DependencyManagement.Dependencies.Dependency)

	return pkgs, nil
}

// reGradleDep matches Gradle dependency declarations such as:
//
//	implementation 'group:artifact:version'
//	implementation "group:artifact:version"
//	api("group:artifact:version")
//	compile 'group:artifact:version'
//	testImplementation("group:artifact:version")
var reGradleDep = regexp.MustCompile(
	`(?:implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly|classpath|annotationProcessor)\s*[\("']+([^:'"]+):([^:'"]+):([^'")\s]+)`,
)

// parseBuildGradle extracts dependencies from a Gradle build file
// (build.gradle or build.gradle.kts) using line-based regex matching.
func parseBuildGradle(content []byte) ([]Package, error) {
	var pkgs []Package
	type key struct{ name, ver string }
	seen := make(map[key]struct{})

	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		matches := reGradleDep.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 4 {
				continue
			}
			group, artifact, ver := m[1], m[2], m[3]
			// Skip Gradle property references.
			if strings.HasPrefix(ver, "$") {
				continue
			}
			name := group + ":" + artifact
			k := key{name, ver}
			if _, exists := seen[k]; exists {
				continue
			}
			seen[k] = struct{}{}
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   ver,
				Ecosystem: "gradle",
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning build.gradle: %w", err)
	}

	return pkgs, nil
}

// nugetPackagesLock is the structure of a NuGet packages.lock.json file.
// The top-level keys are target framework monikers, each containing a
// dependencies map of package name -> info.
type nugetPackagesLock struct {
	Dependencies map[string]map[string]struct {
		Resolved string `json:"resolved"`
	} `json:"dependencies"`
}

// parseNuGetPackagesLock extracts packages from a NuGet packages.lock.json file.
func parseNuGetPackagesLock(content []byte) ([]Package, error) {
	var lock nugetPackagesLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parsing packages.lock.json: %w", err)
	}

	type key struct{ name, ver string }
	seen := make(map[key]struct{})
	var pkgs []Package

	for _, frameworks := range lock.Dependencies {
		for name, info := range frameworks {
			if name == "" || info.Resolved == "" {
				continue
			}
			k := key{name, info.Resolved}
			if _, exists := seen[k]; exists {
				continue
			}
			seen[k] = struct{}{}
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   info.Resolved,
				Ecosystem: "nuget",
			})
		}
	}

	return pkgs, nil
}

// composerLock is the minimal structure for PHP Composer lock files.
type composerLock struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages"`
	PackagesDev []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages-dev"`
}

// parseComposerLock extracts dependencies from a PHP composer.lock file.
func parseComposerLock(content []byte) ([]Package, error) {
	var lock composerLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parsing composer.lock: %w", err)
	}

	type key struct{ name, ver string }
	seen := make(map[key]struct{})
	var pkgs []Package

	addPkgs := func(entries []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}) {
		for _, p := range entries {
			if p.Name == "" || p.Version == "" {
				continue
			}
			// Composer versions may have a "v" prefix.
			ver := strings.TrimPrefix(p.Version, "v")
			k := key{p.Name, ver}
			if _, exists := seen[k]; exists {
				continue
			}
			seen[k] = struct{}{}
			pkgs = append(pkgs, Package{
				Name:      p.Name,
				Version:   ver,
				Ecosystem: "composer",
			})
		}
	}

	addPkgs(lock.Packages)
	addPkgs(lock.PackagesDev)

	return pkgs, nil
}
