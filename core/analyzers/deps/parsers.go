package deps

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
)

// parseGoSum extracts unique module/version pairs from go.sum content.
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

	scanner := bufio.NewScanner(bytes.NewReader(content))
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
// version from >=, <=, ~=, and != specifiers (taking the version after the
// operator). Lines without a version specifier are skipped.
func parseRequirementsTxt(content []byte) ([]Package, error) {
	var pkgs []Package

	// Version specifier operators ordered from longest to shortest so that
	// two-character operators match before single-character ones.
	operators := []string{"==", ">=", "<=", "~=", "!="}

	scanner := bufio.NewScanner(bytes.NewReader(content))
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

		// Try each operator to split name and version.
		var name, version string
		found := false
		for _, op := range operators {
			if idx := strings.Index(line, op); idx != -1 {
				name = strings.TrimSpace(line[:idx])
				// Take only the first version (before any comma for
				// compound specifiers like >=1.0,<2.0).
				ver := strings.TrimSpace(line[idx+len(op):])
				if comma := strings.Index(ver, ","); comma != -1 {
					ver = strings.TrimSpace(ver[:comma])
				}
				version = ver
				found = true
				break
			}
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

	scanner := bufio.NewScanner(bytes.NewReader(content))
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
		if len(line) > 0 && line[0] != ' ' && trimmed != "" {
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

	scanner := bufio.NewScanner(bytes.NewReader(content))
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

	scanner := bufio.NewScanner(bytes.NewReader(content))
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
