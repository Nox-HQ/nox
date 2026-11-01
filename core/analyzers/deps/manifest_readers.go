package deps

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// The readers below follow parsePackageJSONManifest's conventions: an exact pin
// is looked up as written, a range at its lower bound (kept in Package.Spec so a
// finding says so), and anything that names no registry version -- git and path
// sources, "*", a missing constraint -- is reported as unresolved rather than
// guessed. What differs per ecosystem is only what counts as an exact pin.

const (
	reasonNoConstraint = "no version constraint"
	reasonNotRegistry  = "not a registry version"
	reasonNoLowerBound = "range has no lower bound"
)

// resolveRangeSpec resolves a semver-style spec shared by Cargo, Poetry,
// Composer and pub. bareIsRange says whether a bare "1.2.3" is a range (Cargo,
// where it means ^1.2.3) or an exact pin.
func resolveRangeSpec(declared, spec string, bareIsRange bool) (name, version string, isRange bool, reason string) {
	if spec == "" || spec == "*" || strings.EqualFold(spec, "any") {
		return "", "", false, reasonNoConstraint
	}
	s := strings.TrimPrefix(spec, "==")
	if m := npmExactRe.FindStringSubmatch(s); m != nil {
		return declared, m[1], bareIsRange && !strings.HasPrefix(s, "="), ""
	}
	ver, ok := npmLowerBound(spec)
	if !ok {
		return "", "", false, reasonNoLowerBound
	}
	return declared, ver, true, ""
}

func resolveBareExact(declared, spec string) (name, version string, isRange bool, reason string) {
	return resolveRangeSpec(declared, spec, false)
}

func resolveBareRange(declared, spec string) (name, version string, isRange bool, reason string) {
	return resolveRangeSpec(declared, spec, true)
}

func (m *manifestAccumulator) addUnresolved(declared, spec, reason string) {
	key := nameKey(m.ecosystem, declared)
	if _, dup := m.seen[key]; dup {
		return
	}
	m.seen[key] = struct{}{}
	m.unresolved = append(m.unresolved, unresolvedSpec{Name: declared, Spec: spec, Reason: reason})
}

func tomlTable(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---- pyproject.toml --------------------------------------------------------

var (
	pepRequirementRe = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$`)
	pyVersionRe      = regexp.MustCompile(`^\d+(?:\.\d+)*[A-Za-z0-9.+!_-]*$`)
)

// parsePyprojectManifest reads PEP 621 [project] dependencies (and
// optional-dependencies), PEP 735 [dependency-groups] and Poetry's
// [tool.poetry] dependency tables.
func parsePyprojectManifest(content []byte) ([]Package, []unresolvedSpec, error) {
	var doc map[string]any
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, nil, fmt.Errorf("parsing pyproject.toml: %w", err)
	}
	acc := newManifestAccumulator("pypi")

	project := tomlTable(doc["project"])
	addPEP508List(acc, project["dependencies"])
	optional := tomlTable(project["optional-dependencies"])
	for _, k := range sortedKeys(optional) {
		addPEP508List(acc, optional[k])
	}
	groups := tomlTable(doc["dependency-groups"])
	for _, k := range sortedKeys(groups) {
		addPEP508List(acc, groups[k])
	}

	poetry := tomlTable(tomlTable(doc["tool"])["poetry"])
	addPoetryTable(acc, tomlTable(poetry["dependencies"]))
	addPoetryTable(acc, tomlTable(poetry["dev-dependencies"]))
	poetryGroups := tomlTable(poetry["group"])
	for _, k := range sortedKeys(poetryGroups) {
		addPoetryTable(acc, tomlTable(tomlTable(poetryGroups[k])["dependencies"]))
	}
	pkgs, unresolved := acc.result()
	return pkgs, unresolved, nil
}

func addPEP508List(acc *manifestAccumulator, v any) {
	list, _ := v.([]any)
	for _, item := range list {
		s, ok := item.(string) // PEP 735 {include-group = ...} tables are not requirements
		if !ok {
			continue
		}
		m := pepRequirementRe.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		name, rest := m[1], strings.TrimSpace(m[2])
		if strings.HasPrefix(rest, "@") {
			acc.addUnresolved(name, rest, reasonNotRegistry)
			continue
		}
		rest, _, _ = strings.Cut(rest, ";") // environment marker
		rest = strings.Trim(strings.TrimSpace(rest), "()")
		acc.add(name, strings.ReplaceAll(rest, " ", ""), resolvePython)
	}
}

func resolvePython(declared, spec string) (name, version string, isRange bool, reason string) {
	if spec == "" {
		return "", "", false, reasonNoConstraint
	}
	for _, clause := range strings.Split(spec, ",") {
		for _, op := range []string{"===", "==", "~=", ">=", ">"} {
			v, ok := strings.CutPrefix(strings.TrimSpace(clause), op)
			if !ok {
				continue
			}
			wild := strings.HasSuffix(v, ".*")
			v = strings.TrimSuffix(v, ".*")
			if !pyVersionRe.MatchString(v) {
				return "", "", false, reasonNoLowerBound
			}
			if wild {
				return declared, v + ".0", true, ""
			}
			return declared, v, op != "==" && op != "===", ""
		}
	}
	return "", "", false, reasonNoLowerBound
}

func addPoetryTable(acc *manifestAccumulator, deps map[string]any) {
	for _, declared := range sortedKeys(deps) {
		if declared == "python" {
			continue
		}
		switch v := deps[declared].(type) {
		case string:
			acc.add(declared, v, resolveBareExact)
		case map[string]any:
			if hasAnyKey(v, "git", "path", "url") {
				acc.addUnresolved(declared, "", reasonNotRegistry)
				continue
			}
			version, _ := v["version"].(string)
			acc.add(declared, version, resolveBareExact)
		default:
			acc.addUnresolved(declared, "", "multiple constraints")
		}
	}
}

func hasAnyKey(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// ---- Cargo.toml ------------------------------------------------------------

// parseCargoManifest reads [dependencies], [dev-dependencies],
// [build-dependencies], [workspace.dependencies] and target-specific tables,
// whether written as `name = "1"`, `name = { version = "1" }` or
// `[dependencies.name]`. A bare "1.2.3" is Cargo's ^1.2.3, so it is a range.
func parseCargoManifest(content []byte) ([]Package, []unresolvedSpec, error) {
	var doc map[string]any
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, nil, fmt.Errorf("parsing Cargo.toml: %w", err)
	}
	acc := newManifestAccumulator("cargo")
	sections := []string{"dependencies", "build-dependencies", "dev-dependencies"}
	read := func(table map[string]any) {
		for _, s := range sections {
			addCargoTable(acc, tomlTable(table[s]))
		}
	}
	read(doc)
	addCargoTable(acc, tomlTable(tomlTable(doc["workspace"])["dependencies"]))
	targets := tomlTable(doc["target"])
	for _, k := range sortedKeys(targets) {
		read(tomlTable(targets[k]))
	}
	pkgs, unresolved := acc.result()
	return pkgs, unresolved, nil
}

func addCargoTable(acc *manifestAccumulator, deps map[string]any) {
	for _, declared := range sortedKeys(deps) {
		switch v := deps[declared].(type) {
		case string:
			acc.add(declared, v, resolveBareRange)
		case map[string]any:
			switch {
			case v["workspace"] == true:
				acc.addUnresolved(declared, "", "version inherited from [workspace.dependencies]")
			case hasAnyKey(v, "git", "path"):
				acc.addUnresolved(declared, "", reasonNotRegistry)
			default:
				version, _ := v["version"].(string)
				crate := declared
				if pkg, ok := v["package"].(string); ok && pkg != "" {
					crate = pkg
				}
				acc.add(declared, version, func(_, spec string) (string, string, bool, string) {
					return resolveRangeSpec(crate, spec, true)
				})
			}
		}
	}
}

// ---- *.csproj, Directory.Packages.props -------------------------------------

type msbuildItem struct {
	Include   string `xml:"Include,attr"`
	Version   string `xml:"Version,attr"`
	VersionEl string `xml:"Version"`
}

type msbuildProject struct {
	ItemGroups []struct {
		References []msbuildItem `xml:"PackageReference"`
		Versions   []msbuildItem `xml:"PackageVersion"`
	} `xml:"ItemGroup"`
}

var nugetPlainVersionRe = regexp.MustCompile(`^\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// parseCsprojManifest reads PackageReference items from an SDK-style project
// file and PackageVersion items from Directory.Packages.props. A reference with
// no version of its own takes it from central package management, which this
// reader sees only if Directory.Packages.props is in the same scan, so the
// reference is reported unresolved and the props file supplies the version.
func parseCsprojManifest(content []byte) ([]Package, []unresolvedSpec, error) {
	var proj msbuildProject
	if err := xml.Unmarshal(content, &proj); err != nil {
		return nil, nil, fmt.Errorf("parsing project file: %w", err)
	}
	acc := newManifestAccumulator("nuget")
	version := func(it msbuildItem) string {
		if it.Version != "" {
			return it.Version
		}
		return strings.TrimSpace(it.VersionEl)
	}
	for _, g := range proj.ItemGroups {
		for _, it := range g.Versions {
			if it.Include != "" {
				acc.add(it.Include, version(it), resolveNuGet)
			}
		}
	}
	for _, g := range proj.ItemGroups {
		for _, it := range g.References {
			if it.Include != "" {
				acc.add(it.Include, version(it), resolveNuGet)
			}
		}
	}
	pkgs, unresolved := acc.result()
	return pkgs, unresolved, nil
}

func resolveNuGet(declared, spec string) (name, version string, isRange bool, reason string) {
	switch {
	case spec == "":
		return "", "", false, "no version (central package management or implicit)"
	case strings.Contains(spec, "$("):
		return "", "", false, "version comes from an MSBuild property"
	case nugetPlainVersionRe.MatchString(spec):
		// "1.0" is NuGet's minimum, and restore picks that lowest applicable
		// version, so it is what the project runs.
		return declared, spec, false, ""
	}
	inner := strings.TrimLeft(spec, "[(")
	inner = strings.TrimRight(inner, "])")
	lower, _, hasUpper := strings.Cut(inner, ",")
	lower = strings.TrimSpace(strings.ReplaceAll(lower, "*", "0"))
	if lower == "" || !nugetPlainVersionRe.MatchString(lower) {
		return "", "", false, reasonNoLowerBound
	}
	if !hasUpper && strings.HasPrefix(spec, "[") {
		return declared, lower, false, "" // "[1.0]" is an exact pin
	}
	return declared, lower, true, ""
}

// ---- composer.json ----------------------------------------------------------

var composerStabilityRe = regexp.MustCompile(`@[A-Za-z]+$`)

type composerManifest struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// parseComposerManifest reads require and require-dev. Platform requirements
// (php, ext-*, lib-*, composer-plugin-api) have no vendor and name no package.
func parseComposerManifest(content []byte) ([]Package, []unresolvedSpec, error) {
	var m composerManifest
	if err := json.Unmarshal(content, &m); err != nil {
		return nil, nil, fmt.Errorf("parsing composer.json: %w", err)
	}
	acc := newManifestAccumulator("composer")
	for _, section := range []map[string]string{m.Require, m.RequireDev} {
		for _, declared := range sortedKeys(section) {
			if !strings.Contains(declared, "/") {
				continue
			}
			acc.add(declared, section[declared], resolveComposer)
		}
	}
	pkgs, unresolved := acc.result()
	return pkgs, unresolved, nil
}

func resolveComposer(declared, spec string) (name, version string, isRange bool, reason string) {
	s := composerStabilityRe.ReplaceAllString(spec, "")
	s, _, _ = strings.Cut(s, " as ")
	first, _, _ := strings.Cut(s, "|") // "|" and "||" both separate alternatives
	first = strings.TrimSpace(first)
	if strings.HasPrefix(first, "dev-") || strings.HasSuffix(first, "-dev") {
		return "", "", false, "not a release version"
	}
	return resolveRangeSpec(declared, first, false)
}

// ---- Gemfile ----------------------------------------------------------------

var (
	gemLineRe      = regexp.MustCompile(`^\s*gem\s+["']([^"']+)["']\s*(.*)$`)
	gemQuotedRe    = regexp.MustCompile(`^\s*,?\s*["']([^"']*)["']`)
	gemSourceRe    = regexp.MustCompile(`\b(?:git|github|gitlab|bitbucket|path|source)\s*(?::|=>)`)
	gemClauseRe    = regexp.MustCompile(`^(~>|>=|>|=|<=|<|!=)?\s*(\d[0-9A-Za-z.]*)$`)
	gemConstraint  = regexp.MustCompile(`^\s*(?:~>|>=|>|=|<=|<|!=)?\s*\d`)
	gemQuotedStrip = regexp.MustCompile(`^\s*,?\s*["'][^"']*["']`)
)

// parseGemfileManifest reads `gem` declarations. Only a quoted version
// constraint counts as a version; a gem with none, or sourced from git or a
// path, is reported unresolved.
func parseGemfileManifest(content []byte) ([]Package, []unresolvedSpec, error) {
	acc := newManifestAccumulator("rubygems")
	for _, line := range strings.Split(string(content), "\n") {
		m := gemLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, rest := m[1], m[2]
		var constraints []string
		for {
			q := gemQuotedRe.FindStringSubmatch(rest)
			if len(q) < 2 || !gemConstraint.MatchString(q[1]) {
				break
			}
			constraints = append(constraints, strings.TrimSpace(q[1]))
			rest = gemQuotedStrip.ReplaceAllString(rest, "")
		}
		if gemSourceRe.MatchString(rest) {
			acc.addUnresolved(name, strings.Join(constraints, ", "), reasonNotRegistry)
			continue
		}
		acc.add(name, strings.Join(constraints, ", "), resolveGem)
	}
	pkgs, unresolved := acc.result()
	return pkgs, unresolved, nil
}

func resolveGem(declared, spec string) (name, version string, isRange bool, reason string) {
	if spec == "" {
		return "", "", false, reasonNoConstraint
	}
	for _, clause := range strings.Split(spec, ",") {
		m := gemClauseRe.FindStringSubmatch(strings.TrimSpace(clause))
		if m == nil {
			continue
		}
		switch m[1] {
		case "", "=":
			return declared, m[2], false, ""
		case "~>", ">=", ">":
			return declared, m[2], true, ""
		}
	}
	return "", "", false, reasonNoLowerBound
}

// ---- pubspec.yaml -----------------------------------------------------------

type pubspecManifest struct {
	Dependencies    map[string]yaml.Node `yaml:"dependencies"`
	DevDependencies map[string]yaml.Node `yaml:"dev_dependencies"`
}

// parsePubspecManifest reads dependencies and dev_dependencies. A bare
// "1.2.3" in pub is an exact pin; "^1.2.3" and ">=1.0.0 <2.0.0" are ranges.
func parsePubspecManifest(content []byte) ([]Package, []unresolvedSpec, error) {
	var m pubspecManifest
	if err := yaml.Unmarshal(content, &m); err != nil {
		return nil, nil, fmt.Errorf("parsing pubspec.yaml: %w", err)
	}
	acc := newManifestAccumulator("pub")
	for _, section := range []map[string]yaml.Node{m.Dependencies, m.DevDependencies} {
		for _, declared := range sortedKeys(section) {
			node := section[declared]
			switch node.Kind {
			case yaml.ScalarNode:
				acc.add(declared, node.Value, resolveBareExact)
			case yaml.MappingNode:
				addPubMapping(acc, declared, &node)
			}
		}
	}
	pkgs, unresolved := acc.result()
	return pkgs, unresolved, nil
}

func addPubMapping(acc *manifestAccumulator, declared string, node *yaml.Node) {
	var version string
	for i := 0; i+1 < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "sdk":
			return // flutter and friends ship with the SDK, not a package
		case "git", "path":
			acc.addUnresolved(declared, "", reasonNotRegistry)
			return
		case "version":
			version = node.Content[i+1].Value
		}
	}
	acc.add(declared, version, resolveBareExact)
}
