package deps

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// npmManifestSections are the package.json dependency maps nox reads, in
// precedence order when a name appears in more than one.
//
// devDependencies are included, as package-lock.json and composer.lock's
// packages-dev already are: a vulnerable build tool is a supply-chain exposure
// even though it does not ship. peerDependencies are NOT read. A peer entry is
// a compatibility contract with the host ("react": ">=16"), not a statement of
// what is installed, and its lower bound is routinely years older than any
// version a project actually runs; checking it would manufacture findings for
// versions nobody uses. When a peer is also a real dependency, it is listed
// there.
var npmManifestSections = []string{"dependencies", "optionalDependencies", "devDependencies"}

// npmManifest is the part of package.json that declares dependencies.
type npmManifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

// unresolvedSpec is a declared dependency nox could not turn into a version.
type unresolvedSpec struct {
	Name   string
	Spec   string
	Reason string
}

func (u unresolvedSpec) String() string {
	return fmt.Sprintf("%s@%s (%s)", u.Name, u.Spec, u.Reason)
}

var (
	// npmExactRe matches a fully specified semver, which npm treats as an exact
	// pin. A leading "=" or "v" is accepted by npm and means the same thing.
	npmExactRe = regexp.MustCompile(`^[=v]*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:\+[0-9A-Za-z.-]+)?$`)
	// npmVersionRe matches a possibly partial version: 1, 1.2, 1.2.3, 1.x, 1.2.3-rc.1.
	npmVersionRe = regexp.MustCompile(`^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	npmTagRe     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)
	// npmOpSpaceRe closes the gap in ">= 1.2.3" so the operator and version are one token.
	npmOpSpaceRe = regexp.MustCompile(`([<>=~^]+)\s+`)
)

// parsePackageJSONManifest reads the dependencies a package.json declares.
//
// It returns the ones with a usable version and, separately, the ones without.
// Nothing is guessed:
//
//   - an exact version ("0.21.1") is looked up as written, like a lockfile entry;
//   - a range ("^0.21.1", "~1.2", ">=1.0.0 <2", "1.x") is looked up at its LOWER
//     bound and the declared range is kept in Package.Spec so the finding says so.
//     That is the convention parseRequirementsTxt already applies to Python
//     ("requests>=2.0" is checked at 2.0). One deliberate difference: a range
//     with only an upper bound ("<2.0.0") has no lower bound to check, and
//     requirements.txt's "take whatever follows the operator" would check the
//     first version the range EXCLUDES, so it is reported as unresolved instead;
//   - git and URL sources, file:/link:/workspace: specs, dist-tags, "*" and "" name no
//     registry version and are unresolved.
//
// An "npm:real@1.2.3" alias is read as the package it points at.
func parsePackageJSONManifest(content []byte) (pkgs []Package, unresolved []unresolvedSpec, err error) {
	var m npmManifest
	if err := json.Unmarshal(content, &m); err != nil {
		return nil, nil, fmt.Errorf("parsing package.json: %w", err)
	}

	maps := map[string]map[string]string{
		"dependencies":         m.Dependencies,
		"optionalDependencies": m.OptionalDependencies,
		"devDependencies":      m.DevDependencies,
	}
	seen := make(map[string]struct{})
	for _, section := range npmManifestSections {
		names := make([]string, 0, len(maps[section]))
		for n := range maps[section] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, declared := range names {
			if _, dup := seen[declared]; dup {
				continue
			}
			seen[declared] = struct{}{}

			spec := strings.TrimSpace(maps[section][declared])
			name, ver, isRange, reason := resolveNPMSpec(declared, spec)
			if reason != "" {
				unresolved = append(unresolved, unresolvedSpec{Name: declared, Spec: spec, Reason: reason})
				continue
			}
			p := Package{Name: name, Version: ver, Ecosystem: "npm"}
			if isRange {
				p.Spec = spec
			}
			pkgs = append(pkgs, p)
		}
	}
	sort.SliceStable(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	sort.SliceStable(unresolved, func(i, j int) bool { return unresolved[i].Name < unresolved[j].Name })
	return pkgs, unresolved, nil
}

// resolveNPMSpec turns one declared spec into (registry name, version). A
// non-empty reason means no version could be determined.
func resolveNPMSpec(declared, spec string) (name, version string, isRange bool, reason string) {
	name = declared
	if rest, ok := strings.CutPrefix(spec, "npm:"); ok {
		at := strings.LastIndex(rest, "@")
		if at <= 0 {
			return "", "", false, "npm alias without a version"
		}
		name, spec = rest[:at], strings.TrimSpace(rest[at+1:])
	}

	low := strings.ToLower(spec)
	switch {
	case spec == "" || spec == "*" || strings.EqualFold(spec, "x") || low == "latest":
		return "", "", false, "no version constraint"
	case strings.ContainsAny(spec, "/:#@") || strings.HasPrefix(spec, "."):
		// git+https://, github:user/repo, user/repo, file:, link:, workspace:,
		// https://tarball, portal:, ../path.
		return "", "", false, "not a registry version"
	}

	if m := npmExactRe.FindStringSubmatch(spec); m != nil {
		return name, m[1], false, ""
	}

	ver, ok := npmLowerBound(spec)
	if !ok {
		if npmTagRe.MatchString(spec) {
			return "", "", false, "dist-tag"
		}
		return "", "", false, "range has no lower bound"
	}
	return name, ver, true, ""
}

// npmLowerBound returns the lowest version a range admits, taken from its first
// alternative and first comparator, as requirements.txt does.
func npmLowerBound(spec string) (string, bool) {
	first, _, _ := strings.Cut(spec, "||")
	first = strings.TrimSpace(first)
	if lo, _, ok := strings.Cut(first, " - "); ok { // hyphen range: 1.2.3 - 2.3.4
		first = strings.TrimSpace(lo)
	}
	first = npmOpSpaceRe.ReplaceAllString(first, "$1")
	fields := strings.FieldsFunc(first, func(r rune) bool { return r == ' ' || r == ',' })
	if len(fields) == 0 {
		return "", false
	}
	tok := fields[0]

	op := ""
	for _, o := range []string{"~>", ">=", "<=", "^", "~", ">", "<", "="} {
		if strings.HasPrefix(tok, o) {
			op, tok = o, tok[len(o):]
			break
		}
	}
	if op == "<" || op == "<=" {
		return "", false
	}
	m := npmVersionRe.FindStringSubmatch(tok)
	if len(m) == 0 || isWild(m[1]) {
		return "", false
	}
	part := func(s string) string {
		if s == "" || isWild(s) {
			return "0"
		}
		return s
	}
	return part(m[1]) + "." + part(m[2]) + "." + part(m[3]) + m[4], true
}

func isWild(s string) bool { return s == "x" || s == "X" || s == "*" }

// npmLockfiles are the lockfiles that make a package.json's versions
// authoritative.
var npmLockfiles = map[string]bool{"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true}

// manifestDedupe tracks the npm lockfiles seen during a scan, by directory, so a
// package.json can defer to the lockfile that governs it.
type manifestDedupe struct {
	// names maps a lockfile directory to the npm package names it resolved.
	names map[string]map[string]struct{}
}

func newManifestDedupe() *manifestDedupe {
	return &manifestDedupe{names: map[string]map[string]struct{}{}}
}

// record notes that the npm lockfile in dir resolved these packages. A lockfile
// that failed to parse is still recorded, with no names: it exists, so the
// manifest is not "without a lockfile", but it resolved nothing, so the manifest
// still fills in.
func (d *manifestDedupe) record(dir string, pkgs []Package) {
	set := d.names[dir]
	if set == nil {
		set = map[string]struct{}{}
		d.names[dir] = set
	}
	for _, p := range pkgs {
		if p.Ecosystem == "npm" {
			set[p.Name] = struct{}{}
		}
	}
}

// governing returns the names resolved by the npm lockfiles that govern a
// manifest in dir (its own directory or any ancestor, which is how a workspace
// root's lockfile covers member packages), and whether any such lockfile exists.
func (d *manifestDedupe) governing(dir string) (map[string]struct{}, bool) {
	names := map[string]struct{}{}
	found := false
	for lockDir, set := range d.names {
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

// manifestDegradation words the advisory for a package.json with no governing
// lockfile: what was read, and what that leaves unchecked.
func manifestDegradation(path string, checked int, unresolved []unresolvedSpec) (detail, impact string) {
	detail = fmt.Sprintf("%s declares %d dependencies and no lockfile (package-lock.json, yarn.lock or pnpm-lock.yaml) is committed beside it",
		path, checked+len(unresolved))
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
