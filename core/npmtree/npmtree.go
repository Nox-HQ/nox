// Package npmtree answers what an npm project's own files say about one of its
// packages: whether package.json lists it, which copies the lockfile installs,
// and whether those copies can move to a fixed version.
//
// It is the one place these questions are answered. A finding's remediation,
// nox fix plan and nox fix apply all ask them, and when each asked its own
// copy they disagreed about the same package: the finding said `npm install
// minimatch@11.0.1` (a second, direct copy beside the vulnerable one), the
// plan said "a major version, check the release notes", and apply ran `npm
// update` to find that a parent's range kept it at 10.2.6.
//
// Reads files only; never runs a package manager or reaches the network.
package npmtree

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Tool is the package manager a workspace uses, picked from its lockfile:
// "pnpm", "yarn", "bun", or "npm".
func Tool(dir string) string {
	has := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	switch {
	case has("pnpm-lock.yaml"):
		return "pnpm"
	case has("yarn.lock"):
		return "yarn"
	case has("bun.lock"), has("bun.lockb"):
		return "bun"
	}
	return "npm"
}

// LockName is the lockfile a tool writes.
func LockName(tool string) string {
	switch tool {
	case "pnpm":
		return "pnpm-lock.yaml"
	case "yarn":
		return "yarn.lock"
	case "bun":
		return "bun lockfile"
	}
	return "package-lock.json"
}

// declaredSections are the package.json sections that make a package one the
// project lists itself: each is installed and each is the project's choice.
var declaredSections = []string{"dependencies", "devDependencies", "optionalDependencies"}

// Declaration is how dir's package.json lists pkg: the section and the
// specifier written there ("^4.17.15"). Both are "" when pkg is not listed.
// known is false when there is no package.json nox could read, and then
// nothing is claimed either way.
func Declaration(dir, pkg string) (section, spec string, known bool) {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json")) //nolint:gosec // dir is the project under scan or fix
	if err != nil {
		return "", "", false
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(raw, &manifest) != nil {
		return "", "", false
	}
	for _, name := range declaredSections {
		var deps map[string]string
		if json.Unmarshal(manifest[name], &deps) != nil {
			continue
		}
		if s, ok := deps[pkg]; ok {
			return name, s, true
		}
	}
	return "", "", true
}

// Transitive reports whether package.json establishes that pkg is not listed:
// false both for a listed package and when there is no readable manifest.
func Transitive(dir, pkg string) bool {
	section, _, known := Declaration(dir, pkg)
	return known && section == ""
}

type lockEntry struct {
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

func readLock(dir string) (map[string]lockEntry, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "package-lock.json")) //nolint:gosec // dir is the project under scan or fix
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]lockEntry `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	return lock.Packages, nil
}

// Copies maps each package-lock.json path that installs pkg to its version.
// Nested copies count: node_modules/a/node_modules/pkg is loaded just the same.
func Copies(dir, pkg string) (map[string]string, error) {
	pkgs, err := readLock(dir)
	if err != nil {
		return nil, err
	}
	copies := map[string]string{}
	for path, e := range pkgs {
		if isCopyOf(path, pkg) {
			copies[path] = e.Version
		}
	}
	return copies, nil
}

// Below lists every copy of pkg in dir's package-lock.json still below
// version, as "path@version", sorted. A copy whose version cannot be read is
// listed too: nothing establishes that it is fixed.
func Below(dir, pkg, version string) ([]string, error) {
	copies, err := Copies(dir, pkg)
	if err != nil {
		return nil, err
	}
	target, ok := parseNPMVersion(version)
	if !ok {
		return nil, fmt.Errorf("unreadable fixed version %q", version)
	}
	var below []string
	for path, v := range copies {
		if got, ok := parseNPMVersion(v); !ok || got.cmp(target) < 0 {
			below = append(below, path+"@"+v)
		}
	}
	sort.Strings(below)
	return below, nil
}

// Hold is something that keeps a copy of a package below its fixed version.
type Hold struct {
	// By names the holder: "express@4.21.2", or "package.json overrides".
	By string
	// Requires is what the holder asks for, as written: "qs 6.13.0".
	Requires string
}

func (h Hold) String() string { return h.By + " requires " + h.Requires }

// Reach is what the lockfile says about moving a package to a fixed version.
type Reach struct {
	// Tool is the package manager the workspace uses.
	Tool string
	// Established is false when the lockfile could not answer the question:
	// none, a format not read here (pnpm, yarn, bun), or an unreadable fixed
	// version. A caller must then not promise the move.
	Established bool
	// Holds are the dependents whose declared range excludes the fix, and an
	// overrides entry that pins lower. Empty with Established set means every
	// copy can move within the ranges that load it.
	Holds []Hold
}

// Held reports whether the lockfile establishes that something holds the
// package below the fix.
func (r Reach) Held() bool { return r.Established && len(r.Holds) > 0 }

// Movable reports whether the lockfile establishes that nothing does.
func (r Reach) Movable() bool { return r.Established && len(r.Holds) == 0 }

// Holders names the packages that hold it, for "upgrade X" advice; the
// project's own package.json is not one of them.
func (r Reach) Holders() string {
	var names []string
	for _, h := range r.Holds {
		if h.By != "package.json overrides" && h.By != "package.json" {
			names = append(names, h.By)
		}
	}
	if len(names) == 0 {
		return "the package that depends on it"
	}
	return strings.Join(names, ", ")
}

// HoldList is every hold, "; "-joined, for "because ..." text.
func (r Reach) HoldList() string {
	parts := make([]string, len(r.Holds))
	for i, h := range r.Holds {
		parts[i] = h.String()
	}
	return strings.Join(parts, "; ")
}

// OverrideEntry is the exact package.json entry that forces pkg to version
// under tool.
func OverrideEntry(tool, pkg, version string) string {
	switch tool {
	case "yarn":
		return fmt.Sprintf(`"resolutions": { %q: %q }`, pkg, version)
	case "pnpm":
		return fmt.Sprintf(`"pnpm": { "overrides": { %q: %q } }`, pkg, version)
	}
	return fmt.Sprintf(`"overrides": { %q: %q }`, pkg, version)
}

// ReachOf decides whether pkg can move to fixed in dir without any
// dependent's range being violated. See Project.Reach; this reads the
// workspace for one question.
func ReachOf(dir, pkg, fixed string) Reach { return Open(dir).Reach(pkg, fixed) }

// Project is one workspace's package.json and package-lock.json, read once
// for many questions. A scan asks about every vulnerable package in a
// lockfile, and a lockfile can run to megabytes.
type Project struct {
	dir  string
	tool string
	pkgs map[string]lockEntry // nil: no package-lock.json nox could read
}

// Open reads dir's lockfile when the workspace uses npm.
func Open(dir string) *Project {
	p := &Project{dir: dir, tool: Tool(dir)}
	if p.tool == "npm" {
		if pkgs, err := readLock(dir); err == nil && len(pkgs) > 0 {
			p.pkgs = pkgs
		}
	}
	return p
}

// Reach decides whether pkg can move to fixed without any dependent's range
// being violated.
//
// It mirrors what `npm update pkg` can do and nothing more: each installed
// copy moves only as far as every package that resolves to that copy allows.
// A range that excludes the fix is a hold; so is an overrides entry in
// package.json that pins the package lower. The size of the step does not
// enter into it: a parent holds a minor fix and a major one alike.
func (p *Project) Reach(pkg, fixed string) Reach {
	r := Reach{Tool: p.tool}
	if p.pkgs == nil {
		return r // no npm lockfile; pnpm, yarn and bun lockfiles are not read here
	}
	target, ok := parseNPMVersion(fixed)
	if !ok {
		return r
	}
	r.Established = true

	paths := sortedKeys(p.pkgs)
	seen := map[Hold]bool{}
	for _, path := range paths {
		if !isCopyOf(path, pkg) {
			continue
		}
		installed, ok := parseNPMVersion(p.pkgs[path].Version)
		if !ok || installed.cmp(target) >= 0 {
			continue // already at or past the fix
		}
		for _, q := range paths {
			e := p.pkgs[q]
			rng, declares := declaredRange(e, q, pkg)
			if !declares || resolveCopy(p.pkgs, q, pkg) != path {
				continue
			}
			if in, known := satisfiesNPMRange(target, rng); known && in {
				continue
			}
			h := Hold{By: holderName(q, e), Requires: pkg + " " + rng}
			if !seen[h] {
				seen[h] = true
				r.Holds = append(r.Holds, h)
			}
		}
	}
	if h, held := overrideHold(p.dir, pkg, target); held {
		r.Holds = append(r.Holds, h)
	}
	return r
}

func isCopyOf(path, pkg string) bool {
	return path == "node_modules/"+pkg || strings.HasSuffix(path, "/node_modules/"+pkg)
}

// declaredRange is the range an entry asks for pkg in. The root entry's
// devDependencies count: they are installed too.
func declaredRange(e lockEntry, path, pkg string) (string, bool) {
	for _, m := range []map[string]string{e.Dependencies, e.OptionalDependencies, e.PeerDependencies} {
		if rng, ok := m[pkg]; ok {
			return rng, true
		}
	}
	if path == "" {
		if rng, ok := e.DevDependencies[pkg]; ok {
			return rng, true
		}
	}
	return "", false
}

// resolveCopy is the lockfile path of the copy of pkg that the package at path
// loads: the nearest node_modules on the way up from it.
func resolveCopy(pkgs map[string]lockEntry, path, pkg string) string {
	cur := path
	for {
		cand := "node_modules/" + pkg
		if cur != "" {
			cand = cur + "/" + cand
		}
		if _, ok := pkgs[cand]; ok {
			return cand
		}
		if cur == "" {
			return ""
		}
		i := strings.LastIndex(cur, "node_modules/")
		if i <= 0 {
			cur = ""
		} else {
			cur = strings.TrimSuffix(cur[:i], "/")
		}
	}
}

func holderName(path string, e lockEntry) string {
	if path == "" {
		return "package.json"
	}
	name := path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
	if e.Version == "" {
		return name
	}
	return name + "@" + e.Version
}

// overrideHold reports an overrides entry already in package.json that keeps
// pkg below the fixed version.
func overrideHold(dir, pkg string, target npmVersion) (Hold, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json")) //nolint:gosec // dir is the project under scan or fix
	if err != nil {
		return Hold{}, false
	}
	var manifest struct {
		Overrides map[string]json.RawMessage `json:"overrides"`
	}
	if json.Unmarshal(raw, &manifest) != nil {
		return Hold{}, false
	}
	val, ok := manifest.Overrides[pkg]
	if !ok {
		return Hold{}, false
	}
	var rng string
	if json.Unmarshal(val, &rng) != nil {
		return Hold{By: "package.json overrides", Requires: pkg + " (a nested overrides entry)"}, true
	}
	if in, known := satisfiesNPMRange(target, strings.TrimPrefix(rng, "$")); known && in {
		return Hold{}, false
	}
	return Hold{By: "package.json overrides", Requires: pkg + " " + rng}, true
}

func sortedKeys(m map[string]lockEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
