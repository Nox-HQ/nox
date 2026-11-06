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

// Copies maps each copy of pkg the workspace's lockfile installs to its
// version, keyed by where the lockfile records it (a node_modules path, a
// bun.lock key, a "name@version" entry). Nested copies count: they are loaded
// just the same. npm, yarn v1, text bun.lock and pnpm-lock.yaml are read.
func Copies(dir, pkg string) (map[string]string, error) {
	p := Open(dir)
	if p.g == nil {
		return nil, fmt.Errorf("no lockfile nox reads in %s: %s", dir, p.why)
	}
	return p.g.copies(pkg), nil
}

// Below lists every copy of pkg in dir's lockfile still below version, as
// "key@version", sorted. A copy whose version cannot be read is listed too:
// nothing establishes that it is fixed.
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
	for key, v := range copies {
		if got, ok := parseNPMVersion(v); !ok || got.cmp(target) < 0 {
			if !strings.HasSuffix(key, "@"+v) {
				key += "@" + v
			}
			below = append(below, key)
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
	// none, one that records no ranges (pnpm), a format not read here (yarn
	// berry, bun's binary lockfile), or an unreadable fixed version. A caller
	// must then not promise the move.
	Established bool
	// Why says what kept Reach from being established. Empty when it is.
	Why string
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
		if !strings.HasPrefix(h.By, "package.json") {
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

// Project is one workspace's package.json and lockfile, read once for many
// questions. A scan asks about every vulnerable package in a lockfile, and a
// lockfile can run to megabytes.
type Project struct {
	dir  string
	tool string
	// g is the lockfile's graph; nil when there is none nox can read.
	g *graph
	// ranges is false when the lockfile records resolved versions only
	// (pnpm): Below can be answered, Reach cannot.
	ranges bool
	// why says what kept g or ranges from being had.
	why string
}

// Open reads dir's lockfile, whichever package manager wrote it.
func Open(dir string) *Project {
	p := &Project{dir: dir, tool: Tool(dir)}
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // dir is the project under scan or fix
		if err != nil {
			return nil
		}
		return raw
	}
	switch p.tool {
	case "npm":
		if pkgs, err := readLock(dir); err == nil && len(pkgs) > 0 {
			p.g, p.ranges = npmGraph(pkgs), true
		} else {
			p.why = "there is no package-lock.json nox could read"
		}
	case "yarn":
		raw := read("yarn.lock")
		switch {
		case raw == nil:
			p.why = "nox could not read yarn.lock"
		case strings.Contains(string(raw), "__metadata:"):
			p.why = "yarn.lock is yarn 2+ (berry), which nox does not read yet"
		default:
			p.g, p.ranges = yarnV1Graph(raw, readManifestDeps(dir)), true
		}
	case "bun":
		if raw := read("bun.lock"); raw != nil {
			if g, ok := bunGraph(raw); ok {
				p.g, p.ranges = g, true
				break
			}
		}
		p.why = "bun's lockfile is the binary bun.lockb, or a bun.lock nox could not parse; " +
			"bun 1.2+ writes the text bun.lock (bun install --save-text-lockfile)"
	case "pnpm":
		if raw := read("pnpm-lock.yaml"); raw != nil {
			p.g = &graph{nodes: pnpmCopies(raw), root: map[string]string{}}
		}
		p.why = "pnpm-lock.yaml records the version each dependent resolved, not the range it allows, " +
			"so it cannot show whether a parent holds the package"
	}
	return p
}

// Reach decides whether pkg can move to fixed without any dependent's range
// being violated.
//
// It mirrors what an update of pkg can do and nothing more: each installed
// copy moves only as far as every package that resolves to that copy allows.
// A range that excludes the fix is a hold; so is an override in package.json
// that pins the package lower. The size of the step does not enter into it: a
// parent holds a minor fix and a major one alike.
func (p *Project) Reach(pkg, fixed string) Reach {
	r := Reach{Tool: p.tool}
	if p.g == nil || !p.ranges {
		r.Why = p.why
		return r
	}
	target, ok := parseNPMVersion(fixed)
	if !ok {
		r.Why = "the fixed version " + fixed + " is not one nox can compare"
		return r
	}
	if len(p.g.copies(pkg)) == 0 {
		// Nothing installed to move, as far as the lockfile says: an empty or
		// unrelated lockfile establishes nothing about pkg.
		r.Why = LockName(p.tool) + " has no copy of " + pkg
		return r
	}
	r.Established = true

	keys := p.g.keys()
	seen := map[Hold]bool{}
	addHold := func(by, rng string) {
		h := Hold{By: by, Requires: pkg + " " + rng}
		if !seen[h] {
			seen[h] = true
			r.Holds = append(r.Holds, h)
		}
	}
	for _, key := range keys {
		n := p.g.nodes[key]
		if n.name != pkg {
			continue
		}
		installed, ok := parseNPMVersion(n.version)
		if !ok || installed.cmp(target) >= 0 {
			continue // already at or past the fix
		}
		if rng, declares := p.g.root[pkg]; declares && p.g.resolve("", pkg, rng) == key {
			if in, known := satisfiesNPMRange(target, rng); !known || !in {
				addHold("package.json", rng)
			}
		}
		for _, q := range keys {
			dep := p.g.nodes[q]
			rng, declares := dep.deps[pkg]
			if !declares || p.g.resolve(q, pkg, rng) != key {
				continue
			}
			if in, known := satisfiesNPMRange(target, rng); known && in {
				continue
			}
			by := dep.name
			if dep.version != "" {
				by += "@" + dep.version
			}
			addHold(by, rng)
		}
	}
	if h, held := overrideHold(p.dir, p.tool, pkg, target); held {
		r.Holds = append(r.Holds, h)
	}
	return r
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

// overrideHold reports a forcing entry already in package.json that keeps
// pkg below the fixed version: overrides (npm, bun), resolutions (yarn, bun),
// pnpm.overrides (pnpm).
func overrideHold(dir, tool, pkg string, target npmVersion) (Hold, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json")) //nolint:gosec // dir is the project under scan or fix
	if err != nil {
		return Hold{}, false
	}
	var manifest struct {
		Overrides   map[string]json.RawMessage `json:"overrides"`
		Resolutions map[string]json.RawMessage `json:"resolutions"`
		Pnpm        struct {
			Overrides map[string]json.RawMessage `json:"overrides"`
		} `json:"pnpm"`
	}
	if json.Unmarshal(raw, &manifest) != nil {
		return Hold{}, false
	}
	sections := map[string]map[string]json.RawMessage{
		"package.json overrides":      manifest.Overrides,
		"package.json resolutions":    manifest.Resolutions,
		"package.json pnpm.overrides": manifest.Pnpm.Overrides,
	}
	applies := map[string][]string{
		"npm":  {"package.json overrides"},
		"bun":  {"package.json overrides", "package.json resolutions"},
		"yarn": {"package.json resolutions"},
		"pnpm": {"package.json pnpm.overrides"},
	}
	for _, by := range applies[tool] {
		val, ok := sections[by][pkg]
		if !ok {
			continue
		}
		var rng string
		if json.Unmarshal(val, &rng) != nil {
			return Hold{By: by, Requires: pkg + " (a nested entry)"}, true
		}
		if in, known := satisfiesNPMRange(target, strings.TrimPrefix(rng, "$")); known && in {
			continue
		}
		return Hold{By: by, Requires: pkg + " " + rng}, true
	}
	return Hold{}, false
}
