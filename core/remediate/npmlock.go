package remediate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// npmHold is something that keeps a transitive package below its fixed version.
type npmHold struct {
	// By names the holder: "express@4.21.2", or "package.json overrides".
	By string
	// Requires is what the holder asks for, as written.
	Requires string
}

// npmReach is what the lockfile says about moving a transitive npm package to
// its fixed version.
type npmReach struct {
	// Tool is the package manager the workspace uses, from its lockfile.
	Tool string
	// Established is false when the lockfile could not be read for this
	// question (no lockfile, a format nox does not read, a version it cannot
	// parse). The caller must then not promise the move.
	Established bool
	// Holds are the dependents whose declared range excludes the fix. Empty
	// with Established set means the fix is reachable within every range.
	Holds []npmHold
}

// npmLockTool picks the package manager from the lockfile in dir, as nox fix
// apply does.
func npmLockTool(dir string) string {
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

type npmLockEntry struct {
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

// analyzeNPMReach reads dir's package-lock.json and decides whether pkg can be
// moved to fixed without any dependent's range being violated.
//
// It mirrors what `npm update pkg` can do and nothing more: each installed copy
// of the package is moved only as far as every package that resolves to that
// copy allows. A range that excludes the fixed version is a hold; so is an
// existing overrides entry in package.json that pins the package lower.
func analyzeNPMReach(dir, pkg, fixed string) npmReach {
	r := npmReach{Tool: npmLockTool(dir)}
	if r.Tool != "npm" {
		return r // pnpm, yarn and bun lockfiles are not read here
	}
	target, ok := parseNPMVersion(fixed)
	if !ok {
		return r
	}
	raw, err := os.ReadFile(filepath.Join(dir, "package-lock.json")) //nolint:gosec // dir is the scanned project
	if err != nil {
		return r
	}
	var lock struct {
		Packages map[string]npmLockEntry `json:"packages"`
	}
	if json.Unmarshal(raw, &lock) != nil || len(lock.Packages) == 0 {
		return r
	}
	r.Established = true

	seen := map[npmHold]bool{}
	for _, path := range sortedKeys(lock.Packages) {
		if !isCopyOf(path, pkg) {
			continue
		}
		installed, ok := parseNPMVersion(lock.Packages[path].Version)
		if !ok || installed.cmp(target) >= 0 {
			continue // already at or past the fix
		}
		for _, q := range sortedKeys(lock.Packages) {
			e := lock.Packages[q]
			rng, declares := declaredRange(e, q, pkg)
			if !declares || resolveCopy(lock.Packages, q, pkg) != path {
				continue
			}
			if in, known := satisfiesNPMRange(target, rng); known && in {
				continue
			}
			h := npmHold{By: holderName(q, e), Requires: pkg + " " + rng}
			if !seen[h] {
				seen[h] = true
				r.Holds = append(r.Holds, h)
			}
		}
	}
	if h, held := overrideHold(dir, pkg, target); held {
		r.Holds = append(r.Holds, h)
	}
	return r
}

func isCopyOf(path, pkg string) bool {
	return path == "node_modules/"+pkg || strings.HasSuffix(path, "/node_modules/"+pkg)
}

// declaredRange is the range an entry asks for pkg in. The root entry's
// devDependencies count: they are installed too.
func declaredRange(e npmLockEntry, path, pkg string) (string, bool) {
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
func resolveCopy(pkgs map[string]npmLockEntry, path, pkg string) string {
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

func holderName(path string, e npmLockEntry) string {
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
func overrideHold(dir, pkg string, target npmVersion) (npmHold, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json")) //nolint:gosec // dir is the scanned project
	if err != nil {
		return npmHold{}, false
	}
	var manifest struct {
		Overrides map[string]json.RawMessage `json:"overrides"`
	}
	if json.Unmarshal(raw, &manifest) != nil {
		return npmHold{}, false
	}
	val, ok := manifest.Overrides[pkg]
	if !ok {
		return npmHold{}, false
	}
	var rng string
	if json.Unmarshal(val, &rng) != nil {
		return npmHold{By: "package.json overrides", Requires: pkg + " (a nested overrides entry)"}, true
	}
	if in, known := satisfiesNPMRange(target, strings.TrimPrefix(rng, "$")); known && in {
		return npmHold{}, false
	}
	return npmHold{By: "package.json overrides", Requires: pkg + " " + rng}, true
}

func sortedKeys(m map[string]npmLockEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// heldReason says why the move is not reachable and what to do about it. The
// remedy names the entry to add, so the person does not have to look it up.
func heldReason(a upgradePlan, reach npmReach) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The fix (%s) is published on the same major version, but %s is not a package you list yourself", a.step, a.pkg)
	if !reach.Established {
		fmt.Fprintf(&b, " and nox could not read this workspace's %s to see whether the packages that need it allow the move", lockName(reach.Tool))
	} else {
		var by []string
		for _, h := range reach.Holds {
			by = append(by, h.By+" requires "+h.Requires)
		}
		fmt.Fprintf(&b, " and %s: the range excludes %s", strings.Join(by, "; "), a.to)
	}
	b.WriteString(", so nox fix apply cannot move it. ")
	fmt.Fprintf(&b, "Either upgrade %s to a release that depends on a fixed %s, or force the version with an entry in package.json: %s",
		holderList(reach), a.pkg, overrideEntry(reach.Tool, a.pkg, a.to))
	return b.String()
}

func lockName(tool string) string {
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

func holderList(reach npmReach) string {
	var names []string
	for _, h := range reach.Holds {
		if h.By != "package.json overrides" && h.By != "package.json" {
			names = append(names, h.By)
		}
	}
	if len(names) == 0 {
		return "the package that depends on it"
	}
	return strings.Join(names, ", ")
}

// overrideEntry is the exact package.json entry that forces the version.
func overrideEntry(tool, pkg, to string) string {
	switch tool {
	case "yarn":
		return fmt.Sprintf(`"resolutions": { %q: %q }`, pkg, to)
	case "pnpm":
		return fmt.Sprintf(`"pnpm": { "overrides": { %q: %q } }`, pkg, to)
	}
	return fmt.Sprintf(`"overrides": { %q: %q }`, pkg, to)
}

// upgradePlan is the part of an upgrade the reason needs.
type upgradePlan struct{ pkg, step, to string }
