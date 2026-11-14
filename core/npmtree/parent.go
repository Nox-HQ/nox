package npmtree

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// A transitive package that a parent's range holds below its fix moves only
// when that parent moves. "Upgrade express to a release that allows it" is
// true, and leaves the person to read express's release history for which one:
// for express 4.21.2 holding body-parser, path-to-regexp and qs, the answer is
// 4.22.3, which nothing in the lockfile says. The registry does: every release
// of a package records the ranges it declares.
//
// ParentRelease answers it the way npm would. It replaces the parent with each
// of its later releases in turn and re-resolves only what that changes: a
// dependency whose installed copy still satisfies the new range is kept, as
// npm keeps it, and one that does not becomes the highest published release
// inside the range. The first release under which every copy of the held
// packages in the parent's tree reaches its fix is the one to name.

// Registry lists what a package has published: for each release, the
// dependency ranges it declares (dependencies and optionalDependencies).
type Registry interface {
	Releases(ctx context.Context, pkg string) (map[string]map[string]string, error)
}

// ParentUpgrade is a release of a package the project lists itself that lets
// held copies of other packages reach their fixes.
type ParentUpgrade struct {
	// Parent is the package in package.json; From is the installed version.
	Parent string `json:"parent"`
	From   string `json:"from"`
	To     string `json:"to"`
	// Major is set when To is on a later major version than From.
	Major bool `json:"major,omitempty"`
	// Frees is every held package this release lets move, sorted.
	Frees []string `json:"frees"`
}

// maxSimDepth bounds the re-resolution below a parent. A dependency tree is
// finite and seen-sets stop cycles; the bound is for a registry answer that
// keeps inventing new subtrees.
const maxSimDepth = 16

// ListedAncestors names the packages the project lists itself whose trees
// hold a copy of pkg below fixed. A copy the project loads directly (pkg is in
// package.json) has no ancestor to upgrade, and makes ok false, as does a
// lockfile that records no ranges.
func (p *Project) ListedAncestors(pkg, fixed string) (names []string, ok bool) {
	if p.g == nil || !p.ranges {
		return nil, false
	}
	target, okv := parseNPMVersion(fixed)
	if !okv {
		return nil, false
	}
	if _, listed := p.g.root[pkg]; listed {
		return nil, false
	}
	// loaders maps each copy to the copies whose requests resolve to it.
	keys := p.g.keys()
	loaders := map[string][]string{}
	for _, q := range keys {
		for dep, rng := range p.g.nodes[q].deps {
			if k := p.g.resolve(q, dep, rng); k != "" {
				loaders[k] = append(loaders[k], q)
			}
		}
	}
	listed := map[string]bool{}
	for name, rng := range p.g.root {
		if k := p.g.resolve("", name, rng); k != "" {
			listed[k] = true
		}
	}
	found := map[string]bool{}
	for _, key := range keys {
		n := p.g.nodes[key]
		if n.name != pkg {
			continue
		}
		v, okn := parseNPMVersion(n.version)
		if !okn || v.cmp(target) >= 0 {
			continue
		}
		// The walk up starts at the copy's holders: what loads it with a
		// range that excludes the fix. Another package loading the same copy
		// with a range that allows the fix does not hold it, and npm moves the
		// copy under it as soon as the holders move.
		seen := map[string]bool{key: true}
		var work []string
		for _, l := range loaders[key] {
			if in, known := satisfiesNPMRange(target, p.g.nodes[l].deps[pkg]); known && in {
				continue
			}
			seen[l] = true
			work = append(work, l)
		}
		for len(work) > 0 {
			k := work[len(work)-1]
			work = work[:len(work)-1]
			if listed[k] {
				found[p.g.nodes[k].name] = true
				continue
			}
			for _, l := range loaders[k] {
				if !seen[l] {
					seen[l] = true
					work = append(work, l)
				}
			}
		}
	}
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, len(names) > 0
}

// ParentRelease finds the lowest release of parent, a package the project
// lists, under which every copy of each target (package -> fixed version) in
// parent's tree reaches its fix. A release on the installed major is preferred;
// a later major is named only when no release on this one does it. The zero
// ParentUpgrade, with no error, means no published release does.
func (p *Project) ParentRelease(ctx context.Context, reg Registry, parent string, targets map[string]string) (ParentUpgrade, error) {
	if p.g == nil || !p.ranges {
		return ParentUpgrade{}, fmt.Errorf("%s", p.why)
	}
	rng, listed := p.g.root[parent]
	if !listed {
		return ParentUpgrade{}, fmt.Errorf("%s is not in package.json", parent)
	}
	key := p.g.resolve("", parent, rng)
	if key == "" {
		return ParentUpgrade{}, fmt.Errorf("%s has no copy of %s", LockName(p.tool), parent)
	}
	from, ok := parseNPMVersion(p.g.nodes[key].version)
	if !ok {
		return ParentUpgrade{}, fmt.Errorf("the installed %s %s is not a version nox can compare", parent, p.g.nodes[key].version)
	}
	want := map[string]npmVersion{}
	for pkg, fixed := range targets {
		v, okv := parseNPMVersion(fixed)
		if !okv {
			return ParentUpgrade{}, fmt.Errorf("the fixed version %s of %s is not one nox can compare", fixed, pkg)
		}
		want[pkg] = v
	}

	s := &simulation{p: p, reg: reg, ctx: ctx, want: want, releases: map[string]map[string]map[string]string{}}
	rels, err := s.releasesOf(parent)
	if err != nil {
		return ParentUpgrade{}, err
	}
	candidates := laterReleases(rels, from)
	for _, sameMajor := range []bool{true, false} {
		for _, c := range candidates {
			if (c.v[0] == from[0]) != sameMajor {
				continue
			}
			freed, err := s.clears(key, rels[c.s])
			if err != nil {
				return ParentUpgrade{}, err
			}
			if freed {
				frees := make([]string, 0, len(targets))
				for pkg := range targets {
					frees = append(frees, pkg)
				}
				sort.Strings(frees)
				return ParentUpgrade{Parent: parent, From: p.g.nodes[key].version, To: c.s, Major: !sameMajor, Frees: frees}, nil
			}
		}
	}
	return ParentUpgrade{}, nil
}

type release struct {
	s string
	v npmVersion
}

// laterReleases is every release above from, ascending. Pre-releases do not
// parse, and are left out: a parent upgrade nox names is a release.
func laterReleases(rels map[string]map[string]string, from npmVersion) []release {
	var out []release
	for s := range rels {
		if v, ok := parseNPMVersion(s); ok && v.cmp(from) > 0 {
			out = append(out, release{s: s, v: v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v.cmp(out[j].v) < 0 })
	return out
}

type simulation struct {
	p        *Project
	reg      Registry
	ctx      context.Context //nolint:containedctx // one simulation is one call
	want     map[string]npmVersion
	releases map[string]map[string]map[string]string
}

func (s *simulation) releasesOf(pkg string) (map[string]map[string]string, error) {
	if r, ok := s.releases[pkg]; ok {
		return r, nil
	}
	r, err := s.reg.Releases(s.ctx, pkg)
	if err != nil {
		return nil, err
	}
	s.releases[pkg] = r
	return r, nil
}

// clears reports whether, with the node at key declaring deps instead of what
// the lockfile records, every copy of a wanted package below it reaches its
// fix.
func (s *simulation) clears(key string, deps map[string]string) (bool, error) {
	return s.walk(key, deps, 0, map[string]bool{})
}

// walk follows deps, declared by a node at key: a request whose locked copy
// still satisfies its range keeps that copy and the copy's locked tree; one
// that does not becomes the highest published release inside the range, with
// that release's declared dependencies.
func (s *simulation) walk(key string, deps map[string]string, depth int, seen map[string]bool) (bool, error) {
	if depth > maxSimDepth {
		return false, nil
	}
	names := make([]string, 0, len(deps))
	for n := range deps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		rng := deps[name]
		locked := s.p.g.resolve(key, name, rng)
		if locked != "" {
			n := s.p.g.nodes[locked]
			if v, ok := parseNPMVersion(n.version); ok {
				if in, known := satisfiesNPMRange(v, rng); known && in {
					if !s.reaches(name, v) {
						return false, nil
					}
					if seen[locked] {
						continue
					}
					seen[locked] = true
					ok, err := s.walk(locked, n.deps, depth+1, seen)
					if err != nil || !ok {
						return ok, err
					}
					continue
				}
			}
		}
		// The locked copy does not satisfy the new range (or there is none):
		// npm installs the highest release inside it.
		rels, err := s.releasesOf(name)
		if err != nil {
			return false, err
		}
		best, ok := highestIn(rels, rng)
		if !ok {
			return false, nil
		}
		if !s.reaches(name, best.v) {
			return false, nil
		}
		at := locked
		if at == "" {
			at = key
		}
		mark := "new:" + name + "@" + best.s
		if seen[mark] {
			continue
		}
		seen[mark] = true
		ok, err = s.walk(at, rels[best.s], depth+1, seen)
		if err != nil || !ok {
			return ok, err
		}
	}
	return true, nil
}

// reaches reports whether a copy of name at v satisfies what is wanted of it.
func (s *simulation) reaches(name string, v npmVersion) bool {
	w, wanted := s.want[name]
	return !wanted || v.cmp(w) >= 0
}

// highestIn is the highest release inside rng. ok is false when rng is a form
// nox does not read, or nothing published satisfies it.
func highestIn(rels map[string]map[string]string, rng string) (release, bool) {
	var best release
	found := false
	for s := range rels {
		v, ok := parseNPMVersion(s)
		if !ok {
			continue
		}
		in, known := satisfiesNPMRange(v, rng)
		if !known {
			return release{}, false
		}
		if in && (!found || v.cmp(best.v) > 0) {
			best, found = release{s: s, v: v}, true
		}
	}
	return best, found
}

// String is the upgrade as advice: "express 4.21.2 -> 4.22.3".
func (u ParentUpgrade) String() string {
	return u.Parent + " " + u.From + " -> " + u.To
}

// FreesList is Frees for prose: "body-parser, path-to-regexp and qs".
func (u ParentUpgrade) FreesList() string {
	switch len(u.Frees) {
	case 0:
		return ""
	case 1:
		return u.Frees[0]
	}
	return strings.Join(u.Frees[:len(u.Frees)-1], ", ") + " and " + u.Frees[len(u.Frees)-1]
}
