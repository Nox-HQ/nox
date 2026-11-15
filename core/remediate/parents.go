package remediate

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/npmtree"
)

// nameParentUpgrades adds, to every held npm upgrade, the release of the
// package the project lists that lets it move: "upgrade express to a release
// that allows it" becomes "express 4.21.2 -> 4.22.3".
//
// Held items under one listed package are answered together. Upgrading
// express moves body-parser, path-to-regexp and qs at once, and three items
// each naming a different express release would be three upgrades where one
// does. When no single release frees them all, each is answered on its own.
func nameParentUpgrades(ctx context.Context, plan *Plan, root string, reg npmtree.Registry) {
	type group struct {
		dir, parent string
		targets     map[string]string
		froms       map[string]string
		items       []int
	}
	projects := map[string]*npmtree.Project{}
	groups := map[string]*group{}
	var order []string
	for i := range plan.Items {
		it := &plan.Items[i]
		if it.Kind != KindHeldUpgrade || it.Upgrade == nil || it.Upgrade.Ecosystem != "npm" {
			continue
		}
		dir := filepath.Join(root, filepath.Dir(it.Upgrade.Manifest))
		p := projects[dir]
		if p == nil {
			p = npmtree.Open(dir)
			projects[dir] = p
		}
		parents, ok := p.ListedAncestorsFrom(it.Upgrade.Package, it.Upgrade.From, it.Upgrade.To)
		if !ok {
			continue
		}
		for _, parent := range parents {
			k := dir + "\x00" + parent
			g := groups[k]
			if g == nil {
				g = &group{dir: dir, parent: parent, targets: map[string]string{}, froms: map[string]string{}}
				groups[k] = g
				order = append(order, k)
			}
			g.targets[it.Upgrade.Package] = it.Upgrade.To
			g.froms[it.Upgrade.Package] = it.Upgrade.From
			g.items = append(g.items, i)
		}
	}
	sort.Strings(order)
	defer func() {
		for i := range plan.Items {
			it := &plan.Items[i]
			if it.Upgrade != nil && len(it.ParentUpgrades) > 0 {
				rewordHeld(it, filepath.Join(root, filepath.Dir(it.Upgrade.Manifest)))
			}
		}
	}()
	for _, k := range order {
		g := groups[k]
		p := projects[g.dir]
		up, err := p.ParentReleaseFrom(ctx, reg, g.parent, g.targets, g.froms)
		if err != nil {
			for _, i := range g.items {
				noteParentLookup(&plan.Items[i], g.parent, err)
			}
			continue
		}
		if up.To != "" {
			for _, i := range g.items {
				addParentUpgrade(&plan.Items[i], g.dir, up)
			}
			continue
		}
		for _, i := range g.items {
			it := &plan.Items[i]
			one, err := p.ParentReleaseFrom(ctx, reg, g.parent,
				map[string]string{it.Upgrade.Package: it.Upgrade.To}, map[string]string{it.Upgrade.Package: it.Upgrade.From})
			switch {
			case err != nil:
				noteParentLookup(it, g.parent, err)
			case one.To == "":
				it.Why += fmt.Sprintf(" No published release of %s lets %s reach %s, so forcing the version is the remedy.",
					g.parent, it.Upgrade.Package, it.Upgrade.To)
			default:
				addParentUpgrade(it, g.dir, one)
			}
		}
	}
}

func addParentUpgrade(it *Item, _ string, up npmtree.ParentUpgrade) {
	it.ParentUpgrades = append(it.ParentUpgrades, up)
}

// rewordHeld replaces the generic remedy ("upgrade express@4.21.2 to a
// release that depends on a fixed qs") with the releases that were found.
func rewordHeld(it *Item, dir string) {
	if len(it.ParentUpgrades) == 0 {
		return
	}
	pkg, to := it.Upgrade.Package, it.Upgrade.To
	why := it.Why
	if i := strings.Index(why, " Either upgrade "); i >= 0 {
		why = why[:i]
	}
	// apply can now make the change: the parent's upgrade, not the package's.
	why = strings.Replace(why, ", so nox fix apply cannot move it.", ", so it moves only when that package does.", 1)
	var b strings.Builder
	b.WriteString(why)
	for _, up := range it.ParentUpgrades {
		fmt.Fprintf(&b, " Upgrade %s, the first release of %s that lets it move", up.String(), up.Parent)
		if up.Major {
			b.WriteString(" (a new major version: review it)")
		}
		if others := withoutPkg(up.Frees, pkg); len(others) > 0 {
			fmt.Fprintf(&b, "; it also frees %s", npmtree.ParentUpgrade{Frees: others}.FreesList())
		}
		if cmd := npmtree.AdviceFor(dir, up.Parent, up.To).Command; cmd != "" {
			fmt.Fprintf(&b, ": %s", cmd)
		}
		b.WriteString(".")
	}
	b.WriteString(" nox fix apply --include-review makes the upgrade, once for every item it frees, and reads the lockfile back.")
	fmt.Fprintf(&b, " Or force the version with an entry in package.json: %s",
		npmtree.OverrideEntry(npmtree.Tool(dir), pkg, to))
	it.Why = b.String()
}

func noteParentLookup(it *Item, parent string, err error) {
	it.Why += fmt.Sprintf(" nox could not read %s's releases to name the one that allows it: %v.", parent, err)
}

func withoutPkg(names []string, pkg string) []string {
	var out []string
	for _, n := range names {
		if n != pkg {
			out = append(out, n)
		}
	}
	return out
}
