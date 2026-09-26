package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/fix"
)

// `nox fix` upgrades a dependency only when a VULN-001 finding names a
// fixed_in version. That is the right default for a security tool — it acts on
// evidence of a vulnerability, not on the passage of time — but it means a
// dependency that is merely old is never touched, which is the job a version
// bumper like Dependabot was doing.
//
// --outdated is the opt-in currency pass, deliberately separate from the
// default. A security fix is something an operator wants applied without
// argument; routine version churn is a choice with its own risk of breakage.
// Folding them together would make `nox fix` unpredictable — you could no
// longer tell, from the fact that it changed something, whether there had been
// a vulnerability.
//
// Go resolves through the toolchain (`go list -m -u -json all`), which already
// understands replace directives, retractions and the module graph — none of
// which a bare proxy query honours. Every other ecosystem resolves against its
// own registry; see outdated_registry.go.

// goModuleUpdate is the `Update` field `go list -m -u` attaches to a module
// that has a newer version available.
type goModuleUpdate struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
}

// goModuleStatus is the subset of `go list -m -u -json all` output that the
// currency planner needs.
type goModuleStatus struct {
	Path     string          `json:"Path"`
	Version  string          `json:"Version"`
	Main     bool            `json:"Main"`
	Indirect bool            `json:"Indirect"`
	Update   *goModuleUpdate `json:"Update"`
}

// parseGoListModules reads the stream `go list -m -u -json all` writes: a
// sequence of concatenated JSON objects, not a JSON array.
func parseGoListModules(out []byte) ([]goModuleStatus, error) {
	dec := json.NewDecoder(bytes.NewReader(out))
	var mods []goModuleStatus
	for {
		var m goModuleStatus
		err := dec.Decode(&m)
		if err == io.EOF {
			return mods, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parsing go list output: %w", err)
		}
		mods = append(mods, m)
	}
}

// planCurrencyUpgrades turns module status into upgrade actions.
//
// Deliberately narrow about what it will touch:
//   - the main module is never upgraded (`go get` on your own module is
//     meaningless, and it always appears in the listing)
//   - indirect dependencies are left to `go mod tidy`; bumping them writes
//     explicit requirements for packages the project does not import
//   - a major bump needs --include-major, matching the security path
//   - an "update" that is not actually newer is dropped, so this cannot
//     downgrade the way VULN-001 remediation could before #372
func planCurrencyUpgrades(mods []goModuleStatus, includeMajor bool) upgradePlan {
	var plan upgradePlan
	for _, m := range mods {
		if m.Main || m.Indirect || m.Update == nil {
			continue
		}
		to := m.Update.Version
		if to == "" || m.Version == "" {
			continue
		}
		// go list should only report newer versions, but a replace directive
		// or a retracted version can produce one that is not. Applying it
		// would be a downgrade presented as an upgrade.
		if !versionLess(m.Version, to) {
			continue
		}
		if !includeMajor && fix.IsMajorBump(m.Version, to) {
			plan.majorSkipped++
			continue
		}
		plan.actions = append(plan.actions, upgradeAction{
			ruleID:    "OUTDATED",
			pkg:       m.Path,
			fromVer:   m.Version,
			toVersion: to,
			ecosystem: "go",
			action:    goGetBase,
		})
	}
	return plan
}

// goListModules runs `go list -m -u -json all` in root.
//
// This reaches the network — the module proxy has to be consulted to know what
// is newer — so it only ever runs behind the explicit --outdated flag, and
// never as part of a scan. nox's offline-first guarantee is about scanning;
// asking "is there a newer release" cannot be answered offline by anything.
func goListModules(root string) ([]goModuleStatus, error) {
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return nil, fmt.Errorf("no go.mod in %s: %w", root, err)
	}
	cmd := exec.Command("go", "list", "-m", "-u", "-json", "all")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list -m -u: %w: %s", err, stderr.String())
	}
	return parseGoListModules(stdout.Bytes())
}

// runOutdatedFix is the --outdated entry point: enumerate modules, plan the
// currency upgrades, and apply them through the same machinery the security
// path uses.
//
// Output distinguishes the two reasons a dependency can move. A line tagged
// OUTDATED means "newer version exists", not "you were vulnerable" — conflating
// them would inflate what a remediation PR appears to have fixed.
//
// The directories come from fix.outdated.directories in .nox.yaml, defaulting
// to the root. Each is planned on its own and each upgrade runs in the
// directory whose manifest it came from.
func runOutdatedFix(manifestRoot string, dryRun, includeMajor bool) int {
	cfg, err := nox.LoadScanConfig(manifestRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	dirs, err := outdatedDirectories(cfg.Fix.Outdated.Directories)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: fix.outdated.directories: %v\n", err)
		return 1
	}
	holds := cfg.Fix.Outdated.Hold
	if err := validateHolds(holds); err != nil {
		fmt.Fprintf(os.Stderr, "error: fix.outdated.hold: %v\n", err)
		return 1
	}
	plan, degraded := planOutdated(manifestRoot, dirs, includeMajor, registryBase)
	var capped []string
	plan.actions, capped = applyHolds(plan.actions, holds)
	for _, c := range capped {
		fmt.Printf("held: %s\n", c)
	}

	// Report what could not be checked before reporting what was found, so a
	// short list is never mistaken for a clean bill of health. This is the same
	// contract as the scan degradations model.
	for _, d := range degraded {
		fmt.Fprintf(os.Stderr, "degraded: %s\n", d)
	}

	// Every target is checked against known advisories before it is shown as
	// a plan, so a dry run tells the operator the same thing an apply would do.
	advDeg := &degrade.Degradations{}
	kept, held, checked := holdAffectedTargets(context.Background(), advisorySource(advDeg), advDeg, plan.actions)
	if !checked {
		for _, d := range advDeg.Items() {
			fmt.Fprintf(os.Stderr, "degraded: %s\n", d)
		}
		fmt.Fprintf(os.Stderr, "error: could not check %d upgrade target(s) against known advisories; applying none\n", len(plan.actions))
		return 1
	}
	plan.actions = kept
	for _, h := range held {
		fmt.Printf("held: %s\n", h)
	}

	if len(plan.actions) == 0 {
		switch {
		case len(held) > 0:
			fmt.Printf("nox fix --outdated: nothing applied; %d upgrade(s) held because the target has a known advisory.\n", len(held))
		case len(degraded) > 0:
			fmt.Printf("nox fix --outdated: no upgrades found, but %d dependency check(s) could not complete (see above).\n", len(degraded))
		default:
			fmt.Println("nox fix --outdated: all direct dependencies are current.")
		}
		if plan.majorSkipped > 0 {
			fmt.Printf("note: %d major-bump upgrade(s) held back (use --include-major to apply)\n", plan.majorSkipped)
		}
		return 0
	}

	for _, a := range plan.actions {
		fmt.Printf("plan: %s %s %s -> %s  (%s)%s\n", a.action, a.pkg, a.fromVer, a.toVersion, a.ruleID, inDir(a))
	}
	if plan.majorSkipped > 0 {
		fmt.Printf("note: %d major-bump upgrade(s) held back (use --include-major to apply)\n", plan.majorSkipped)
	}
	if dryRun {
		return 0
	}

	failed := 0
	used := map[[2]string]bool{}
	for _, a := range plan.actions {
		dir, err := workdirFor(manifestRoot, a)
		if err == nil {
			err = applyUpgrade(dir, a)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", a.pkg, err)
			failed++
			continue
		}
		used[[2]string{dir, a.ecosystem}] = true
		fmt.Printf("applied: %s -> %s%s\n", a.pkg, a.toVersion, inDir(a))
	}

	// Only tidy when every upgrade landed. Tidying over a partial application
	// can rewrite go.mod around a state the operator did not intend.
	if failed == 0 {
		for key := range used {
			if err := tidyEco(key[0], key[1]); err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s tidy failed in %s: %v\n", key[1], key[0], err)
			}
		}
		return 0
	}
	return 1
}

// outdatedDirectories normalises fix.outdated.directories: the root when
// nothing is configured, duplicates collapsed, and no entry allowed to be
// absolute or to climb out of the repository.
func outdatedDirectories(configured []string) ([]string, error) {
	if len(configured) == 0 {
		return []string{"."}, nil
	}
	seen := map[string]bool{}
	var dirs []string
	for _, d := range configured {
		// filepath.IsAbs alone is not enough: on Windows "/etc" has no drive
		// letter and is not "absolute", yet it is rooted and still names a
		// directory outside the repository.
		if filepath.IsAbs(d) || filepath.VolumeName(d) != "" || strings.HasPrefix(d, "/") || strings.HasPrefix(d, `\`) {
			return nil, fmt.Errorf("%q is absolute; directories are relative to the repository root", d)
		}
		clean := filepath.ToSlash(filepath.Clean(d))
		if clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("%q lies outside the repository", d)
		}
		if !seen[clean] {
			seen[clean] = true
			dirs = append(dirs, clean)
		}
	}
	return dirs, nil
}

// planOutdated plans the currency pass for each directory under root. Every
// action records the manifest it came from, so workdirFor runs it in that
// directory — and refuses one that is not there.
func planOutdated(root string, dirs []string, includeMajor bool, base map[string]string) (plan upgradePlan, degraded []string) {
	for _, dir := range dirs {
		abs := filepath.Join(root, dir)
		if info, err := os.Stat(abs); err != nil || !info.IsDir() {
			degraded = append(degraded, fmt.Sprintf("fix.outdated.directories names %s, which is not a directory", dir))
			continue
		}
		where := ""
		if dir != "." {
			where = " in " + dir
		}

		var dirPlan upgradePlan
		// Go is resolved through the toolchain rather than a registry call:
		// `go list -m -u` already understands replace directives, retractions
		// and the module graph, none of which a proxy query would honour.
		// Absent go.mod is not an error — a JavaScript project has nothing to
		// report here.
		if _, statErr := os.Stat(filepath.Join(abs, "go.mod")); statErr == nil {
			mods, err := goListModules(abs)
			if err != nil {
				degraded = append(degraded, fmt.Sprintf("could not enumerate Go modules%s: %v", where, err))
			} else {
				dirPlan.merge(planCurrencyUpgrades(mods, includeMajor))
			}
		}
		// Everything else resolves against its own registry.
		regPlan, regDegraded := planRegistryCurrency(abs, includeMajor, base)
		dirPlan.merge(regPlan)
		for _, d := range regDegraded {
			degraded = append(degraded, d+where)
		}

		for i := range dirPlan.actions {
			dirPlan.actions[i].manifest = manifestIn(dir, dirPlan.actions[i].ecosystem)
		}
		plan.merge(dirPlan)
	}
	return plan, degraded
}

// outdatedHold is a fix.outdated.hold entry from .nox.yaml.
type outdatedHold = nox.OutdatedHold

// holdAllows ranks the bump sizes a hold can permit.
var holdAllows = map[string]int{"patch": 1, "minor": 2}

// validateHolds refuses a hold that explains nothing: no package, no reason,
// or an allow level nobody defined. Such an entry would hold silently, or
// silently not.
func validateHolds(holds []outdatedHold) error {
	for _, h := range holds {
		switch {
		case h.Package == "":
			return fmt.Errorf("an entry names no package")
		case h.Reason == "":
			return fmt.Errorf("%s has no reason; say why it is held", h.Package)
		case holdAllows[h.Allow] == 0:
			return fmt.Errorf("%s: allow is %q, want \"patch\" or \"minor\"", h.Package, h.Allow)
		}
	}
	return nil
}

// applyHolds drops each action that moves a held package further than its
// hold allows, and describes each one it drops.
func applyHolds(actions []upgradeAction, holds []outdatedHold) (kept []upgradeAction, held []string) {
	byPkg := map[string]outdatedHold{}
	for _, h := range holds {
		byPkg[h.Package] = h
	}
	for _, a := range actions {
		h, ok := byPkg[a.pkg]
		if !ok || bumpSize(a.fromVer, a.toVersion) <= holdAllows[h.Allow] {
			kept = append(kept, a)
			continue
		}
		held = append(held, fmt.Sprintf("%s %s -> %s: fix.outdated.hold allows %s only — %s",
			a.pkg, a.fromVer, a.toVersion, h.Allow, h.Reason))
	}
	return kept, held
}

// bumpSize ranks the move from one version to another: 1 patch, 2 minor,
// 3 major.
func bumpSize(from, to string) int {
	a, b := parseVer(from), parseVer(to)
	switch {
	case a[0] != b[0]:
		return 3
	case a[1] != b[1]:
		return 2
	default:
		return 1
	}
}

// merge folds another plan into p.
func (p *upgradePlan) merge(o upgradePlan) {
	p.actions = append(p.actions, o.actions...)
	p.skipped += o.skipped
	p.majorSkipped += o.majorSkipped
}

// manifestIn names a manifest path inside dir for eco. workdirFor only takes
// its directory, then checks that one of the ecosystem's manifests is there.
func manifestIn(dir, eco string) string {
	name := "project"
	if names := ecoManifests[eco]; len(names) > 0 {
		name = names[0]
	}
	return filepath.ToSlash(filepath.Join(dir, name))
}

// inDir renders " in <dir>" for an action outside the root, and nothing for
// one at it, so a single-directory run reads exactly as it always has.
func inDir(a upgradeAction) string {
	dir := filepath.ToSlash(filepath.Dir(a.manifest))
	if a.manifest == "" || dir == "." {
		return ""
	}
	return " in " + dir
}

// goGetBase is the base command for a go upgrade, from the shared registry.
var goGetBase = func() string { c, _ := fix.SupportedEcosystem("go"); return c }()
