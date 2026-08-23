package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

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
func runOutdatedFix(manifestRoot string, dryRun, includeMajor bool) int {
	var plan upgradePlan
	var degraded []string

	// Go is resolved through the toolchain rather than a registry call:
	// `go list -m -u` already understands replace directives, retractions and
	// the module graph, none of which a proxy query would honour. Absent go.mod
	// is not an error — a JavaScript project has nothing to report here.
	if _, statErr := os.Stat(filepath.Join(manifestRoot, "go.mod")); statErr == nil {
		mods, err := goListModules(manifestRoot)
		if err != nil {
			degraded = append(degraded, fmt.Sprintf("could not enumerate Go modules: %v", err))
		} else {
			goPlan := planCurrencyUpgrades(mods, includeMajor)
			plan.actions = append(plan.actions, goPlan.actions...)
			plan.skipped += goPlan.skipped
			plan.majorSkipped += goPlan.majorSkipped
		}
	}

	// Everything else resolves against its own registry.
	regPlan, regDegraded := planRegistryCurrency(manifestRoot, includeMajor, registryBase)
	plan.actions = append(plan.actions, regPlan.actions...)
	plan.skipped += regPlan.skipped
	plan.majorSkipped += regPlan.majorSkipped
	degraded = append(degraded, regDegraded...)

	// Report what could not be checked before reporting what was found, so a
	// short list is never mistaken for a clean bill of health. This is the same
	// contract as the scan degradations model.
	for _, d := range degraded {
		fmt.Fprintf(os.Stderr, "degraded: %s\n", d)
	}

	if len(plan.actions) == 0 {
		if len(degraded) > 0 {
			fmt.Printf("nox fix --outdated: no upgrades found, but %d dependency check(s) could not complete (see above).\n", len(degraded))
		} else {
			fmt.Println("nox fix --outdated: all direct dependencies are current.")
		}
		if plan.majorSkipped > 0 {
			fmt.Printf("note: %d major-bump upgrade(s) held back (use --include-major to apply)\n", plan.majorSkipped)
		}
		return 0
	}

	for _, a := range plan.actions {
		fmt.Printf("plan: %s %s %s -> %s  (%s)\n", a.action, a.pkg, a.fromVer, a.toVersion, a.ruleID)
	}
	if plan.majorSkipped > 0 {
		fmt.Printf("note: %d major-bump upgrade(s) held back (use --include-major to apply)\n", plan.majorSkipped)
	}
	if dryRun {
		return 0
	}

	failed := 0
	for _, a := range plan.actions {
		if err := applyUpgrade(manifestRoot, a); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", a.pkg, err)
			failed++
			continue
		}
		fmt.Printf("applied: %s -> %s\n", a.pkg, a.toVersion)
	}

	// Only tidy when every upgrade landed. Tidying over a partial application
	// can rewrite go.mod around a state the operator did not intend.
	if failed == 0 {
		used := map[string]bool{}
		for _, a := range plan.actions {
			used[a.ecosystem] = true
		}
		for eco := range used {
			if err := tidyEco(manifestRoot, eco); err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s tidy failed: %v\n", eco, err)
			}
		}
		return 0
	}
	return 1
}

// goGetBase is the base command for a go upgrade, from the shared registry.
var goGetBase = func() string { c, _ := fix.SupportedEcosystem("go"); return c }()
