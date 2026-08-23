package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
)

// runFix applies safe upgrade actions derived from VULN-001 findings.
// "Safe" means: a fixed_in version is present in the OSV record AND the
// upgrade does not cross a major version boundary. Operators bypass the
// major-bump guard with --include-major.
//
// Each upgrade is applied in the directory of the manifest its finding named,
// which in a monorepo is not the project root.
func runFix(args []string) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	var (
		inputPath    string
		dryRun       bool
		includeMajor bool
		manifestRoot string
		doActions    bool
		onlyActions  bool
		doOutdated   bool
		doContent    bool
		write        bool
	)
	fs.StringVar(&inputPath, "input", "findings.json", "path to findings.json from a previous scan")
	fs.BoolVar(&dryRun, "dry-run", false, "print actions without applying them")
	fs.BoolVar(&includeMajor, "include-major", false, "apply upgrades that cross a major version boundary")
	fs.StringVar(&manifestRoot, "root", ".", "directory containing the project's manifest (go.mod)")
	fs.BoolVar(&doActions, "actions", false, "also upgrade outdated GitHub Actions pins in .github/workflows (needs GITHUB_TOKEN)")
	fs.BoolVar(&onlyActions, "actions-only", false, "only upgrade GitHub Actions pins; skip the package-dependency pass")
	fs.BoolVar(&doOutdated, "outdated", false, "upgrade dependencies that are merely out of date (opt-in currency pass; reaches the network, Go only)")
	fs.BoolVar(&doContent, "content", false, "generate deterministic patches for mechanical IAC misconfigurations (previews the diff; add --write to apply)")
	fs.BoolVar(&write, "write", false, "with --content: apply the patches instead of only previewing them")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Content-rule fixing is a distinct mode: it reads findings.json and
	// rewrites the flagged lines with their one unambiguous secure value.
	if doContent {
		return runContentFix(inputPath, write)
	}

	// --outdated is a currency pass, not a security pass: it acts on the
	// passage of time rather than on a finding, so it needs no findings.json.
	// Handled before the deps path so it does not require a scan to have run.
	if doOutdated {
		return runOutdatedFix(manifestRoot, dryRun, includeMajor)
	}

	// GitHub Actions remediation runs independently of findings.json — it
	// scans the workflows directly and pins each `uses:` to the latest release.
	if onlyActions {
		return actionsExit(runActionsFix(manifestRoot, dryRun, includeMajor, newGithubResolver()))
	}

	code := runDepsFix(inputPath, manifestRoot, dryRun, includeMajor)
	if doActions {
		if ac := actionsExit(runActionsFix(manifestRoot, dryRun, includeMajor, newGithubResolver())); ac != 0 {
			code = ac
		}
	}
	return code
}

// actionsExit maps the actions-fix counters to a process exit code: non-zero
// only when a rewrite failed (an already-latest or unresolved pin is fine).
func actionsExit(applied, skipped, failed int) int {
	if failed > 0 {
		return 1
	}
	if applied == 0 && skipped == 0 {
		fmt.Println("nox fix: no GitHub Actions pins found to check.")
	}
	return 0
}

// runDepsFix applies OSV package-dependency upgrades from a scan's
// findings.json (the original nox fix behavior).
func runDepsFix(inputPath, manifestRoot string, dryRun, includeMajor bool) int {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", inputPath, err)
		return 2
	}
	var doc struct {
		Findings []findings.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", inputPath, err)
		return 2
	}

	plan := planUpgrades(doc.Findings, includeMajor)
	if len(plan.actions) == 0 {
		fmt.Println("nox fix: no eligible upgrades found.")
		if plan.skipped > 0 {
			fmt.Printf("(%d findings skipped — no fixed_in version or non-Go ecosystem)\n", plan.skipped)
		}
		return 0
	}

	// Resolved before anything is printed, so --dry-run shows the directory
	// each upgrade would run in — and names the ones that cannot run at all.
	dirs := make([]string, len(plan.actions))
	unresolved := 0
	for i, a := range plan.actions {
		dir, err := workdirFor(manifestRoot, a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip: %s [%s]: %v\n", a.pkg, a.ecosystem, err)
			unresolved++
			continue
		}
		dirs[i] = dir
		fmt.Printf("plan: %s %s -> %s  (%s) in %s\n",
			commandFor(dir, a), a.pkg, a.toVersion, a.ruleID, describeDir(manifestRoot, dir))
	}
	if plan.majorSkipped > 0 {
		fmt.Printf("note: %d major-bump upgrades skipped (use --include-major to apply)\n", plan.majorSkipped)
	}

	if dryRun {
		return 0
	}

	failed := unresolved
	// Keyed by directory as well as ecosystem: a monorepo has one go.mod per
	// module, and each needs its own tidy.
	tidied := map[[2]string]bool{}
	for i, a := range plan.actions {
		dir := dirs[i]
		if dir == "" {
			continue
		}
		before, verifiable := treeDigest(dir, a.ecosystem)
		if err := applyUpgrade(dir, a); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s (%s) in %s: %v\n", a.pkg, a.ecosystem, describeDir(manifestRoot, dir), err)
			failed++
			continue
		}
		if after, _ := treeDigest(dir, a.ecosystem); verifiable && after == before {
			// The finding exists because the installed version is vulnerable,
			// so an upgrade that rewrote nothing did not fix it, whatever the
			// tool's exit code said.
			fmt.Fprintf(os.Stderr, "no change: %s [%s] -> %s in %s — the tool reported success but rewrote nothing; the version is likely held by an override or a parent constraint\n",
				a.pkg, a.ecosystem, a.toVersion, describeDir(manifestRoot, dir))
			failed++
			continue
		}
		tidied[[2]string{dir, a.ecosystem}] = true
		fmt.Printf("applied: %s [%s] -> %s in %s\n", a.pkg, a.ecosystem, a.toVersion, describeDir(manifestRoot, dir))
	}

	if failed == 0 {
		for key := range tidied {
			if err := tidyEco(key[0], key[1]); err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s tidy failed: %v\n", key[1], err)
			}
		}
	}
	if failed > 0 {
		return 1
	}

	// Postcondition: re-read the manifests and confirm nothing moved backwards.
	//
	// planUpgrades refuses to ASK for a downgrade; this refuses to SHIP one.
	// Both are needed, because the planner cannot see what the package manager
	// actually did — `go get` resolves against the whole module graph, and a
	// constraint elsewhere can land a package below the requested version.
	//
	// Failing here is the point. A remediation that lowered a dependency is
	// worse than no remediation: it arrives titled "chore(security)", which is
	// exactly what stops a reviewer looking closely.
	bad, unchecked := verifyNoRegression(manifestRoot, plan.actions)
	for _, u := range unchecked {
		fmt.Printf("unverified: %s — nox cannot yet read this ecosystem's resolved version\n", u)
	}
	if len(bad) > 0 {
		for _, r := range bad {
			fmt.Fprintf(os.Stderr, "error: %s went backwards: %s -> %s\n", r.pkg, r.from, r.actual)
		}
		fmt.Fprintln(os.Stderr, "error: refusing to report success — these changes reintroduce whatever was fixed between those versions. Inspect the manifest before committing.")
		return 1
	}

	return 0
}

type upgradeAction struct {
	ruleID    string
	pkg       string
	fromVer   string
	toVersion string
	ecosystem string
	action    string
	// manifest is the repo-relative file the finding was reported against
	// (go.mod, apps/web/pnpm-lock.yaml). It decides where the package
	// manager runs; without it a monorepo gets upgraded at its root, which
	// is a directory no dependency lives in.
	manifest string
}

type upgradePlan struct {
	actions      []upgradeAction
	skipped      int
	majorSkipped int
}

// planUpgrades projects the shared core/fix planner into the CLI's internal
// action shape. The planning — which packages, to what version, and every
// safety guard — lives in core/fix so `nox fix` and the MCP fix_plan tool
// decide identically. This wrapper only adapts the result to what the CLI
// applier consumes (the ecosystem base command and the manifest path).
func planUpgrades(items []findings.Finding, includeMajor bool) upgradePlan {
	p := fix.PlanUpgrades(items, fix.Options{IncludeMajor: includeMajor})
	plan := upgradePlan{skipped: p.Skipped, majorSkipped: p.MajorSkipped}
	for _, a := range p.Actions {
		base, _ := fix.SupportedEcosystem(a.Ecosystem)
		plan.actions = append(plan.actions, upgradeAction{
			ruleID:    a.RuleID,
			pkg:       a.Package,
			fromVer:   a.From,
			toVersion: a.To,
			ecosystem: a.Ecosystem,
			action:    base,
			manifest:  a.Manifest,
		})
	}
	return plan
}

// ecoManifests names the file that has to be present for an ecosystem's
// package manager to be run in a directory. An ecosystem absent from the map
// is satisfied by the directory existing (nuget's project files are named
// after the project, so there is nothing fixed to look for).
var ecoManifests = map[string][]string{
	"go":       {"go.mod"},
	"npm":      {"package.json"},
	"pypi":     {"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg"},
	"cargo":    {"Cargo.toml"},
	"rubygems": {"Gemfile"},
	"composer": {"composer.json"},
}

// workdirFor says where an upgrade should be applied.
//
// The answer is the directory of the manifest the finding named, not the
// project root. In a monorepo those differ, and the difference is not
// cosmetic: `npm install` in a directory with no package.json does not fail,
// it creates one — a phantom root manifest and lockfile that upgrade nothing,
// while the real dependency in apps/web stays vulnerable and the finding
// survives the fix that claimed to have applied.
//
// So this refuses rather than falling back. A skipped upgrade you can read is
// worth more than an applied one that landed in the wrong directory.
func workdirFor(root string, a upgradeAction) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}

	dir := rootAbs
	if a.manifest != "" {
		dir = filepath.Join(rootAbs, filepath.Dir(a.manifest))
	}

	// findings.json is an input file. A manifest path that climbs out of the
	// project would run a package manager somewhere nobody pointed nox at.
	rel, err := filepath.Rel(rootAbs, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("manifest %q lies outside %s", a.manifest, root)
	}

	names := ecoManifests[a.ecosystem]
	if len(names) == 0 {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			return "", fmt.Errorf("no directory %s", rel)
		}
		return dir, nil
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no %s in %s — nothing to upgrade there", strings.Join(names, " or "), rel)
}

// ecoTrees names the files an upgrade in that ecosystem must touch. An
// ecosystem absent from the map cannot be verified this way (nuget's project
// files are named after the project), and is taken at the tool's word.
var ecoTrees = map[string][]string{
	"go":       {"go.mod", "go.sum"},
	"npm":      {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"},
	"pypi":     {"requirements.txt", "pyproject.toml", "poetry.lock", "setup.py", "setup.cfg"},
	"cargo":    {"Cargo.toml", "Cargo.lock"},
	"rubygems": {"Gemfile", "Gemfile.lock"},
	"composer": {"composer.json", "composer.lock"},
}

// treeDigest fingerprints the manifests an upgrade is supposed to rewrite.
//
// Package managers exit 0 without doing anything. pnpm answers "Already up to
// date" for a transitive dependency held down by a pnpm.overrides entry; npm
// and bundler have their own versions of the same shrug. nox then printed
// "applied" for an upgrade that never happened, which is the worst possible
// report: the operator stops looking and the advisory is still live.
//
// verifyNoRegression is the other half of this and not a substitute — it
// catches a version that moved the wrong way, and only for Go. This catches
// one that did not move at all, in every ecosystem with fixed file names.
//
// The second return value is false when the ecosystem has no such names, in
// which case the tool's exit code is all there is.
func treeDigest(dir, eco string) (string, bool) {
	names, ok := ecoTrees[eco]
	if !ok {
		return "", false
	}
	h := sha256.New()
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		// Length-prefixed so two files cannot be confused for one.
		_, _ = fmt.Fprintf(h, "%s:%d:", name, len(body))
		_, _ = h.Write(body)
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// commandFor is the command the plan line should claim, which for npm depends
// on the lockfile rather than on the ecosystem name.
func commandFor(dir string, a upgradeAction) string {
	if a.ecosystem == "npm" {
		name, args := npmCommand(dir, a.pkg, a.toVersion)
		return name + " " + args[0]
	}
	return a.action
}

// describeDir renders a working directory relative to the root, so the plan
// reads "in apps/web" rather than repeating an absolute path on every line.
func describeDir(root, dir string) string {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return dir
	}
	rel, err := filepath.Rel(rootAbs, dir)
	if err != nil {
		return dir
	}
	if rel == "." {
		return "."
	}
	return rel
}

// applyUpgrade dispatches to the appropriate ecosystem-specific
// applier. Each applier runs the canonical package-manager command in
// manifestRoot. Operators wire their own venv / nvm / asdf via the
// shell environment; nox doesn't try to manage them.
func applyUpgrade(manifestRoot string, a upgradeAction) error {
	switch a.ecosystem {
	case "go":
		return applyGoUpgrade(manifestRoot, a)
	case "npm":
		return applyNpmUpgrade(manifestRoot, a)
	case "pypi":
		return applyPyPIUpgrade(manifestRoot, a)
	case "cargo":
		return applyCargoUpgrade(manifestRoot, a)
	case "rubygems":
		return applyRubyGemsUpgrade(manifestRoot, a)
	case "composer":
		return applyComposerUpgrade(manifestRoot, a)
	case "nuget":
		return applyNuGetUpgrade(manifestRoot, a)
	}
	return fmt.Errorf("ecosystem %q not supported by applyUpgrade", a.ecosystem)
}

// applyGoUpgrade runs `go get pkg@vVERSION` in manifestRoot.
func applyGoUpgrade(manifestRoot string, a upgradeAction) error {
	target := a.pkg + "@v" + strings.TrimPrefix(a.toVersion, "v")
	return runIn(manifestRoot, "go", "get", target)
}

// applyNpmUpgrade drives whichever package manager the workspace actually
// uses.
func applyNpmUpgrade(manifestRoot string, a upgradeAction) error {
	name, args := npmCommand(manifestRoot, a.pkg, strings.TrimPrefix(a.toVersion, "v"))
	return runIn(manifestRoot, name, args...)
}

// npmCommand picks the package manager from the lockfile in dir.
//
// "npm" is an OSV ecosystem, not a tool: the same ecosystem is served by npm,
// pnpm, yarn and bun, and they do not share a lockfile. Running `npm install`
// in a pnpm workspace writes a package-lock.json next to the pnpm-lock.yaml
// and resolves a tree the workspace will never install from.
//
// pnpm gets --depth Infinity because most advisories land on transitive
// dependencies, which a default-depth update does not reach.
func npmCommand(dir, pkg, version string) (tool string, args []string) {
	target := pkg + "@" + version
	has := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	switch {
	case has("pnpm-lock.yaml"):
		return "pnpm", []string{"update", "--depth", "Infinity", target}
	case has("yarn.lock"):
		// Berry renamed the verb and is told apart by its own config file.
		if has(".yarnrc.yml") {
			return "yarn", []string{"up", target}
		}
		return "yarn", []string{"upgrade", target}
	case has("bun.lock"), has("bun.lockb"):
		return "bun", []string{"update", target}
	}
	return "npm", []string{"install", target}
}

// applyPyPIUpgrade runs `pip install --upgrade pkg==version`. Operators
// who manage requirements.txt / pyproject.toml directly should re-pin
// after running. Plain pip is the lowest common denominator.
func applyPyPIUpgrade(manifestRoot string, a upgradeAction) error {
	target := a.pkg + "==" + strings.TrimPrefix(a.toVersion, "v")
	return runIn(manifestRoot, "pip", "install", "--upgrade", target)
}

// applyCargoUpgrade runs `cargo update -p pkg --precise version`.
// Cargo has no separate "install" semantics for project deps; update
// rewrites Cargo.lock.
func applyCargoUpgrade(manifestRoot string, a upgradeAction) error {
	return runIn(manifestRoot, "cargo", "update", "-p", a.pkg, "--precise", strings.TrimPrefix(a.toVersion, "v"))
}

// applyRubyGemsUpgrade runs `bundle update <gem> --conservative`.
//
// Deliberately not a Gemfile rewrite: the Gemfile constraint is the operator's
// declared intent, and bundler resolving within it is the behaviour a Ruby
// project expects. If the constraint pins below the latest release, bundler
// says so rather than nox silently editing the pin away.
func applyRubyGemsUpgrade(manifestRoot string, a upgradeAction) error {
	return runIn(manifestRoot, "bundle", "update", a.pkg, "--conservative")
}

// applyComposerUpgrade runs `composer update <vendor/pkg> --with-dependencies`.
// Composer resolves within the composer.json constraint for the same reason.
func applyComposerUpgrade(manifestRoot string, a upgradeAction) error {
	return runIn(manifestRoot, "composer", "update", a.pkg, "--with-dependencies")
}

// applyNuGetUpgrade runs `dotnet add package <id> --version <v>`, which
// rewrites the PackageReference in the project file.
func applyNuGetUpgrade(manifestRoot string, a upgradeAction) error {
	return runIn(manifestRoot, "dotnet", "add", "package", a.pkg, "--version", strings.TrimPrefix(a.toVersion, "v"))
}

func runIn(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// tidyEco runs the canonical post-upgrade clean-up for an ecosystem.
// Unsupported ecosystems no-op; missing manifests no-op too so the
// cleanup is safe to call unconditionally.
func tidyEco(manifestRoot, eco string) error {
	switch eco {
	case "go":
		if _, err := os.Stat(filepath.Join(manifestRoot, "go.mod")); err != nil {
			return nil
		}
		return runIn(manifestRoot, "go", "mod", "tidy")
	case "npm":
		// `npm install` already updates the lockfile in place; no extra
		// tidy step needed.
		return nil
	case "pypi", "cargo":
		// Nothing canonical to run.
		return nil
	}
	return nil
}
