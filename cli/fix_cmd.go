package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
	"github.com/nox-hq/nox/core/fix/osvcheck"
)

// runFix applies safe upgrade actions derived from VULN-001 findings.
// "Safe" means: a fixed_in version is present in the OSV record AND the
// upgrade does not cross a major version boundary. Operators bypass the
// major-bump guard with --include-major.
//
// Each upgrade is applied in the directory of the manifest its finding named,
// which in a monorepo is not the project root.
func runFix(args []string) int {
	if len(args) > 0 && fixSubcommands[args[0]] {
		return runFixSub(args[0], args[1:])
	}
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
	fs.BoolVar(&doOutdated, "outdated", false, "upgrade dependencies that are merely out of date (opt-in currency pass; reaches the network: go, npm, pypi, cargo, rubygems, composer, nuget)")
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
		for _, n := range plan.heldNotes {
			fmt.Printf("  - %s\n", n)
		}
	}

	if dryRun {
		return 0
	}

	failed := unresolved
	applied := map[string]bool{}
	// Keyed by directory as well as ecosystem: a monorepo has one go.mod per
	// module, and each needs its own tidy.
	tidied := map[[2]string]bool{}
	for i, a := range plan.actions {
		dir := dirs[i]
		if dir == "" {
			continue
		}
		res, err := applyChecked(dir, a)
		var noChange *noChangeError
		switch {
		case errors.As(err, &noChange):
			// The finding exists because the installed version is vulnerable,
			// so an upgrade that rewrote nothing did not fix it, whatever the
			// tool's exit code said.
			fmt.Fprintf(os.Stderr, "no change: %s [%s] -> %s in %s — the tool reported success but rewrote nothing; the version is likely held by an override or a parent constraint\n",
				a.pkg, a.ecosystem, a.toVersion, describeDir(manifestRoot, dir))
			failed++
			continue
		case err != nil:
			fmt.Fprintf(os.Stderr, "error: %s (%s) in %s: %v\n", a.pkg, a.ecosystem, describeDir(manifestRoot, dir), err)
			failed++
			continue
		case res == upgradeSatisfied:
			fmt.Printf("satisfied: %s [%s] -> %s in %s — already at or above the fix; an earlier upgrade in this run moved it\n",
				a.pkg, a.ecosystem, a.toVersion, describeDir(manifestRoot, dir))
			continue
		}
		tidied[[2]string{dir, a.ecosystem}] = true
		applied[a.ecosystem] = true
		fmt.Printf("applied: %s [%s] -> %s in %s\n", a.pkg, a.ecosystem, a.toVersion, describeDir(manifestRoot, dir))
	}

	printScriptsNotRun(os.Stdout, applied)

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

// scriptsNotRun says, per ecosystem, what nox deliberately did not execute
// and what the operator does to run it once they have looked at the new code.
var scriptsNotRun = []struct {
	ecosystem string
	text      string
}{
	{"npm", "npm/pnpm/yarn/bun: install scripts (preinstall, install, postinstall, prepare) of the new versions were not run. Native addons and generated files may be missing until you review the packages and run `npm rebuild` (or your manager's equivalent)."},
	{"pypi", "pip: only prebuilt wheels were installed; no source distribution was built, because building one runs the package's own setup code."},
	{"rubygems", "bundler: Gemfile.lock was updated but the gems were not installed, so no native extension was compiled. Run `bundle install` after reviewing."},
	{"composer", "composer: scripts and plugins were not run (--no-scripts --no-plugins)."},
	{"nuget", "dotnet: the project file was updated but not restored (--no-restore), so no package build logic ran. Run `dotnet restore` after reviewing."},
}

// printScriptsNotRun tells the operator which package-manager steps nox kept
// switched off. Silence here would let "applied" read as "installed and
// working", which is not what happened.
func printScriptsNotRun(w io.Writer, applied map[string]bool) {
	var lines []string
	for _, n := range scriptsNotRun {
		if applied[n.ecosystem] {
			lines = append(lines, n.text)
		}
	}
	if len(lines) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "note: nox does not execute code from the packages it upgrades, so these steps were skipped:")
	for _, l := range lines {
		_, _ = fmt.Fprintln(w, "  - "+l)
	}
}

// upgradeResult is what applying one upgrade did.
type upgradeResult int

const (
	// upgradeApplied means the package manager rewrote the manifests.
	upgradeApplied upgradeResult = iota
	// upgradeSatisfied means nothing needed rewriting: an earlier upgrade in the
	// same run already moved the package to or past the fix.
	upgradeSatisfied
)

// noChangeError is an upgrade the package manager accepted and did nothing
// for. Reported as a failure: the version is vulnerable, so an upgrade that
// rewrote nothing did not fix it, whatever the exit code said.
type noChangeError struct{}

func (*noChangeError) Error() string {
	return "the package manager reported success but rewrote nothing; the version is likely held by an override or a parent constraint"
}

// applyChecked runs one upgrade in dir and checks that it did something.
func applyChecked(dir string, a upgradeAction) (upgradeResult, error) {
	before, verifiable := treeDigest(dir, a.ecosystem)
	if err := applyUpgrade(dir, a); err != nil {
		return upgradeApplied, err
	}
	if after, _ := treeDigest(dir, a.ecosystem); verifiable && after == before {
		if alreadySatisfied(dir, a) {
			return upgradeSatisfied, nil
		}
		return upgradeApplied, &noChangeError{}
	}
	return upgradeApplied, nil
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
	// heldNotes say which advisories a plan leaves, and what clears them.
	heldNotes []string
}

// planUpgrades projects the shared core/fix planner into the CLI's internal
// action shape. The planning — which packages, to what version, and every
// safety guard — lives in core/fix so `nox fix` and the MCP fix_plan tool
// decide identically. This wrapper only adapts the result to what the CLI
// applier consumes (the ecosystem base command and the manifest path).
func planUpgrades(items []findings.Finding, includeMajor bool) upgradePlan {
	p := fix.PlanUpgrades(items, fix.Options{IncludeMajor: includeMajor, Checker: targetChecker(false)})
	plan := upgradePlan{skipped: p.Skipped, majorSkipped: p.MajorSkipped}
	for _, h := range p.Held {
		if h.PolicyTarget != "" {
			plan.heldNotes = append(plan.heldNotes, fmt.Sprintf("%s: %s would still be affected by %s; only %s clears them (needs --include-major)",
				h.Package, h.PolicyTarget, strings.Join(h.Remaining, ", "), h.To))
		}
	}
	for _, a := range p.Actions {
		if len(a.Remaining) > 0 {
			plan.heldNotes = append(plan.heldNotes, fmt.Sprintf("%s %s: still affected by %s, no fix published", a.Package, a.To, strings.Join(a.Remaining, ", ")))
		}
	}
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
	// Finding paths are relative to the directory that was scanned, so a
	// --root pointing anywhere else joins them onto the wrong base: --root app
	// with app/package-lock.json looks in app/app. Say where it looked, from
	// the root's own name, rather than naming a directory that may well hold
	// the manifest.
	looked := filepath.ToSlash(filepath.Join(filepath.Base(rootAbs), rel))
	return "", fmt.Errorf("no %s in %s — nothing to upgrade there (finding paths are relative to the scanned directory; --root must be that directory)",
		strings.Join(names, " or "), looked)
}

// ecoTrees names the files an upgrade in that ecosystem must touch. An
// ecosystem absent from the map cannot be verified this way (nuget's project
// files are named after the project), and is taken at the tool's word.
var ecoTrees = map[string][]string{
	"go":       {"go.mod", "go.sum"},
	"npm":      {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"},
	"pypi":     {"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock", "uv.lock", "setup.py", "setup.cfg"},
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
	case "docker":
		return applyImageUpgrade(manifestRoot, a)
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
//
// When npm updates a transitive package, the lockfile is read back: `npm
// update` moves it only as far as its parents' ranges allow, and a copy still
// short of the fixed version means the advisory is still there.
func applyNpmUpgrade(manifestRoot string, a upgradeAction) error {
	version := strings.TrimPrefix(a.toVersion, "v")
	name, args := npmCommand(manifestRoot, a.pkg, version)
	if err := runInEnv(manifestRoot, scriptsOffEnv, name, args...); err != nil {
		return err
	}
	if name != "npm" || args[0] != "update" {
		return nil
	}
	below, err := npmLockBelow(manifestRoot, a.pkg, version)
	if err != nil {
		return fmt.Errorf("reading package-lock.json after npm update: %w", err)
	}
	if len(below) > 0 {
		return fmt.Errorf("%s is transitive and npm update left %s below %s: a parent's "+
			"version range excludes the fix; upgrade that parent, or pin it with an "+
			"\"overrides\" entry in package.json", a.pkg, strings.Join(below, ", "), version)
	}
	return nil
}

// npmDirectDeclaration names the package.json section that declares pkg and
// the version specifier written there ("4.17.15", "^4.17.15", "~4.17.0").
// Both are "" when pkg is only pulled in by another package.
func npmDirectDeclaration(dir, pkg string) (section, spec string) {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return "", ""
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(raw, &manifest) != nil {
		return "", ""
	}
	for _, name := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		var deps map[string]string
		if json.Unmarshal(manifest[name], &deps) != nil {
			continue
		}
		if s, ok := deps[pkg]; ok {
			return name, s
		}
	}
	return "", ""
}

// specStyle is how a package.json specifier pins a version.
type specStyle int

const (
	// styleOther covers ranges, wildcards, tags and non-registry sources. The
	// package manager's own default applies; nox has no faithful way to keep
	// them.
	styleOther specStyle = iota
	styleExact
	styleCaret
	styleTilde
)

// styleOfSpec classifies a specifier so an upgrade can keep the operator's
// choice. An exact pin is a decision (reproducible builds, a vetted version),
// and rewriting it to a caret range silently widens what any later install
// may resolve.
func styleOfSpec(spec string) specStyle {
	spec = strings.TrimSpace(spec)
	switch {
	case strings.HasPrefix(spec, "^"):
		return styleCaret
	case strings.HasPrefix(spec, "~"):
		return styleTilde
	case exactVersionRE.MatchString(spec):
		return styleExact
	}
	return styleOther
}

var exactVersionRE = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]+)?$`)

// saveFlags are the npm/yarn flags that make a written specifier match style.
// styleOther gets none: the manager's default is the best nox can do.
func saveFlags(tool string, style specStyle) []string {
	switch tool {
	case "npm":
		switch style {
		case styleExact:
			return []string{"--save-exact"}
		case styleTilde:
			return []string{"--save-prefix=~"}
		case styleCaret:
			return []string{"--save-prefix=^"}
		}
	case "yarn":
		switch style {
		case styleExact:
			return []string{"--exact"}
		case styleTilde:
			return []string{"--tilde"}
		case styleCaret:
			return []string{"--caret"}
		}
	}
	// pnpm and bun keep the existing specifier's style when given an explicit
	// version (measured, pnpm 10.24 and bun 1.x), so they need nothing.
	return nil
}

// npmLockBelow lists every copy of pkg in dir's package-lock.json whose
// version is still below version, as "path@version". Nested copies count:
// node_modules/a/node_modules/pkg is installed and loaded just the same.
func npmLockBelow(dir, pkg, version string) ([]string, error) {
	copies, err := npmLockCopies(dir, pkg)
	if err != nil {
		return nil, err
	}
	var below []string
	for path, v := range copies {
		if v != "" && versionLess(v, version) {
			below = append(below, path+"@"+v)
		}
	}
	sort.Strings(below)
	return below, nil
}

// npmLockCopies maps each lockfile path that installs pkg to its version.
func npmLockCopies(dir, pkg string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	copies := map[string]string{}
	for path, entry := range lock.Packages {
		if path == "node_modules/"+pkg || strings.HasSuffix(path, "/node_modules/"+pkg) {
			copies[path] = entry.Version
		}
	}
	return copies, nil
}

// alreadySatisfied reports whether an npm upgrade that rewrote nothing had
// nothing left to do: the lockfile holds at least one copy of the package and
// every copy is at or above the fixed version. That happens when an earlier
// upgrade in the same run moved it as a dependency of something else. With no
// lockfile, or no copy found in one, nothing is claimed.
func alreadySatisfied(dir string, a upgradeAction) bool {
	if a.ecosystem != "npm" {
		return false
	}
	copies, err := npmLockCopies(dir, a.pkg)
	if err != nil || len(copies) == 0 {
		return false
	}
	below, err := npmLockBelow(dir, a.pkg, strings.TrimPrefix(a.toVersion, "v"))
	return err == nil && len(below) == 0
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
	section, spec := npmDirectDeclaration(dir, pkg)
	style := styleOfSpec(spec)
	// Every command here installs packages, and installing runs their
	// lifecycle scripts: arbitrary code from whatever version nox just chose.
	// nox never executes untrusted code, so scripts are always off.
	switch {
	case has("pnpm-lock.yaml"):
		return "pnpm", []string{"update", "--ignore-scripts", "--depth", "Infinity", target}
	case has("yarn.lock"):
		// Berry renamed the verb and is told apart by its own config file.
		// Berry has no --ignore-scripts on `up`; applyNpmUpgrade sets
		// YARN_ENABLE_SCRIPTS=false for it.
		if has(".yarnrc.yml") {
			return "yarn", append(append([]string{"up"}, saveFlags("yarn", style)...), target)
		}
		return "yarn", append(append([]string{"upgrade", "--ignore-scripts"}, saveFlags("yarn", style)...), target)
	case has("bun.lock"), has("bun.lockb"):
		return "bun", []string{"update", "--ignore-scripts", target}
	}
	// npm install writes whatever it is given into package.json: a transitive
	// package becomes a new direct dependency, and a devDependency moves into
	// dependencies. So the manifest decides. A declared package keeps its
	// section; anything else is moved by `npm update`, which touches only the
	// lockfile and takes no version — applyNpmUpgrade checks where it landed.
	install := func(extra ...string) []string {
		a := append([]string{"install", "--ignore-scripts"}, extra...)
		a = append(a, saveFlags("npm", style)...)
		return append(a, target)
	}
	switch section {
	case "dependencies":
		return "npm", install()
	case "devDependencies":
		return "npm", install("--save-dev")
	case "optionalDependencies":
		return "npm", install("--save-optional")
	}
	return "npm", []string{"update", "--ignore-scripts", pkg}
}

// scriptsOffEnv switches install scripts off for every JavaScript package
// manager through its environment, as well as through flags: yarn Berry has no
// flag on `up`, and an environment setting also covers a manager that grows a
// new verb. The three are no-ops for tools that do not read them.
var scriptsOffEnv = []string{
	"npm_config_ignore_scripts=true",
	"YARN_ENABLE_SCRIPTS=false",
}

// pipUpgradeArgs is `pip install --upgrade --only-binary :all: pkg==version`.
// A source distribution is built by running the package's own setup code, so
// only wheels are accepted: installing one runs nothing. A package that ships
// no wheel fails loudly rather than executing its build.
func pipUpgradeArgs(a upgradeAction) []string {
	return []string{"install", "--upgrade", "--only-binary", ":all:", a.pkg + "==" + strings.TrimPrefix(a.toVersion, "v")}
}

// applyPyPIUpgrade runs pipUpgradeArgs. Operators who manage
// requirements.txt / pyproject.toml directly should re-pin after running.
// Plain pip is the lowest common denominator.
func applyPyPIUpgrade(manifestRoot string, a upgradeAction) error {
	err := runIn(manifestRoot, "pip", pipUpgradeArgs(a)...)
	if err != nil {
		return fmt.Errorf("%w (nox installs wheels only, because building a source distribution runs the package's code; "+
			"if %s publishes no wheel for this platform, review it and install it yourself)", err, a.pkg)
	}
	return nil
}

// applyCargoUpgrade runs `cargo update -p pkg --precise version`.
// Cargo has no separate "install" semantics for project deps; update
// rewrites Cargo.lock. It resolves only: no crate is built, so no build.rs
// runs.
func applyCargoUpgrade(manifestRoot string, a upgradeAction) error {
	return runIn(manifestRoot, "cargo", "update", "-p", a.pkg, "--precise", strings.TrimPrefix(a.toVersion, "v"))
}

// rubyGemsUpgradeArgs is `bundle lock --update <gem> --conservative`.
//
// Deliberately not `bundle update`, which installs the gems and so compiles
// native extensions (extconf.rb is arbitrary Ruby). `bundle lock` resolves
// and rewrites Gemfile.lock only; the next `bundle install` is the
// operator's.
//
// Deliberately not a Gemfile rewrite either: the Gemfile constraint is the
// operator's declared intent, and bundler resolving within it is the
// behaviour a Ruby project expects. If the constraint pins below the latest
// release, bundler says so rather than nox silently editing the pin away.
func rubyGemsUpgradeArgs(a upgradeAction) []string {
	return []string{"lock", "--update", a.pkg, "--conservative"}
}

func applyRubyGemsUpgrade(manifestRoot string, a upgradeAction) error {
	return runIn(manifestRoot, "bundle", rubyGemsUpgradeArgs(a)...)
}

// composerUpgradeArgs is `composer update <vendor/pkg> --with-dependencies
// --no-scripts --no-plugins`. Composer resolves within the composer.json
// constraint for the same reason as bundler. Scripts (post-update-cmd and
// friends) and plugins are code the project or its dependencies supply, and
// both run during an update.
func composerUpgradeArgs(a upgradeAction) []string {
	return []string{"update", a.pkg, "--with-dependencies", "--no-scripts", "--no-plugins"}
}

func applyComposerUpgrade(manifestRoot string, a upgradeAction) error {
	return runIn(manifestRoot, "composer", composerUpgradeArgs(a)...)
}

// nugetUpgradeArgs is `dotnet add package <id> --version <v> --no-restore`.
// It rewrites the PackageReference in the project file and stops: restore
// pulls MSBuild props and targets out of the new package, which are executed.
func nugetUpgradeArgs(a upgradeAction) []string {
	return []string{"add", "package", a.pkg, "--version", strings.TrimPrefix(a.toVersion, "v"), "--no-restore"}
}

func applyNuGetUpgrade(manifestRoot string, a upgradeAction) error {
	return runIn(manifestRoot, "dotnet", nugetUpgradeArgs(a)...)
}

func runIn(dir, name string, args ...string) error {
	return runInEnv(dir, nil, name, args...)
}

// runInEnv is runIn with extra environment entries layered over nox's own.
func runInEnv(dir string, env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
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

// targetChecker asks the advisory database what each upgrade target is still
// vulnerable to, so the plan names a version that clears every known advisory.
// Offline plans from the findings alone.
func targetChecker(offline bool) fix.Checker {
	if offline {
		return nil
	}
	return osvcheck.New("")
}
