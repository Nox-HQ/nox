package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// runFix applies safe upgrade actions derived from VULN-001 findings.
// "Safe" means: a fixed_in version is present in the OSV record AND the
// upgrade does not cross a major version boundary. Operators bypass the
// major-bump guard with --include-major.
//
// Today this targets the Go ecosystem only (go.mod / go get); npm,
// PyPI, and Cargo land in follow-up work because each requires
// ecosystem-specific manifest rewriting.
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

	for _, a := range plan.actions {
		fmt.Printf("plan: %s %s -> %s  (%s)\n", a.action, a.pkg, a.toVersion, a.ruleID)
	}
	if plan.majorSkipped > 0 {
		fmt.Printf("note: %d major-bump upgrades skipped (use --include-major to apply)\n", plan.majorSkipped)
	}

	if dryRun {
		return 0
	}

	failed := 0
	usedEcos := map[string]bool{}
	for _, a := range plan.actions {
		if err := applyUpgrade(manifestRoot, a); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s (%s): %v\n", a.pkg, a.ecosystem, err)
			failed++
			continue
		}
		usedEcos[a.ecosystem] = true
		fmt.Printf("applied: %s [%s] -> %s\n", a.pkg, a.ecosystem, a.toVersion)
	}

	if failed == 0 {
		for eco := range usedEcos {
			if err := tidyEco(manifestRoot, eco); err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s tidy failed: %v\n", eco, err)
			}
		}
	}
	if failed > 0 {
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
}

type upgradePlan struct {
	actions      []upgradeAction
	skipped      int
	majorSkipped int
}

// supportedFixEcosystems lists the package managers nox fix can drive
// directly. Other ecosystems get counted as skipped — operators can
// still see the fixed_in metadata in findings.json, just not auto-apply.
var supportedFixEcosystems = map[string]string{
	"go":       "go get",
	"npm":      "npm install",
	"pypi":     "pip install",
	"cargo":    "cargo update",
	"rubygems": "bundle update",
	"composer": "composer update",
	"nuget":    "dotnet add package",
}

// planUpgrades extracts upgrade actions from VULN findings. Skips
// findings without fixed_in metadata, ecosystems we can't drive yet,
// and major-version-boundary upgrades unless includeMajor is set.
func planUpgrades(items []findings.Finding, includeMajor bool) upgradePlan {
	var plan upgradePlan
	seen := map[string]bool{}
	for i := range items {
		f := &items[i]
		if f.RuleID != "VULN-001" {
			continue
		}
		fixed := f.Metadata["fixed_in"]
		eco := f.Metadata["ecosystem"]
		pkg := f.Metadata["package"]
		from := f.Metadata["version"]
		if fixed == "" || pkg == "" {
			plan.skipped++
			continue
		}
		action, ok := supportedFixEcosystems[eco]
		if !ok {
			plan.skipped++
			continue
		}
		if !includeMajor && isMajorBump(from, fixed) {
			plan.majorSkipped++
			continue
		}
		key := eco + ":" + pkg + "@" + fixed
		if seen[key] {
			continue
		}
		seen[key] = true
		plan.actions = append(plan.actions, upgradeAction{
			ruleID:    f.RuleID,
			pkg:       pkg,
			fromVer:   from,
			toVersion: fixed,
			ecosystem: eco,
			action:    action,
		})
	}
	return plan
}

// isMajorBump returns true when the fix version's leading numeric
// component differs from the current version's leading component.
// Treats a non-numeric leading segment as same-major to be conservative.
func isMajorBump(from, to string) bool {
	if from == "" || to == "" {
		return false
	}
	return majorOf(from) != majorOf(to)
}

func majorOf(version string) string {
	v := strings.TrimPrefix(version, "v")
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	return v
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

// applyNpmUpgrade runs `npm install pkg@version`. Works against
// package.json + package-lock.json. Yarn / pnpm projects need to be
// driven via their own CLI; this targets the npm baseline.
func applyNpmUpgrade(manifestRoot string, a upgradeAction) error {
	target := a.pkg + "@" + strings.TrimPrefix(a.toVersion, "v")
	return runIn(manifestRoot, "npm", "install", target)
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
