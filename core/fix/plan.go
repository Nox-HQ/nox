package fix

import (
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// fixRuleID is the finding rule that carries dependency-upgrade metadata.
const fixRuleID = "VULN-001"

// ecosystemCommands maps an ecosystem to the base package-manager verb nox uses
// to apply an upgrade. An ecosystem absent from this map is one nox fix cannot
// drive: its findings are counted as skipped rather than dressed up with a
// command the applier will not run. That honesty is the point — a plan must not
// claim actionable where the tool does nothing.
//
// maven and gradle are deliberately absent: nox does not edit build files, so a
// maven vuln is skipped, not shown as a fake "upgrade in your build file" step.
var ecosystemCommands = map[string]string{
	"go":       "go get",
	"npm":      "npm install",
	"pypi":     "pip install",
	"cargo":    "cargo update",
	"rubygems": "bundle update",
	"composer": "composer update",
	"nuget":    "dotnet add package",
}

// SupportedEcosystem returns the base command for an ecosystem nox fix can
// drive, and whether it is supported at all.
func SupportedEcosystem(eco string) (baseCommand string, ok bool) {
	cmd, ok := ecosystemCommands[eco]
	return cmd, ok
}

// UpgradeAction is one package the planner decided to move. It carries what both
// the display (the operator-runnable Command) and the applier (Package, To,
// Ecosystem, Manifest) need, so neither adapter re-derives it.
type UpgradeAction struct {
	// RuleID is the finding rule (always VULN-001 today).
	RuleID string `json:"rule_id"`
	// Package is the vulnerable package.
	Package string `json:"package"`
	// From is the installed version, possibly empty when the scanner omitted it.
	From string `json:"from"`
	// To is the version to move to — the highest fix that clears every advisory.
	To string `json:"to"`
	// Ecosystem is the package ecosystem (go, npm, ...).
	Ecosystem string `json:"ecosystem"`
	// Manifest is the repo-relative file the finding was reported against. It
	// decides where the package manager runs; without it a monorepo gets
	// upgraded at its root, a directory no dependency lives in.
	Manifest string `json:"manifest,omitempty"`
}

// Command returns the operator-runnable upgrade command for the action, the
// generic form shown in a plan. The CLI applier may run a directory-aware
// variant (npm in the manifest's directory); this is the canonical display and
// the exact command the MCP fix_plan tool surfaces.
func (a UpgradeAction) Command() string {
	v := strings.TrimPrefix(a.To, "v")
	switch a.Ecosystem {
	case "go":
		return "go get " + a.Package + "@v" + v
	case "npm":
		return "npm install " + a.Package + "@" + v
	case "pypi":
		return "pip install '" + a.Package + ">=" + v + "'"
	case "rubygems":
		return "bundle update " + a.Package + " --conservative"
	case "cargo":
		return "cargo update -p " + a.Package + " --precise " + v
	case "composer":
		return "composer update " + a.Package
	case "nuget":
		return "dotnet add package " + a.Package + " --version " + v
	}
	return ""
}

// Options control planning.
type Options struct {
	// IncludeMajor allows upgrades that cross a major-version boundary. Off by
	// default, because a major bump can break the build and a security PR is the
	// wrong place to force one.
	IncludeMajor bool
}

// Plan is the result of planning upgrades over a finding set.
type Plan struct {
	// Actions are the upgrades to apply, one per package per manifest directory,
	// in discovery order.
	Actions []UpgradeAction
	// VulnCount is how many VULN-001 findings were considered.
	VulnCount int
	// Skipped counts findings dropped for missing metadata, an unsupported
	// ecosystem, or failing the upgrade-safety guard.
	Skipped int
	// MajorSkipped counts upgrades held back only because they cross a major
	// boundary and IncludeMajor was not set.
	MajorSkipped int
}

// PlanUpgrades decides which packages to move from a finding set. It is the one
// planner behind both `nox fix` and the MCP fix_plan tool, so the plan an agent
// is shown is exactly the plan the CLI would apply.
//
// The pipeline, in order — each step a rule that must hold identically on both
// surfaces:
//
//  1. Consider only VULN-001 findings with fixed_in, a package, and an
//     ecosystem nox can drive. Everything else is skipped, not faked.
//  2. Aggregate all advisories for a package IN ITS MANIFEST DIRECTORY before
//     deciding. One package with several fixed_in values yields one move, to the
//     highest fix (BestFix) — not several conflicting actions. Two workspaces on
//     the same vulnerable version are two distinct upgrades.
//  3. Refuse a move that is not a genuine forward upgrade (IsUpgrade): no
//     downgrades, no sideways moves, no stable-to-prerelease jumps.
//  4. Hold back a major-boundary bump unless IncludeMajor.
func PlanUpgrades(items []findings.Finding, opts Options) Plan {
	var plan Plan

	type candidate struct {
		ruleID    string
		from      string
		ecosystem string
		manifest  string
		pkg       string
		fixes     []string
	}
	order := []string{}
	byPkg := map[string]*candidate{}

	for i := range items {
		f := &items[i]
		if f.RuleID != fixRuleID {
			continue
		}
		plan.VulnCount++
		fixed := f.Metadata["fixed_in"]
		eco := f.Metadata["ecosystem"]
		pkg := f.Metadata["package"]
		from := f.Metadata["version"]
		if fixed == "" || pkg == "" {
			plan.Skipped++
			continue
		}
		if _, ok := ecosystemCommands[eco]; !ok {
			plan.Skipped++
			continue
		}
		// Keyed by directory as well as package: two workspaces on the same
		// vulnerable version are two upgrades, and collapsing them leaves one
		// vulnerable.
		key := filepath.Dir(f.Location.FilePath) + "|" + eco + ":" + pkg
		c, seen := byPkg[key]
		if !seen {
			c = &candidate{ruleID: f.RuleID, from: from, ecosystem: eco, manifest: f.Location.FilePath, pkg: pkg}
			byPkg[key] = c
			order = append(order, key)
		}
		c.fixes = append(c.fixes, fixed)
	}

	for _, key := range order {
		c := byPkg[key]
		target := BestFix(c.fixes)
		if target == "" {
			plan.Skipped++
			continue
		}
		if !IsUpgrade(c.from, target) {
			plan.Skipped++
			continue
		}
		if !opts.IncludeMajor && IsMajorBump(c.from, target) {
			plan.MajorSkipped++
			continue
		}
		plan.Actions = append(plan.Actions, UpgradeAction{
			RuleID:    c.ruleID,
			Package:   c.pkg,
			From:      c.from,
			To:        target,
			Ecosystem: c.ecosystem,
			Manifest:  c.manifest,
		})
	}
	return plan
}
