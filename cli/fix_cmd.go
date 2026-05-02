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
	)
	fs.StringVar(&inputPath, "input", "findings.json", "path to findings.json from a previous scan")
	fs.BoolVar(&dryRun, "dry-run", false, "print actions without applying them")
	fs.BoolVar(&includeMajor, "include-major", false, "apply upgrades that cross a major version boundary")
	fs.StringVar(&manifestRoot, "root", ".", "directory containing the project's manifest (go.mod)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

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
	for _, a := range plan.actions {
		if err := applyGoUpgrade(manifestRoot, a); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", a.pkg, err)
			failed++
			continue
		}
		fmt.Printf("applied: %s -> %s\n", a.pkg, a.toVersion)
	}

	if failed == 0 {
		if err := tidyGoMod(manifestRoot); err != nil {
			fmt.Fprintf(os.Stderr, "warn: go mod tidy failed: %v\n", err)
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

// planUpgrades extracts upgrade actions from VULN findings. Skips
// findings without fixed_in metadata, non-Go ecosystems (until follow-up),
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
		if eco != "go" {
			plan.skipped++
			continue
		}
		if !includeMajor && isMajorBump(from, fixed) {
			plan.majorSkipped++
			continue
		}
		key := pkg + "@" + fixed
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
			action:    "go get",
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

// applyGoUpgrade runs `go get pkg@vVERSION` in manifestRoot. Goreleaser /
// vendoring concerns are deferred to the follow-up `go mod tidy`.
func applyGoUpgrade(manifestRoot string, a upgradeAction) error {
	target := a.pkg + "@v" + strings.TrimPrefix(a.toVersion, "v")
	cmd := exec.Command("go", "get", target)
	cmd.Dir = manifestRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// tidyGoMod runs go mod tidy to clean up indirect dependencies after
// upgrades.
func tidyGoMod(manifestRoot string) error {
	if _, err := os.Stat(filepath.Join(manifestRoot, "go.mod")); err != nil {
		return nil
	}
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = manifestRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
