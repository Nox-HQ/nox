package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
	"github.com/nox-hq/nox/core/remediate"
)

// fixSubcommands are the plan / apply / verify halves of `nox fix`. Anything
// else is the original flag-driven `nox fix`, unchanged, because a CI workflow
// calls it and a changed default there would apply or stop applying upgrades
// that nobody reviewed.
var fixSubcommands = map[string]bool{"plan": true, "apply": true, "verify": true}

// fixSubOptions are the flags the three subcommands share.
type fixSubOptions struct {
	input         string
	root          string
	format        string
	includeMajor  bool
	includeReview bool
	offline       bool
	noVerify      bool
}

// runFixSub answers "can you fix these?".
//
// plan shows what nox can change and what it cannot, and writes nothing.
// apply makes the changes that need no decision (and, when asked, the ones
// that need a look), then runs the checks again. verify runs the checks again
// over a tree someone changed by hand.
func runFixSub(mode string, args []string) int {
	fs := flag.NewFlagSet("fix "+mode, flag.ContinueOnError)
	var o fixSubOptions
	fs.StringVar(&o.input, "input", "findings.json", "path to findings.json from a previous scan")
	fs.StringVar(&o.root, "root", ".", "the directory that was scanned (finding paths are relative to it)")
	fs.StringVar(&o.format, "format", "text", "output format: text or json")
	fs.BoolVar(&o.offline, "offline", false, "re-run checks without any network call (dependency vulnerabilities then cannot be re-checked, and are reported as not verified)")
	if mode == "apply" {
		fs.BoolVar(&o.includeMajor, "include-major", false, "also apply upgrades that cross a major version")
		fs.BoolVar(&o.includeReview, "include-review", false, "also apply every change that needs review (major upgrades and settings changes)")
		fs.BoolVar(&o.noVerify, "no-verify", false, "do not re-run the checks afterwards (the changes are then unverified)")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if o.format != "text" && o.format != "json" {
		fmt.Fprintf(os.Stderr, "error: --format must be text or json, got %q\n", o.format)
		return 2
	}
	active, err := readActiveFindings(o.input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if mode == "verify" {
		// Verify checks changes already made, so it cannot ask the files for the
		// lines a patch would change: they are the lines that were changed. The
		// plan is built from the findings alone, and each item's class follows
		// from its rule.
		return runVerifySub(remediate.Build(remediate.Input{Findings: active}), active, o)
	}
	plan := remediate.Build(remediate.Input{Findings: active, Root: o.root, Targets: targetChecker(o.offline)})
	if mode == "plan" {
		return printPlan(plan, o.format)
	}
	return runApplySub(plan, active, o)
}

func readActiveFindings(path string) ([]findings.Finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w (run nox scan --format json first, or pass --input)", path, err)
	}
	var doc struct {
		Findings []findings.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	var active []findings.Finding
	for i := range doc.Findings {
		if doc.Findings[i].Status.IsActive() {
			active = append(active, doc.Findings[i])
		}
	}
	return active, nil
}

func printPlan(plan remediate.Plan, format string) int {
	if format == "json" {
		if err := remediate.WritePlanJSON(os.Stdout, plan); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		return 0
	}
	if err := remediate.RenderPlan(os.Stdout, plan); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	return 0
}

// selected says whether apply makes an item's change. The safe set always; the
// rest only when the person asked for them.
func selected(it *remediate.Item, o fixSubOptions) bool {
	if it.Kind == remediate.KindHeldUpgrade {
		// A parent's range excludes the fix; nox has no change to make. The
		// plan item names the parent and the entry that would force it.
		return false
	}
	switch it.Class {
	case remediate.ClassSafe:
		return true
	case remediate.ClassReview:
		return o.includeReview || (o.includeMajor && it.Kind == remediate.KindMajorUpgrade)
	}
	return false
}

// applyResult is the JSON form of an apply run.
type applyResult struct {
	Plan     remediate.Plan    `json:"plan"`
	Attempts []applyAttempt    `json:"attempts"`
	Report   *remediate.Report `json:"report,omitempty"`
}

type applyAttempt struct {
	N       int    `json:"n"`
	Applied bool   `json:"applied"`
	Error   string `json:"error,omitempty"`
}

func runApplySub(plan remediate.Plan, active []findings.Finding, o fixSubOptions) int {
	asJSON := o.format == "json"
	restore := func() {}
	if asJSON {
		// Package managers write to stdout; keep it a single JSON document.
		saved := os.Stdout
		os.Stdout = os.Stderr
		restore = func() { os.Stdout = saved }
	}
	defer restore()

	var chosen []*remediate.Item
	for i := range plan.Items {
		if selected(&plan.Items[i], o) {
			chosen = append(chosen, &plan.Items[i])
		}
	}
	if len(chosen) == 0 {
		restore()
		if !asJSON {
			_ = remediate.RenderPlan(os.Stdout, plan)
			fmt.Println("\nNothing to apply: no change in the plan is both possible and permitted by the flags given.")
		} else {
			writeApplyJSON(applyResult{Plan: plan, Attempts: []applyAttempt{}})
		}
		return 0
	}

	var attempts []remediate.Attempt
	tidy := map[[2]string]bool{}
	for _, it := range chosen {
		fmt.Printf("applying %d. %s\n", it.N, it.Title)
		err := applyItem(it, o, tidy)
		a := remediate.Attempt{N: it.N, Applied: err == nil}
		if err != nil {
			a.Error = err.Error()
			fmt.Fprintf(os.Stderr, "  not applied: %v\n", err)
		}
		attempts = append(attempts, a)
	}
	for key := range tidy {
		if err := tidyEco(key[0], key[1]); err != nil {
			fmt.Fprintf(os.Stderr, "warn: %s tidy failed: %v\n", key[1], err)
		}
	}

	var report *remediate.Report
	if !o.noVerify {
		r := remediate.Verify(context.Background(), plan, active, attempts, remediate.CoreRescanner(o.root, o.offline))
		report = &r
	}
	restore()
	return finishApply(plan, attempts, report, o)
}

func finishApply(plan remediate.Plan, attempts []remediate.Attempt, report *remediate.Report, o fixSubOptions) int {
	switch {
	case o.format == "json":
		res := applyResult{Plan: plan, Report: report, Attempts: []applyAttempt{}}
		for _, a := range attempts {
			res.Attempts = append(res.Attempts, applyAttempt{N: a.N, Applied: a.Applied, Error: a.Error})
		}
		writeApplyJSON(res)
	case report != nil:
		_ = remediate.RenderReport(os.Stdout, *report)
	default:
		fmt.Printf("\nApplied %d change(s). They were not verified (--no-verify): run nox fix verify.\n", countApplied(attempts))
	}
	if report == nil {
		for _, a := range attempts {
			if !a.Applied {
				return 1
			}
		}
		return 0
	}
	return reportExit(*report)
}

func countApplied(as []remediate.Attempt) int {
	n := 0
	for _, a := range as {
		if a.Applied {
			n++
		}
	}
	return n
}

func writeApplyJSON(r applyResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

// reportExit is non-zero unless every change was observed to work. A check
// that could not run is not a pass, so it fails the run too: a CI step reading
// the exit code must not see success it was never shown.
func reportExit(r remediate.Report) int {
	c := r.Counts
	if c.StillPresent+c.NewFinding+c.NotVerified+c.NotApplied > 0 {
		return 1
	}
	return 0
}

func runVerifySub(plan remediate.Plan, active []findings.Finding, o fixSubOptions) int {
	var attempts []remediate.Attempt
	for i := range plan.Items {
		if plan.Items[i].Actionable() {
			attempts = append(attempts, remediate.Attempt{N: plan.Items[i].N, Applied: true})
		}
	}
	r := remediate.Verify(context.Background(), plan, active, attempts, remediate.CoreRescanner(o.root, o.offline))
	if o.format == "json" {
		if err := remediate.WriteReportJSON(os.Stdout, r); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	} else {
		_ = remediate.RenderReport(os.Stdout, r)
	}
	return reportExit(r)
}

// applyItem makes one planned change. It returns nil only when the change was
// made; whether it worked is Verify's question, not this one's.
func applyItem(it *remediate.Item, o fixSubOptions, tidy map[[2]string]bool) error {
	switch it.Kind {
	case remediate.KindUpgrade, remediate.KindMajorUpgrade:
		return applyUpgradeItem(it.Upgrade, o.root, tidy)
	case remediate.KindActionsPin:
		applied, _, failed := runActionsFix(o.root, false, false, newGithubResolver())
		switch {
		case failed > 0:
			return fmt.Errorf("%d pin(s) could not be rewritten", failed)
		case applied == 0:
			return errors.New("no pin was changed (each is already pinned, kept on its tag on purpose, or could not be looked up; set GITHUB_TOKEN if GitHub rate-limited the lookup)")
		}
		return nil
	case remediate.KindContentPatch:
		return applyPatches(it.Patches, o.root)
	}
	return fmt.Errorf("nox cannot apply a %s change", it.Kind)
}

func applyUpgradeItem(up *fix.UpgradeAction, root string, tidy map[[2]string]bool) error {
	base, _ := fix.SupportedEcosystem(up.Ecosystem)
	a := upgradeAction{
		ruleID: up.RuleID, pkg: up.Package, fromVer: up.From, toVersion: up.To,
		ecosystem: up.Ecosystem, action: base, manifest: up.Manifest,
	}
	dir, err := workdirFor(root, a)
	if err != nil {
		return err
	}
	res, err := applyChecked(dir, a)
	if err != nil {
		return err
	}
	if res == upgradeApplied {
		tidy[[2]string{dir, a.ecosystem}] = true
	}
	return nil
}

// applyPatches writes each file's patches once. A patch recomputes from the
// live line, so one the file no longer matches is skipped and reported rather
// than written from a stale plan.
func applyPatches(patches []fix.Patch, root string) error {
	byFile := map[string][]fix.Patch{}
	for _, p := range patches {
		byFile[p.File] = append(byFile[p.File], p)
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)
	var stale []string
	for _, file := range files {
		full := file
		if !filepath.IsAbs(file) {
			full = filepath.Join(root, file)
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		lines := strings.Split(string(data), "\n")
		changed := false
		for _, p := range byFile[file] {
			if p.Apply(lines) {
				changed = true
				fmt.Printf("  %s:%d  %s\n", file, p.Line, p.Summary)
			} else {
				stale = append(stale, fmt.Sprintf("%s:%d", file, p.Line))
			}
		}
		if changed {
			if err := writeFileKeepingMode(full, strings.Join(lines, "\n")); err != nil {
				return err
			}
		}
	}
	if len(stale) > 0 {
		return fmt.Errorf("the line no longer matches at %s; run nox scan again", strings.Join(stale, ", "))
	}
	return nil
}

func writeFileKeepingMode(path, content string) error {
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	return os.WriteFile(path, []byte(content), mode)
}
