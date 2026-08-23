package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
)

func runBaseline(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox baseline <init|write|update|add|diff|show|migrate> [path]")
		return 2
	}

	subcommand := args[0]
	remaining := args[1:]

	switch subcommand {
	case "init":
		return baselineInit(remaining)
	case "write":
		return baselineWrite(remaining)
	case "update":
		return baselineUpdate(remaining)
	case "add":
		return baselineAdd(remaining)
	case "diff":
		return baselineDiff(remaining)
	case "show":
		return baselineShow(remaining)
	case "migrate":
		return baselineMigrate(remaining)
	default:
		fmt.Fprintf(os.Stderr, "unknown baseline subcommand: %s\n", subcommand)
		fmt.Fprintln(os.Stderr, "Usage: nox baseline <init|write|update|add|diff|show|migrate> [path]")
		return 2
	}
}

// baselineMigrate re-fingerprints an existing baseline from one fingerprint
// version to another (default V1 → V2) IN PLACE, preserving each entry's
// reason / owner / created_at. It scans the target twice — once at the source
// version, once at the target — and matches findings by location to build an
// exact old→new fingerprint map, so no entry is dropped or duplicated by
// ambiguity. Entries whose finding no longer exists are reported and left
// untouched unless --prune is given. This is the upgrade path when the default
// fingerprint flips: existing V1 baselines keep working instead of silently
// un-suppressing on the first scan.
func baselineMigrate(args []string) int {
	fs := flag.NewFlagSet("baseline migrate", flag.ContinueOnError)
	var baselinePath string
	var fromV, toV int
	var prune bool
	fs.StringVar(&baselinePath, "baseline", "", "baseline file path (default: .nox/baseline.json)")
	fs.IntVar(&fromV, "from", 1, "source fingerprint version (1 or 2)")
	fs.IntVar(&toV, "to", 2, "target fingerprint version (1 or 2)")
	fs.BoolVar(&prune, "prune", false, "drop entries whose finding no longer exists instead of keeping them")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fromV == toV {
		fmt.Fprintln(os.Stderr, "error: --from and --to are the same version; nothing to migrate")
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(target)
	}

	bl, err := baseline.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
		return 2
	}
	if bl.Len() == 0 {
		fmt.Printf("baseline: empty — nothing to migrate (%s)\n", baselinePath)
		return 0
	}

	// locKey identifies a finding independent of fingerprint version, so the
	// same finding can be matched across the two scans.
	locKey := func(f *findings.Finding) string {
		l := f.Location
		return fmt.Sprintf("%s|%s|%d|%d|%d|%d", f.RuleID, l.FilePath, l.StartLine, l.EndLine, l.StartColumn, l.EndColumn)
	}

	scanAt := func(v findings.FingerprintVersion) (map[string]string, error) {
		prev := findings.GetFingerprintVersion()
		findings.SetFingerprintVersion(v)
		defer findings.SetFingerprintVersion(prev)
		result, err := nox.RunScan(target)
		if err != nil {
			return nil, err
		}
		m := make(map[string]string)
		ff := result.Findings.Findings()
		for i := range ff {
			m[locKey(&ff[i])] = ff[i].Fingerprint
		}
		return m, nil
	}

	oldByLoc, err := scanAt(findings.FingerprintVersion(fromV))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan at v%d failed: %v\n", fromV, err)
		return 2
	}
	newByLoc, err := scanAt(findings.FingerprintVersion(toV))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan at v%d failed: %v\n", toV, err)
		return 2
	}

	// Invert the old map: old-fingerprint → location, so a baseline entry
	// (which stores only the fingerprint) can be matched to its location and
	// then to the new fingerprint.
	locByOldFP := make(map[string]string, len(oldByLoc))
	for loc, fp := range oldByLoc {
		locByOldFP[fp] = loc
	}

	migrated, alreadyNew, unmatched := 0, 0, 0
	kept := bl.Entries[:0]
	for i := range bl.Entries {
		e := bl.Entries[i]
		if _, isNew := newByLocReverse(newByLoc, e.Fingerprint); isNew {
			alreadyNew++
			kept = append(kept, e)
			continue
		}
		loc, ok := locByOldFP[e.Fingerprint]
		if !ok {
			unmatched++
			fmt.Fprintf(os.Stderr, "  unmatched: %s %s (%s) — finding not found in current scan\n", e.RuleID, e.Fingerprint[:min(12, len(e.Fingerprint))], e.FilePath)
			if !prune {
				kept = append(kept, e)
			}
			continue
		}
		if newFP, ok := newByLoc[loc]; ok {
			e.Fingerprint = newFP
			migrated++
		}
		kept = append(kept, e)
	}
	bl.Entries = kept

	if err := bl.Save(baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving baseline: %v\n", err)
		return 2
	}

	fmt.Printf("baseline migrate v%d→v%d: %d migrated, %d already v%d, %d unmatched%s — %s\n",
		fromV, toV, migrated, alreadyNew, toV, unmatched, pruneNote(prune, unmatched), baselinePath)
	return 0
}

// newByLocReverse reports whether fp is one of the new-version fingerprints.
func newByLocReverse(newByLoc map[string]string, fp string) (string, bool) {
	for loc, v := range newByLoc {
		if v == fp {
			return loc, true
		}
	}
	return "", false
}

func pruneNote(prune bool, unmatched int) string {
	if prune && unmatched > 0 {
		return " (pruned)"
	}
	if unmatched > 0 {
		return " (kept; use --prune to drop)"
	}
	return ""
}

// baselineInit is the one-command adoption entry point for a repo with existing
// security debt: it scans, records every current finding as accepted baseline
// debt, and prints the "gate the change, not the history" policy to add. Unlike
// `write`, it refuses to clobber an existing baseline (use `update`), and it
// reports the debt by severity so the operator sees what they're accepting.
func baselineInit(args []string) int {
	fs := flag.NewFlagSet("baseline init", flag.ContinueOnError)
	var outputPath string
	var force bool
	fs.StringVar(&outputPath, "output", "", "baseline file path (default: .nox/baseline.json)")
	fs.BoolVar(&force, "force", false, "recreate the baseline even if one already exists")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	if outputPath == "" {
		outputPath = baseline.DefaultPath(target)
	}

	if !force {
		if _, err := os.Stat(outputPath); err == nil {
			fmt.Fprintf(os.Stderr, "baseline already exists at %s — use `nox baseline update` to refresh it, or `--force` to recreate.\n", outputPath)
			return 2
		}
	}

	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	ff := result.Findings.Findings()
	bl := &baseline.Baseline{}
	entries := baseline.FromFindings(ff)
	for i := range entries {
		bl.Add(&entries[i])
	}
	if err := bl.Save(outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing baseline: %v\n", err)
		return 2
	}

	counts := map[findings.Severity]int{}
	for i := range ff {
		counts[ff[i].Severity]++
	}
	fmt.Printf("baseline: recorded %d existing findings as accepted debt in %s\n", bl.Len(), outputPath)
	if bd := severityBreakdown(counts); bd != "" {
		fmt.Printf("  by severity: %s\n", bd)
	}
	fmt.Print(`
Next — gate the change, not the history. Add to .nox.yaml:

  policy:
    fail_on: high        # new high/critical findings fail the gate
    baseline_mode: warn  # the recorded debt above only warns, never fails

Commit the baseline so CI shares it. From now on, new findings gate; the
existing debt does not. Burn it down with ` + "`nox baseline update`" + ` as you fix.
`)
	return 0
}

// severityBreakdown formats per-severity counts in severity order, e.g.
// "2 critical, 11 high, 40 medium".
func severityBreakdown(counts map[findings.Severity]int) string {
	return findings.FormatSeverityCounts(counts)
}

func baselineWrite(args []string) int {
	fs := flag.NewFlagSet("baseline write", flag.ContinueOnError)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "baseline file path (default: .nox/baseline.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	if outputPath == "" {
		outputPath = baseline.DefaultPath(target)
	}

	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	ff := result.Findings.Findings()
	bl := &baseline.Baseline{}
	entries := baseline.FromFindings(ff)
	for i := range entries {
		bl.Add(&entries[i])
	}

	if err := bl.Save(outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing baseline: %v\n", err)
		return 2
	}

	fmt.Printf("baseline: wrote %d entries to %s\n", bl.Len(), outputPath)
	return 0
}

func baselineUpdate(args []string) int {
	fs := flag.NewFlagSet("baseline update", flag.ContinueOnError)
	var baselinePath string
	fs.StringVar(&baselinePath, "baseline", "", "baseline file path (default: .nox/baseline.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(target)
	}

	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	bl, err := baseline.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
		return 2
	}

	ff := result.Findings.Findings()

	// Add new findings not already in baseline.
	added := 0
	existing := make(map[string]struct{}, bl.Len())
	for i := range bl.Entries {
		existing[bl.Entries[i].Fingerprint] = struct{}{}
	}
	entries := baseline.FromFindings(ff)
	for i := range entries {
		if _, ok := existing[entries[i].Fingerprint]; !ok {
			bl.Add(&entries[i])
			existing[entries[i].Fingerprint] = struct{}{}
			added++
		}
	}

	// Prune stale entries.
	pruned := bl.Prune(ff)

	if err := bl.Save(baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving baseline: %v\n", err)
		return 2
	}

	fmt.Printf("baseline: %d total, %d added, %d pruned — %s\n", bl.Len(), added, pruned, baselinePath)
	return 0
}

// baselineAdd is the additive counterpart to `baseline update`: it
// scans the target, inserts findings that don't yet appear in the
// baseline, and EXITS WITHOUT pruning entries that no longer match.
//
// Use case: a new finding pops up on a branch (rule sharpened, scanner
// version bumped, file shifted) that the operator wants to baseline
// without losing entries that happen to be missing from this scan.
// `baseline update` would prune those — `baseline add` won't touch them.
//
// Filters (each accepts a comma-separated list of values):
//
//	--rule <id,id,…>          only add findings whose rule_id is in the set.
//	--fingerprint <fp,fp,…>   add these exact fingerprints. Bypasses the
//	                          scan entirely; entries get empty rule_id /
//	                          file_path until an editor fills them in.
//
// The --fingerprint path is the workflow nox-hq/nox#73 item 4 calls
// out: "add these specific fingerprints without rewriting the file".
func baselineAdd(args []string) int {
	fs := flag.NewFlagSet("baseline add", flag.ContinueOnError)
	var (
		baselinePath string
		ruleFilter   string
		fpFilter     string
		reason       string
		owner        string
	)
	fs.StringVar(&baselinePath, "baseline", "", "baseline file path (default: .nox/baseline.json)")
	fs.StringVar(&ruleFilter, "rule", "", "only add findings with these rule IDs (comma-separated)")
	fs.StringVar(&fpFilter, "fingerprint", "", "add these specific fingerprints (comma-separated; skips the scan)")
	fs.StringVar(&reason, "reason", "", "free-form rationale stored on each new entry")
	fs.StringVar(&owner, "owner", "", "owner/team tag stored on each new entry")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(target)
	}

	bl, err := baseline.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
		return 2
	}

	existing := make(map[string]struct{}, bl.Len())
	for i := range bl.Entries {
		existing[bl.Entries[i].Fingerprint] = struct{}{}
	}

	added := 0
	if fpFilter != "" {
		// Surgical: no scan, no rule-id filter — just the explicit
		// fingerprints. RuleID/FilePath stay empty (the operator can
		// fill them in later via an editor).
		for _, fp := range splitCSV(fpFilter) {
			if _, ok := existing[fp]; ok {
				continue
			}
			bl.Add(&baseline.Entry{
				Fingerprint: fp,
				CreatedAt:   time.Now().UTC(),
				Reason:      reason,
				Owner:       owner,
			})
			existing[fp] = struct{}{}
			added++
		}
	} else {
		// Scan + additive merge.
		result, err := nox.RunScan(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
			return 2
		}
		ruleAllow := buildSet(splitCSV(ruleFilter))
		ff := result.Findings.Findings()
		entries := baseline.FromFindings(ff)
		for i := range entries {
			if _, ok := existing[entries[i].Fingerprint]; ok {
				continue
			}
			if len(ruleAllow) > 0 {
				if _, ok := ruleAllow[entries[i].RuleID]; !ok {
					continue
				}
			}
			e := entries[i]
			if reason != "" {
				e.Reason = reason
			}
			if owner != "" {
				e.Owner = owner
			}
			bl.Add(&e)
			existing[e.Fingerprint] = struct{}{}
			added++
		}
	}

	if err := bl.Save(baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving baseline: %v\n", err)
		return 2
	}
	fmt.Printf("baseline: %d total, %d added (no entries pruned) — %s\n", bl.Len(), added, baselinePath)
	return 0
}

// baselineDiff reports what `baseline update` WOULD change against the
// current scan, without touching the file. Lists adds and prunes
// separately so the operator can decide whether the prune is real
// (finding genuinely resolved) or a regression (rule sharpened, file
// renamed, fingerprint algorithm bumped).
//
// The diff is informational: a non-zero exit code is reserved for the
// usual hard failures (flag-parse, baseline-load, scan errors). A
// "diff that shows differences" is itself success.
func baselineDiff(args []string) int {
	fs := flag.NewFlagSet("baseline diff", flag.ContinueOnError)
	var baselinePath string
	fs.StringVar(&baselinePath, "baseline", "", "baseline file path (default: .nox/baseline.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(target)
	}

	bl, err := baseline.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
		return 2
	}

	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}
	ff := result.Findings.Findings()

	current := make(map[string]struct{}, len(ff))
	for i := range ff {
		current[ff[i].Fingerprint] = struct{}{}
	}
	existing := make(map[string]*baseline.Entry, bl.Len())
	for i := range bl.Entries {
		existing[bl.Entries[i].Fingerprint] = &bl.Entries[i]
	}

	// Adds: findings present in the scan but not in baseline.
	var adds []findings.Finding
	for i := range ff {
		if _, ok := existing[ff[i].Fingerprint]; !ok {
			adds = append(adds, ff[i])
		}
	}
	// Prunes: baseline entries no longer matched by any current finding.
	// Map iteration order is random in Go; sort for stable diff output
	// so subsequent runs against the same baseline produce the same
	// terminal output (helpful for piping to git diff or grep).
	var prunes []baseline.Entry
	for fp, e := range existing {
		if _, ok := current[fp]; !ok {
			prunes = append(prunes, *e)
		}
	}
	sort.Slice(adds, func(i, j int) bool {
		return adds[i].Fingerprint < adds[j].Fingerprint
	})
	sort.Slice(prunes, func(i, j int) bool {
		return prunes[i].Fingerprint < prunes[j].Fingerprint
	})

	fmt.Printf("baseline diff — %s vs scan of %s\n", baselinePath, target)
	fmt.Printf("  +%d would be added\n", len(adds))
	for i := range adds {
		fmt.Printf("    + %s %s:%d  %s\n", adds[i].RuleID, adds[i].Location.FilePath, adds[i].Location.StartLine, shortFP(adds[i].Fingerprint))
	}
	fmt.Printf("  -%d would be pruned\n", len(prunes))
	for i := range prunes {
		fmt.Printf("    - %s %s  %s\n", prunes[i].RuleID, prunes[i].FilePath, shortFP(prunes[i].Fingerprint))
	}
	if len(adds) > 0 || len(prunes) > 0 {
		fmt.Println()
		fmt.Println("Run `nox baseline update` to apply both adds and prunes,")
		fmt.Println("or `nox baseline add` to insert the adds without pruning.")
	}
	return 0
}

// shortFP returns the leading 12 hex chars of fp, or the whole string
// if it's shorter (caller-supplied / user-typed fingerprints can be
// arbitrary lengths). Avoids the panic that a fixed `fp[:12]` slice
// would cause on short inputs.
func shortFP(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12]
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func buildSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}

func baselineShow(args []string) int {
	fs := flag.NewFlagSet("baseline show", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	baselinePath := baseline.DefaultPath(target)
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
		return 2
	}

	if bl.Len() == 0 {
		fmt.Printf("baseline: no entries in %s\n", baselinePath)
		return 0
	}

	st := bl.Status()
	fmt.Printf("baseline: %d entries (%d expired) — %s\n", st.Total, st.Expired, baselinePath)

	// Per-severity counts, in canonical severity order (the old loop iterated a
	// map non-deterministically).
	for _, sev := range findings.SeverityOrder {
		if n := st.BySeverity[sev]; n > 0 {
			fmt.Printf("  %s: %d\n", sev, n)
		}
	}

	return 0
}
