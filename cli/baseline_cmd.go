package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
)

func runBaseline(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox baseline <write|update|add|diff|show> [path]")
		return 2
	}

	subcommand := args[0]
	remaining := args[1:]

	switch subcommand {
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
	default:
		fmt.Fprintf(os.Stderr, "unknown baseline subcommand: %s\n", subcommand)
		fmt.Fprintln(os.Stderr, "Usage: nox baseline <write|update|add|diff|show> [path]")
		return 2
	}
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
// Filters:
//
//	--rule <id>   only add findings whose rule_id matches (repeatable
//	              by passing comma-separated values).
//	--fingerprint <fp>
//	              only add the entries whose fingerprint matches one
//	              of the supplied values (repeatable / comma list).
//	              Useful when piping fingerprints from `baseline diff`.
//
// When --fingerprint is set, no scan is run; the supplied fingerprints
// are added as bare entries with empty rule_id / file_path. The
// surgical-add path is the workflow nox-hq/nox#73 item 4 calls out:
// "add these specific fingerprints without rewriting the file".
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
// Exit status is always 0 unless the scan itself fails. The diff is
// informational.
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
	var prunes []baseline.Entry
	for fp, e := range existing {
		if _, ok := current[fp]; !ok {
			prunes = append(prunes, *e)
		}
	}

	fmt.Printf("baseline diff — %s vs scan of %s\n", baselinePath, target)
	fmt.Printf("  +%d would be added\n", len(adds))
	for i := range adds {
		fmt.Printf("    + %s %s:%d  %s\n", adds[i].RuleID, adds[i].Location.FilePath, adds[i].Location.StartLine, adds[i].Fingerprint[:12])
	}
	fmt.Printf("  -%d would be pruned\n", len(prunes))
	for i := range prunes {
		fmt.Printf("    - %s %s  %s\n", prunes[i].RuleID, prunes[i].FilePath, prunes[i].Fingerprint[:12])
	}
	if len(prunes) > 0 {
		fmt.Println()
		fmt.Println("Run `nox baseline update` to apply both changes,")
		fmt.Println("or `nox baseline add` to keep the prunes but pick up the adds.")
	}
	return 0
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range splitCommaTrim(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitCommaTrim(s string) []string {
	parts := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			parts = append(parts, trimSpace(s[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, trimSpace(s[start:]))
	return parts
}

func trimSpace(s string) string {
	a, b := 0, len(s)
	for a < b && (s[a] == ' ' || s[a] == '\t') {
		a++
	}
	for b > a && (s[b-1] == ' ' || s[b-1] == '\t') {
		b--
	}
	return s[a:b]
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

	fmt.Printf("baseline: %d entries (%d expired) — %s\n", bl.Len(), bl.ExpiredCount(), baselinePath)

	// Show per-severity counts.
	counts := make(map[string]int)
	for i := range bl.Entries {
		counts[string(bl.Entries[i].Severity)]++
	}
	for sev, count := range counts {
		fmt.Printf("  %s: %d\n", sev, count)
	}

	return 0
}
