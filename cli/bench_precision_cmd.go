package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/bench"
	"github.com/nox-hq/nox/core/findings"
)

// hasFlag reports whether args contains the named flag in any accepted form
// (-name, --name, -name=..., --name=...). Used to route `nox bench --precision`
// before the fire-rate flag set parses, so the two modes never share a flag
// namespace.
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		trimmed := strings.TrimLeft(a, "-")
		if trimmed == name || strings.HasPrefix(trimmed, name+"=") {
			return true
		}
	}
	return false
}

// runBenchPrecision scores a labeled corpus for SAST precision/recall/F1.
//
// It scans the corpus offline (the corpus is ground truth, not a live target —
// determinism matters more than dependency lookups), parses the inline
// `nox-expect` annotations into expectations, and hands both to the pure
// bench.Score function. The table is sorted worst-precision-first so the rules
// most in need of attention are impossible to miss. With --min-precision set,
// any rule that scored (TP+FP > 0) below the threshold makes the command exit
// non-zero, turning the harness into a CI gate against precision regressions.
func runBenchPrecision(args []string) int {
	fs := flag.NewFlagSet("bench --precision", flag.ContinueOnError)
	var (
		corpusDir    string
		jsonOut      bool
		minPrecision float64
	)
	fs.StringVar(&corpusDir, "precision", "", "path to a labeled precision corpus (directory of samples with inline nox-expect annotations)")
	fs.BoolVar(&jsonOut, "json", false, "emit the report as JSON instead of a table")
	fs.Float64Var(&minPrecision, "min-precision", -1, "fail (exit 1) if any rule that fired scores below this precision (0..1); default off")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Allow `nox bench --precision <dir>` (positional) as well as
	// `--precision=<dir>`: if the flag consumed nothing, take the first
	// positional argument.
	if corpusDir == "" {
		if fs.NArg() > 0 {
			corpusDir = fs.Arg(0)
		} else {
			fmt.Fprintln(os.Stderr, "usage: nox bench --precision <corpus-dir> [--json] [--min-precision F]")
			return 2
		}
	}

	expectations, err := bench.ParseCorpus(corpusDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing corpus: %v\n", err)
		return 2
	}

	scanFindings, err := scanCorpusFindings(corpusDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scanning corpus: %v\n", err)
		return 2
	}

	report := bench.Score(scanFindings, expectations)

	if jsonOut {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: marshalling report: %v\n", err)
			return 2
		}
		fmt.Println(string(out))
	} else {
		fmt.Print(renderPrecisionTable(corpusDir, &report))
	}

	if minPrecision >= 0 {
		if failed := rulesBelowPrecision(&report, minPrecision); len(failed) > 0 {
			fmt.Fprintf(os.Stderr, "\nprecision gate FAILED: %s below --min-precision %.2f\n",
				strings.Join(failed, ", "), minPrecision)
			return 1
		}
	}
	return 0
}

// scanCorpusFindings runs an offline scan over the corpus and returns its
// findings with file paths made relative to the corpus root, so they line up
// with the corpus-relative paths ParseCorpus produces. Scanning offline keeps
// the score reproducible: no network, no OSV lookups, no LLM.
func scanCorpusFindings(corpusDir string) ([]findings.Finding, error) {
	result, err := nox.RunScanWithOptions(corpusDir, nox.ScanOptions{Offline: true})
	if err != nil {
		return nil, err
	}
	all := result.Findings.Findings()
	out := make([]findings.Finding, 0, len(all))
	for i := range all {
		f := all[i]
		f.Location.FilePath = relToCorpus(corpusDir, f.Location.FilePath)
		out = append(out, f)
	}
	return out, nil
}

// relToCorpus normalises a finding path to be relative to the corpus root.
// Scan findings may carry absolute or corpus-relative paths depending on how
// the analyzer recorded them; normalising both sides to corpus-relative slash
// paths lets the scorer compare them directly.
func relToCorpus(corpusDir, path string) string {
	if rel, err := filepath.Rel(corpusDir, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

// rulesBelowPrecision returns the IDs of rules that actually fired (TP+FP > 0)
// and scored below threshold. Rules that never fired are exempt: they have no
// false positives to penalise, and gating on them would fail CI for rules a
// corpus simply doesn't exercise.
func rulesBelowPrecision(report *bench.Report, threshold float64) []string {
	var failed []string
	for i := range report.Rules {
		r := &report.Rules[i]
		if r.TP+r.FP == 0 {
			continue
		}
		if r.Precision() < threshold {
			failed = append(failed, r.RuleID)
		}
	}
	sort.Strings(failed)
	return failed
}

// renderPrecisionTable formats the per-rule metrics (worst precision first) and
// the overall roll-up as an aligned text table. It returns the rendered text so
// the caller owns the single Print — building into a strings.Builder keeps this
// pure and sidesteps unhandled-write errors from writing straight to a file.
func renderPrecisionTable(corpusDir string, report *bench.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Precision/recall for corpus %s\n\n", corpusDir)

	tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "RULE\tTP\tFP\tFN\tPRECISION\tRECALL\tF1")
	for i := range report.Rules {
		r := &report.Rules[i]
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\n",
			r.RuleID, r.TP, r.FP, r.FN, r.Precision(), r.Recall(), r.F1())
	}
	_, _ = fmt.Fprintln(tw, "\t\t\t\t\t\t")
	o := &report.Overall
	_, _ = fmt.Fprintf(tw, "OVERALL\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\n",
		o.TP, o.FP, o.FN, o.Precision(), o.Recall(), o.F1())
	_ = tw.Flush() //nolint:errcheck // strings.Builder never errors on write
	return b.String()
}
