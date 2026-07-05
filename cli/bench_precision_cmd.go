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
		baselineFile string
	)
	fs.StringVar(&corpusDir, "precision", "", "path to a labeled precision corpus (directory of samples with inline nox-expect annotations)")
	fs.BoolVar(&jsonOut, "json", false, "emit the report as JSON instead of a table")
	fs.Float64Var(&minPrecision, "min-precision", -1, "fail (exit 1) if any rule that fired scores below this precision (0..1); default off")
	fs.StringVar(&baselineFile, "baseline", "", "snapshot file: written if absent, else compared (exit 1 on regression)")
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

	if baselineFile != "" {
		if code := runBaselineGate(baselineFile, &report); code != 0 {
			return code
		}
	}
	return 0
}

// runBaselineGate implements the ratchet. When the snapshot file is absent it
// writes the current metrics and returns success (bootstrapping a new baseline).
// When present it compares and returns non-zero on any regression, printing a
// clear diff of what moved the wrong way. A legitimate improvement passes but
// prints a hint to refresh the snapshot so the ratchet keeps tightening.
func runBaselineGate(path string, report *bench.Report) int {
	current := bench.BaselineFromReport(report)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if writeErr := writeBaseline(path, current); writeErr != nil {
			fmt.Fprintf(os.Stderr, "error: writing baseline %s: %v\n", path, writeErr)
			return 2
		}
		fmt.Fprintf(os.Stderr, "baseline written: %s (precision %.3f, recall %.3f, F1 %.3f, FP %d, findings/issue %.2f)\n",
			path, current.Precision, current.Recall, current.F1, current.FP, current.FindingsPerIssue)
		return 0
	}

	base, err := readBaseline(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading baseline %s: %v\n", path, err)
		return 2
	}

	if regressions := bench.CompareBaseline(base, current); len(regressions) > 0 {
		fmt.Fprintf(os.Stderr, "\nbaseline gate FAILED: %d metric(s) regressed vs %s\n", len(regressions), path)
		for i := range regressions {
			fmt.Fprintf(os.Stderr, "  %s\n", regressions[i].String())
		}
		fmt.Fprintln(os.Stderr, "fix the regression, or if this change is intended, refresh the baseline by deleting it and re-running.")
		return 1
	}

	if bench.Improved(base, current) {
		fmt.Fprintf(os.Stderr, "\nbaseline PASSED and improved: precision %.3f->%.3f, FP %d->%d, findings/issue %.2f->%.2f\n",
			base.Precision, current.Precision, base.FP, current.FP, base.FindingsPerIssue, current.FindingsPerIssue)
		fmt.Fprintln(os.Stderr, "refresh the baseline (delete and re-run, or commit the new snapshot) to lock in the gain.")
	}
	return 0
}

// writeBaseline serialises a baseline snapshot as indented JSON with a trailing
// newline so the committed file is diff-friendly.
func writeBaseline(path string, b bench.Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644) //nolint:gosec // a metrics snapshot is not sensitive
}

// readBaseline loads and parses a baseline snapshot file.
func readBaseline(path string) (bench.Baseline, error) {
	var b bench.Baseline
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path, not user input
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, err
	}
	return b, nil
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
		// Drop findings on documentation files. ParseCorpus never gathers
		// expectations from docs (the suite README explains the annotation
		// format and contains example rule IDs), so a finding on a doc file has
		// no expectation to match and would score as a false positive purely
		// because the scanner read the README. Both sides must treat docs the
		// same way for the score to be honest.
		if bench.IsNonSample(f.Location.FilePath) {
			continue
		}
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

	renderFamilyTable(&b, report)
	renderDensityTable(&b, report)
	return b.String()
}

// renderFamilyTable prints the per-family roll-up (worst precision first) so a
// human sees "the SEC family is the precision drag" without scanning twenty
// individual rows. Only shown when more than one family is present, otherwise it
// is redundant with the per-rule table.
func renderFamilyTable(b *strings.Builder, report *bench.Report) {
	if len(report.Families) <= 1 {
		return
	}
	fmt.Fprintf(b, "\nBy rule family (worst precision first)\n\n")
	tw := tabwriter.NewWriter(b, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "FAMILY\tTP\tFP\tFN\tPRECISION\tRECALL\tF1")
	for i := range report.Families {
		f := &report.Families[i]
		_, _ = fmt.Fprintf(tw, "%s-*\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\n",
			f.Family, f.TP, f.FP, f.FN, f.Precision(), f.Recall(), f.F1())
	}
	_ = tw.Flush() //nolint:errcheck // strings.Builder never errors on write
}

// renderDensityTable prints the over-firing view: the headline findings-per-issue
// and noise-ratio numbers, then a per-file table sorted worst-noise-first so the
// loudest samples (clean files with FPs, then most-inflated issues) sit at the
// top. This is the metric per-rule precision cannot show.
func renderDensityTable(b *strings.Builder, report *bench.Report) {
	d := &report.Density
	fmt.Fprintf(b, "\nOver-firing / finding density\n")
	fmt.Fprintf(b, "  findings-per-issue: %.2f  (%d findings across %d annotated issues; 1.00 is ideal)\n",
		d.FindingsPerIssue(), d.FindingsAtIssues, d.TotalIssues)
	fmt.Fprintf(b, "  noise ratio:        %.2f  (%d of %d total findings were false positives)\n\n",
		d.NoiseRatio(), d.FP, d.TotalFindings)

	tw := tabwriter.NewWriter(b, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "FILE\tKIND\tISSUES\tFINDINGS\tDENSITY\tFP")
	for i := range d.Files {
		f := &d.Files[i]
		kind := "tp"
		density := fmt.Sprintf("%.2f", f.Density())
		if f.Clean {
			kind = "clean"
			density = "-" // density is undefined for a file with no issues
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%d\n",
			f.FilePath, kind, f.Issues, f.Findings, density, f.FP)
	}
	_ = tw.Flush() //nolint:errcheck // strings.Builder never errors on write
}
