package bench

import (
	"sort"

	"github.com/nox-hq/nox/core/findings"
)

// Over-firing is the blind spot that per-rule precision/recall cannot see. A
// single GitHub token can trip six or seven overlapping secret rules; per-rule
// scoring calls each of those a true positive (the token IS a secret) and so
// reports the location as "fine". But to a human triager, one issue that
// produces seven findings is six units of noise — a precision and UX problem
// the confusion matrix never surfaces because it counts findings, not issues.
//
// The density metrics below re-slice the same findings by *issue* (an annotated
// expectation location) rather than by rule, so over-firing becomes a first
// class, measurable number: findings-per-issue. A value of 1.0 is ideal (one
// finding per real issue); 7.0 means the scanner emitted seven findings where a
// human needed one.

// FileDensity summarises how many findings landed on one corpus file relative
// to how many issues that file actually contains, plus its false-positive load.
// It is the per-file unit the CLI groups and ranks by.
type FileDensity struct {
	// FilePath is the corpus-relative path of the sample.
	FilePath string `json:"file_path"`
	// Clean reports whether the file carries no expectations at all. Every
	// finding on a clean file is by definition a false positive, so a clean file
	// with findings is a pure noise source and should sort to the top.
	Clean bool `json:"clean"`
	// Issues is the number of distinct annotated expectation locations on the
	// file (deduplicated by line — several rules expected on one line is still
	// one issue for density purposes, because it is one thing a human looks at).
	Issues int `json:"issues"`
	// Findings is the total number of scan findings that landed on the file.
	Findings int `json:"findings"`
	// FindingsAtIssues is the number of findings that landed on a line that
	// carries at least one expectation. Used with Issues to compute the
	// inflation factor at real issues (excludes findings on clean lines, which
	// are noise of a different kind — FPs away from any real issue).
	FindingsAtIssues int `json:"findings_at_issues"`
	// FP is the number of false positives on this file (findings with no
	// matching expectation, including duplicates on an already-satisfied issue).
	FP int `json:"fp"`
}

// Density is the inflation factor at real issues: findings landing on annotated
// lines divided by the number of annotated issues. 1.0 is ideal. A clean file
// has no issues, so its density is 0 by convention (its noise is measured by FP,
// not by inflation) — callers rank clean files by FP instead.
func (d *FileDensity) Density() float64 {
	if d.Issues == 0 {
		return 0
	}
	return float64(d.FindingsAtIssues) / float64(d.Issues)
}

// DensityReport is the over-firing roll-up: per-file density plus corpus-wide
// summary numbers. It is embedded in Report so JSON and table consumers get the
// over-firing story alongside precision/recall.
type DensityReport struct {
	// Files is every scored file, sorted worst-first: clean files with the most
	// false positives first, then annotated files by highest density. This puts
	// the loudest noise sources at the top of the report.
	Files []FileDensity `json:"files"`
	// TotalFindings is every finding the scan produced across the corpus.
	TotalFindings int `json:"total_findings"`
	// TotalIssues is the number of distinct annotated issue locations across the
	// corpus (deduplicated by file+line).
	TotalIssues int `json:"total_issues"`
	// FindingsAtIssues is the corpus-wide count of findings landing on annotated
	// lines. FindingsPerIssue = FindingsAtIssues / TotalIssues is the headline
	// over-firing number.
	FindingsAtIssues int `json:"findings_at_issues"`
	// FP is the corpus-wide false-positive count (matches Report.Overall.FP).
	FP int `json:"fp"`
}

// FindingsPerIssue is the headline over-firing metric: across every annotated
// issue in the corpus, the average number of findings emitted at that issue's
// location. 1.0 means one finding per real issue (ideal); higher means the
// scanner inflates real issues into duplicate noise. With no issues it is 0.
func (d *DensityReport) FindingsPerIssue() float64 {
	if d.TotalIssues == 0 {
		return 0
	}
	return float64(d.FindingsAtIssues) / float64(d.TotalIssues)
}

// NoiseRatio is FP / total findings: the fraction of all findings that were
// false positives. It is the complement of the corpus-wide precision but
// computed over raw finding volume (including duplicates on real issues), so it
// answers "what share of everything the scanner emitted was noise?". With no
// findings it is 0.
func (d *DensityReport) NoiseRatio() float64 {
	if d.TotalFindings == 0 {
		return 0
	}
	return float64(d.FP) / float64(d.TotalFindings)
}

// scoreDensity computes the over-firing / density roll-up from the same inputs
// Score consumes. It is pure: no I/O, no mutation of its arguments.
//
// issueFP maps a file path to the number of false positives Score attributed to
// that file; Score computes it as a side product and passes it in so the two
// views (per-rule and per-file) can never disagree on the FP total.
func scoreDensity(scanFindings []findings.Finding, expectations []Expectation, fileFP map[string]int) DensityReport {
	// Distinct issue locations per file (deduplicated by line: several rules on
	// one line is one issue for density purposes).
	issueLines := map[string]map[int]struct{}{}
	for _, e := range expectations {
		if issueLines[e.FilePath] == nil {
			issueLines[e.FilePath] = map[int]struct{}{}
		}
		issueLines[e.FilePath][e.Line] = struct{}{}
	}

	// Every file that appears in either findings or expectations gets a row.
	findingsPerFile := map[string]int{}
	findingsAtIssuesPerFile := map[string]int{}
	files := map[string]struct{}{}
	for path := range issueLines {
		files[path] = struct{}{}
	}
	for i := range scanFindings {
		loc := scanFindings[i].Location.Normalized()
		path := loc.FilePath
		files[path] = struct{}{}
		findingsPerFile[path]++
		if lineOnAnIssue(loc, issueLines[path]) {
			findingsAtIssuesPerFile[path]++
		}
	}

	report := DensityReport{}
	for path := range files {
		lines := issueLines[path]
		fd := FileDensity{
			FilePath:         path,
			Clean:            len(lines) == 0,
			Issues:           len(lines),
			Findings:         findingsPerFile[path],
			FindingsAtIssues: findingsAtIssuesPerFile[path],
			FP:               fileFP[path],
		}
		report.Files = append(report.Files, fd)
		report.TotalFindings += fd.Findings
		report.TotalIssues += fd.Issues
		report.FindingsAtIssues += fd.FindingsAtIssues
		report.FP += fd.FP
	}

	sortWorstDensityFirst(report.Files)
	return report
}

// lineOnAnIssue reports whether any line in the finding's [StartLine, EndLine]
// range is an annotated issue line on the same file. A finding that spans an
// issue line counts toward that issue's inflation.
func lineOnAnIssue(loc findings.Location, issueLines map[int]struct{}) bool {
	if issueLines == nil {
		return false
	}
	for line := loc.StartLine; line <= loc.EndLine; line++ {
		if _, ok := issueLines[line]; ok {
			return true
		}
	}
	return false
}

// sortWorstDensityFirst orders files so the loudest noise sources surface first:
// clean files (all findings are FPs) ranked by FP count, then annotated files
// ranked by inflation density. Ties are broken by path for determinism.
func sortWorstDensityFirst(files []FileDensity) {
	sort.Slice(files, func(i, j int) bool {
		a, b := &files[i], &files[j]
		// Clean files with findings are the purest noise: rank them ahead of
		// annotated files, most-FP first.
		if a.Clean != b.Clean {
			// A clean file with any findings outranks annotated files; a clean
			// file with zero findings (perfectly clean) sinks to the bottom.
			if a.Clean {
				return a.FP > 0
			}
			return b.FP == 0
		}
		if a.Clean {
			if a.FP != b.FP {
				return a.FP > b.FP
			}
			return a.FilePath < b.FilePath
		}
		da, db := a.Density(), b.Density()
		if da != db {
			return da > db
		}
		if a.FP != b.FP {
			return a.FP > b.FP
		}
		return a.FilePath < b.FilePath
	})
}
