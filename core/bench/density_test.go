package bench

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// TestScoreDensityOverFiring is the headline test: one annotated issue that
// seven findings land on must report a findings-per-issue density of 7.0. This
// is exactly the blind spot per-rule precision misses — every one of the seven
// findings is a real secret (so per-rule they look fine), yet the human sees one
// issue inflated seven-fold.
func TestScoreDensityOverFiring(t *testing.T) {
	t.Parallel()

	// Seven distinct rules all fire on line 2 of secret.py; the ground truth
	// declares one issue there (SEC-003, the correct secret rule).
	fs := []findings.Finding{
		finding("SEC-003", "secret.py", 2),
		finding("SEC-161", "secret.py", 2),
		finding("SEC-163", "secret.py", 2),
		finding("SEC-216", "secret.py", 2),
		finding("SEC-435", "secret.py", 2),
		finding("SEC-496", "secret.py", 2),
		finding("SEC-508", "secret.py", 2),
	}
	exp := []Expectation{expect("SEC-003", "secret.py", 2)}

	report := Score(fs, exp)
	d := report.Density

	if got, want := d.TotalIssues, 1; got != want {
		t.Errorf("TotalIssues = %d, want %d", got, want)
	}
	if got, want := d.FindingsAtIssues, 7; got != want {
		t.Errorf("FindingsAtIssues = %d, want %d", got, want)
	}
	if got, want := d.FindingsPerIssue(), 7.0; !almostEqual(got, want) {
		t.Errorf("FindingsPerIssue = %v, want %v", got, want)
	}
	// One issue satisfied (SEC-003 TP); the other six findings are FPs.
	if got, want := d.FP, 6; got != want {
		t.Errorf("FP = %d, want %d", got, want)
	}
	// Noise ratio = 6 FP / 7 total findings.
	if got, want := d.NoiseRatio(), 6.0/7.0; !almostEqual(got, want) {
		t.Errorf("NoiseRatio = %v, want %v", got, want)
	}

	// The per-file row for secret.py must carry the density.
	sec := fileRow(t, &d, "secret.py")
	if sec.Clean {
		t.Errorf("secret.py should not be clean (it has an expectation)")
	}
	if got, want := sec.Density(), 7.0; !almostEqual(got, want) {
		t.Errorf("secret.py density = %v, want %v", got, want)
	}
}

func TestScoreDensityFileViews(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		findings     []findings.Finding
		expectations []Expectation
		wantTotalF   int     // TotalFindings
		wantTotalI   int     // TotalIssues
		wantFPI      float64 // FindingsPerIssue
		wantNoise    float64 // NoiseRatio
		// wantFile maps path -> {clean(0/1), issues, findings, findingsAtIssues, fp}
		wantFile map[string][5]int
	}{
		{
			name:         "empty corpus",
			findings:     nil,
			expectations: nil,
			wantTotalF:   0,
			wantTotalI:   0,
			wantFPI:      0,
			wantNoise:    0,
			wantFile:     map[string][5]int{},
		},
		{
			name:         "one clean file, one FP: pure noise source",
			findings:     []findings.Finding{finding("SEC-161", "clean.js", 1)},
			expectations: nil,
			wantTotalF:   1,
			wantTotalI:   0,
			wantFPI:      0, // no issues -> density undefined -> 0
			wantNoise:    1, // 1 FP / 1 finding
			wantFile: map[string][5]int{
				"clean.js": {1, 0, 1, 0, 1}, // clean, 0 issues, 1 finding, 0 at issues, 1 FP
			},
		},
		{
			name: "perfect scan: one finding per issue, no noise",
			findings: []findings.Finding{
				finding("SEC-001", "a.py", 1),
				finding("AI-002", "b.py", 2),
			},
			expectations: []Expectation{
				expect("SEC-001", "a.py", 1),
				expect("AI-002", "b.py", 2),
			},
			wantTotalF: 2,
			wantTotalI: 2,
			wantFPI:    1.0,
			wantNoise:  0.0,
			wantFile: map[string][5]int{
				"a.py": {0, 1, 1, 1, 0},
				"b.py": {0, 1, 1, 1, 0},
			},
		},
		{
			name: "several rules on one line count as one issue",
			findings: []findings.Finding{
				finding("SEC-001", "s.py", 1),
				finding("SEC-508", "s.py", 1),
			},
			// Two rules expected on the SAME line -> one issue for density.
			expectations: []Expectation{
				expect("SEC-001", "s.py", 1),
				expect("SEC-508", "s.py", 1),
			},
			wantTotalF: 2,
			wantTotalI: 1,   // deduplicated by line
			wantFPI:    2.0, // 2 findings at 1 issue
			wantNoise:  0.0, // both are TPs
			wantFile: map[string][5]int{
				"s.py": {0, 1, 2, 2, 0},
			},
		},
		{
			name: "FP on a clean line of an annotated file is noise but not inflation",
			findings: []findings.Finding{
				finding("SEC-001", "m.py", 1), // TP at the issue
				finding("SEC-161", "m.py", 9), // FP far from the issue
			},
			expectations: []Expectation{expect("SEC-001", "m.py", 1)},
			wantTotalF:   2,
			wantTotalI:   1,
			wantFPI:      1.0, // only the finding AT the issue line counts toward inflation
			wantNoise:    0.5, // 1 FP / 2 findings
			wantFile: map[string][5]int{
				"m.py": {0, 1, 2, 1, 1},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			report := Score(tt.findings, tt.expectations)
			d := report.Density

			if d.TotalFindings != tt.wantTotalF {
				t.Errorf("TotalFindings = %d, want %d", d.TotalFindings, tt.wantTotalF)
			}
			if d.TotalIssues != tt.wantTotalI {
				t.Errorf("TotalIssues = %d, want %d", d.TotalIssues, tt.wantTotalI)
			}
			if !almostEqual(d.FindingsPerIssue(), tt.wantFPI) {
				t.Errorf("FindingsPerIssue = %v, want %v", d.FindingsPerIssue(), tt.wantFPI)
			}
			if !almostEqual(d.NoiseRatio(), tt.wantNoise) {
				t.Errorf("NoiseRatio = %v, want %v", d.NoiseRatio(), tt.wantNoise)
			}
			if len(d.Files) != len(tt.wantFile) {
				t.Fatalf("file count = %d %v, want %d %v",
					len(d.Files), fileNames(d.Files), len(tt.wantFile), tt.wantFile)
			}
			for path, want := range tt.wantFile {
				fd := fileRow(t, &d, path)
				got := [5]int{boolToInt(fd.Clean), fd.Issues, fd.Findings, fd.FindingsAtIssues, fd.FP}
				if got != want {
					t.Errorf("file %s: got {clean,issues,findings,atIssues,fp}=%v, want %v", path, got, want)
				}
			}
		})
	}
}

// TestScoreDensitySortWorstFirst asserts the ranking contract: clean files with
// FPs come before annotated files, most-FP first; annotated files are ranked by
// density. This is what lets the CLI put the loudest noise at the top.
func TestScoreDensitySortWorstFirst(t *testing.T) {
	t.Parallel()

	fs := []findings.Finding{
		// annotated file, density 3 (3 findings on 1 issue)
		finding("SEC-001", "tp.py", 1),
		finding("SEC-161", "tp.py", 1),
		finding("SEC-163", "tp.py", 1),
		// clean file with 2 FPs
		finding("SEC-073", "noisy_clean.py", 1),
		finding("SEC-080", "noisy_clean.py", 2),
		// clean file with 1 FP
		finding("SEC-240", "quiet_clean.py", 1),
	}
	exp := []Expectation{expect("SEC-001", "tp.py", 1)}

	report := Score(fs, exp)
	got := fileNames(report.Density.Files)
	want := []string{"noisy_clean.py", "quiet_clean.py", "tp.py"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("sort order = %v, want %v", got, want)
		}
	}
}

// TestRollUpFamilies checks the rule-family aggregation used by the per-category
// report: SEC- rules aggregate into one SEC family, sorted worst-precision-first.
func TestRollUpFamilies(t *testing.T) {
	t.Parallel()

	fs := []findings.Finding{
		finding("SEC-001", "a.py", 1), // TP
		finding("SEC-161", "a.py", 1), // FP (only SEC-001 expected)
		finding("SEC-163", "a.py", 1), // FP
		finding("AI-002", "b.py", 1),  // TP
	}
	exp := []Expectation{
		expect("SEC-001", "a.py", 1),
		expect("AI-002", "b.py", 1),
	}
	report := Score(fs, exp)

	fam := map[string]FamilyMetrics{}
	for _, f := range report.Families {
		fam[f.Family] = f
	}
	sec, ok := fam["SEC"]
	if !ok {
		t.Fatalf("no SEC family in %v", report.Families)
	}
	if sec.TP != 1 || sec.FP != 2 || sec.FN != 0 {
		t.Errorf("SEC family TP/FP/FN = %d/%d/%d, want 1/2/0", sec.TP, sec.FP, sec.FN)
	}
	ai, ok := fam["AI"]
	if !ok {
		t.Fatalf("no AI family in %v", report.Families)
	}
	if ai.TP != 1 || ai.FP != 0 {
		t.Errorf("AI family TP/FP = %d/%d, want 1/0", ai.TP, ai.FP)
	}
	// Worst precision (SEC at 0.33) must sort before AI (1.0).
	if report.Families[0].Family != "SEC" {
		t.Errorf("families[0] = %s, want SEC (worst precision first)", report.Families[0].Family)
	}
}

func fileRow(t *testing.T, d *DensityReport, path string) FileDensity {
	t.Helper()
	for i := range d.Files {
		if d.Files[i].FilePath == path {
			return d.Files[i]
		}
	}
	t.Fatalf("file %s not in density report %v", path, fileNames(d.Files))
	return FileDensity{}
}

func fileNames(files []FileDensity) []string {
	out := make([]string, len(files))
	for i := range files {
		out[i] = files[i].FilePath
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
