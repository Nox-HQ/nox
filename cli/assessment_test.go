package main

import (
	"testing"

	nox "github.com/nox-hq/nox/core"
)

// A failed check prints under every mode; a declined one moves behind
// --verbose only when the assessment is there to say it in plain words.
func TestDegradationsToPrint(t *testing.T) {
	failed := nox.Degradation{Kind: "osv_lookup", Detail: "OSV unreachable", Impact: "vulnerabilities not looked up"}
	declined := nox.Degradation{Kind: "plugin", Detail: "15 installed plugin(s) ...", Impact: "...", Advisory: true}
	all := []nox.Degradation{failed, declined}

	tests := []struct {
		name            string
		shown, verbose  bool
		wantN           int
		wantAdvisoryOut bool
	}{
		{"assessment shown hides the declined plugin line", true, false, 1, false},
		{"--verbose restores the full line", true, true, 2, true},
		{"no assessment (--quiet, --staged, --history) keeps it", false, false, 2, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := degradationsToPrint(all, tc.shown, tc.verbose)
			if len(got) != tc.wantN {
				t.Fatalf("want %d lines, got %d: %+v", tc.wantN, len(got), got)
			}
			if got[0] != failed {
				t.Errorf("the failed check must always print first, got %+v", got[0])
			}
			hasAdvisory := false
			for _, d := range got {
				hasAdvisory = hasAdvisory || d.Advisory
			}
			if hasAdvisory != tc.wantAdvisoryOut {
				t.Errorf("advisory printed = %v, want %v", hasAdvisory, tc.wantAdvisoryOut)
			}
		})
	}
}

func TestAssessmentShownOnlyForADefaultScan(t *testing.T) {
	if !assessmentShown(false, false, false) {
		t.Error("a default scan shows the assessment")
	}
	for _, c := range [][3]bool{{true, false, false}, {false, true, false}, {false, false, true}} {
		if assessmentShown(c[0], c[1], c[2]) {
			t.Errorf("quiet=%v staged=%v history=%v must not show the assessment", c[0], c[1], c[2])
		}
	}
}

// The commands it offers read findings.json, so they point at the file this
// run wrote, and say so when it wrote none.
func TestAssessmentFindingsPath(t *testing.T) {
	if got := (scanAssessment{outDir: "out", formats: []string{"sarif", "json"}}).findingsPath(); got != "out/findings.json" {
		t.Errorf("got %q", got)
	}
	if got := (scanAssessment{outDir: "out", formats: []string{"sarif"}}).findingsPath(); got != "" {
		t.Errorf("no json format means no findings.json, got %q", got)
	}
}
