package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
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

// The assessment's upgrade line is the command `nox fix` applies, so it has to
// name the same version. A version the findings name can itself be affected by
// an advisory introduced after the installed one (axios 0.33.0 carries two that
// 0.21.1 does not); only asking the advisory database finds that out.
func TestScanTargetCheckerAsksOnlyWhenTheScanAsked(t *testing.T) {
	cfg := &nox.ScanConfig{}
	if scanTargetChecker(cfg, false, false) == nil {
		t.Error("an online scan must check its upgrade targets")
	}
	if scanTargetChecker(cfg, true, false) != nil {
		t.Error("--offline must not reach the network for upgrade targets")
	}
	if scanTargetChecker(cfg, false, true) != nil {
		t.Error("--no-osv must not reach the network for upgrade targets")
	}
	disabled := &nox.ScanConfig{}
	disabled.Scan.OSV.Disabled = true
	if scanTargetChecker(disabled, false, false) != nil {
		t.Error("scan.osv.disabled must not reach the network for upgrade targets")
	}
}

// stubTargets answers what each candidate version is still affected by.
type stubTargets map[string][]fix.Residual

func (s stubTargets) Remaining(_ context.Context, _, _, v string) ([]fix.Residual, error) {
	return s[v], nil
}

func axiosVuln(fixed string) findings.Finding {
	return findings.Finding{
		RuleID: "VULN-001", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
		Location: findings.Location{FilePath: "package-lock.json"},
		Metadata: map[string]string{"ecosystem": "npm", "package": "axios", "version": "0.21.1", "fixed_in": fixed},
	}
}

// Counterexample from the dogfood run: the scan said "Upgrade axios 0.21.1 ->
// 0.33.0" while `nox fix plan` said 0.34.0, because the assessment never asked
// the advisory database about its target.
func TestScanAssessmentNamesATargetThatClearsEveryAdvisory(t *testing.T) {
	active := []findings.Finding{axiosVuln("0.21.2"), axiosVuln("0.33.0")}
	targets := stubTargets{"0.33.0": {{ID: "GHSA-9fr6-4gfg-395g", FixedIn: "0.34.0"}, {ID: "GHSA-x97p-jq2g-jp4f", FixedIn: "0.34.0"}}}

	var withCheck, without bytes.Buffer
	scanAssessment{active: active, target: ".", targets: targets}.print(&withCheck)
	scanAssessment{active: active, target: "."}.print(&without)

	if !strings.Contains(withCheck.String(), "Upgrade axios 0.21.1 -> 0.34.0") {
		t.Errorf("the assessment must name the version that clears every advisory:\n%s", withCheck.String())
	}
	if strings.Contains(withCheck.String(), "-> 0.33.0") {
		t.Errorf("0.33.0 is still affected and must not be offered:\n%s", withCheck.String())
	}
	// Without a checker (offline) the plan is built from the findings alone and
	// says so rather than presenting 0.33.0 as verified.
	if !strings.Contains(without.String(), "-> 0.33.0") {
		t.Errorf("an unchecked plan names the findings' own target:\n%s", without.String())
	}
}
