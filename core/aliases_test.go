package core

import (
	"os"
	"path/filepath"
	"testing"
)

// A retirement is only safe if the alias reaches the finding.
//
// Attaching one used to live inside rules.Engine.ScanFile, so it happened only
// for findings the ENGINE matched. deps builds CONT-001 and CONT-002 by hand
// from the parsed Dockerfile, and the IaC analyzer evaluates several rules by
// parsing — none of those could carry an alias. Retiring a rule into any of them
// would have silently un-waived, in every consuming repository, findings an
// operator had explicitly accepted.
//
// So the pass moved to core, and this is the test that licenses the retirement
// it enabled: IAC-002 into CONT-002, across an analyzer boundary, onto a finding
// that was never matched by a rules engine at all.

// TestARetiredIDSurvivesAnAnalyzerBoundary is the whole guarantee in one test.
func TestARetiredIDSurvivesAnAnalyzerBoundary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"),
		[]byte("FROM ubuntu\nRUN echo hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var found bool
	for _, f := range res.Findings.Findings() {
		if f.RuleID != "CONT-002" {
			continue
		}
		found = true
		if !f.MatchesRuleID("IAC-002") {
			t.Errorf("the CONT-002 finding does not answer to IAC-002 (%v). Every "+
				"baseline entry, VEX statement and nox:ignore comment written against "+
				"IAC-002 stops matching.", f.RetiredRuleIDs)
		}
		if len(f.AliasFingerprints) == 0 {
			t.Error("the finding carries no alias fingerprint, so a BASELINE keyed on " +
				"IAC-002's fingerprint cannot recognise it — baselines hash the rule ID")
		}
	}
	if !found {
		t.Fatal("CONT-002 did not report `FROM ubuntu`; the retirement moved the " +
			"condition to a rule that does not report it")
	}
	// And the retired ID must not ALSO be reported as a live rule, or the
	// retirement achieved nothing.
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "IAC-002" {
			t.Error("IAC-002 is still reported as a live rule")
		}
	}
}

// TestAliasesReachAFindingNoEngineMatched states the mechanism directly, so a
// refactor that moves attachment back into the engine fails here with the
// reason attached rather than through a retirement quietly breaking.
func TestAliasesReachAFindingNoEngineMatched(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"),
		[]byte("FROM ubuntu\nRUN echo hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings.Findings() {
		if f.RuleID != "CONT-002" {
			continue
		}
		// CONT-002 is constructed in deps/deps.go, not matched by a rules
		// engine. If this has aliases, the core pass ran.
		if len(f.RetiredRuleIDs) == 0 {
			t.Fatal("a finding built directly by an analyzer carries no retired " +
				"identity; alias attachment is back inside the rules engine, where " +
				"only engine-matched findings can reach it")
		}
		return
	}
	t.Fatal("no CONT-002 finding to check")
}
