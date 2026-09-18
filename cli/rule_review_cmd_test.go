package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/catalog"
)

// TestTheSweepFixtureIsTheSweepsOwnOutput guards the field names this command
// reads out of another tool's report.
//
// The fixture is a trimmed copy of a real scripts/metamorphic/sweep.py run,
// not a hand-written approximation, because the first draft of the ingestion
// read `suspicious` where the sweep writes `suspicious_rules`. It parsed
// without error, reported nothing, and the empty section was indistinguishable
// from a clean catalogue — the exact failure mode nox's own coherence checks
// exist to prevent, reproduced in the tool meant to find it.
func TestTheSweepFixtureIsTheSweepsOwnOutput(t *testing.T) {
	path := filepath.Join("testdata", "sweep_triage_report.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema     string            `json:"schema"`
		Suspicious []json.RawMessage `json:"suspicious_rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "nox-metamorphic-triage/v1" {
		t.Fatalf("fixture schema %q is not the sweep's; re-capture it", doc.Schema)
	}
	if len(doc.Suspicious) == 0 {
		t.Fatal("fixture has no suspicious_rules, so it cannot detect a key rename")
	}

	rows, err := singleConstructCandidates(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("ingestion read no rows from a fixture that has them")
	}
	for _, r := range rows {
		if r.Rule == "" || r.SeedCount == 0 || len(r.Seeds) == 0 {
			t.Errorf("row %+v lost evidence in ingestion", r)
		}
	}
}

// TestOnlyCollapsingRulesAreListed pins the threshold-free definition.
func TestOnlyCollapsingRulesAreListed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bench.json")
	write(t, path, `{"rule_prevalence":{
		"COLLAPSE-1":{"repos":2,"findings":100,"sites":10},
		"EXACT-1":{"repos":3,"findings":50,"sites":50},
		"BARELY-1":{"repos":1,"findings":10,"sites":9},
		"NOSITES-1":{"repos":1,"findings":7,"sites":0}}}`)

	rows, err := collapseCandidates(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, r := range rows {
		got[r.Rule] = r.Factor
	}
	if _, ok := got["EXACT-1"]; ok {
		t.Error("a rule whose findings are all distinct authored lines was listed as collapsing")
	}
	// A rule with no site data has not been measured; reporting it as a
	// collapse of unknown size would invent the measurement.
	if _, ok := got["NOSITES-1"]; ok {
		t.Error("a rule with no site data was listed")
	}
	if got["COLLAPSE-1"] != 10 {
		t.Errorf("factor %v, want 10", got["COLLAPSE-1"])
	}
	// The barely-collapsing rule IS listed. There is no cutoff; the factor is
	// what makes it dismissible.
	if _, ok := got["BARELY-1"]; !ok {
		t.Error("a 10/9 collapse was dropped, which means a threshold crept in")
	}
	if len(rows) != 2 || rows[0].Rule != "BARELY-1" || rows[1].Rule != "COLLAPSE-1" {
		t.Errorf("rows are not sorted by rule ID: %+v", rows)
	}
}

// TestTheReportRanksNothing is the structural guarantee behind the design.
//
// Asserted on the JSON shape rather than on the prose, because prose promising
// restraint is not a constraint. A score, rank or severity field is how this
// report would start prescribing, so the schema must not grow one by accident.
func TestTheReportRanksNothing(t *testing.T) {
	dir := t.TempDir()
	benchPath := filepath.Join(dir, "bench.json")
	write(t, benchPath, `{"rule_prevalence":{"A-1":{"repos":2,"findings":100,"sites":10}}}`)
	out := filepath.Join(dir, "out.json")

	if code := runRuleReview([]string{"--bench", benchPath, "--json", "--output", out}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"score", "rank", "severity", "priority", "risk", "verdict", "action"} {
		if strings.Contains(strings.ToLower(string(raw)), `"`+forbidden+`"`) {
			t.Errorf("report grew a %q field; this command reports evidence and prescribes nothing", forbidden)
		}
	}
	if _, ok := generic["remediation_contradicts_trigger"]; !ok {
		t.Error("the computed signal is missing from the schema")
	}
}

// TestAnUnmeasuredSignalSaysSo separates "nothing found" from "never asked",
// the same distinction renderPrevalence draws for tier 3.
func TestAnUnmeasuredSignalSaysSo(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.md")
	if code := runRuleReview([]string{"--output", out}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "Not measured — pass `--bench") {
		t.Error("an unsupplied bench source reads as though nothing collapsed")
	}
	if !strings.Contains(got, "Not measured — pass `--sweep") {
		t.Error("an unsupplied sweep source reads as though nothing was suspicious")
	}
	// The computed signal always runs, so its empty result is a real "none".
	if !strings.Contains(got, "None.") {
		t.Error("the contradiction section did not report its (empty) result")
	}
}

func TestBadSourcesFailLoudly(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.json")
	if code := runRuleReview([]string{"--bench", missing}); code != 2 {
		t.Errorf("missing bench report exited %d, want 2", code)
	}
	empty := filepath.Join(dir, "empty.json")
	write(t, empty, `{"projects":[]}`)
	if code := runRuleReview([]string{"--bench", empty}); code != 2 {
		t.Errorf("a bench report with no prevalence data exited %d, want 2", code)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestEveryBuiltInPatternSurvivesTheScanner runs the regex-source scanner over
// the whole catalogue.
//
// The scanner walks regex syntax by hand — character classes, escapes, group
// prefixes — and every one of those is an index it can walk off. 1,496
// hand-written patterns is a better adversary than any fixture, and this is
// the cheapest place to find out. It asserts safety and determinism only: what
// the analysis CONCLUDES about the catalogue is a measurement recorded in
// docs/design/rule-review-candidates.md, not a gate, because deciding which
// rules deserve a maintainer's attention is a judgement this tool does not make.
func TestEveryBuiltInPatternSurvivesTheScanner(t *testing.T) {
	first := contradictionCandidates()
	second := contradictionCandidates()
	if len(first) != len(second) {
		t.Fatalf("analysis is not deterministic: %d then %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("analysis is not deterministic at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
	for _, c := range first {
		if c.Rule == "" || c.Param == "" || c.Flagged == "" || c.Endorsement == "" {
			t.Errorf("candidate %+v is missing the evidence a maintainer would check", c)
		}
	}
	t.Logf("catalogue: %d rules, %d remediation contradictions", len(catalog.Rules()), len(first))
}

// TestTheCutoffIsPresentationNotMeasurement pins the guarantee that makes the
// default list safe to change later.
//
// The factor is the canonical measurement. The threshold decides which rows a
// maintainer is shown FIRST and nothing else: every measured row is still
// computed, still counted, and still reachable. If filtering ever started
// happening inside collapseCandidates, moving the number would silently change
// the signal rather than the presentation.
func TestTheCutoffIsPresentationNotMeasurement(t *testing.T) {
	dir := t.TempDir()
	bench := filepath.Join(dir, "bench.json")
	write(t, bench, `{"rule_prevalence":{
		"BIG-1":{"repos":4,"findings":260,"sites":20},
		"AT-CUTOFF-1":{"repos":1,"findings":4,"sites":2},
		"UNDER-1":{"repos":7,"findings":673,"sites":667}}}`)

	// The measurement itself never filters.
	all, err := collapseCandidates(bench)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("collapseCandidates returned %d rows; it must measure every collapse", len(all))
	}

	shown := atOrAboveFactor(all, defaultCollapseFactor)
	if len(shown) != 2 {
		t.Errorf("shown %d rows at factor >= %g, want 2", len(shown), defaultCollapseFactor)
	}
	// Exactly at the cutoff is shown: "factor >= 2", not "> 2".
	var sawCutoff bool
	for _, r := range shown {
		if r.Rule == "AT-CUTOFF-1" {
			sawCutoff = true
			if r.Factor != 2 {
				t.Errorf("AT-CUTOFF-1 factor %v, want 2", r.Factor)
			}
		}
		if r.Rule == "UNDER-1" {
			t.Error("a row below the cutoff was shown")
		}
	}
	if !sawCutoff {
		t.Error("a row exactly at the cutoff was withheld; the comparison is > rather than >=")
	}
	if got := atOrAboveFactor(all, 0); len(got) != 3 {
		t.Errorf("--all showed %d of 3 measured rows", len(got))
	}
}

// TestAFilteredListDoesNotLookLikeAShortOne is the same distinction
// renderPrevalence draws for tier 3, applied to the cutoff: a reader must never
// have to guess whether a list is short because little collapsed or because
// most of it was withheld.
func TestAFilteredListDoesNotLookLikeAShortOne(t *testing.T) {
	dir := t.TempDir()
	bench := filepath.Join(dir, "bench.json")
	write(t, bench, `{"rule_prevalence":{
		"BIG-1":{"repos":4,"findings":260,"sites":20},
		"UNDER-1":{"repos":7,"findings":673,"sites":667}}}`)

	filtered := filepath.Join(dir, "filtered.md")
	if code := runRuleReview([]string{"--bench", bench, "--output", filtered}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	got := readFile(t, filtered)
	if !strings.Contains(got, "Showing 1 of 2 measured rows") {
		t.Errorf("filtered report does not say what it withheld:\n%s", got)
	}
	if !strings.Contains(got, "`--all`") {
		t.Error("filtered report does not say how to see the rest")
	}

	everything := filepath.Join(dir, "all.md")
	if code := runRuleReview([]string{"--bench", bench, "--all", "--output", everything}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	got = readFile(t, everything)
	if !strings.Contains(got, "Showing all 2 measured rows") {
		t.Errorf("--all report does not state that nothing was withheld:\n%s", got)
	}
	if strings.Contains(got, "pass `--all`") {
		t.Error("--all report still advertises --all")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
