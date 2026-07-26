package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/vex"
)

// Retiring a duplicate rule ID is only safe if the waivers written against it
// keep working. These tests are the proof, and they are deliberately end-to-end:
// a repo on disk, a waiver file an operator could have committed months ago, and
// a real scan.
//
// The legacy waiver is not hand-written. It is produced by running the RETIRED
// rule — its ID, its pattern, its file patterns, exactly as they stood before
// this change — through the normal engine, which is what an older nox did. So
// the fingerprint under test is the fingerprint that nox actually shipped, not
// one re-derived from the alias code the tests are checking.
//
// IAC-310 ("GHA step continues on error", medium) is the case that started
// #394: it and IAC-018 (low) both fired on every `continue-on-error: true`.

const continueOnErrorWorkflow = `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Flaky integration suite
        continue-on-error: true
        run: make integration
`

// retiredIAC310 is IAC-310 as it stood at retirement, verbatim.
func retiredIAC310() *rules.Rule {
	return &rules.Rule{
		ID:          "IAC-310",
		Version:     "1.0",
		Description: "GHA step continues on error",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		MatcherType: "regex",
		Pattern:     `(?i)continue-on-error:\s*true`,
		Keywords:    []string{"continue-on-error"},
		FilePatterns: []string{
			".github/workflows/*.yml", ".github/workflows/*.yaml", "*.yml", "*.yaml",
		},
		Metadata: map[string]string{"cwe": "CWE-755"},
	}
}

// legacyIAC310Finding returns the finding the retired rule produced for path,
// as an older nox would have recorded it in a baseline or VEX document.
func legacyIAC310Finding(t *testing.T, path string, content []byte) findings.Finding {
	t.Helper()
	rs := rules.NewRuleSet()
	rs.Add(retiredIAC310())
	got, err := rules.NewEngine(rs).ScanFile(path, content)
	if err != nil {
		t.Fatalf("reproducing the retired IAC-310: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("retired IAC-310 produced %d findings for %s, want 1", len(got), path)
	}
	return got[0]
}

// writeWorkflowRepo lays out a repo whose only content is a workflow with one
// continue-on-error step, and returns the repo root and the workflow's
// repo-relative path.
func writeWorkflowRepo(t *testing.T) (root, rel string) {
	t.Helper()
	root = t.TempDir()
	rel = filepath.Join(".github", "workflows", "ci.yml")
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(continueOnErrorWorkflow), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, rel
}

// findingFor returns the single finding with the given rule ID.
func findingFor(t *testing.T, fs []findings.Finding, ruleID string) findings.Finding {
	t.Helper()
	var out []findings.Finding
	for i := range fs {
		if fs[i].RuleID == ruleID {
			out = append(out, fs[i])
		}
	}
	if len(out) != 1 {
		t.Fatalf("expected exactly one %s finding, got %d", ruleID, len(out))
	}
	return out[0]
}

// TestRetiredRuleID_BaselineWrittenBeforeRetirementStillSuppresses is the
// central guarantee: a .nox/baseline.json entry recorded when the condition was
// reported as IAC-310 still suppresses it now that IAC-018 reports it alone.
//
// Without the alias the entry's fingerprint — which hashes the rule ID — simply
// stops matching, and a finding an operator explicitly accepted comes back as
// new in every repo that baselined one.
func TestRetiredRuleID_BaselineWrittenBeforeRetirementStillSuppresses(t *testing.T) {
	t.Parallel()

	root, rel := writeWorkflowRepo(t)
	content, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}

	// Control: with no baseline the surviving rule reports the condition.
	res, err := RunScan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	live := findingFor(t, res.Findings.Findings(), "IAC-018")
	if live.Status == findings.StatusBaselined {
		t.Fatal("finding was baselined before any baseline was written")
	}

	// The waiver an older nox would have written, keyed on the retired ID.
	legacy := legacyIAC310Finding(t, live.Location.FilePath, content)
	if legacy.Fingerprint == live.Fingerprint {
		t.Fatal("the retired rule's fingerprint equals the surviving rule's — " +
			"this test would pass without any alias at all")
	}
	writeBaselineEntries(t, root, baseline.Entry{
		Fingerprint: legacy.Fingerprint,
		RuleID:      "IAC-310",
		FilePath:    live.Location.FilePath,
		Severity:    findings.SeverityMedium,
		Reason:      "flaky integration suite, accepted",
		CreatedAt:   time.Now().UTC(),
	})

	res2, err := RunScan(root)
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	got := findingFor(t, res2.Findings.Findings(), "IAC-018")
	if got.Status != findings.StatusBaselined {
		t.Errorf("finding status = %q, want %q — the baseline entry written against the "+
			"retired IAC-310 no longer suppresses it, so retiring the ID un-waived it",
			got.Status, findings.StatusBaselined)
	}
}

// TestRetiredRuleID_UnrelatedBaselineEntryDoesNotSuppress is the control for the
// test above: the alias must match the retired rule's OWN fingerprint, not
// anything that happens to name the retired ID.
func TestRetiredRuleID_UnrelatedBaselineEntryDoesNotSuppress(t *testing.T) {
	t.Parallel()

	root, _ := writeWorkflowRepo(t)
	writeBaselineEntries(t, root, baseline.Entry{
		Fingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
		RuleID:      "IAC-310",
		FilePath:    filepath.Join(".github", "workflows", "ci.yml"),
		Severity:    findings.SeverityMedium,
		CreatedAt:   time.Now().UTC(),
	})

	res, err := RunScan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := findingFor(t, res.Findings.Findings(), "IAC-018")
	if got.Status == findings.StatusBaselined {
		t.Error("a baseline entry naming the retired ID but a different occurrence " +
			"suppressed the finding — the alias is matching by rule ID, not by fingerprint")
	}
}

// TestRetiredRuleID_VEXStatementStillApplies covers the other waiver surface:
// OpenVEX statements name the rule ID outright.
func TestRetiredRuleID_VEXStatementStillApplies(t *testing.T) {
	t.Parallel()

	root, _ := writeWorkflowRepo(t)
	vexPath := filepath.Join(root, "vex.json")
	doc := vex.Document{
		Context: "https://openvex.dev/ns/v0.2.0",
		ID:      "legacy-waiver",
		Author:  "platform-team",
		Statements: []vex.Statement{{
			VulnerabilityID: "IAC-310",
			Status:          vex.StatusNotAffected,
			Justification:   "vulnerable_code_not_in_execute_path",
		}},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vexPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := RunScanWithOptions(root, ScanOptions{VEXPath: vexPath})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := findingFor(t, res.Findings.Findings(), "IAC-018")
	if got.Status != findings.StatusVEXNotAffected {
		t.Errorf("finding status = %q, want %q — the VEX statement written against the "+
			"retired IAC-310 no longer applies", got.Status, findings.StatusVEXNotAffected)
	}
}

// TestRetiredRuleID_InlineSuppressionStillApplies covers the third waiver
// surface: a nox:ignore comment naming an ID the scanner no longer emits.
func TestRetiredRuleID_InlineSuppressionStillApplies(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	rel := filepath.Join(".github", "workflows", "ci.yml")
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Flaky integration suite
        # nox:ignore IAC-310 -- accepted, reported by a job summary instead
        continue-on-error: true
        run: make integration
`
	if err := os.WriteFile(full, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := RunScan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := findingFor(t, res.Findings.Findings(), "IAC-018")
	if got.Status != findings.StatusSuppressed {
		t.Errorf("finding status = %q, want %q — `nox:ignore IAC-310` stopped waiving the "+
			"condition it was written for", got.Status, findings.StatusSuppressed)
	}
}

// TestRetiredRuleID_DisabledInConfigStaysDisabled covers the fourth surface: a
// config that switched the rule off by ID.
func TestRetiredRuleID_DisabledInConfigStaysDisabled(t *testing.T) {
	t.Parallel()

	root, _ := writeWorkflowRepo(t)
	cfg := `version: "1"
scan:
  rules:
    disable:
      - IAC-310
`
	if err := os.WriteFile(filepath.Join(root, ".nox.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := RunScan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if hasRule(res.Findings.Findings(), "IAC-018") {
		t.Error("`rules.disable: [IAC-310]` no longer switches the condition off — " +
			"retiring the ID silently re-enabled a rule the operator turned off")
	}
}

// writeBaselineEntries commits a baseline containing exactly the given entries.
func writeBaselineEntries(t *testing.T, root string, entries ...baseline.Entry) {
	t.Helper()
	bl := baseline.Baseline{SchemaVersion: "1.0.0", Entries: entries}
	data, err := json.Marshal(bl)
	if err != nil {
		t.Fatal(err)
	}
	path := baseline.DefaultPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
