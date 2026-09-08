package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// Milestone 3.3's exit: missing evidence is never REFUTES.
//
// Its work item — "wire REFUTES from the refiners that currently record
// Unknown" — has the premise inverted, and the audit is recorded here rather
// than acted on. Every Unknown-polarity recording in the tree is deliberately
// Unknown:
//
//   - dedup, in secrets and slop. An entropy rule that matched a real GitHub
//     token matched a real GitHub token; it is gone because five reports of one
//     credential is noise. Filing it as a refutation would make the ledger
//     assert that five true detections were each evidence of nothing.
//   - configuration, in recordWithheld. A rule the operator disabled, a path
//     they excluded. Neither says anything about whether the finding was true.
//   - analysis limitations, in recordAnalysisLimitations. A construct the
//     analysis cannot follow is not an argument against a finding — it is a
//     statement that the search behind any negative was incomplete.
//
// Turning any of them into REFUTES would put fabricated evidence in the ledger:
// nox would appear to have established something it never examined. So the exit
// is enforced as a property instead, and the work item is closed as already
// correct.
func TestWithheldEvidenceIsNeverARefutation(t *testing.T) {
	res, err := RunScanWithOptions(filepath.Join("..", "testdata", "precision-suite"),
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var withheld int
	for _, s := range res.Reasoning.Subjects() {
		for _, c := range res.Reasoning.About(s).Claims {
			if c.Polarity != evidence.PolarityUnknown {
				continue
			}
			withheld++
			if c.Refutes() {
				t.Errorf("a withheld claim refutes: %q. Configuration, deduplication and "+
					"an unfollowable construct say nothing about whether the finding was "+
					"true, and recording them as evidence against it is the fabrication "+
					"the polarity distinction exists to prevent.", c.Statement)
			}
			if c.Supports() {
				t.Errorf("a withheld claim supports: %q", c.Statement)
			}
		}
	}
	if withheld == 0 {
		t.Fatal("no withheld claim in the corpus; this test asserts nothing")
	}
}

// An analysis limitation is never recorded as an argument against a finding.
//
// This is the case the milestone is really about. A construct nox cannot follow
// — reflection, dynamic loading, FFI — is the reason a negative would be
// unearned, so recording it AS a negative would be exactly backwards.
func TestAnAnalysisLimitationDoesNotRefute(t *testing.T) {
	// A file that both trips a rule and carries a construct nox cannot follow.
	// Built here rather than borrowed: no committed corpus produces both, and a
	// test that skips asserts nothing at all.
	dir := t.TempDir()
	src := `import importlib

# A hardcoded credential, so the file produces a finding at all.
GITHUB_TOKEN = "ghp_noxPolarityAuditSample0000000000TdEvA"

def load(name):
    # importlib is a construct the analysis cannot follow.
    return importlib.import_module(name)
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var limitations int
	for _, s := range res.Reasoning.Subjects() {
		for _, c := range res.Reasoning.About(s).Claims {
			if !strings.Contains(c.Statement, "analysis of this file is incomplete") {
				continue
			}
			limitations++
			if c.Polarity != evidence.PolarityUnknown {
				t.Errorf("an analysis limitation was recorded with polarity %q; the one "+
					"thing it establishes is that any negative here is unearned",
					c.Polarity)
			}
			if c.Refutes() {
				t.Error("a construct nox cannot follow was recorded as an argument " +
					"AGAINST the finding, which is exactly backwards")
			}
		}
	}
	if limitations == 0 {
		t.Fatal("the fixture produced no analysis limitation; importlib should trip " +
			"reach.Detect and the file produces a finding, so this test asserts nothing")
	}
}
