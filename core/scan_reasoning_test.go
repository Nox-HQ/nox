package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/reasoning"
)

// reasoningFixture writes a small tree holding one finding that survives, one
// candidate that a refiner drops, and one clean file.
func reasoningFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		// Survives: a live-format GitHub token.
		"app/creds.py": "GITHUB_TOKEN = \"ghp_7Kd2mQ9xR4tB1nZ6wY3vC8hL5jF0gS2pA9eU\"\n",
		// Dropped by the placeholder refiner.
		"app/example.py": "API_KEY = \"your-api-key-here\"\nPASSWORD = \"changeme\"\n",
		// Nothing to say about this one either way.
		"app/plain.py": "def add(a, b):\n    return a + b\n",
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// TestReasoningIsOptInAndOffByDefault pins the A3 consequence. A scan that did
// not ask for reasoning must not pay for the option existing, and a nil store
// is how that is achieved rather than by branching at each recording site.
func TestReasoningIsOptInAndOffByDefault(t *testing.T) {
	dir := reasoningFixture(t)

	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Reasoning != nil {
		t.Error("a scan that did not request reasoning allocated a store")
	}
	if res.Reasoning.Len() != 0 {
		t.Error("nil store reported claims")
	}
}

// TestRecordingChangesNoFindings is the shadow-mode guarantee at pipeline
// level. C1 records and changes nothing; if that were untrue it would be a
// behaviour change wearing an observability change's clothes.
func TestRecordingChangesNoFindings(t *testing.T) {
	dir := reasoningFixture(t)

	quiet, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan without reasoning: %v", err)
	}
	loud, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan with reasoning: %v", err)
	}

	a, b := quiet.Findings.Findings(), loud.Findings.Findings()
	if len(a) != len(b) {
		t.Fatalf("recording changed the finding count: %d without, %d with", len(a), len(b))
	}
	for i := range a {
		if a[i].Fingerprint != b[i].Fingerprint {
			t.Errorf("finding %d differs: %s vs %s", i, a[i].Fingerprint, b[i].Fingerprint)
		}
		if a[i].Severity != b[i].Severity || a[i].Confidence != b[i].Confidence {
			t.Errorf("finding %d changed severity/confidence", i)
		}
	}
}

// TestEveryReportedFindingHasASupportingClaim is the substance of C1. A store
// that recorded refutations but left the surviving findings unexplained would
// be half a ledger — it could say why nox stopped believing something and never
// why it believed anything.
func TestEveryReportedFindingHasASupportingClaim(t *testing.T) {
	dir := reasoningFixture(t)
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Reasoning == nil {
		t.Fatal("RecordReasoning was set but no store was returned")
	}

	reported := res.Findings.Findings()
	if len(reported) == 0 {
		t.Fatal("the fixture produced no findings, so this test asserts nothing")
	}

	for _, f := range reported {
		subject := SubjectForFinding(f)
		ledger := res.Reasoning.About(subject)
		if ledger.Len() == 0 {
			t.Errorf("finding %s at %s:%d has no recorded reason for existing",
				f.RuleID, f.Location.FilePath, f.Location.StartLine)
			continue
		}

		var supported bool
		for _, c := range ledger.Claims {
			if !c.Supports() {
				continue
			}
			supported = true
			if c.Provenance.Source != "nox-scan" {
				t.Errorf("claim for %s has source %q, want nox-scan", f.RuleID, c.Provenance.Source)
			}
			if got, want := c.Attributes["analyzer_confidence"], string(f.Confidence); got != want {
				t.Errorf("claim for %s carries analyzer_confidence %q, want %q — the "+
					"analyzer's own label must be preserved as data for C2 to compare against",
					f.RuleID, got, want)
			}
		}
		if !supported {
			t.Errorf("finding %s has a ledger with no supporting claim", f.RuleID)
		}
	}
}

// TestRefutedCandidateKeepsItsReason checks the other half: a candidate the
// pipeline dropped is still explained, and explained as a refutation.
func TestRefutedCandidateKeepsItsReason(t *testing.T) {
	dir := reasoningFixture(t)
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	reported := make(map[evidence.Subject]bool)
	for _, f := range res.Findings.Findings() {
		reported[SubjectForFinding(f)] = true
	}

	var refutedSubjects int
	for _, subject := range res.Reasoning.Subjects() {
		if reported[subject] {
			continue
		}
		ledger := res.Reasoning.About(subject)
		for _, c := range ledger.Claims {
			if !c.Refutes() {
				t.Errorf("dropped candidate %s recorded a %s claim; a drop is a refutation",
					subject, c.Polarity.Effective())
			}
			if c.Statement == "" {
				t.Errorf("dropped candidate %s recorded an empty reason", subject)
			}
		}
		if ledger.Len() > 0 {
			refutedSubjects++
		}
		if got := ledger.ConfidenceAbout(subject); got != evidence.ConfidenceLow {
			t.Errorf("refuted candidate %s scored %s, want LOW", subject, got)
		}
	}

	if refutedSubjects == 0 {
		t.Error("no dropped candidate was recorded; the fixture's placeholder file " +
			"should produce at least one refutation, so either the refiners stopped " +
			"recording or the fixture stopped triggering them")
	}
}

// TestObservationKindMatchesHowTheRuleWorks guards the mapping from drifting
// toward flattery. Over-claiming a pattern match's strength puts weight behind
// something nothing checked, which is what the strength ladder exists to stop.
func TestObservationKindMatchesHowTheRuleWorks(t *testing.T) {
	for _, tc := range []struct {
		ruleID string
		want   evidence.Kind
	}{
		{"TAINT-002", evidence.KindStatic},
		{"TAINT-AI-001", evidence.KindStatic},
		{"VULN-001", evidence.KindStatic},
		{"SEC-003", evidence.KindHeuristic},
		{"AI-006", evidence.KindHeuristic},
		{"IAC-013", evidence.KindHeuristic},
		{"MCP-023", evidence.KindHeuristic},
		{"SOMETHING-NEW-999", evidence.KindHeuristic},
		{"", evidence.KindHeuristic},
	} {
		if got := reasoning.ObservationKind(tc.ruleID); got != tc.want {
			t.Errorf("ObservationKind(%q) = %q, want %q", tc.ruleID, got, tc.want)
		}
	}
}

// TestSubjectIsDerivedNotStored pins the property that keeps the reference
// free: the same finding always resolves to the same subject, and no field on
// Finding holds it.
func TestSubjectIsDerivedNotStored(t *testing.T) {
	dir := reasoningFixture(t)
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings.Findings() {
		a, b := SubjectForFinding(f), SubjectForFinding(f)
		if a != b {
			t.Fatalf("SubjectForFinding is not deterministic: %s vs %s", a, b)
		}
		if a.Kind != evidence.SubjectCandidate {
			t.Errorf("subject kind = %q, want %q", a.Kind, evidence.SubjectCandidate)
		}
		if !a.Valid() {
			t.Errorf("derived subject %s is not valid", a)
		}
	}
}

// TestAdjudicationIsShadowOnly is the C2 safety property. The verdict is
// written and nothing acts on it: the policy gate, the severities and the
// analyzer confidences are all exactly what they were. A build cannot pass or
// fail differently because adjudication happened.
func TestAdjudicationIsShadowOnly(t *testing.T) {
	dir := reasoningFixture(t)

	quiet, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan without reasoning: %v", err)
	}
	loud, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan with reasoning: %v", err)
	}

	a, b := quiet.Findings.Findings(), loud.Findings.Findings()
	if len(a) != len(b) {
		t.Fatalf("adjudication changed the finding count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Severity != b[i].Severity {
			t.Errorf("finding %d severity changed: %s -> %s", i, a[i].Severity, b[i].Severity)
		}
		if a[i].Confidence != b[i].Confidence {
			t.Errorf("finding %d analyzer confidence changed: %s -> %s; adjudication must "+
				"record a verdict, never overwrite the label C5 has to compare against",
				i, a[i].Confidence, b[i].Confidence)
		}
		if a[i].Fingerprint != b[i].Fingerprint {
			t.Errorf("finding %d fingerprint changed", i)
		}
	}

	if (quiet.PolicyResult == nil) != (loud.PolicyResult == nil) {
		t.Fatal("adjudication changed whether a policy result exists")
	}
	if quiet.PolicyResult != nil {
		if quiet.PolicyResult.Pass != loud.PolicyResult.Pass {
			t.Error("adjudication changed the policy gate outcome")
		}
		if quiet.PolicyResult.ExitCode != loud.PolicyResult.ExitCode {
			t.Errorf("adjudication changed the exit code: %d -> %d",
				quiet.PolicyResult.ExitCode, loud.PolicyResult.ExitCode)
		}
	}
}

// TestExploitabilityIsAbsentUnlessAdjudicated pins the distinction a consumer
// must not lose: an empty state means nothing was asked, POTENTIAL means static
// evidence exists and no attack path was constructed. Neither is a clearance,
// and conflating them would turn "we did not look" into a verdict.
func TestExploitabilityIsAbsentUnlessAdjudicated(t *testing.T) {
	dir := reasoningFixture(t)

	quiet, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range quiet.Findings.Findings() {
		if f.Exploitability != "" {
			t.Errorf("a scan that did not adjudicate set Exploitability=%q on %s",
				f.Exploitability, f.RuleID)
		}
	}

	loud, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	reported := loud.Findings.Findings()
	if len(reported) == 0 {
		t.Fatal("fixture produced no findings; this test asserts nothing")
	}
	for _, f := range reported {
		if f.Exploitability != string(evidence.Potential) {
			t.Errorf("finding %s has Exploitability=%q, want POTENTIAL — a scan "+
				"executes nothing, so no other state is honest", f.RuleID, f.Exploitability)
		}
	}
}

// TestDivergenceIsMeasuredNotAssumed. The report is the input to C5, so it must
// actually contain the comparison rather than being an empty slice that reads
// like agreement.
func TestDivergenceIsMeasuredNotAssumed(t *testing.T) {
	res, err := RunScanWithOptions("../testdata/precision-suite",
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings.Findings()) == 0 {
		t.Fatal("the suite produced no findings; this test asserts nothing")
	}
	if len(res.Divergences) == 0 {
		t.Fatal("no divergence was reported across the whole precision suite. Either " +
			"every analyzer's confidence now matches its evidence — which would be " +
			"remarkable — or the comparison stopped running.")
	}

	for _, d := range res.Divergences {
		if d.Fingerprint == "" || d.RuleID == "" {
			t.Errorf("divergence %+v is unattributable to a finding", d)
		}
		if d.Analyzer == d.Adjudicated {
			t.Errorf("divergence recorded for %s where the two agree (%s)", d.RuleID, d.Analyzer)
		}
		if d.Overclaimed && !d.Analyzer.AtLeast(d.Adjudicated) {
			t.Errorf("%s marked overclaimed but analyzer %s is not above adjudicated %s",
				d.RuleID, d.Analyzer, d.Adjudicated)
		}
	}

	// A scan that did not record reasoning has nothing to compare and must say
	// nothing rather than report agreement.
	off, err := RunScanWithOptions("../testdata/precision-suite", ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(off.Divergences) != 0 {
		t.Error("a scan without reasoning reported divergences it could not have measured")
	}
}
