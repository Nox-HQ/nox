package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
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

		// A finding's ledger now holds more than one shape of supporting claim:
		// the shim's observation, and the corroborating checks E3 records. The
		// analyzer's own confidence label belongs on the OBSERVATION — it is
		// the claim C2 compares against — and requiring it on every supporting
		// claim would be requiring the wrong thing of the others. What has to
		// hold is that the label is preserved somewhere retrievable.
		var supported, labelled bool
		for _, c := range ledger.Claims {
			if !c.Supports() {
				continue
			}
			supported = true
			if c.Provenance.Source != "nox-scan" {
				t.Errorf("claim for %s has source %q, want nox-scan", f.RuleID, c.Provenance.Source)
			}
			if got := c.Attributes["analyzer_confidence"]; got != "" {
				if got != string(f.Confidence) {
					t.Errorf("claim for %s carries analyzer_confidence %q, want %q",
						f.RuleID, got, f.Confidence)
				}
				labelled = true
			}
		}
		if !supported {
			t.Errorf("finding %s has a ledger with no supporting claim", f.RuleID)
		}
		if !labelled {
			t.Errorf("finding %s records no analyzer_confidence anywhere; the "+
				"analyzer's own label must be preserved as data for C2 to compare against",
				f.RuleID)
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

// TestCapabilityCoverageIsReportedOnEveryScan. "What could nox not tell you?"
// is answerable without collecting any evidence, so it is answered
// unconditionally — including on a scan that did not record reasoning.
func TestCapabilityCoverageIsReportedOnEveryScan(t *testing.T) {
	dir := reasoningFixture(t)
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Capabilities == nil || res.Coverage == nil {
		t.Fatal("a scan without reasoning reported no capability registry or coverage")
	}
	if len(res.Capabilities.Missing()) == 0 {
		t.Error("the scan claims nox is missing no capability, which cannot be true " +
			"of a scanner that never executes the code it reads")
	}

	reported := res.Findings.Findings()
	if len(reported) == 0 {
		t.Fatal("fixture produced no findings; this test asserts nothing")
	}
	for _, f := range reported {
		subject := SubjectForFinding(f)

		// Nothing executed, so no finding may claim dynamic verification.
		if got := res.Coverage.State(subject, capability.DynamicVerification); got.Conclusive() {
			t.Errorf("finding %s reports dynamic verification as %q; nox scan "+
				"executes nothing", f.RuleID, got)
		}
		// And the gap must be visible rather than implied by silence.
		var sawDynamic bool
		for _, g := range res.Coverage.Gaps(subject) {
			if g.Capability == capability.DynamicVerification {
				sawDynamic = true
			}
			if g.State.SuppressesFinding() {
				t.Errorf("gap %+v is reported as suppressing; only a conclusive "+
					"negative may do that", g)
			}
		}
		if !sawDynamic {
			t.Errorf("finding %s does not list dynamic verification as unevaluated", f.RuleID)
		}
	}
}

// TestUnevaluatedNeverReadsAsCleared is Track D's exit criterion, at pipeline
// level: breaking or uninstalling an analyzer must not be able to make a build
// look better than it is.
func TestUnevaluatedNeverReadsAsCleared(t *testing.T) {
	dir := reasoningFixture(t)
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings.Findings() {
		subject := SubjectForFinding(f)
		for _, c := range capability.All() {
			s := res.Coverage.State(subject, c)
			if !s.Valid() {
				t.Errorf("capability %q reported an undefined state %q", c, s)
			}
			if s.SuppressesFinding() && s != capability.Negative {
				t.Errorf("state %q for %q may suppress a finding; only a conclusive "+
					"negative may", s, c)
			}
		}
	}
}

// TestConfigDrivenRemovalsLeaveATrail closes the gap C1 left open.
//
// Suppression, baselining and VEX were never actually silent — each sets a
// Status the reporters carry. The genuinely silent removals are the
// config-driven ones: a disabled rule, an excluded path, a generated-file
// filter. Those delete the finding outright, and an operator reading a clean
// scan cannot tell "nox found nothing here" from "nox found it and my config
// removed it".
func TestConfigDrivenRemovalsLeaveATrail(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "creds.py"),
		[]byte("GITHUB_TOKEN = \"ghp_7Kd2mQ9xR4tB1nZ6wY3vC8hL5jF0gS2pA9eU\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// First establish the finding exists, so the assertion below cannot pass
	// because nothing was ever found.
	base, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var ruleID string
	for _, f := range base.Findings.Findings() {
		ruleID = f.RuleID
	}
	if ruleID == "" {
		t.Fatal("the fixture produced no finding; this test would assert nothing")
	}

	// Now disable the rule that produced it.
	cfgYAML := "scan:\n  rules:\n    disable:\n      - " + ruleID + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings.Findings() {
		if f.RuleID == ruleID {
			t.Fatalf("%s was not removed; the fixture does not exercise the path", ruleID)
		}
	}

	var trail int
	for _, subject := range res.Reasoning.Subjects() {
		for _, c := range res.Reasoning.About(subject).Claims {
			if c.Polarity.Effective() != evidence.PolarityUnknown {
				continue
			}
			if !strings.Contains(c.Statement, ruleID) {
				continue
			}
			trail++
			// The claim must not weigh as evidence in either direction. A
			// configuration decision says nothing about whether the finding was
			// true, and recording it as a refutation would put fabricated
			// evidence in the ledger.
			if c.Refutes() || c.Supports() {
				t.Errorf("a config removal was recorded as %s; it is not evidence",
					c.Polarity.Effective())
			}
			if !strings.Contains(c.Statement, ".nox.yaml") {
				t.Errorf("the trail does not name the configuration that removed it: %q",
					c.Statement)
			}
		}
	}
	if trail == 0 {
		t.Errorf("%s was removed by configuration and left no trail; an operator "+
			"cannot tell this from nox never having found it", ruleID)
	}
}

// TestRemovalTrailCostsNothingWhenUnasked. The snapshot is O(findings) per
// removal step, which is not a price to pay on a scan that never asked for the
// trail.
func TestRemovalTrailCostsNothingWhenUnasked(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "creds.py"),
		[]byte("GITHUB_TOKEN = \"ghp_7Kd2mQ9xR4tB1nZ6wY3vC8hL5jF0gS2pA9eU\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"),
		[]byte("scan:\n  rules:\n    disable:\n      - SEC-003\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	quiet, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	loud, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if quiet.Reasoning != nil {
		t.Error("a scan that did not ask for reasoning allocated a store")
	}
	if len(quiet.Findings.Findings()) != len(loud.Findings.Findings()) {
		t.Errorf("recording changed the finding count: %d vs %d",
			len(quiet.Findings.Findings()), len(loud.Findings.Findings()))
	}
}

// TestCorroborationExplainsButDoesNotPromote pins E3's real effect, including
// the half that is easy to assume and wrong.
//
// Recording what an analyzer verified makes a finding explicable: its ledger
// now says what nox checked before believing it, not only what would have made
// it stop. It does NOT raise confidence, and asserting that here stops a later
// reader concluding it should. Aggregation takes the strongest supporting
// claim; every corroborating check is a heuristic; three heuristics are still a
// heuristic. The independence promotion cannot apply either, because they all
// come from one producer — counting them as independent would be the "one
// project scanning itself a hundred times" fallacy with the numbers changed.
func TestCorroborationExplainsButDoesNotPromote(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "creds.py"),
		[]byte("GITHUB_TOKEN = \"ghp_7Kd2mQ9xR4tB1nZ6wY3vC8hL5jF0gS2pA9eU\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	all := res.Findings.Findings()
	if len(all) == 0 {
		t.Fatal("fixture produced no finding; this test asserts nothing")
	}

	for _, f := range all {
		subject := SubjectForFinding(f)
		ledger := res.Reasoning.About(subject)

		var supporting int
		var readTheValue bool
		for _, c := range ledger.Claims {
			if !c.Supports() {
				continue
			}
			supporting++
			if strings.Contains(c.Statement, "inspected and is not a documentation placeholder") {
				readTheValue = true
			}
		}
		if supporting < 2 {
			t.Errorf("finding %s carries %d supporting claim(s); the checks the "+
				"analyzer performed are not being recorded", f.RuleID, supporting)
		}
		if !readTheValue {
			t.Errorf("finding %s does not record that its VALUE was inspected — the "+
				"precise check ENRICH-004 never performed", f.RuleID)
		}

		// The part that is easy to assume and wrong.
		if got := ledger.ConfidenceAbout(subject); got != evidence.ConfidenceLow {
			t.Errorf("finding %s aggregated to %s from %d heuristic claims; more "+
				"heuristics must not become a stronger claim", f.RuleID, got, supporting)
		}
	}
}
