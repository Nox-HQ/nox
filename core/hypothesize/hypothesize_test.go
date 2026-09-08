package hypothesize_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/hypothesize"
)

// injectionFixture writes a Python file that trips AI-PI-001: untrusted request
// data interpolated into an LLM call.
func injectionFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := `import openai
from flask import request

def chat():
    client = openai.OpenAI()
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Answer this: {request.json['q']}"}],
    )
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return dir
}

// Milestone 8.1: a scan produces a structured active-testing question.
func TestAScanEmitsAStructuredQuestion(t *testing.T) {
	dir := injectionFixture(t)
	res, err := nox.RunScanWithOptions(dir, nox.ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	plan, err := hypothesize.From(res, dir, "2026-09-08T00:00:00Z")
	if err != nil {
		t.Fatalf("hypotheses: %v", err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Fatal("an injection finding raised no hypothesis; this test asserts nothing")
	}

	h := plan.Hypotheses[0]
	// The fields the milestone names. Each is a separate assertion because a
	// hypothesis missing any one of them is not a question somebody can act on.
	if h.Subject.Kind == "" || h.Subject.ID == "" {
		t.Error("the hypothesis names no subject, so a run could not file its claims against " +
			"the proposition it tested")
	}
	if h.TriggerCondition == "" {
		t.Error("no trigger condition: nothing states what would have to hold")
	}
	if h.ExpectedOracle == "" {
		t.Error("no expected oracle: a reader cannot tell what success would look like " +
			"before anything runs")
	}
	if len(h.Assumptions) == 0 {
		t.Error("no assumptions: a reader can only disagree with the result, not the question")
	}
	if len(h.Unknowns) == 0 {
		t.Error("no unknowns: nothing says why this is a hypothesis rather than a conclusion")
	}
	if len(h.Evidence.Claims) == 0 {
		t.Error("no evidence: the hypothesis carries nothing the scan established, so a run " +
			"would rediscover it badly or not at all")
	}
	for _, a := range h.Assumptions {
		if strings.Contains(a, "  ") {
			t.Errorf("assumption has a hole where a value should be: %q", a)
		}
	}
}

// The reason this is worth building in-process rather than reading an artifact.
//
// The artifact records capability counts per SCAN, so the file-driven path
// hands every hypothesis the same scan-wide list and its own comment says so.
// Coverage is per-subject since milestone 2.2, and "nothing established taint
// for this finding" is actionable where "taint answered 30 subjects somewhere"
// is not.
//
// It takes a corpus spanning more than one language to show the difference, and
// that is the point rather than an inconvenience: competence varies by
// (language x analyses) class, so a fixture with one class produces one answer
// legitimately. The first version of this test used a single Python file, got
// the same seven unknowns for every subject, and was measuring its fixture.
func TestUnknownsAreAboutTheSubjectNotTheScan(t *testing.T) {
	res, err := nox.RunScanWithOptions(filepath.Join("..", "..", "testdata", "precision-suite"),
		nox.ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	unknowns := hypothesize.UnknownsFor(res)
	if unknowns == nil {
		t.Fatal("no unknowns function; the scan recorded coverage and should have one")
	}

	distinct := map[string]int{}
	for _, f := range res.Findings.Findings() {
		distinct[strings.Join(unknowns(nox.SubjectForFinding(f)), "|")]++
	}
	if len(distinct) < 2 {
		t.Errorf("every finding in a corpus spanning Go, Python and YAML reports the same "+
			"open questions (%d distinct sets). The list is scan-wide, not per-subject, and "+
			"each hypothesis is being told the same thing about a different proposition.",
			len(distinct))
	}
}

// An unknown nothing can answer must say so. It is still worth naming — the
// silence is a limit rather than an oversight — but it is not a next step, and
// a reader who cannot tell the two apart will go looking for a plugin that does
// not exist.
func TestUnansweredCapabilitiesSayWhetherAnythingCouldAnswerThem(t *testing.T) {
	dir := injectionFixture(t)
	res, err := nox.RunScanWithOptions(dir, nox.ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	plan, err := hypothesize.From(res, dir, "2026-09-08T00:00:00Z")
	if err != nil {
		t.Fatalf("hypotheses: %v", err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Fatal("no hypotheses")
	}

	var flagged int
	for _, u := range plan.Hypotheses[0].Unknowns {
		if strings.Contains(u, "nothing on this installation can answer it") {
			flagged++
		}
	}
	// call_graph and entry_point have no implementation on a stock build.
	if flagged < 2 {
		t.Errorf("%d unknowns are marked unanswerable; call_graph and entry_point have no "+
			"implementation here and both should be", flagged)
	}
}

// A scan with no reasoning still emits a plan, and says nothing it did not
// establish. The ledger being absent is different from the ledger being empty.
func TestHypothesesWithoutReasoning(t *testing.T) {
	dir := injectionFixture(t)
	res, err := nox.RunScanWithOptions(dir, nox.ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	plan, err := hypothesize.From(res, dir, "2026-09-08T00:00:00Z")
	if err != nil {
		t.Fatalf("hypotheses: %v", err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Fatal("no hypotheses without reasoning; the finding is the same either way")
	}
	if n := len(plan.Hypotheses[0].Evidence.Claims); n != 0 {
		t.Errorf("a scan that recorded no reasoning produced %d claims", n)
	}
}

// A nil result must not panic. Emitting is optional and its failure is a
// warning, so the path has to survive being called on nothing.
func TestNilResultEmitsAnEmptyPlan(t *testing.T) {
	var r *nox.ScanResult
	plan, err := hypothesize.From(r, ".", "2026-09-08T00:00:00Z")
	if err != nil {
		t.Fatalf("hypotheses: %v", err)
	}
	if len(plan.Hypotheses) != 0 {
		t.Errorf("a nil result produced %d hypotheses", len(plan.Hypotheses))
	}
}

// Gate E: emitting a question is not asking it.
//
// The whole value of the passive/active split is that `nox scan` never contacts
// what it is scanning. Producing hypotheses is the one place that boundary could
// plausibly erode — the output is literally a list of attacks — so the property
// is asserted rather than assumed.
//
// The proof is structural, not behavioural, and deliberately so. A test that
// watched for network traffic would pass on a build where the traffic happened
// to be suppressed. What matters is that BuildPlan is pure computation over
// findings and an inventory: it takes no target, no client, no address, and
// there is nothing in a Plan for it to have contacted.
func TestEmittingHypothesesContactsNothing(t *testing.T) {
	dir := injectionFixture(t)
	res, err := nox.RunScanWithOptions(dir, nox.ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	before, err := os.ReadFile(filepath.Join(dir, "app.py"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	entriesBefore, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("listing fixture: %v", err)
	}

	plan, err := hypothesize.From(res, dir, "2026-09-08T00:00:00Z")
	if err != nil {
		t.Fatalf("hypotheses: %v", err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Fatal("no hypotheses; this test asserts nothing")
	}

	// Nothing was written into the scanned tree, and nothing was modified.
	// `nox attack` plants canaries; a scan must not.
	after, err := os.ReadFile(filepath.Join(dir, "app.py"))
	if err != nil {
		t.Fatalf("re-reading fixture: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("emitting hypotheses modified the scanned source")
	}
	entriesAfter, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("re-listing fixture: %v", err)
	}
	if len(entriesBefore) != len(entriesAfter) {
		t.Errorf("emitting hypotheses changed the scanned tree from %d entries to %d",
			len(entriesBefore), len(entriesAfter))
	}

	// And every hypothesis is a question, not a result: nothing ran, so none of
	// them may carry a verdict stronger than the scan earned.
	for _, h := range plan.Hypotheses {
		if h.ExpectedOracle == "" {
			t.Errorf("%s names no oracle, so it states no way to be settled", h.ID)
		}
	}
}
