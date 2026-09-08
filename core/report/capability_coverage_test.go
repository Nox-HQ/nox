package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

func subj(t *testing.T, id string) evidence.Subject {
	t.Helper()
	return evidence.Subject{Kind: evidence.SubjectCandidate, ID: id}
}

// The matrix lists every capability, always — including the ones nothing
// provides and the ones that answered nothing.
//
// A matrix that listed only what worked would be worse than no matrix at all: a
// reader would take the rows present as the complete set of questions nox asks,
// and a capability missing from the list is exactly the one they need to know
// about.
func TestCapabilityMatrixListsEveryCapability(t *testing.T) {
	got := report.CapabilitiesFrom(capability.DefaultRegistry(), nil)
	if len(got) != len(capability.All()) {
		t.Fatalf("matrix has %d rows, want one per capability (%d)", len(got), len(capability.All()))
	}
	for i, c := range capability.All() {
		if got[i].Capability != string(c) {
			t.Errorf("row %d is %q, want %q — order must follow capability.All()", i, got[i].Capability, c)
		}
	}
}

// A capability nothing implements is reported as unprovided rather than
// omitted. On a stock installation that is call_graph and entry_point, and an
// operator reading a clean scan has no other way to learn it.
func TestUnprovidedCapabilitiesAreReportedNotOmitted(t *testing.T) {
	// A registry that genuinely lacks something, constructed rather than
	// borrowed. This used DefaultRegistry and named call_graph and entry_point,
	// which core/callgraph now provides — at which point the test was asserting
	// a property of the installation rather than of the matrix. An installation
	// can gain a plugin at any time; the fixture has to own its gap.
	reg := capability.NewRegistry()
	reg.Register(lexOnly{})

	got := report.CapabilitiesFrom(reg, nil)
	if len(got) != len(capability.All()) {
		t.Fatalf("matrix has %d rows, want one per capability", len(got))
	}
	var unprovided int
	for _, row := range got {
		if row.Provided {
			continue
		}
		unprovided++
		if len(row.Providers) != 0 {
			t.Errorf("%s: unprovided but names providers %v", row.Capability, row.Providers)
		}
	}
	if unprovided != len(capability.All())-1 {
		t.Errorf("%d capabilities reported unprovided; the fixture registry offers exactly "+
			"one, and every other row must say so rather than being omitted", unprovided)
	}
}

// lexOnly provides a single capability, so every other row in the matrix is a
// genuine, fixture-owned gap.
type lexOnly struct{}

func (lexOnly) Name() string { return "test/lex-only" }
func (lexOnly) Provides() []capability.AnalysisCapability {
	return []capability.AnalysisCapability{capability.LexicalContext}
}

// THE EXIT CRITERION for milestone 1.2: two scans differing only in what could
// be analyzed must not produce the same artifact.
//
// Before this, they did. Capability state lived on ScanResult and was
// serialized nowhere, so an installation that lost its taint engine wrote a
// findings.json byte-identical to one that had it and found nothing — and an
// empty findings list is read as clean by every consumer that cannot see the
// difference.
func TestLosingAProviderChangesTheArtifact(t *testing.T) {
	full := capability.NewRegistry()
	for _, p := range capability.Builtins() {
		full.Register(p)
	}
	// The same installation minus the taint engine.
	reduced := capability.NewRegistry()
	for _, p := range capability.Builtins() {
		if p.Name() == "core/taint" {
			continue
		}
		reduced.Register(p)
	}

	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{RuleID: "SEC-001", Message: "m", Severity: findings.SeverityHigh})

	render := func(reg *capability.Registry) string {
		r := report.NewJSONReporter("test")
		r.Capabilities = report.CapabilitiesFrom(reg, nil)
		data, err := r.Generate(fs)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		return string(data)
	}

	withTaint, withoutTaint := render(full), render(reduced)
	if withTaint == withoutTaint {
		t.Fatal("a scan that lost the taint engine produced a byte-identical artifact " +
			"to one that had it — the capability state never reached the report")
	}
	if !strings.Contains(withTaint, `"capability": "taint"`) {
		t.Error("the taint row is missing from the artifact entirely")
	}
}

// Answered and Provided are different questions and must not collapse.
//
// reachability is provided by every nox build, and on a scan whose advisory
// source was unreachable it establishes nothing. A consumer reading only
// Provided would see a capability nox has; the run-level truth is that it
// answered nobody.
func TestProvidedAndAnsweredAreSeparate(t *testing.T) {
	reg := capability.DefaultRegistry()
	cov := capability.NewCoverage(reg)
	cov.Record(subj(t, "a"), capability.Reachability, capability.Negative)
	cov.Record(subj(t, "b"), capability.Reachability, capability.Unknown)
	cov.Record(subj(t, "c"), capability.Taint, capability.Positive)

	rows := map[string]report.CapabilityCoverage{}
	for _, row := range report.CapabilitiesFrom(reg, cov) {
		rows[row.Capability] = row
	}

	// Negative is an answer — the strongest a static scan reaches.
	if got := rows["reachability"]; got.Answered != 1 || got.Inconclusive != 1 {
		t.Errorf("reachability: answered=%d inconclusive=%d, want 1 and 1", got.Answered, got.Inconclusive)
	}
	// Provided, and asked nothing. Answered must stay 0, never be inferred
	// from the capability existing.
	if got := rows["constant_evaluation"]; !got.Provided || got.Answered != 0 {
		t.Errorf("constant_evaluation: provided=%v answered=%d, want provided with nothing answered",
			got.Provided, got.Answered)
	}
}

// An inconclusive result is not coverage. Counting "evaluated and could not
// tell" toward Answered would rebuild the false all-clear one layer up, in the
// very field added to prevent it.
func TestInconclusiveNeverCountsAsAnswered(t *testing.T) {
	reg := capability.DefaultRegistry()
	cov := capability.NewCoverage(reg)
	cov.Record(subj(t, "a"), capability.Taint, capability.Unknown)
	cov.Record(subj(t, "b"), capability.Taint, capability.TimedOut)

	for _, row := range report.CapabilitiesFrom(reg, cov) {
		if row.Capability != "taint" {
			continue
		}
		if row.Answered != 0 {
			t.Errorf("taint answered=%d, want 0: unknown and timed_out are not answers", row.Answered)
		}
		if row.Inconclusive != 2 {
			t.Errorf("taint inconclusive=%d, want 2", row.Inconclusive)
		}
	}
}

// A report with no scan behind it — a fixture, a filtered re-render — must not
// publish a capability matrix it never had. Absent is honest; a matrix of
// zeroes claiming a full installation is not.
func TestReportWithoutCoverageOmitsTheMatrix(t *testing.T) {
	fs := findings.NewFindingSet()
	data, err := report.NewJSONReporter("test").Generate(fs)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var rep report.JSONReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rep.Meta.Capabilities) != 0 {
		t.Errorf("a reporter given no coverage emitted %d capability rows", len(rep.Meta.Capabilities))
	}
	if strings.Contains(string(data), "capabilities") {
		t.Error(`the "capabilities" key is present in a report with no capability data`)
	}
}

// The matrix round-trips: what a consumer reads back is what was written.
func TestCapabilityMatrixRoundTrips(t *testing.T) {
	reg := capability.DefaultRegistry()
	cov := capability.NewCoverage(reg)
	cov.Record(subj(t, "a"), capability.LexicalContext, capability.Positive)

	r := report.NewJSONReporter("test")
	r.Capabilities = report.CapabilitiesFrom(reg, cov)
	data, err := r.Generate(findings.NewFindingSet())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var rep report.JSONReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rep.Meta.Capabilities) != len(capability.All()) {
		t.Fatalf("read back %d rows, wrote %d", len(rep.Meta.Capabilities), len(capability.All()))
	}
	for _, row := range rep.Meta.Capabilities {
		if row.Capability == "lexical_context" && row.Answered != 1 {
			t.Errorf("lexical_context answered=%d after round-trip, want 1", row.Answered)
		}
	}
}
