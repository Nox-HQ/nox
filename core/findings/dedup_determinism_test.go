package findings

import (
	"math/rand"
	"reflect"
	"testing"
)

// Analyzers run concurrently and hand their results over in completion order,
// so the order findings reach Deduplicate is not a property of the input tree.
// A dedup that keeps "the first one" therefore keeps a different finding from
// run to run whenever two of them tie on the dedup key but differ in anything
// else. These tests feed the same findings in many shuffled orders and require
// one answer; they fail on a first-occurrence dedup.

// tied returns findings that share a dedup key (fingerprint, line, column) and
// differ in the fields a first-occurrence dedup would have decided between.
func tied() []Finding {
	loc := Location{FilePath: "web/Dockerfile", StartLine: 16, EndLine: 16, StartColumn: 1, EndColumn: 5}
	return []Finding{
		{RuleID: "IAC-003", Severity: SeverityLow, Confidence: ConfidenceHigh, Location: loc,
			Message: "Dockerfile uses ADD instead of COPY", Fingerprint: "fp-add",
			Metadata: map[string]string{"analyzer": "iac"}},
		{RuleID: "IAC-003", Severity: SeverityMedium, Confidence: ConfidenceMedium, Location: loc,
			Message: "Dockerfile uses ADD instead of COPY", Fingerprint: "fp-add",
			Metadata: map[string]string{"analyzer": "other"}},
		{RuleID: "IAC-003", Severity: SeverityLow, Confidence: ConfidenceHigh, Location: loc,
			Message: "Dockerfile uses ADD instead of COPY", Fingerprint: "fp-add",
			Metadata: map[string]string{"analyzer": "iac", "extra": "x"}},
	}
}

func shuffled(in []Finding, rng *rand.Rand) []Finding {
	out := append([]Finding(nil), in...)
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func run(in []Finding, step func(*FindingSet)) []Finding {
	fs := NewFindingSet()
	for i := range in {
		fs.Add(in[i])
	}
	step(fs)
	return fs.Findings()
}

func assertStable(t *testing.T, name string, in []Finding, step func(*FindingSet)) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	want := run(in, step)
	for i := 0; i < 500; i++ {
		got := run(shuffled(in, rng), step)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: output depends on input order\nfirst: %+v\n  got: %+v", name, want, got)
		}
	}
}

func TestDeduplicateRepresentativeIsIndependentOfInputOrder(t *testing.T) {
	in := tied()
	assertStable(t, "Deduplicate", in, func(fs *FindingSet) { fs.Deduplicate() })
	if got := run(in, func(fs *FindingSet) { fs.Deduplicate() }); len(got) != 1 {
		t.Fatalf("findings tied on the dedup key must collapse to one, got %d", len(got))
	}
}

func TestDeduplicateKeepsDistinctPositionsThatShareAFingerprint(t *testing.T) {
	// IAC-003 on lines 16 and 17 shares a v2 fingerprint; both are real.
	a := tied()[0]
	b := a
	b.Location.StartLine, b.Location.EndLine = 17, 17
	got := run([]Finding{b, a}, func(fs *FindingSet) { fs.Deduplicate(); fs.SortDeterministic() })
	if len(got) != 2 || got[0].Location.StartLine != 16 || got[1].Location.StartLine != 17 {
		t.Fatalf("both positions must survive in line order, got %+v", got)
	}
}

func TestDeduplicateFlowsRepresentativeIsIndependentOfInputOrder(t *testing.T) {
	flow := func(sev Severity, extra string) Finding {
		return Finding{
			RuleID: "TAINT-001", Severity: sev, Fingerprint: "fp-flow",
			Location: Location{FilePath: "app.py", StartLine: 9, EndLine: 9, StartColumn: 1},
			Message:  "tainted value reaches sink",
			Metadata: map[string]string{"source_line": "5", "source_var": "code", "sink_line": "9", "who": extra},
		}
	}
	in := []Finding{flow(SeverityHigh, "a"), flow(SeverityCritical, "b"), flow(SeverityHigh, "c")}
	assertStable(t, "DeduplicateFlows", in, func(fs *FindingSet) { fs.DeduplicateFlows() })
}

func TestIndexByFingerprintIsIndependentOfInputOrder(t *testing.T) {
	a := tied()[0]
	b := a
	b.Location.StartLine, b.Location.EndLine = 17, 17
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 200; i++ {
		in := shuffled([]Finding{a, b}, rng)
		got := in[IndexByFingerprint(in)["fp-add"]]
		if got.Location.StartLine != 17 {
			t.Fatalf("representative must be the last in sort order (line 17), got line %d", got.Location.StartLine)
		}
	}
}

func TestSortDeterministicIsTotal(t *testing.T) {
	assertStable(t, "SortDeterministic", tied(), func(fs *FindingSet) { fs.SortDeterministic() })
}
