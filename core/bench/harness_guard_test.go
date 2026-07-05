package bench

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// These tests are the harness's guard against itself. A precision number is only
// worth trusting if it can actually go down: a corpus curated (accidentally or
// deliberately) to always report 1.00 measures nothing. The tests below prove
// the scorer genuinely responds to a broken rule — that Score STRICTLY drops
// below 1.0 and the ratchet FAILS when a false positive is injected or a true
// positive is dropped. If a future change silently made Score unable to fall
// below 1.0, these tests would catch it before the number lied in CI.

// perfectCorpus is a tiny synthetic scenario that scores a clean 1.0/1.0/1.0:
// two rules, each firing exactly on its one expected line, nothing else. It is
// the honest baseline the anti-cheat tests then perturb.
func perfectCorpus() ([]findings.Finding, []Expectation) {
	fs := []findings.Finding{
		finding("SEC-001", "a.py", 1),
		finding("AI-002", "b.py", 2),
	}
	exp := []Expectation{
		expect("SEC-001", "a.py", 1),
		expect("AI-002", "b.py", 2),
	}
	return fs, exp
}

// TestCorpusCannotFakePerfectScore is the anti-cheat guardrail. It first
// confirms the honest scenario scores a perfect 1.0, then perturbs it two ways —
// an injected false positive and a dropped true positive — and asserts that in
// each case Score STRICTLY drops below 1.0. A harness that kept reporting 1.0
// after either perturbation would be measuring nothing, and this test fails
// loudly if that ever happens.
func TestCorpusCannotFakePerfectScore(t *testing.T) {
	t.Parallel()

	fs, exp := perfectCorpus()
	clean := Score(fs, exp)
	if p, r := clean.Overall.Precision(), clean.Overall.Recall(); p != 1.0 || r != 1.0 {
		t.Fatalf("control corpus is not perfect: precision %v recall %v; the perturbation tests below are meaningless", p, r)
	}

	t.Run("injected false positive drops precision below 1.0", func(t *testing.T) {
		t.Parallel()
		// A synthetic finding on a clean line: no expectation matches it, so it is
		// a false positive that MUST pull precision under 1.0.
		poisoned := append(append([]findings.Finding(nil), fs...), finding("SEC-001", "clean.py", 99))
		got := Score(poisoned, exp)
		if got.Overall.Precision() >= 1.0 {
			t.Fatalf("injected FP did not drop precision: got %v, want < 1.0 — the harness cannot detect a false positive", got.Overall.Precision())
		}
		if got.Overall.FP == 0 {
			t.Errorf("injected FP not counted: overall FP = 0")
		}
	})

	t.Run("dropped true positive drops recall below 1.0", func(t *testing.T) {
		t.Parallel()
		// Remove one real finding: its expectation is now unsatisfied, a false
		// negative that MUST pull recall under 1.0.
		short := []findings.Finding{fs[0]} // drop the AI-002 finding
		got := Score(short, exp)
		if got.Overall.Recall() >= 1.0 {
			t.Fatalf("dropped TP did not drop recall: got %v, want < 1.0 — the harness cannot detect a missed finding", got.Overall.Recall())
		}
		if got.Overall.FN == 0 {
			t.Errorf("dropped TP not counted as FN: overall FN = 0")
		}
	})
}

// TestHarnessCatchesRegression proves the whole ratchet chain fires: a baseline
// snapshotted from the perfect corpus, compared against a perturbed run, MUST
// report at least one regression. This is the end-to-end version of the anti-
// cheat guarantee — not just that Score drops, but that CompareBaseline turns
// that drop into a CI failure, at both the overall and per-rule level.
func TestHarnessCatchesRegression(t *testing.T) {
	t.Parallel()

	fs, exp := perfectCorpus()
	base := baselineOf(fs, exp)

	tests := []struct {
		name     string
		findings []findings.Finding
		// wantRule is a per-rule regression metric that must appear; empty means
		// only "some regression must appear".
		wantRule string
	}{
		{
			name:     "injected false positive is caught",
			findings: append(append([]findings.Finding(nil), fs...), finding("SEC-001", "clean.py", 99)),
			wantRule: "SEC-001 precision",
		},
		{
			name:     "dropped true positive is caught",
			findings: []findings.Finding{fs[0]}, // AI-002 finding gone
			wantRule: "AI-002 recall",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			current := baselineOf(tt.findings, exp)
			regressions := CompareBaseline(base, current)
			if len(regressions) == 0 {
				t.Fatalf("ratchet did not fail on a broken corpus: no regressions reported")
			}
			if tt.wantRule != "" {
				found := false
				for _, r := range regressions {
					if r.Metric == tt.wantRule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("per-rule regression %q not among reported %v", tt.wantRule, regressions)
				}
			}
		})
	}
}

// TestScoreJSONDeterministic is the determinism guard. nox core guarantees
// byte-identical output; the scorer builds its Report from Go maps (per-rule
// counters, per-file density), whose iteration order is randomized, so the only
// thing standing between us and nondeterministic JSON is the explicit sorting in
// Score. This test scores the same inputs many times and asserts the marshalled
// JSON is byte-for-byte identical every time, which would fail immediately if a
// map ever leaked into the output ordering.
func TestScoreJSONDeterministic(t *testing.T) {
	t.Parallel()

	// A scenario deliberately rich in ties and shared families so any unsorted
	// map iteration would surface as reordering: multiple rules per family,
	// multiple files, clean and annotated files, duplicate FPs.
	fs := []findings.Finding{
		finding("SEC-508", "s.py", 1),
		finding("SEC-001", "s.py", 1),
		finding("SEC-003", "s.py", 1),
		finding("AI-002", "p.py", 2),
		finding("AI-002", "clean.py", 5), // FP
		finding("TAINT-005", "t.py", 3),
		finding("TAINT-004", "t.py", 3),
		finding("SEC-001", "clean2.py", 9), // FP
	}
	exp := []Expectation{
		expect("SEC-001", "s.py", 1),
		expect("SEC-003", "s.py", 1),
		expect("AI-002", "p.py", 2),
		expect("TAINT-005", "t.py", 3),
		expect("SEC-999", "missing.py", 7), // FN
	}

	var first []byte
	const runs = 50
	for i := 0; i < runs; i++ {
		report := Score(fs, exp)
		out, err := json.Marshal(report)
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if first == nil {
			first = out
			continue
		}
		if !bytes.Equal(first, out) {
			t.Fatalf("Score JSON is nondeterministic across runs:\nrun 0:  %s\nrun %d: %s", first, i, out)
		}
	}

	// Also assert the baseline snapshot derived from the report is deterministic:
	// its per-rule floors are built from a map and sorted, so a missing sort would
	// show up here too.
	var firstBase []byte
	for i := 0; i < runs; i++ {
		report := Score(fs, exp)
		b := BaselineFromReport(&report)
		out, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal baseline: %v", err)
		}
		if firstBase == nil {
			firstBase = out
			continue
		}
		if !bytes.Equal(firstBase, out) {
			t.Fatalf("Baseline JSON is nondeterministic across runs:\nrun 0:  %s\nrun %d: %s", firstBase, i, out)
		}
	}
}

// baselineOf scores the inputs and derives the baseline snapshot in one step,
// so the ratchet tests can go straight from (findings, expectations) to the
// gated Baseline without an intermediate Report variable.
func baselineOf(fs []findings.Finding, exp []Expectation) Baseline {
	report := Score(fs, exp)
	return BaselineFromReport(&report)
}
