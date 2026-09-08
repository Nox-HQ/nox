package core

import (
	"path/filepath"
	"strings"
	"testing"
)

// The counts partition the candidates exactly.
//
// Without this the numbers are four independent tallies that happen to be
// printed together, and a candidate counted twice — or not at all — would be
// invisible. With it, an accounting that does not add up is a bug rather than a
// judgement call, which is what makes the rest of the numbers worth reading.
func TestStageCountsPartitionTheCandidates(t *testing.T) {
	for _, corpus := range []string{"precision-suite", "refutation-suite", "precision-corpus"} {
		t.Run(corpus, func(t *testing.T) {
			res, err := RunScanWithOptions(filepath.Join("..", "testdata", corpus),
				ScanOptions{Offline: true, RecordReasoning: true})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(res.Stages) == 0 {
				t.Fatal("no stage accounting from a scan that recorded reasoning")
			}
			for _, s := range res.Stages {
				sum := s.Promoted + s.Refuted + s.Withheld + s.Unresolved
				if sum != s.Candidates {
					t.Errorf("%s: promoted %d + refuted %d + withheld %d + unresolved %d = %d, "+
						"but %d candidates. A candidate counted twice or not at all makes "+
						"every other number here unreadable.",
						s.Family, s.Promoted, s.Refuted, s.Withheld, s.Unresolved, sum, s.Candidates)
				}
			}
		})
	}
}

// Refuted and Withheld must not merge.
//
// A refutation is evidence: the match was inside a comment, the value was a
// placeholder. A withholding is a configuration decision or a deduplication,
// and says nothing about whether the finding was true. Collapsing them would
// make a family that only dedupes look like one that reasons — and on the
// precision suite that is exactly SEC, whose 32 withheld are dedup drops
// against 8 real refutations.
func TestWithheldIsNotCountedAsRefutation(t *testing.T) {
	res, err := RunScanWithOptions(filepath.Join("..", "testdata", "precision-suite"),
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var sec *StageCount
	for i := range res.Stages {
		if res.Stages[i].Family == "SEC" {
			sec = &res.Stages[i]
		}
	}
	if sec == nil {
		t.Fatal("no SEC family in the accounting")
	}
	if sec.Withheld == 0 {
		t.Fatal("SEC withheld nothing, so this test cannot tell the two apart")
	}
	if sec.Refuted == 0 {
		t.Error("SEC refuted nothing; the secrets refiners record refutations and this " +
			"should be non-zero")
	}
}

// A scan without reasoning reports no accounting at all, rather than reporting
// that every family refuted nothing.
//
// A refuted candidate never becomes a finding, so the ledger is the only place
// it exists. Deriving an accounting without one would produce exactly the
// misreading this instrument was built to detect.
func TestNoLedgerMeansNoAccountingRatherThanZeroes(t *testing.T) {
	res, err := RunScanWithOptions(filepath.Join("..", "testdata", "precision-suite"),
		ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Stages) != 0 {
		t.Errorf("a scan that recorded no reasoning produced %d stage counts; every one "+
			"would report zero refutations for a family that refutes", len(res.Stages))
	}
}

// IaC refutes, and the number is what caught it not doing so.
//
// Three of its filters — comments, kind references, artifacts-always — shipped
// as bare `continue`s. They removed findings on every scan and the accounting
// reported IaC as refuting nothing, which is precisely the pattern
// core/reasoning was built to end: the finding and the reason for dropping it
// discarded in the same statement.
func TestIaCRecordsWhyItDropsFindings(t *testing.T) {
	res, err := RunScanWithOptions(filepath.Join("..", "testdata", "precision-suite"),
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, s := range res.Stages {
		if s.Family != "IAC" {
			continue
		}
		if s.Refuted == 0 {
			t.Error("IaC refuted nothing while its filters remove findings on every scan; " +
				"a refiner that drops without recording is indistinguishable from one " +
				"that had nothing to drop")
		}
		return
	}
	t.Fatal("no IAC family in the accounting")
}

// The accounting is deterministic, because it reaches the artifact and
// findings.json is byte-identical across runs by contract.
func TestStageAccountingIsDeterministic(t *testing.T) {
	render := func() string {
		res, err := RunScanWithOptions(filepath.Join("..", "testdata", "precision-suite"),
			ScanOptions{Offline: true, RecordReasoning: true})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		var b []byte
		for _, s := range res.Stages {
			b = append(b, []byte(s.Family)...)
			b = append(b, byte(s.Candidates), byte(s.Promoted), byte(s.Refuted),
				byte(s.Withheld), byte(s.Unresolved))
		}
		return string(b)
	}
	first := render()
	for i := 0; i < 4; i++ {
		if again := render(); again != first {
			t.Fatalf("run %d produced different stage counts", i+2)
		}
	}
}

// No timing reaches the artifact. Latency is on milestone 6.3's list and cannot
// go there: findings.json is byte-identical across runs by contract, and a
// duration is different every time.
func TestNoTimingInTheAccounting(t *testing.T) {
	res, err := RunScanWithOptions(filepath.Join("..", "testdata", "precision-suite"),
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	data, err := res.JSONReporter("test").Generate(res.Findings)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, banned := range []string{"latency", "duration_ms", "elapsed", "\"ms\""} {
		if strings.Contains(string(data), banned) {
			t.Errorf("the artifact contains %q; a duration is different on every run and "+
				"this file is byte-identical by contract", banned)
		}
	}
}
