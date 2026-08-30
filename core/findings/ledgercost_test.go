package findings_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
)

// The largest run in docs/benchmarks/2026-Q2 produced 5,698,790 findings from
// one project in six minutes. Every projection here is stated at that scale,
// because it is the real ceiling nox has actually hit — not a round number.
const benchScaleFindings = 5_698_790

// sampleFinding is shaped like what a secrets rule actually emits: a rule ID, a
// real path, a message, a fingerprint, and the two metadata keys nearly every
// finding carries. Measuring an empty struct would flatter the result.
func sampleFinding(i int) findings.Finding {
	return findings.Finding{
		ID:       fmt.Sprintf("f-%d", i),
		RuleID:   "SEC-003",
		Severity: findings.SeverityHigh,

		Confidence: findings.ConfidenceHigh,
		Location: findings.Location{
			FilePath:    "src/services/billing/internal/client/credentials.go",
			StartLine:   i%2000 + 1,
			EndLine:     i%2000 + 1,
			StartColumn: 14,
			EndColumn:   58,
		},
		Message:     "Hardcoded GitHub personal access token",
		Fingerprint: fmt.Sprintf("%064x", i),
		Metadata:    map[string]string{"cwe": "CWE-798", "owasp": "A07:2021"},
	}
}

// sampleLedger is the smallest ledger the target architecture actually implies
// for an ordinary finding: the observation that produced it, the lexical
// context that survived refutation, and one refuting claim that lost. Three
// claims is the floor, not a worst case — a dependency finding carrying an
// advisory, a version match and a reachability path will hold more.
func sampleLedger() evidence.Ledger {
	var l evidence.Ledger
	l.Add(evidence.Claim{
		Kind:      evidence.KindHeuristic,
		Statement: "pattern SEC-003 matched a GitHub PAT prefix",
		Provenance: evidence.Provenance{
			Source: "nox-scan", Tool: "nox", Version: "dev",
			ObservedAt: "2026-08-30T00:00:00Z",
		},
	})
	l.Add(evidence.Claim{
		Kind:      evidence.KindStatic,
		Statement: "match lies in a code region, not a comment or docstring",
		Provenance: evidence.Provenance{
			Source: "nox-scan", Tool: "lexctx", Version: "dev",
			ObservedAt: "2026-08-30T00:00:00Z",
		},
	})
	l.Add(evidence.Claim{
		Kind:      evidence.KindHeuristic,
		Statement: "identifier does not carry a placeholder marker",
		Provenance: evidence.Provenance{
			Source: "nox-scan", Tool: "value-semantics", Version: "dev",
			ObservedAt: "2026-08-30T00:00:00Z",
		},
	})
	return l
}

// heapFor measures the live heap cost of building n items with build. Two
// forced collections before and after keep the reading close to live data
// rather than allocation churn; the result is a floor, not an exact figure.
func heapFor(n int, build func(int) any) uint64 {
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	held := make([]any, n)
	for i := range n {
		held[i] = build(i)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(held)

	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

// TestLedgerCardinalityBudget is milestone A3 of the evidence-native programme
// (docs/design/evidence-native-nox.md). It answers one question that has to be
// answered BEFORE the kernel work starts, because it decides the shape of the
// thing being built: can an evidence ledger be carried inline on every Finding,
// or must it live out-of-band and be referenced?
//
// The roadmap measures per-stage analysis budgets. Nothing measured the ledger
// itself, and at six million findings a three-claim ledger per finding is not a
// rounding error — it is the difference between a design that works on the
// largest project nox has scanned and one that does not.
//
// This is a measurement first and a guard second. The ceiling is deliberately
// generous: it exists to catch an order-of-magnitude mistake, not to pin a
// number that will drift with Go's allocator. Read the logged figures; treat
// the assertion as a smoke alarm.
func TestLedgerCardinalityBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("cardinality spike allocates hundreds of MB; skipped in -short")
	}

	const n = 200_000

	bare := heapFor(n, func(i int) any {
		f := sampleFinding(i)
		return &f
	})
	withLedger := heapFor(n, func(i int) any {
		f := sampleFinding(i)
		l := sampleLedger()
		return &struct {
			findings.Finding
			Ledger evidence.Ledger
		}{f, l}
	})

	perBare := float64(bare) / n
	perLedger := float64(withLedger) / n
	overhead := perLedger - perBare
	ratio := perLedger / perBare

	projBare := perBare * benchScaleFindings / (1 << 30)
	projLedger := perLedger * benchScaleFindings / (1 << 30)

	// Serialized size matters independently: findings.json is written to disk
	// and read back by every consumer, and the scan cache round-trips it.
	fj, err := json.Marshal(sampleFinding(1))
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	lj, err := json.Marshal(sampleLedger())
	if err != nil {
		t.Fatalf("marshal ledger: %v", err)
	}

	t.Logf("per finding:      %.0f B bare, %.0f B with a 3-claim ledger (+%.0f B, %.2fx)",
		perBare, perLedger, overhead, ratio)
	t.Logf("at %d findings:  %.2f GiB bare, %.2f GiB with ledgers (+%.2f GiB)",
		benchScaleFindings, projBare, projLedger, projLedger-projBare)
	t.Logf("serialized:       %d B finding, %d B ledger (%.2fx on disk)",
		len(fj), len(lj), float64(len(fj)+len(lj))/float64(len(fj)))

	// Two budgets, because the ratio alone hides the thing that decides the
	// design.
	//
	// The ratio catches an order-of-magnitude mistake in the ledger's own
	// shape: an inline ledger that costs several times the finding it
	// annotates is not an enrichment, it is the payload.
	const maxRatio = 4.0
	if ratio > maxRatio {
		t.Errorf("inline ledger costs %.2fx a bare finding, over the %.1fx budget; "+
			"the ledger representation itself is too heavy before scale is considered",
			ratio, maxRatio)
	}

	// The absolute projection is what actually constrains Track C, and it is
	// why the ratio is not enough on its own: nox has already scanned a project
	// where the BARE finding set projects to several GiB. A modest multiplier
	// on an already-large number is what pushes a scan past the memory of an
	// ordinary CI runner — a hosted GitHub runner offers 7 GB, less whatever
	// the OS and toolchain hold.
	//
	// As measured today, a three-claim inline ledger blows this budget. That is
	// the spike's answer, and it is a design input rather than a defect: nox
	// does not carry ledgers yet, so nothing is broken and main stays green.
	//
	// The gate therefore arms itself. The moment Finding gains a ledger field,
	// this becomes a hard failure, and the answer will not be to shrink the
	// ledger — it will be that the ledger cannot be inline unconditionally. It
	// goes out-of-band keyed by fingerprint, or it is dropped above a threshold
	// AND that drop is recorded as a degradation, because a finding whose
	// reasoning was silently discarded must not read like one that never had
	// any.
	const maxProjectedGiB = 6.0
	if !findingCarriesLedger() {
		t.Logf("CONSTRAINT for Track C (C1): an inline 3-claim ledger projects to "+
			"%.2f GiB at %d findings, over the %.1f GiB budget. Finding does not carry "+
			"a ledger yet, so this is recorded rather than enforced; it becomes a hard "+
			"gate as soon as it does. See docs/design/evidence-native-nox.md, A3.",
			projLedger, benchScaleFindings, maxProjectedGiB)
		return
	}
	if projLedger > maxProjectedGiB {
		t.Errorf("at %d findings an inline ledger projects to %.2f GiB (bare: %.2f GiB), "+
			"over the %.1f GiB budget. The ledger must not be carried inline "+
			"unconditionally — see docs/design/evidence-native-nox.md, A3.",
			benchScaleFindings, projLedger, projBare, maxProjectedGiB)
	}
}

// findingCarriesLedger reports whether findings.Finding has grown a field that
// holds evidence inline. It is deliberately structural rather than a version
// check or a hand-flipped constant: the budget above must start binding on the
// commit that introduces the field, not on a later commit where someone
// remembers to turn it on.
func findingCarriesLedger() bool {
	t := reflect.TypeOf(findings.Finding{})
	ledger := reflect.TypeOf(evidence.Ledger{})
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Type == ledger || f.Type == reflect.PointerTo(ledger) {
			return true
		}
	}
	return false
}
