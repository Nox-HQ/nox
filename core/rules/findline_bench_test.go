package rules

import (
	"bytes"
	"fmt"
	"testing"
)

// A large file with many matches is the ordinary case for a security scanner,
// not an exotic one: a vendored bundle, a generated client, a lockfile. This
// benchmark exists because findLine scanned its (sorted) line-start table
// BACKWARDS, linearly, once per match — so a match near the top of the file
// walked almost the whole table, and total cost grew as matches x lines.
//
// It surfaced as the fuzzer stalling: FuzzScanFile logged repeated "0/sec"
// windows and then died with "context deadline exceeded", which reads like
// flaky infrastructure and is actually the engine being quadratic.

// benchContent builds a file of n lines where every line matches.
func benchContent(n int) []byte {
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "password = 'secret%d'\n", i)
	}
	return b.Bytes()
}

func benchEngine() *Engine {
	rs := NewRuleSet()
	rs.Add(&Rule{
		ID: "BENCH-001", Description: "bench", Severity: "high",
		MatcherType: "regex", Version: "1.0",
		Pattern: `(?i)password\s*[:=]\s*['"][^'"]+['"]`,
	})
	return NewEngine(rs)
}

func BenchmarkScanFileManyMatches(b *testing.B) {
	for _, n := range []int{1000, 4000, 16000, 64000} {
		content := benchContent(n)
		e := benchEngine()
		b.Run(fmt.Sprintf("lines=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := e.ScanFile("bench.txt", content); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestFindLineMatchesLinearScan pins the binary search against the linear
// definition it replaced, across every offset of a representative table —
// including the boundaries where an off-by-one would land a finding on the
// wrong line.
func TestFindLineMatchesLinearScan(t *testing.T) {
	linear := func(lineStarts []int, offset int) int {
		for i := len(lineStarts) - 1; i >= 0; i-- {
			if lineStarts[i] <= offset {
				return i
			}
		}
		return 0
	}

	for _, content := range [][]byte{
		[]byte(""),
		[]byte("one line no newline"),
		[]byte("a\n"),
		[]byte("a\nbb\nccc\n\n\ndddd\n"),
		bytes.Repeat([]byte("line\n"), 200),
	} {
		starts := computeLineStarts(content)
		for off := -2; off <= len(content)+2; off++ {
			if got, want := findLine(starts, off), linear(starts, off); got != want {
				t.Fatalf("findLine(%d) = %d, linear scan says %d (content %q)",
					off, got, want, truncForMsg(content))
			}
		}
	}
}

// truncForMsg keeps a failure message readable.
func truncForMsg(b []byte) string {
	if len(b) > 40 {
		return string(b[:40]) + "…"
	}
	return string(b)
}
