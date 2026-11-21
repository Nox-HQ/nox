package rules

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

// The reference: the check as it was, lower-casing the line up to the
// candidate. The window must answer exactly as it did.
func isSRIIntegrityHashWholeLine(line string, col int) bool {
	start := col - 1
	if start < 0 || start > len(line) {
		return false
	}
	prefixRegion := strings.ToLower(line[:start])
	for _, p := range sriPrefixes {
		if !strings.HasSuffix(prefixRegion, p) {
			continue
		}
		before := len(prefixRegion) - len(p)
		if before == 0 {
			return true
		}
		if b := prefixRegion[before-1]; !isAlphaNum(b) {
			return true
		}
	}
	return false
}

func TestSRIWindowAnswersAsTheWholeLineDid(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(751))
	pieces := []string{"sha256-", "SHA384-", "sha512-", "xsha512-", "a", "Z", "9", " ", "\"", "=", "-", "é", "integrity=\""}
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := r.Intn(12); n >= 0; n-- {
			b.WriteString(pieces[r.Intn(len(pieces))])
		}
		line := b.String()
		for col := 0; col <= len(line)+2; col++ {
			if got, want := isSRIIntegrityHash(line, col), isSRIIntegrityHashWholeLine(line, col); got != want {
				t.Fatalf("isSRIIntegrityHash(%q, %d) = %v, the whole-line check said %v", line, col, got, want)
			}
		}
	}
}

// The cost of one check must not grow with the text before the candidate.
// Lower-casing the whole prefix scanned it for every candidate on the line,
// and a scan of one 12.7 MB single-line JSON file had not finished after 15
// minutes.
// Compared as a ratio, best of several runs, so machine speed and load cancel:
// the whole-line check is ~10^5 times slower at the end of this line than at
// its start; the window is the same at both.
func TestSRICheckCostDoesNotGrowWithTheLine(t *testing.T) {
	line := strings.Repeat("abcdefgh ", 1<<17) // ~1.2 MB
	best := func(col int) time.Duration {
		min := time.Duration(1 << 62)
		for run := 0; run < 7; run++ {
			t0 := time.Now()
			for i := 0; i < 200; i++ {
				isSRIIntegrityHash(line, col)
			}
			if d := time.Since(t0); d < min {
				min = d
			}
		}
		return max(min, time.Microsecond)
	}
	early, late := best(20), best(len(line)-1)
	if late > 100*early {
		t.Fatalf("a check at the end of a %d-byte line took %v, one at its start %v", len(line), late, early)
	}
}
