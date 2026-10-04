package secrets

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// TestSpansOverlapAcrossLines: a span that continues onto later lines covers
// every column after its start on its first line. Comparing EndColumn as if
// it were on the start line made a two-line span "end" before it began.
func TestSpansOverlapAcrossLines(t *testing.T) {
	multi := findings.Finding{Location: findings.Location{StartLine: 1, StartColumn: 8, EndLine: 3, EndColumn: 2}}
	tests := []struct {
		name string
		b    findings.Finding
		want bool
	}{
		{"single-line span inside the first line", mkFinding("X", 1, 20, 60), true},
		{"single-line span ending before it starts", mkFinding("X", 1, 1, 7), false},
		{"single-line span touching its start", mkFinding("X", 1, 1, 8), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := spansOverlap(&multi, &tt.b); got != tt.want {
				t.Fatalf("spansOverlap(multi, %+v) = %v, want %v", tt.b.Location, got, tt.want)
			}
			if got := spansOverlap(&tt.b, &multi); got != tt.want {
				t.Fatalf("not symmetric for %+v", tt.b.Location)
			}
		})
	}
	// Two multi-line spans from the same start line always overlap.
	other := findings.Finding{Location: findings.Location{StartLine: 1, StartColumn: 1, EndLine: 2, EndColumn: 1}}
	if !spansOverlap(&multi, &other) {
		t.Fatal("two spans continuing past line 1 must overlap")
	}
}
