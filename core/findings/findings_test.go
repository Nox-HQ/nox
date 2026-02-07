package findings

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Fingerprint tests
// ---------------------------------------------------------------------------

func TestComputeFingerprint_Determinism(t *testing.T) {
	t.Parallel()

	loc := Location{
		FilePath:  "cmd/server/main.go",
		StartLine: 42,
	}

	fp1 := ComputeFingerprint("SEC001", loc, "hardcoded credential")
	fp2 := ComputeFingerprint("SEC001", loc, "hardcoded credential")

	if fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: got %q and %q for identical inputs", fp1, fp2)
	}
}

func TestComputeFingerprint_Uniqueness(t *testing.T) {
	t.Parallel()

	loc := Location{
		FilePath:  "cmd/server/main.go",
		StartLine: 42,
	}

	tests := []struct {
		name    string
		ruleID  string
		loc     Location
		content string
	}{
		{
			name:    "different rule ID",
			ruleID:  "SEC002",
			loc:     loc,
			content: "hardcoded credential",
		},
		{
			name:   "different file path",
			ruleID: "SEC001",
			loc: Location{
				FilePath:  "cmd/worker/main.go",
				StartLine: 42,
			},
			content: "hardcoded credential",
		},
		{
			name:   "different start line",
			ruleID: "SEC001",
			loc: Location{
				FilePath:  "cmd/server/main.go",
				StartLine: 99,
			},
			content: "hardcoded credential",
		},
		{
			name:    "different content",
			ruleID:  "SEC001",
			loc:     loc,
			content: "leaked API key",
		},
	}

	baseline := ComputeFingerprint("SEC001", loc, "hardcoded credential")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fp := ComputeFingerprint(tt.ruleID, tt.loc, tt.content)
			if fp == baseline {
				t.Fatalf("expected unique fingerprint for %s, got same as baseline: %s", tt.name, fp)
			}
		})
	}
}

func TestComputeFingerprint_IsHexSHA256(t *testing.T) {
	t.Parallel()

	fp := ComputeFingerprint("R1", Location{FilePath: "f.go", StartLine: 1}, "x")

	// SHA-256 hex digest is exactly 64 hex characters.
	if len(fp) != 64 {
		t.Fatalf("expected 64 hex characters, got %d: %q", len(fp), fp)
	}
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("non-hex character %q in fingerprint %q", c, fp)
		}
	}
}

// ---------------------------------------------------------------------------
// FindingSet.Add tests
// ---------------------------------------------------------------------------

func TestFindingSet_Add_ComputesFingerprint(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "main.go", StartLine: 10},
		Message:  "secret detected",
	})

	findings := fs.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Fingerprint == "" {
		t.Fatal("expected fingerprint to be auto-computed, got empty string")
	}
}

func TestFindingSet_Add_PreservesExistingFingerprint(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	custom := "custom-fingerprint-value"
	fs.Add(Finding{
		RuleID:      "SEC001",
		Location:    Location{FilePath: "main.go", StartLine: 10},
		Message:     "secret detected",
		Fingerprint: custom,
	})

	findings := fs.Findings()
	if findings[0].Fingerprint != custom {
		t.Fatalf("expected fingerprint %q, got %q", custom, findings[0].Fingerprint)
	}
}

// ---------------------------------------------------------------------------
// FindingSet.Deduplicate tests
// ---------------------------------------------------------------------------

func TestFindingSet_Deduplicate(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()

	// Add two identical findings -- they will receive the same fingerprint.
	f := Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "main.go", StartLine: 10},
		Message:  "secret detected",
	}
	fs.Add(f)
	fs.Add(f)

	// Add a distinct finding.
	fs.Add(Finding{
		RuleID:   "SEC002",
		Location: Location{FilePath: "main.go", StartLine: 20},
		Message:  "insecure hash",
	})

	if len(fs.Findings()) != 3 {
		t.Fatalf("expected 3 findings before dedup, got %d", len(fs.Findings()))
	}

	fs.Deduplicate()

	if len(fs.Findings()) != 2 {
		t.Fatalf("expected 2 findings after dedup, got %d", len(fs.Findings()))
	}
}

func TestFindingSet_Deduplicate_KeepsFirst(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()

	fs.Add(Finding{
		ID:       "first",
		RuleID:   "SEC001",
		Location: Location{FilePath: "main.go", StartLine: 10},
		Message:  "secret detected",
	})
	fs.Add(Finding{
		ID:       "second",
		RuleID:   "SEC001",
		Location: Location{FilePath: "main.go", StartLine: 10},
		Message:  "secret detected",
	})

	fs.Deduplicate()

	findings := fs.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "first" {
		t.Fatalf("expected first occurrence to be kept, got ID=%q", findings[0].ID)
	}
}

func TestFindingSet_Deduplicate_Empty(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Deduplicate()

	if len(fs.Findings()) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs.Findings()))
	}
}

// ---------------------------------------------------------------------------
// FindingSet.SortDeterministic tests
// ---------------------------------------------------------------------------

func TestFindingSet_SortDeterministic(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()

	// Add findings in intentionally non-sorted order.
	fs.Add(Finding{
		RuleID:   "SEC003",
		Location: Location{FilePath: "z.go", StartLine: 1},
		Message:  "third rule",
	})
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "b.go", StartLine: 50},
		Message:  "first rule, second file",
	})
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "a.go", StartLine: 30},
		Message:  "first rule, first file, second line",
	})
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "a.go", StartLine: 10},
		Message:  "first rule, first file, first line",
	})
	fs.Add(Finding{
		RuleID:   "SEC002",
		Location: Location{FilePath: "a.go", StartLine: 1},
		Message:  "second rule",
	})

	fs.SortDeterministic()

	findings := fs.Findings()

	expected := []struct {
		ruleID    string
		filePath  string
		startLine int
	}{
		{"SEC001", "a.go", 10},
		{"SEC001", "a.go", 30},
		{"SEC001", "b.go", 50},
		{"SEC002", "a.go", 1},
		{"SEC003", "z.go", 1},
	}

	if len(findings) != len(expected) {
		t.Fatalf("expected %d findings, got %d", len(expected), len(findings))
	}

	for i, want := range expected {
		got := findings[i]
		if got.RuleID != want.ruleID || got.Location.FilePath != want.filePath || got.Location.StartLine != want.startLine {
			t.Errorf("index %d: want (%s, %s, %d), got (%s, %s, %d)",
				i, want.ruleID, want.filePath, want.startLine,
				got.RuleID, got.Location.FilePath, got.Location.StartLine)
		}
	}
}

func TestFindingSet_SortDeterministic_Idempotent(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{
		RuleID:   "SEC002",
		Location: Location{FilePath: "b.go", StartLine: 5},
		Message:  "b",
	})
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "a.go", StartLine: 1},
		Message:  "a",
	})

	fs.SortDeterministic()
	first := make([]Finding, len(fs.Findings()))
	copy(first, fs.Findings())

	fs.SortDeterministic()
	second := fs.Findings()

	for i := range first {
		if first[i].Fingerprint != second[i].Fingerprint {
			t.Fatalf("sort is not idempotent at index %d", i)
		}
	}
}

// ---------------------------------------------------------------------------
// FindingSet.Findings tests
// ---------------------------------------------------------------------------

func TestFindingSet_Findings_ReturnsEmptySliceOnNew(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	findings := fs.Findings()

	if findings != nil {
		t.Fatalf("expected nil slice for new FindingSet, got length %d", len(findings))
	}
}
