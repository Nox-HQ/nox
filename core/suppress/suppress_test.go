package suppress

import (
	"testing"
	"time"
)

func TestScanForSuppressions_GoComment(t *testing.T) {
	content := []byte("// nox:ignore SEC-001 -- false positive\nvar secret = \"test\"\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].RuleIDs[0] != "SEC-001" {
		t.Fatalf("expected SEC-001, got %s", supps[0].RuleIDs[0])
	}
	if supps[0].Line != 2 {
		t.Fatalf("expected line 2, got %d", supps[0].Line)
	}
	if supps[0].Reason != "false positive" {
		t.Fatalf("expected reason 'false positive', got %q", supps[0].Reason)
	}
}

func TestScanForSuppressions_PythonComment(t *testing.T) {
	content := []byte("# nox:ignore SEC-002\npassword = 'test'\n")
	supps := ScanForSuppressions(content, "script.py")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].RuleIDs[0] != "SEC-002" {
		t.Fatalf("expected SEC-002, got %s", supps[0].RuleIDs[0])
	}
}

func TestScanForSuppressions_SQLComment(t *testing.T) {
	content := []byte("-- nox:ignore SEC-003\nSELECT * FROM users;\n")
	supps := ScanForSuppressions(content, "query.sql")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].RuleIDs[0] != "SEC-003" {
		t.Fatal("wrong rule ID")
	}
}

func TestScanForSuppressions_CSSComment(t *testing.T) {
	content := []byte("/* nox:ignore IAC-001 */\n.class { color: red; }\n")
	supps := ScanForSuppressions(content, "style.css")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
}

func TestScanForSuppressions_HTMLComment(t *testing.T) {
	content := []byte("<!-- nox:ignore AI-001 -->\n<div>content</div>\n")
	supps := ScanForSuppressions(content, "index.html")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
}

func TestScanForSuppressions_MultiRule(t *testing.T) {
	content := []byte("// nox:ignore SEC-001,SEC-002\nvar x = 1\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if len(supps[0].RuleIDs) != 2 {
		t.Fatalf("expected 2 rule IDs, got %d", len(supps[0].RuleIDs))
	}
	if supps[0].RuleIDs[0] != "SEC-001" || supps[0].RuleIDs[1] != "SEC-002" {
		t.Fatalf("expected SEC-001,SEC-002, got %v", supps[0].RuleIDs)
	}
}

func TestScanForSuppressions_TrailingComment(t *testing.T) {
	content := []byte("var secret = \"test\" // nox:ignore SEC-001\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	// Trailing comment: applies to the same line.
	if supps[0].Line != 1 {
		t.Fatalf("expected line 1 for trailing comment, got %d", supps[0].Line)
	}
}

func TestScanForSuppressions_WithExpiration(t *testing.T) {
	content := []byte("// nox:ignore SEC-001 -- known issue expires:2025-12-31\nvar x = 1\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].Expires == nil {
		t.Fatal("expected expiration date")
	}
	expected := time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)
	if !supps[0].Expires.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, *supps[0].Expires)
	}
}

func TestMatchesFinding_Match(t *testing.T) {
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
	}

	if !s.MatchesFinding("SEC-001", 5, time.Now()) {
		t.Fatal("expected match")
	}
}

func TestMatchesFinding_WrongRule(t *testing.T) {
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
	}

	if s.MatchesFinding("SEC-002", 5, time.Now()) {
		t.Fatal("expected no match for wrong rule")
	}
}

func TestMatchesFinding_WrongLine(t *testing.T) {
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
	}

	if s.MatchesFinding("SEC-001", 6, time.Now()) {
		t.Fatal("expected no match for wrong line")
	}
}

func TestMatchesFinding_Expired(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
		Expires: &past,
	}

	if s.MatchesFinding("SEC-001", 5, time.Now()) {
		t.Fatal("expected no match for expired suppression")
	}
}

func TestMatchesFinding_NotYetExpired(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
		Expires: &future,
	}

	if !s.MatchesFinding("SEC-001", 5, time.Now()) {
		t.Fatal("expected match for non-expired suppression")
	}
}

func TestScanForSuppressions_NoMatch(t *testing.T) {
	content := []byte("var x = 1\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 0 {
		t.Fatalf("expected 0 suppressions, got %d", len(supps))
	}
}

func TestScanForSuppressions_NextLineSkipsBlank(t *testing.T) {
	content := []byte("// nox:ignore SEC-001\n\nvar x = 1\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	// Should skip the blank line and target line 3.
	if supps[0].Line != 3 {
		t.Fatalf("expected line 3, got %d", supps[0].Line)
	}
}

// TestScanForSuppressions_DisableAlias — `nox:disable` is accepted
// as a synonym for `nox:ignore` to match gosec/staticcheck/golangci
// convention. Behaviour must be identical: rule list, reason,
// expires, and target-line resolution all work the same way.
func TestScanForSuppressions_DisableAlias(t *testing.T) {
	t.Parallel()
	content := []byte(`# nox:disable SEC-001 -- documented FP
secret = "AKIA..."`)
	supps := ScanForSuppressions(content, "main.py")
	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if len(supps[0].RuleIDs) != 1 || supps[0].RuleIDs[0] != "SEC-001" {
		t.Errorf("rule IDs = %v", supps[0].RuleIDs)
	}
	if supps[0].Reason != "documented FP" {
		t.Errorf("reason = %q", supps[0].Reason)
	}
	if supps[0].Line != 2 {
		t.Errorf("line = %d, want 2", supps[0].Line)
	}
}

// TestScanForSuppressions_DisableAndIgnoreInterop — both spellings
// can appear in the same file and target different rules.
func TestScanForSuppressions_DisableAndIgnoreInterop(t *testing.T) {
	t.Parallel()
	content := []byte(`// nox:ignore SEC-001
foo()
// nox:disable SEC-002 -- alt spelling
bar()`)
	supps := ScanForSuppressions(content, "main.go")
	if len(supps) != 2 {
		t.Fatalf("expected 2 suppressions, got %d", len(supps))
	}
	want := map[string]bool{"SEC-001": false, "SEC-002": false}
	for _, s := range supps {
		for _, id := range s.RuleIDs {
			if _, ok := want[id]; ok {
				want[id] = true
			}
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("did not see suppression for %s", id)
		}
	}
}

// TestScanForSuppressions_DisableTrailingComment — disable as a
// trailing comment must still apply to the same line.
func TestScanForSuppressions_DisableTrailingComment(t *testing.T) {
	t.Parallel()
	content := []byte(`secret = "AKIA..." # nox:disable SEC-001
`)
	supps := ScanForSuppressions(content, "main.py")
	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].Line != 1 {
		t.Errorf("line = %d, want 1 (trailing comment applies to same line)", supps[0].Line)
	}
}
