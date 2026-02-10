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
