package suppress

import "testing"

// A directive quoted in an INLINE code span of a markdown file is documentation,
// exactly as one inside a fenced block is. docs/design/rule-family-migration.md
// explains that a waiver's own text can cause the finding it waives, and to
// explain it, quotes a waiver inline — which was then read as a live waiver and
// reported as unused on every scan of this repository.
func TestInlineCodeSpanInMarkdownIsADocExample(t *testing.T) {
	md := "Each waiver caused the finding it waived:\n" +
		"`fmt.Print(bashCompletion) // nox:ignore AI-006 -- shell completion script`.\n"
	got := ScanForSuppressions([]byte(md), "docs/design/note.md")
	if len(got) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(got))
	}
	if !got[0].DocExample {
		t.Error("a directive inside an inline code span must be a DocExample, not a live waiver")
	}
}

// The escape must not swallow real waivers: a directive with a backtick
// elsewhere on the line (an unmatched one, so no span is open at the marker)
// still waives.
func TestUnpairedBacktickDoesNotMakeAWaiverDocumentation(t *testing.T) {
	md := "<!-- nox:ignore SEC-002 -- the `real thing -->\n"
	got := ScanForSuppressions([]byte(md), "docs/note.md")
	if len(got) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(got))
	}
	if got[0].DocExample {
		t.Error("a directive NOT inside a closed span must stay a live waiver")
	}
}
