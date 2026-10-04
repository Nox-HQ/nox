package rules

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// gitleaksBoundary is the trailing group most of the 135 boundary-ending secret rules end in.
// RE2 has no lookahead, so "followed by a delimiter or the end" is written
// as a group that CONSUMES the delimiter -- a quote, a space, a semicolon, an
// escaped newline, or a real newline.
const gitleaksBoundary = `(?:[\x60'"\s;]|\\[nr]|$)`

func scanBoundaryRule(t *testing.T, pattern, content string) findings.Finding {
	t.Helper()
	rs := NewRuleSet()
	rs.Add(&Rule{ID: "T-1", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh, MatcherType: "regex", Pattern: pattern})
	got, err := NewEngine(rs).ScanFile("f.yaml", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want one finding, got %d: %+v", len(got), got)
	}
	return got[0]
}

// TestTrailingBoundaryIsNotPartOfTheSpan: the delimiter a lookahead-emulating
// group consumed is context, not credential. Reporting it put the end of an
// unquoted token on the NEXT line, which hid the token from every same-span
// check downstream (dedup collapsed nothing against it).
func TestTrailingBoundaryIsNotPartOfTheSpan(t *testing.T) {
	pattern := `\b(tok_[a-z0-9]{8})` + gitleaksBoundary
	tests := []struct {
		name, content string
		startCol      int
	}{
		{"newline", "key: tok_abcd1234\nnext: x\n", 6},
		{"closing quote", "key: \"tok_abcd1234\"\n", 7},
		{"escaped newline", `{"k": "tok_abcd1234\n"}`, 8},
		{"end of file", "key: tok_abcd1234", 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := scanBoundaryRule(t, pattern, tt.content)
			l := f.Location
			want := tt.startCol + len("tok_abcd1234")
			if l.StartLine != 1 || l.StartColumn != tt.startCol || l.EndLine != 1 || l.EndColumn != want {
				t.Fatalf("span %d:%d-%d:%d, want 1:%d-1:%d", l.StartLine, l.StartColumn, l.EndLine, l.EndColumn, tt.startCol, want)
			}
		})
	}
}

// TestTrailingBoundaryKeepsTheFingerprint: the fingerprint is computed from
// the matched text, delimiter included, as it always was. Narrowing the
// reported span must not move a single baseline entry.
func TestTrailingBoundaryKeepsTheFingerprint(t *testing.T) {
	pattern := `\b(tok_[a-z0-9]{8})` + gitleaksBoundary
	f := scanBoundaryRule(t, pattern, "key: tok_abcd1234\nnext: x\n")
	want := findings.ComputeFingerprint("T-1", f.Location, "tok_abcd1234\n")
	if f.Fingerprint != want {
		t.Fatalf("fingerprint moved: got %s, want %s", f.Fingerprint, want)
	}
}

// TestNonBoundaryNewlineStillSpansLines: only a trailing lookahead group is
// trimmed. A pattern whose credential itself crosses lines still reports
// the line it ends on.
func TestNonBoundaryNewlineStillSpansLines(t *testing.T) {
	f := scanBoundaryRule(t, `-----BEGIN KEY-----\n[A-Z]+\n-----END KEY-----`, "-----BEGIN KEY-----\nMIIB\n-----END KEY-----\n")
	if f.Location.EndLine != 3 || f.Location.EndColumn != 18 {
		t.Fatalf("got end %d:%d, want 3:18", f.Location.EndLine, f.Location.EndColumn)
	}
}

// TestCredentialEndingInAClassIsNotTrimmed: a trailing single-character
// class with no empty alternative is part of the credential.
func TestCredentialEndingInAClassIsNotTrimmed(t *testing.T) {
	f := scanBoundaryRule(t, `tok_[a-z]{4}[0-9]`, "key: tok_abcd1\n")
	if f.Location.EndColumn != 6+len("tok_abcd1") {
		t.Fatalf("trimmed a credential character: end column %d", f.Location.EndColumn)
	}
}
