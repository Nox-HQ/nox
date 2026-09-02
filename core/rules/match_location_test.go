package rules

import "testing"

// TestMatchLocation_SpansLines: a match that crosses line breaks reports the
// line it ends on and a column measured on that line, instead of the start
// line and a column past its end.
func TestMatchLocation_SpansLines(t *testing.T) {
	tests := []struct {
		name          string
		mr            MatchResult
		endLine, endC int
	}{
		{"one line", MatchResult{Line: 4, Column: 3, MatchText: "token=abc"}, 4, 12},
		{"trailing newline", MatchResult{Line: 4, Column: 3, MatchText: "token=abc\n"}, 5, 1},
		{"pem block", MatchResult{Line: 1, Column: 1, MatchText: "-----BEGIN KEY-----\nMIIB\n-----END KEY-----"}, 3, 18},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loc := matchLocation("f", tt.mr)
			if loc.StartLine != tt.mr.Line || loc.StartColumn != tt.mr.Column {
				t.Fatalf("start moved: %+v", loc)
			}
			if loc.EndLine != tt.endLine || loc.EndColumn != tt.endC {
				t.Fatalf("got end %d:%d, want %d:%d", loc.EndLine, loc.EndColumn, tt.endLine, tt.endC)
			}
		})
	}
}
