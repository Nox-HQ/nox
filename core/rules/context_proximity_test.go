package rules

import (
	"strings"
	"testing"
)

// RequireContextKeywords is the precision control for vendor rules whose pattern
// carries no literal anchor — `[a-zA-Z0-9]{36}` and similar. Its documented
// premise is that "the vendor name and the value sit on the same line", and it
// is implemented as "within ±4 LINES".
//
// That premise holds for human-written code and fails completely on a line that
// is not human-written. Measured 2026-09-11 on alexrudall/ruby-openai@v8.3.0, a
// 3.2k-star Ruby SDK: `spec/fixtures/cassettes/images_edit_multiple.yml` holds a
// base64-encoded PNG on ONE line of 1,087,625 characters. The word "maven"
// occurs exactly once in that file — inside the base64 data, by coincidence —
// and because it is on the same physical line as every other run of characters
// there, it authorised SEC-505 to fire 3,040 times. Each match sat at a
// different column, so each earned a distinct fingerprint and deduplication
// correctly declined to collapse them: 3,040 HIGH-severity "Detected Maven
// Repository Token" findings out of a 4,014-finding scan, from one line of test
// fixture data.
//
// "Near" has to be measured in characters. A keyword 800KB away is not context
// however few newlines separate it.

// longLineWith builds one physical line of filler with needle placed at
// approximately the given character offset.
func longLineWith(total, at int, needle string) string {
	var b strings.Builder
	b.Grow(total + len(needle))
	for b.Len() < at {
		b.WriteString("QWERTYUIOPASDFGHJKLZXCVBNM0123456789")
	}
	b.WriteString(needle)
	for b.Len() < total {
		b.WriteString("QWERTYUIOPASDFGHJKLZXCVBNM0123456789")
	}
	return b.String()
}

// TestProximityIsMeasuredInCharactersNotLines is the ruby-openai case reduced.
func TestProximityIsMeasuredInCharactersNotLines(t *testing.T) {
	// The keyword sits at the very start of a 200k-character line; the match is
	// at the far end. Nothing about that is context.
	line := longLineWith(200_000, 0, "maven")
	lines := []string{line}
	matchCol := 190_000

	if contextHasKeyword(lines, 1, matchCol, contextWindow, []string{"maven"}) {
		t.Errorf("a keyword %d characters from the match counts as context, so one "+
			"accidental occurrence in a blob authorises every match on the line",
			matchCol)
	}
}

// TestProximityStillHoldsWhereItShould. The fix must not cost the control its
// purpose: a vendor name written beside the value is exactly what it is for.
func TestProximityStillHoldsWhereItShould(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		line  int
		col   int
		want  bool
	}{
		{
			name:  "same line, adjacent — the ordinary credential assignment",
			lines: []string{`maven_token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"`},
			line:  1, col: 15, want: true,
		},
		{
			name: "nearby line — a YAML key above its value",
			lines: []string{
				"maven:",
				"  token: AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
			},
			line: 2, col: 10, want: true,
		},
		{
			name: "four lines away, still inside the line window",
			lines: []string{
				"# maven settings follow", "", "", "",
				`  token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"`,
			},
			line: 5, col: 12, want: true,
		},
		{
			name:  "same line but far away — the blob case",
			lines: []string{longLineWith(100_000, 0, "maven")},
			line:  1, col: 90_000, want: false,
		},
		{
			name:  "absent entirely",
			lines: []string{`token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"`},
			line:  1, col: 9, want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := contextHasKeyword(tc.lines, tc.line, tc.col, contextWindow, []string{"maven"})
			if got != tc.want {
				t.Errorf("contextHasKeyword = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAFarAwayExcludeKeywordDoesNotSuppress is the same defect in the direction
// that costs a finding rather than inventing one, which is the worse of the two.
//
// ExcludeContextKeywords drops a match when a word like "example" or "sample"
// sits near it. On a line that is 200k characters of data, an accidental
// "example" anywhere suppresses every real credential on that line — and a
// suppressed finding is silent by construction.
func TestAFarAwayExcludeKeywordDoesNotSuppress(t *testing.T) {
	lines := []string{longLineWith(200_000, 0, "example")}
	if codeContextHasKeyword(lines, 1, 190_000, contextWindow, []string{"example"}) {
		t.Error("a keyword 190k characters away suppresses the match; a real " +
			"credential in a large minified file would be dropped in silence")
	}
	// Adjacent, it must still suppress.
	near := []string{`token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" # example only`}
	if !codeContextHasKeyword(near, 1, 9, contextWindow, []string{"example"}) {
		t.Error("an adjacent exclude keyword no longer suppresses; the control lost its purpose")
	}
}
