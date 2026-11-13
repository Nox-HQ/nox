package deps

import (
	"strings"
	"testing"
)

// Distribution advisories often carry no summary. The message used to be
// assembled as "…in zlib@1.3.2-r1: " + "" + " — " + the applicability
// sentence, which printed ":  —": punctuation around nothing.
func TestHeadlineWithoutASummarySaysSo(t *testing.T) {
	tests := []struct {
		name    string
		summary string
		want    string
	}{
		{"summary", "Heap overflow in inflate", "Known vulnerability CVE-1 in zlib@1.3.2-r1: Heap overflow in inflate"},
		{"empty", "", "Known vulnerability CVE-1 in zlib@1.3.2-r1 (the advisory carries no summary)"},
		{"blank", " \n", "Known vulnerability CVE-1 in zlib@1.3.2-r1 (the advisory carries no summary)"},
		{"padded", "  Heap overflow\n", "Known vulnerability CVE-1 in zlib@1.3.2-r1: Heap overflow"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := headline("Known vulnerability CVE-1", "zlib", "1.3.2-r1", tc.summary)
			if got != tc.want {
				t.Errorf("headline = %q, want %q", got, tc.want)
			}
			if strings.HasSuffix(got, ": ") || strings.HasSuffix(got, ":") {
				t.Errorf("headline %q ends in a colon with nothing after it", got)
			}
		})
	}
}
