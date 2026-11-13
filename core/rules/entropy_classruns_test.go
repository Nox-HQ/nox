package rules

import (
	"math/rand"
	"regexp"
	"slices"
	"testing"
)

// The regexps the base64 and hex tokenizers replaced; extractClassRuns must
// report exactly their matches.
var (
	base64CandidateOracle = regexp.MustCompile(`[A-Za-z0-9+/=]{30,}`)
	hexCandidateOracle    = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
)

type classRunCandidate struct {
	col  int
	text string
}

func assertClassRunsMatchRegexp(t *testing.T, line string) {
	t.Helper()
	for _, c := range []struct {
		class  *[256]bool
		re     *regexp.Regexp
		minLen int
	}{{base64Chars, base64CandidateOracle, 30}, {hexChars, hexCandidateOracle, 32}} {
		var want, got []classRunCandidate
		for _, loc := range c.re.FindAllStringIndex(line, -1) {
			want = append(want, classRunCandidate{loc[0] + 1, line[loc[0]:loc[1]]})
		}
		extractClassRuns(line, c.class, c.minLen, func(col int, text string) {
			got = append(got, classRunCandidate{col, text})
		})
		if !slices.Equal(got, want) {
			t.Fatalf("line %q, %s: got %v, want %v", line, c.re, got, want)
		}
	}
}

// TestClassRunsMatchTheRegexp draws lines from the classes' edges: runs of
// hex, of base64 outside hex, '=', bytes just outside both classes, and
// multi-byte and invalid UTF-8, with run lengths around both minimums.
func TestClassRunsMatchTheRegexp(t *testing.T) {
	pieces := []string{"a", "F", "9", "g", "Z", "+", "/", "=", "-", "_", ".", " ", "é", "\xff", "\xc3"}
	r := rand.New(rand.NewSource(963))
	for range 20000 {
		var line []byte
		for range r.Intn(6) {
			p := pieces[r.Intn(len(pieces))]
			for range 1 + r.Intn(40) {
				line = append(line, p...)
			}
		}
		assertClassRunsMatchRegexp(t, string(line))
	}
	for _, line := range []string{"", "0123456789abcdef0123456789abcdef", "x0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdefé"} {
		assertClassRunsMatchRegexp(t, line)
	}
}

func FuzzClassRunsMatchTheRegexp(f *testing.F) {
	f.Add("key = \"0123456789abcdef0123456789abcdef\"")
	f.Add("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=")
	f.Fuzz(func(t *testing.T, line string) {
		assertClassRunsMatchRegexp(t, line)
	})
}
