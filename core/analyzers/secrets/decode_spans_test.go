package secrets

import (
	"math/rand"
	"regexp"
	"slices"
	"testing"
)

// The regular expressions the span scanners replaced. They are the
// specification: a scanner that reports anything other than exactly their
// leftmost-first matches changes which segments get decoded, and so which
// encoded secrets are found.
var (
	oracleBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	oracleHex    = regexp.MustCompile(`(?i)[0-9a-f]{40,}`)
)

func oracleSpans(re *regexp.Regexp, content []byte) [][2]int {
	var spans [][2]int
	for _, loc := range re.FindAllIndex(content, -1) {
		spans = append(spans, [2]int{loc[0], loc[1]})
	}
	return spans
}

func assertSpansMatchOracle(t *testing.T, content []byte) {
	t.Helper()
	if got, want := base64Spans(content), oracleSpans(oracleBase64, content); !slices.Equal(got, want) {
		t.Fatalf("base64Spans(%q) = %v, regex reports %v", content, got, want)
	}
	if got, want := hexSpans(content), oracleSpans(oracleHex, content); !slices.Equal(got, want) {
		t.Fatalf("hexSpans(%q) = %v, regex reports %v", content, got, want)
	}
}

// spanPieces are the fragments the generated corpus is assembled from: runs
// either side of the 40-character minimum, padding of every length the
// pattern does and does not accept, characters in one alphabet but not the
// other, the case-fold outliers (Kelvin sign, long s) and multi-byte and invalid UTF-8.
var spanPieces = []string{
	"", "=", "==", "===", "+", "/", "-", "_", " ", "\n", "\"",
	"g", "G", "f", "F", "0", "z",
	"\u212a", "\u017f", "\u00e9", "\xff", "\xc3",
}

func randomRun(r *rand.Rand, alphabet string) string {
	n := 30 + r.Intn(25) // straddles the 40-character minimum
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func TestSpansMatchRegexOnGeneratedCorpus(t *testing.T) {
	const (
		b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		hexAlphabet = "0123456789abcdefABCDEF"
	)
	r := rand.New(rand.NewSource(736))
	for range 20000 {
		var content []byte
		for range 1 + r.Intn(6) {
			switch r.Intn(3) {
			case 0:
				content = append(content, randomRun(r, b64Alphabet)...)
			case 1:
				content = append(content, randomRun(r, hexAlphabet)...)
			default:
				content = append(content, spanPieces[r.Intn(len(spanPieces))]...)
			}
		}
		assertSpansMatchOracle(t, content)
	}
}

func FuzzSpansMatchRegex(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("c2stbGl2ZS1hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Ng=="))
	f.Add([]byte("c2stbGl2ZS1hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Ng===AAAA"))
	f.Add([]byte("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
	f.Add([]byte("DA39A3EE5E6B4B0D3255BFEF95601890AFD8070\u212a"))
	f.Add([]byte("key: \"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo-_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo\""))
	f.Fuzz(func(t *testing.T, content []byte) {
		assertSpansMatchOracle(t, content)
	})
}

// benchmarkContent is a recorded-cassette-shaped file: YAML around long
// base64 bodies, the shape that made the segment regexes expensive.
func benchmarkContent() []byte {
	r := rand.New(rand.NewSource(1))
	var b []byte
	for range 200 {
		b = append(b, "  - request:\n      body: \""...)
		b = append(b, randomRun(r, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")...)
		b = append(b, randomRun(r, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")...)
		b = append(b, "==\"\n      sha: da39a3ee5e6b4b0d3255bfef95601890afd80709\n"...)
	}
	return b
}

func BenchmarkSpansRegex(b *testing.B) {
	content := benchmarkContent()
	b.SetBytes(int64(len(content)))
	for b.Loop() {
		oracleBase64.FindAllIndex(content, -1)
		oracleHex.FindAllIndex(content, -1)
	}
}

func BenchmarkSpansScanner(b *testing.B) {
	content := benchmarkContent()
	b.SetBytes(int64(len(content)))
	for b.Loop() {
		base64Spans(content)
		hexSpans(content)
	}
}
