package rules

import (
	"bytes"
	"math/rand"
	"reflect"
	"regexp"
	"slices"
	"testing"
)

// indexAllOracle is the definition indexAll must keep: every offset where the
// literal occurs, overlapping occurrences included, ASCII case ignored for a
// fold literal.
func indexAllOracle(content []byte, lp literalPrefix) []int {
	var out []int
	needle := []byte(lp.text)
	for i := 0; i+len(needle) <= len(content); i++ {
		w := content[i : i+len(needle)]
		if (lp.fold && bytes.EqualFold(w, needle)) || (!lp.fold && bytes.Equal(w, needle)) {
			out = append(out, i)
		}
	}
	return out
}

var indexAllNeedles = []literalPrefix{
	{text: "apiversion:", fold: true}, {text: "secret", fold: true}, {text: "aa", fold: true},
	{text: "twitter", fold: true}, {text: "_key", fold: true}, {text: "f\"", fold: true},
	{text: "k8s", fold: true}, {text: "ss", fold: true}, {text: "arn:aws", fold: false},
	{text: "https://", fold: false}, {text: "AKIA", fold: false},
}

func assertIndexAll(t *testing.T, content []byte, lp literalPrefix) {
	t.Helper()
	got, want := indexAll(content, lp), indexAllOracle(content, lp)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("indexAll(%q, %+v) = %v, want %v", content, lp, got, want)
	}
}

// The occurrences are found from the needle's rarest byte rather than its
// first, so a candidate's start is the hit minus that byte's offset; the
// cases pin the edges of that: a hit too near either end of the file, runs of
// overlapping occurrences, both cases of the rare byte, and the case-fold
// outliers, which are not ASCII case variants.
func TestIndexAllMatchesTheOracle(t *testing.T) {
	pieces := []string{
		"", " ", "\n", "a", "A", "s", "S", "e", "k", "K", "K", "ſ", ":", "_", "\"", "f", "F",
		"apiVersion:", "APIVERSION:", "apiversion", "SeCrEt", "secre", "twitTER", "_KEY", "aaa",
		"k8S", "ssss", "arn:aws", "ARN:AWS", "https://", "AKIA", "akia", "\xff",
	}
	r := rand.New(rand.NewSource(736))
	for range 20000 {
		var b []byte
		for range r.Intn(10) {
			b = append(b, pieces[r.Intn(len(pieces))]...)
		}
		for _, lp := range indexAllNeedles {
			assertIndexAll(t, b, lp)
		}
	}
}

func FuzzIndexAllMatchesTheOracle(f *testing.F) {
	f.Add([]byte("apiVersion: v1\nkind: Secret\n"))
	f.Add([]byte("aaaa AAAA Key ssſs"))
	f.Fuzz(func(t *testing.T, content []byte) {
		for _, lp := range indexAllNeedles {
			assertIndexAll(t, content, lp)
		}
	})
}

// The one-pass index (literalindex.go) must find what indexAll finds, for
// every literal it holds: the same offsets, overlapping ones included, in the
// same order. Seeded corpus of patterns and contents, as above.
func TestLiteralIndexMatchesIndexAll(t *testing.T) {
	r := rand.New(rand.NewSource(952))
	held := 0
	for range 2000 {
		var rules []*Rule
		for range 1 + r.Intn(8) {
			pattern := regexp.QuoteMeta(string(randomBytes(r, 2+r.Intn(5), "aAbB-_:")))
			if r.Intn(2) == 0 {
				pattern = "(?i)" + pattern
			}
			rules = append(rules, &Rule{MatcherType: "regex", Pattern: pattern + "x"})
		}
		x := newLiteralIndex(rules)
		held += len(x.lits)
		content := randomBytes(r, r.Intn(200), "aAbB-_:x\n")
		// A literal flush with either end of the file is the edge of the
		// pass's last and first windows; random content rarely makes one.
		if len(x.lits) > 0 && r.Intn(2) == 0 {
			lit := []byte(x.lits[r.Intn(len(x.lits))].text)
			if r.Intn(2) == 0 {
				content = append(content, lit...)
			} else {
				content = append(lit, content...)
			}
		}
		assertIndexMatches(t, x, content)
	}
	if held == 0 {
		t.Fatal("the index held no literal; nothing was compared")
	}
}

// FuzzLiteralIndexMatchesIndexAll explores beyond the seeded corpus.
func FuzzLiteralIndexMatchesIndexAll(f *testing.F) {
	f.Add("Bab-a", true, []byte("xxbAB-ABab-a\nbab"))
	f.Add("a:b", false, []byte("a:ba:bA:b"))
	f.Fuzz(func(t *testing.T, needle string, fold bool, content []byte) {
		pattern := regexp.QuoteMeta(needle)
		if fold {
			pattern = "(?i)" + pattern
			// Plans never search a file holding a fold outlier (usableIn).
			for _, o := range foldOutliers {
				if bytes.Contains(content, o) {
					return
				}
			}
		}
		assertIndexMatches(t, newLiteralIndex([]*Rule{{MatcherType: "regex", Pattern: pattern}}), content)
	})
}

func assertIndexMatches(t *testing.T, x *literalIndex, content []byte) {
	t.Helper()
	occ := x.occurrences(content)
	for n, lp := range x.lits {
		if got, want := occ[n], indexAll(content, lp); !slices.Equal(got, want) {
			t.Fatalf("%+v in %q: index %v, indexAll %v", lp, content, got, want)
		}
	}
}

func randomBytes(r *rand.Rand, n int, alphabet string) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return b
}

// The keyword pre-filters are answered from the same pass (literalindex.go).
// That answer must be the one the keyword index gives over the lower-cased
// file, or nil where it cannot be: a file holding a lower outlier.
func TestKeywordsPresentMatchesKeywordIndex(t *testing.T) {
	pieces := []string{
		"", " ", "\n", "k", "K", "e", "y", "i", "I", "d", "D", "ſ", "K", "İ", "\xff",
		"key", "KEY", "Id", "token", "TOKEN", "tok", "en", "_",
	}
	words := []string{"key", "KEY", "Key", "id", "ID", "token", "Token", "ke", "k", "en_", "yk"}
	r := rand.New(rand.NewSource(954))
	answered := 0
	for range 5000 {
		var rules []*Rule
		for range 1 + r.Intn(4) {
			var kws []string
			for range 1 + r.Intn(3) {
				kws = append(kws, words[r.Intn(len(words))])
			}
			rules = append(rules, &Rule{MatcherType: "regex", Pattern: "x", Keywords: kws})
		}
		var content []byte
		for range r.Intn(12) {
			content = append(content, pieces[r.Intn(len(pieces))]...)
		}
		if assertKeywordsPresent(t, newLiteralIndex(rules), content) {
			answered++
		}
	}
	if answered < 2500 {
		t.Fatalf("the one pass answered %d of 5000 files; the fallback is hiding the comparison", answered)
	}
}

// FuzzKeywordsPresentMatchesKeywordIndex explores beyond the seeded corpus.
func FuzzKeywordsPresentMatchesKeywordIndex(f *testing.F) {
	f.Add("key", []byte("KEY = 1"))
	f.Add("id", []byte("İD_TOKEN"))
	f.Fuzz(func(t *testing.T, keyword string, content []byte) {
		assertKeywordsPresent(t, newLiteralIndex([]*Rule{{Keywords: []string{keyword}}}), content)
	})
}

// assertKeywordsPresent reports whether the one pass answered.
func assertKeywordsPresent(t *testing.T, x *literalIndex, content []byte) bool {
	t.Helper()
	want := x.keywords.present(bytes.ToLower(content))
	got := (&fileLiterals{index: x}).keywordsPresent(content)
	if got == nil {
		lower := false
		for _, o := range lowerOutliers {
			lower = lower || bytes.Contains(content, o)
		}
		if !lower && x.kwLit != nil {
			t.Fatalf("keywords %q in %q: no answer, but nothing prevents one", x.keywords.keywords, content)
		}
		return false
	}
	if !slices.Equal(got, want) {
		t.Fatalf("keywords %q in %q: one pass %v, keyword index %v", x.keywords.keywords, content, got, want)
	}
	return true
}

// asciiFoldContainsOracle is the definition asciiFoldContains keeps: k, ASCII
// case ignored, starts at some position of content.
func asciiFoldContainsOracle(content, k []byte) bool {
	for i := 0; i+len(k) <= len(content); i++ {
		if bytes.EqualFold(content[i:i+len(k)], k) {
			return true
		}
	}
	return false
}

// TestAsciiFoldContainsMatchesTheOracle covers the short keywords the
// catalog holds (letters, digits, punctuation, mixed), first bytes of either
// case dense and absent, and occurrences flush against either end.
func TestAsciiFoldContainsMatchesTheOracle(t *testing.T) {
	keywords := []string{"k", "4", "=", "..", "s.", "sk", "de", "jd", "ey", "22", "s3", "key"}
	r := rand.New(rand.NewSource(961))
	for range 20000 {
		k := []byte(keywords[r.Intn(len(keywords))])
		content := randomBytes(r, r.Intn(24), "sSkKdDeEjJyY.=4235 \n\xff")
		if got, want := asciiFoldContains(content, k), asciiFoldContainsOracle(content, k); got != want {
			t.Fatalf("asciiFoldContains(%q, %q) = %v, want %v", content, k, got, want)
		}
	}
}

func FuzzAsciiFoldContainsMatchesTheOracle(f *testing.F) {
	f.Add([]byte("xxSK"), []byte("sk"))
	f.Add([]byte("Jd"), []byte("jd"))
	f.Fuzz(func(t *testing.T, content, k []byte) {
		if len(k) == 0 {
			return
		}
		k = bytes.ToLower(k)
		if !isASCII(string(k)) {
			return
		}
		if got, want := asciiFoldContains(content, k), asciiFoldContainsOracle(content, k); got != want {
			t.Fatalf("asciiFoldContains(%q, %q) = %v, want %v", content, k, got, want)
		}
	})
}
