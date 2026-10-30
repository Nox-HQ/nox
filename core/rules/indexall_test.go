package rules

import (
	"bytes"
	"math/rand"
	"reflect"
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
