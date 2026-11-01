package rules

import (
	"bytes"
	"slices"
	"testing"
)

// An empty keyword occurs in every file: the keyword index answers it with
// bytes.Contains, which is true for an empty needle. The one-pass pre-filter
// indexed it as k[0] and panicked, which the main-branch fuzz job found and a
// custom rule declaring `keywords: [""]` would have hit on every file.
func TestEmptyKeywordIsPresentEverywhere(t *testing.T) {
	x := newLiteralIndex([]*Rule{{Keywords: []string{""}}})
	for _, content := range [][]byte{nil, []byte(""), []byte("x"), []byte("KEY = 1")} {
		want := x.keywords.present(bytes.ToLower(content))
		got := (&fileLiterals{index: x}).keywordsPresent(content)
		if got != nil && !slices.Equal(got, want) {
			t.Errorf("content %q: one pass %v, keyword index %v", content, got, want)
		}
		if len(want) != 1 || !want[0] {
			t.Errorf("content %q: keyword index says the empty keyword is absent", content)
		}
	}
	if !asciiFoldContains([]byte("abc"), nil) || !asciiFoldContains(nil, nil) {
		t.Error("asciiFoldContains: the empty keyword must occur in every content")
	}
}
