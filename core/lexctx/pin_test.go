package lexctx

import (
	"math/rand"
	"reflect"
	"testing"
)

// The pin is an optimisation and nothing else: for every input the pinned
// answer must equal the function's own definition, which is what an
// unpinned slice (a copy of the same bytes) computes.
func TestPinnedAnswersEqualTheDefinition(t *testing.T) {
	r := rand.New(rand.NewSource(826))
	alphabet := []byte("ab \n\n\"'#/*\\=:x{}")
	for trial := 0; trial < 400; trial++ {
		n := r.Intn(300)
		if trial%50 == 0 {
			n = 0
		}
		content := make([]byte, n)
		for i := range content {
			content[i] = alphabet[r.Intn(len(alphabet))]
		}
		if trial%7 == 0 && n > 0 {
			content[n-1] = '\n'
		}
		plain := append([]byte(nil), content...) // a different slice: never pinned
		release := Pin(content)
		for q := 0; q < 200; q++ {
			line, col := r.Intn(n/5+4)-1, r.Intn(n+6)-2
			if got, want := LineColToOffset(content, line, col), LineColToOffset(plain, line, col); got != want {
				t.Fatalf("LineColToOffset(%q, %d, %d) = %d pinned, %d by definition", plain, line, col, got, want)
			}
			off := r.Intn(n+6) - 2
			if got, want := LineForOffset(content, off), LineForOffset(plain, off); got != want {
				t.Fatalf("LineForOffset(%q, %d) = %d pinned, %d by definition", plain, off, got, want)
			}
		}
		for _, lang := range []Lang{LangPython, LangJavaScript, LangGo, LangShell, LangUnknown} {
			for rep := 0; rep < 2; rep++ { // the second call is the cached one
				if got, want := Classify(lang, content), Classify(lang, plain); !reflect.DeepEqual(got, want) {
					t.Fatalf("Classify(%v, %q) pinned differs from definition", lang, plain)
				}
			}
		}
		release()
		if pinnedFor(content) != nil {
			t.Fatal("release left the content pinned")
		}
	}
}

// Only the pinned slice itself is served from the index; a subslice sharing
// its backing array takes the ordinary path.
func TestPinServesOnlyTheExactSlice(t *testing.T) {
	content := []byte("one\ntwo\nthree\n")
	defer Pin(content)()
	if pinnedFor(content) == nil {
		t.Fatal("the pinned slice was not found")
	}
	if pinnedFor(content[:5]) != nil || pinnedFor(content[1:]) != nil {
		t.Fatal("a subslice was served from the pin")
	}
}
