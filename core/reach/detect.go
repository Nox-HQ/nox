package reach

import (
	"regexp"
	"sort"
)

// marker ties a source construct to the limitation it imposes on any analysis
// of the file containing it.
type marker struct {
	limitation Limitation
	pattern    *regexp.Regexp
}

// markers are the constructs that defeat static analysis.
//
// # What is deliberately NOT here
//
// Dynamic dispatch. An interface value whose concrete type comes from data is a
// real limitation and the second case in the hard corpus, and it cannot be
// detected this way: `interface{}` and `any` appear in ordinary Go constantly,
// so a marker for them fires on almost every file. A limitation reported on
// every file carries no information and trains a reader to skip the field,
// which is worse than not reporting it.
//
// That was measured rather than assumed. The first version of this list
// included `interface{}` and a bare `import (`, and on the five-case hard
// corpus it reported dynamic_loading for all five — including the three files
// that contain no dynamic loading at all, because Go's own import block matched.
// A detector that fires everywhere is not a detector.
//
// Lexical on purpose. Recognising these properly means resolving types, which
// is the very analysis the construct defeats — so the detector cannot be
// stronger than the thing it is reporting on. What saves it is the DIRECTION of
// the error: a marker only ever ADDS a limitation, which only ever makes a
// claim weaker. A false positive here means nox says "I may have missed
// something" when it did not, and a scope carrying a spurious limitation can
// still Establish; it just cannot Refute. Failing toward "I could not tell" is
// the safe direction for a tool whose most dangerous output is a negative.
var markers = []marker{
	{Reflection, regexp.MustCompile(`\breflect\.(ValueOf|TypeOf)\b|\bMethodByName\b|\bgetattr\(|\b__import__\(|\beval\(`)},
	{DynamicLoading, regexp.MustCompile(`\bplugin\.Open\b|\bdlopen\b|\bimportlib\b|\bLoadLibrary\b`)},
	{ForeignFunctions, regexp.MustCompile(`import "C"|\bunsafe\.Pointer\b|\bsyscall\.Syscall\b|\bctypes\b|\bJNIEnv\b`)},
}

// Detect returns the limitations a file's contents impose on any analysis of
// it, sorted and deduplicated.
//
// This is the honest half of what nox can say about its own incompleteness. It
// cannot say WHICH flow a reflective call defeated — that needs the engine to
// know it was defeated, and the engine does not. It can say that this file
// contains a call whose target is a string at runtime, which is enough for a
// reader to know that "no flow found here" is a statement about what was
// visible.
//
// Measured on testdata/refutation-hard, where four of five cases produced
// complete silence: nox formed no candidate, so it had nothing to attach an
// explanation to and said nothing at all. A reader could not distinguish that
// from a clean file.
func Detect(content []byte) []Limitation {
	seen := map[Limitation]bool{}
	for _, m := range markers {
		if m.pattern.Match(content) {
			seen[m.limitation] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]Limitation, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
