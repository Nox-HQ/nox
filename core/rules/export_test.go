package rules

import (
	"bytes"
	"strings"
)

// PrefixFindAll exposes the literal-prefix path to the equivalence test:
// the locations it returns for pattern, and whether the pattern has a plan.
func PrefixFindAll(pattern string, content []byte, submatch bool) ([][]int, bool) {
	p := planFor(pattern)
	if p == nil || !p.usable(content) {
		return nil, false
	}
	return p.findAll(content, submatch), true
}

// KeywordsPresent exposes the keyword index to the fixture test: for each of
// keywords, whether the index finds it in content.
func KeywordsPresent(keywords []string, content []byte) []bool {
	x := newKeywordIndex([]*Rule{{Keywords: keywords}})
	present := x.present(bytes.ToLower(content))
	at := make(map[string]int, len(x.keywords))
	for n, kw := range x.keywords {
		at[string(kw)] = n
	}
	out := make([]bool, len(keywords))
	for i, k := range keywords {
		out[i] = present[at[strings.ToLower(k)]]
	}
	return out
}
