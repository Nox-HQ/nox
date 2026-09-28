package rules

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"sort"
	"sync"
	"unicode/utf8"
)

// Literal-prefix matching.
//
// Go's regexp scans a whole file for every rule whose keyword appears anywhere
// in it, and for a pattern with no literal prefix Go can extract -- anything
// opening with `(?i)` or an alternation -- that scan runs the general-purpose
// NFA over every byte. On the 2026-09-27 profile that was about half of all
// CPU (#736): DATA-005 alone ran over 10,000 files, and a family of `(?i)`
// vendor rules spent over a second each on crewAI's largest docs file.
//
// Many of those patterns can only START with one of a few literal words:
// `(?i)(?:phone|tel|mobile|cell)\s*[=:]…`, `(?i)mlflow[_-]?tracking…`. For such
// a pattern every match begins where one of those words occurs, so the file
// needs no scan: find each occurrence of the words (a byte search), try the
// pattern anchored there, and skip occurrences that fall inside the previous
// match. That returns exactly what FindAll returns -- the same matches, in the
// same order, with the same submatches:
//
//   - FindAll reports the leftmost match, then resumes after it. Every match
//     starts at a word occurrence, so trying each occurrence in order, from the
//     end of the previous match, visits every start FindAll could choose.
//   - A match anchored at a start is the one leftmost-first semantics picks for
//     that start, because the preference order of the alternatives does not
//     depend on where the search began.
//   - Matching continues past the start as normal, so a pattern that spans
//     lines (`\s*` crossing a newline) still matches in full.
//
// It is exact only for patterns it can prove this for, and every other pattern
// keeps the full scan (planFor returns nil):
//
//   - the first element must be a literal of two or more ASCII characters, in
//     every alternative (a leading assertion like `\b` looks at the byte
//     BEFORE the start, which an anchored match cannot see);
//   - the pattern must contain no `^` or `\A` anywhere, because in the slice a
//     match is tried on, "start of text" moves to the candidate;
//   - the pattern must not match the empty string.
//
// TestPrefixPlanMatchesFindAll holds the equivalence for every built-in rule.

// prefixPlan is how a pattern can be matched from its literal prefixes.
type prefixPlan struct {
	prefixes []literalPrefix
	anchored *regexp.Regexp // `^(?:pattern)`: matches only at the start of its input
}

type literalPrefix struct {
	text string // lower-cased when fold is set
	fold bool   // case-insensitive
}

var (
	planMu    sync.Mutex
	planCache = map[string]*prefixPlan{}
	noPlan    = &prefixPlan{} // cached "no plan" marker
)

// planFor returns the literal-prefix plan for pattern, or nil when the pattern
// does not provably start with a literal and must be scanned in full.
func planFor(pattern string) *prefixPlan {
	planMu.Lock()
	defer planMu.Unlock()
	if p, ok := planCache[pattern]; ok {
		if p == noPlan {
			return nil
		}
		return p
	}
	p := buildPlan(pattern)
	if p == nil {
		planCache[pattern] = noPlan
		return nil
	}
	planCache[pattern] = p
	return p
}

func buildPlan(pattern string) *prefixPlan {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()
	if full, err := regexp.Compile(pattern); err != nil || full.MatchString("") {
		return nil
	}
	if hasTextStartAssertion(re) {
		return nil
	}
	prefixes, ok := leadingLiterals(re)
	if !ok || len(prefixes) == 0 {
		return nil
	}
	for _, p := range prefixes {
		if len(p.text) < 2 {
			return nil // a one-character literal is too common to narrow anything
		}
	}
	anchored, err := regexp.Compile(`^(?:` + pattern + `)`)
	if err != nil {
		return nil
	}
	return &prefixPlan{prefixes: prefixes, anchored: anchored}
}

// leadingLiterals returns the literal every match must begin with, one per
// alternative, or ok=false when some match could begin otherwise.
//
// Go's parser factors shared prefixes out of an alternation, so
// `api_key|access_key|auth_token` arrives as `a` followed by
// `pi_key|ccess_key|uth_token`. A concatenation that opens with a literal is
// therefore extended with the literals of what follows, one level, so the
// factored letter and its continuations become `api`, `access`, `auth`.
//
// Any widening here is safe and any narrowing is not: every candidate is
// re-checked by the anchored match, so a candidate that cannot match costs a
// failed match, while a start the candidates miss would lose a finding. So
// where two literals disagree on case sensitivity, the combined literal is
// searched case-insensitively. Length is judged by the caller, not here.
func leadingLiterals(re *syntax.Regexp) ([]literalPrefix, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		s := string(re.Rune)
		if s == "" || !isASCII(s) {
			return nil, false
		}
		fold := re.Flags&syntax.FoldCase != 0
		if fold {
			s = string(bytes.ToLower([]byte(s)))
		}
		return []literalPrefix{{text: s, fold: fold}}, true
	case syntax.OpCapture:
		return leadingLiterals(re.Sub[0])
	case syntax.OpConcat:
		if len(re.Sub) == 0 {
			return nil, false
		}
		head, ok := leadingLiterals(re.Sub[0])
		if !ok {
			return nil, false
		}
		// Extend only a first element that is itself a plain literal: then the
		// second element really does start where the literal ends.
		if re.Sub[0].Op != syntax.OpLiteral || len(re.Sub) < 2 {
			return head, true
		}
		tail, ok := leadingLiterals(re.Sub[1])
		if !ok {
			return head, true
		}
		out := make([]literalPrefix, 0, len(tail))
		for _, t := range tail {
			fold := head[0].fold || t.fold
			text := head[0].text + t.text
			if fold {
				text = string(bytes.ToLower([]byte(text)))
			}
			out = append(out, literalPrefix{text: text, fold: fold})
		}
		return out, true
	case syntax.OpAlternate:
		var out []literalPrefix
		for _, sub := range re.Sub {
			p, ok := leadingLiterals(sub)
			if !ok {
				return nil, false
			}
			out = append(out, p...)
		}
		return out, true
	}
	return nil, false
}

// hasTextStartAssertion reports a `^` or `\A` anywhere in the pattern.
func hasTextStartAssertion(re *syntax.Regexp) bool {
	if re.Op == syntax.OpBeginText || re.Op == syntax.OpBeginLine {
		return true
	}
	for _, sub := range re.Sub {
		if hasTextStartAssertion(sub) {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// foldOutliers are the two non-ASCII runes Go's case folding equates with ASCII
// letters: KELVIN SIGN with k, LATIN SMALL LETTER LONG S with s. `(?i)key` matches
// "Key" spelled with a Kelvin sign; an ASCII search for "key" would not find
// it. A file containing either is scanned in full.
var foldOutliers = [][]byte{[]byte("\u212a"), []byte("\u017f")}

// usable reports whether the plan is exact for this content.
func (p *prefixPlan) usable(content []byte) bool {
	for _, lp := range p.prefixes {
		if !lp.fold {
			continue
		}
		for _, o := range foldOutliers {
			if bytes.Contains(content, o) {
				return false
			}
		}
		return true
	}
	return true
}

// findAll returns what re.FindAllSubmatchIndex(content, -1) would, using the
// plan. submatch=false returns only the whole-match pairs, like FindAllIndex.
// Callers check usable first.
func (p *prefixPlan) findAll(content []byte, submatch bool) [][]int {
	starts := p.candidates(content)
	var out [][]int
	resume := 0
	for _, s := range starts {
		if s < resume {
			continue
		}
		loc := p.anchored.FindSubmatchIndex(content[s:])
		if loc == nil {
			continue
		}
		for i := range loc {
			if loc[i] >= 0 {
				loc[i] += s
			}
		}
		if !submatch {
			loc = loc[:2]
		}
		out = append(out, loc)
		resume = loc[1]
	}
	return out
}

// candidates returns every offset where one of the plan's literals begins, in
// ascending order.
func (p *prefixPlan) candidates(content []byte) []int {
	seen := map[int]struct{}{}
	var out []int
	for _, lp := range p.prefixes {
		for _, at := range indexAll(content, lp) {
			if _, dup := seen[at]; !dup {
				seen[at] = struct{}{}
				out = append(out, at)
			}
		}
	}
	sort.Ints(out)
	return out
}

// indexAll returns the offsets of every occurrence of lp in content,
// overlapping occurrences included.
func indexAll(content []byte, lp literalPrefix) []int {
	var out []int
	needle := []byte(lp.text)
	if !lp.fold {
		for from := 0; ; {
			i := bytes.Index(content[from:], needle)
			if i < 0 {
				return out
			}
			out = append(out, from+i)
			from += i + 1
		}
	}
	// Case-insensitive ASCII: walk the occurrences of each case of the first
	// byte (IndexByte is vectorised), keeping the next position of each so
	// neither is rescanned, and confirm the rest with EqualFold.
	lo, up := needle[0], needle[0]
	if lo >= 'a' && lo <= 'z' {
		up = lo - 'a' + 'A'
	}
	nextLo := nextByte(content, 0, lo)
	nextUp := nextLo
	if up != lo {
		nextUp = nextByte(content, 0, up)
	}
	for nextLo >= 0 || nextUp >= 0 {
		i := nextLo
		if i < 0 || (nextUp >= 0 && nextUp < i) {
			i = nextUp
		}
		if i+len(needle) <= len(content) && bytes.EqualFold(content[i:i+len(needle)], needle) {
			out = append(out, i)
		}
		if i == nextLo {
			nextLo = nextByte(content, i+1, lo)
		}
		if i == nextUp {
			nextUp = nextByte(content, i+1, up)
		}
	}
	return out
}

// nextByte returns the offset of the first c at or after from, or -1.
func nextByte(b []byte, from int, c byte) int {
	if from >= len(b) {
		return -1
	}
	j := bytes.IndexByte(b[from:], c)
	if j < 0 {
		return -1
	}
	return from + j
}
