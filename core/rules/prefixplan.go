package rules

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode"
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
//     every alternative -- or `\b` followed by such literals that all begin
//     with a word character, where the boundary is checked on the byte before
//     the candidate, since an anchored match cannot see it;
//   - the pattern must contain no `^` or `\A` anywhere, because in the slice a
//     match is tried on, "start of text" moves to the candidate;
//   - the pattern must not match the empty string.
//
// A second shape is the vendor-token template, `(?i)[\w.-]{0,50}?(?:okta)…`:
// a bounded run of one character class, then a literal. A match starts
// somewhere in the run of class characters before an occurrence of the
// literal, so it is found from the literal too (see leadRun). An optional
// character is a run of at most one (MCP-016's `(?i)"?(?:forward|…)`), and a
// run of word characters may follow `\b` (SEC-469's `\b[A-Z0-9_]*(?:TOKEN|…)`).
//
// A third shape opens with a character class: DATA-003's card numbers,
// `\b(?:4[0-9]{12}…|5[1-5][0-9]{14}…)\b`, DATA-002's SSNs. Nothing literal is
// shared, but the bytes a match can start with are known, and with `\b`
// before them most occurrences are excluded by the byte before. Every match
// starts at one of those bytes, so they are the candidates (see firstBytes).
//
// A fourth shape is anchored to a line: `(?m)^P R`, where P cannot match a
// newline and R opens with literals, like the Ansible markers' `(?m)^[ \t]*-?
// [ \t]*(?:hosts|tasks|…):`. A match starts at the start of a line holding
// one of R's literals, so those line starts are the candidates (see
// buildLinePlan). This is the one shape a `^` is allowed in.
//
// TestPrefixPlanMatchesFindAll holds the equivalence for every built-in rule.

// prefixPlan is how a pattern can be matched from its literal prefixes.
type prefixPlan struct {
	prefixes []literalPrefix
	anchored *regexp.Regexp // `^(?:pattern)`: matches only at the start of its input
	// leadBoundary: the pattern opens with `\b`. The anchored match cannot see
	// the byte before a candidate, so the boundary is checked here instead:
	// every literal starts with a word character, which makes `\b` at the
	// candidate exactly "the previous byte is not a word character".
	leadBoundary bool
	// maxLen bounds the bytes one match can span; -1 when unbounded.
	maxLen int
	// lead is set when the pattern opens with a run of one character class
	// before its literals; prefixes, anchored and leadBoundary then describe
	// what follows the run.
	lead *leadRun
	// first is set when the pattern opens with a character class: the bytes
	// a match can start with. They replace prefixes as the candidates.
	first *[256]bool
	// follow, with first, holds the bytes each next position of a match can
	// be, for as many positions as every match fills with one ASCII byte:
	// DATA-007's `\b[A-Z]{2}\d{2}\s?…` gives [A-Z], [0-9], [0-9]. A first
	// byte not followed by bytes of these sets cannot start a match.
	follow []*[256]bool
	// after, for a plan whose prefixes are exactly what the pattern's opening
	// literals match, holds the bytes the rest of the pattern can start with:
	// DATA-005's `(?i)(?:ip|host|server|addr)\s*[=:]…` gives whitespace, `=`
	// and `:`. An occurrence followed by any other byte cannot start a match.
	after *[256]bool
	// line is set for a pattern `(?m)^P R` where P cannot match a newline and
	// R opens with prefixes: the candidates are the starts of the lines the
	// prefixes occur on (see buildLinePlan).
	line bool
}

// leadRun is a pattern `C{0,max}R` (lazy or greedy) whose rest R opens with
// literals. The leftmost match cannot be found by trying the literals alone,
// because it starts before them, but its start is determined by them:
//
//   - The pattern matches at s exactly when R matches at some t >= s with
//     content[s:t] made of at most max runes of C. Greediness only decides
//     which t, not whether there is one.
//   - Let t be the first offset at or after the previous match's end where R
//     matches. Any start s the search could report has its t' >= t, and
//     content[s:t] is a prefix of content[s:t'], so s is no earlier than the
//     furthest point the run of C before t reaches back (capped at max runes
//     and at the previous match's end). That point is a start, so it is the
//     leftmost one.
//
// Two runs in a row, `C1{0,m1}C2{0,m2}R` (SEC-286's `[\w.-]{0,50}?(?i:[\w.-]
// {0,50}?…`), are taken only when C1 is within C2. Then walking back over as
// much of C2 as allowed, and from there over C1, reaches the furthest start:
// a split point later than the greedy one leaves C2 characters for the C1 run,
// which, being in C1 too, only spend that run's allowance sooner.
//
// The match itself is then the full pattern anchored there, as for a literal
// start. Walking back needs rune boundaries that agree with the forward
// search, so the path is used only on valid UTF-8.
type leadRun struct {
	runs     []classRun // in pattern order
	anchored *regexp.Regexp
	// boundary: the pattern opens with `\b` before its runs, which are all
	// word characters, as is every literal's first byte. Then a start inside
	// the run has a word character on both sides, so the furthest start is
	// the only one `\b` can hold at, and the anchored match, which cannot see
	// the byte before it, has it checked here.
	boundary bool
}

type classRun struct {
	class []rune // the class's ranges, as syntax.Regexp.Rune: lo, hi pairs
	max   int    // at most this many runes of it; -1 for no bound
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
		return buildLinePlan(pattern, re)
	}
	body, leadBoundary := stripLeadingBoundary(re)
	prefixes, ok := leadingLiterals(body)
	if !ok || len(prefixes) == 0 {
		if p := buildLeadPlan(pattern); p != nil {
			return p
		}
		return buildFirstBytePlan(pattern, re, body, leadBoundary)
	}
	if leadBoundary {
		for _, p := range prefixes {
			if !isWordByte(p.text[0]) {
				return nil
			}
		}
	}
	for _, p := range prefixes {
		if len(p.text) < 2 {
			// A one-character literal is too common to search for as a word,
			// but `4|5[1-5]` is a set of first bytes like any other.
			return buildFirstBytePlan(pattern, re, body, leadBoundary)
		}
	}
	anchored, err := regexp.Compile(`^(?:` + pattern + `)`)
	if err != nil {
		return nil
	}
	return &prefixPlan{prefixes: prefixes, anchored: anchored, leadBoundary: leadBoundary, maxLen: maxBytes(re), after: afterPrefixes(body, prefixes)}
}

// buildLinePlan returns the plan for a line-anchored pattern, `(?m)^P R`, or
// nil. re is the simplified pattern. IAC-351 and the Ansible markers open
// this way: `(?m)^[ \t]*-?[ \t]*(?:hosts|tasks|…)[ \t]*:`. A match starts at
// a line start, and the anchored match regexp would try at every byte.
//
// When nothing P matches can hold a newline, a match at line start s reaches
// R on the same line, and R starts with one of its prefixes. So every match
// starts at the start of a line holding a prefix occurrence; trying those
// line starts in order, each skipped once a match has ended past it, finds
// the matches regexp finds. Slicing the content at a line start hides only a
// newline before it, which every assertion sees as it sees the start of the
// text: `^` holds, and `\b` treats both as a non-word byte. R is the shortest
// tail of the concatenation that has a literal plan of its own, so P is
// whatever comes between the anchor and the first literals.
func buildLinePlan(pattern string, re *syntax.Regexp) *prefixPlan {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 || re.Sub[0].Op != syntax.OpBeginLine {
		return nil
	}
	prefixes, ok := lineLiterals(re.Sub[1:], re.Flags)
	if !ok {
		return nil
	}
	anchored, err := regexp.Compile(`^(?:` + pattern + `)`)
	if err != nil {
		return nil
	}
	return &prefixPlan{prefixes: prefixes, anchored: anchored, maxLen: maxBytes(re), line: true}
}

// lineLiterals returns literals one of which every match of the concatenation
// subs holds on its first line, reached only over elements withinLine allows.
// At each element it first asks whether the rest has a literal plan of its
// own; failing that, an alternation is followed down each branch with what
// comes after it (IAC-351's `(?:PASSWORD|SECRET_KEY|(?:[A-Z0-9_]*_)?TOKEN)`,
// whose last branch reaches its literal over a run), and every branch must
// yield literals; otherwise the element is skipped if it cannot hold a
// newline.
func lineLiterals(subs []*syntax.Regexp, flags syntax.Flags) ([]literalPrefix, bool) {
	for k := range subs {
		rest := &syntax.Regexp{Op: syntax.OpConcat, Flags: flags, Sub: subs[k:]}
		if len(rest.Sub) == 1 {
			rest = rest.Sub[0]
		}
		if p := buildPlan(rest.String()); p != nil && p.lead == nil && p.first == nil && !p.line {
			return p.prefixes, true
		}
		alt := subs[k]
		for alt.Op == syntax.OpCapture {
			alt = alt.Sub[0]
		}
		if alt.Op == syntax.OpAlternate {
			if out, ok := branchLineLiterals(alt, subs[k+1:], flags); ok {
				return out, true
			}
		}
		if !withinLine(subs[k]) {
			return nil, false
		}
	}
	return nil, false
}

// branchLineLiterals is lineLiterals down every branch of alt, each followed
// by after.
func branchLineLiterals(alt *syntax.Regexp, after []*syntax.Regexp, flags syntax.Flags) ([]literalPrefix, bool) {
	var out []literalPrefix
	for _, b := range alt.Sub {
		elems := []*syntax.Regexp{b}
		if b.Op == syntax.OpConcat {
			elems = slices.Clone(b.Sub)
		}
		lits, ok := lineLiterals(append(elems, after...), flags)
		if !ok {
			return nil, false
		}
		out = append(out, lits...)
	}
	return out, true
}

// withinLine reports whether re matches only text holding no newline, and
// asserts nothing about its surroundings.
func withinLine(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpAnyCharNotNL:
		return true
	case syntax.OpLiteral:
		return !slices.Contains(re.Rune, '\n')
	case syntax.OpCharClass:
		return !inClass('\n', re.Rune)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat,
		syntax.OpConcat, syntax.OpAlternate, syntax.OpCapture:
		for _, sub := range re.Sub {
			if !withinLine(sub) {
				return false
			}
		}
		return true
	}
	return false
}

// lineStarts maps ascending offsets to the starts of their lines, each once.
// The search for each newline starts at the previous offset, so it is linear.
func lineStarts(content []byte, offsets []int) []int {
	var out []int
	ls, prev := -1, 0
	for _, t := range offsets {
		if nl := bytes.LastIndexByte(content[prev:t], '\n'); nl >= 0 {
			ls = prev + nl + 1
		} else if ls < 0 {
			ls = 0
		}
		if len(out) == 0 || out[len(out)-1] != ls {
			out = append(out, ls)
		}
		prev = t
	}
	return out
}

// buildLeadPlan returns the plan for a pattern that opens with a run of one
// character class followed by literals (see leadRun), or nil.
func buildLeadPlan(pattern string) *prefixPlan {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 {
		return nil
	}
	subs := re.Sub
	boundary := subs[0].Op == syntax.OpWordBoundary
	if boundary {
		subs = subs[1:]
	}
	var runs []classRun
	for len(runs) < 2 && len(runs) < len(subs)-1 {
		run, ok := runOf(subs[len(runs)])
		if !ok {
			break
		}
		if len(runs) > 0 && !classWithin(runs[0].class, run.class) {
			return nil
		}
		runs = append(runs, run)
	}
	if len(runs) == 0 {
		return nil
	}
	if boundary {
		// `\b` holds at the furthest start only if every byte the walk passes
		// over is a word character (see leadRun.boundary).
		for _, run := range runs {
			if !classWithin(run.class, wordClass) {
				return nil
			}
		}
	}
	rest := &syntax.Regexp{Op: syntax.OpConcat, Flags: re.Flags, Sub: subs[len(runs):]}
	if len(rest.Sub) == 1 {
		rest = rest.Sub[0]
	}
	p := buildPlan(rest.String())
	// A rest that opens with `\b` would be checked against the byte before the
	// run, not before the literal; one that has its own run, or opens with a
	// class rather than literals, is not this shape.
	if p == nil || p.leadBoundary || p.lead != nil || p.first != nil {
		return nil
	}
	if boundary {
		for _, lp := range p.prefixes {
			if !isWordByte(lp.text[0]) {
				return nil
			}
		}
	}
	anchored, err := regexp.Compile(`^(?:` + pattern + `)`)
	if err != nil {
		return nil
	}
	return &prefixPlan{
		prefixes: p.prefixes,
		anchored: p.anchored,
		maxLen:   maxBytes(re),
		lead:     &leadRun{runs: runs, anchored: anchored, boundary: boundary},
	}
}

// afterPrefixes returns the bytes that can follow a prefix in a match, or nil
// when that is not known. It is known when body is a concatenation whose
// first element (or first two) matches exactly the prefixes, each a whole
// string: then a match is one of them followed by a match of the rest, which
// cannot be empty and starts with one of firstBytes' bytes. ASCII case
// folding in the rest, or any byte past ASCII, leaves it unknown.
func afterPrefixes(body *syntax.Regexp, prefixes []literalPrefix) *[256]bool {
	for body.Op == syntax.OpCapture {
		body = body.Sub[0]
	}
	if body.Op != syntax.OpConcat {
		return nil
	}
	for k := 1; k < len(body.Sub) && k <= 2; k++ {
		head, ok := literalSet(&syntax.Regexp{Op: syntax.OpConcat, Sub: body.Sub[:k]})
		if !ok || !samePrefixes(head, prefixes) {
			continue
		}
		rest := &syntax.Regexp{Op: syntax.OpConcat, Sub: body.Sub[k:]}
		var set [256]bool
		if canBeEmpty(rest) || !firstBytes(rest, &set) {
			return nil
		}
		return &set
	}
	return nil
}

// literalSet returns every string re matches when that is a finite set of
// ASCII literals (literals, captures, alternations and concatenations of
// them), lower-cased where folded.
func literalSet(re *syntax.Regexp) ([]literalPrefix, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		s := string(re.Rune)
		if s == "" || !isASCII(s) {
			return nil, false
		}
		fold := re.Flags&syntax.FoldCase != 0
		if fold {
			s = strings.ToLower(s)
		}
		return []literalPrefix{{text: s, fold: fold}}, true
	case syntax.OpCapture:
		return literalSet(re.Sub[0])
	case syntax.OpAlternate:
		var out []literalPrefix
		for _, sub := range re.Sub {
			set, ok := literalSet(sub)
			if !ok {
				return nil, false
			}
			out = append(out, set...)
		}
		return out, true
	case syntax.OpConcat:
		out := []literalPrefix{{}}
		for _, sub := range re.Sub {
			set, ok := literalSet(sub)
			if !ok || len(out)*len(set) > maxClassLiterals*maxClassLiterals {
				return nil, false
			}
			var next []literalPrefix
			for _, a := range out {
				for _, b := range set {
					fold := a.fold || b.fold
					text := a.text + b.text
					if fold {
						text = strings.ToLower(text)
					}
					next = append(next, literalPrefix{text: text, fold: fold})
				}
			}
			out = next
		}
		return out, true
	}
	return nil, false
}

// samePrefixes reports whether a and b hold the same literals.
func samePrefixes(a, b []literalPrefix) bool {
	in := map[literalPrefix]bool{}
	for _, lp := range a {
		in[lp] = true
	}
	seen := map[literalPrefix]bool{}
	for _, lp := range b {
		if !in[lp] {
			return false
		}
		seen[lp] = true
	}
	return len(seen) == len(in)
}

// wordClass is `\w` as parsed ranges.
var wordClass = []rune{'0', '9', 'A', 'Z', '_', '_', 'a', 'z'}

// runOf reports an element that is a run of one character class with no
// minimum: `C{0,n}`, `C*`, or `C?` (a run of at most one). C is a class or a
// single character that has no other case, so MCP-016's `"?` is a run too.
func runOf(re *syntax.Regexp) (classRun, bool) {
	limit := 0
	switch {
	case re.Op == syntax.OpRepeat && re.Min == 0:
		limit = re.Max
	case re.Op == syntax.OpStar:
		limit = -1
	case re.Op == syntax.OpQuest:
		limit = 1
	default:
		return classRun{}, false
	}
	sub := re.Sub[0]
	switch {
	case sub.Op == syntax.OpCharClass:
		return classRun{class: sub.Rune, max: limit}, true
	case sub.Op == syntax.OpLiteral && len(sub.Rune) == 1 && unicode.SimpleFold(sub.Rune[0]) == sub.Rune[0]:
		return classRun{class: []rune{sub.Rune[0], sub.Rune[0]}, max: limit}, true
	}
	return classRun{}, false
}

// maxFirstBytes bounds how many distinct bytes may start a match for the
// first-byte path: [A-Z0-9] is 36. Beyond that the candidates are most of a
// file, and trying them one by one costs more than the scan.
const maxFirstBytes = 36

// buildFirstBytePlan returns the plan for a pattern that opens with a
// character class (re is the simplified pattern, body the same without a
// leading `\b`), or nil. It declines whatever it cannot prove every start of:
//
//   - a literal prefix, which regexp already skips ahead to;
//   - case folding, and any first rune outside ASCII: `(?i)[a-z]` includes
//     KELVIN SIGN, and a negated class includes every multi-byte rune;
//   - whitespace among the first bytes, or more than maxFirstBytes of them:
//     too dense to narrow anything;
//   - `\b` before a first byte that is not a word character, where the
//     boundary is not "the previous byte is not a word character";
//   - a body that can match "", whose empty matches no first byte marks.
//
// buildPlan has already declined `^`, `\A` and patterns matching "".
func buildFirstBytePlan(pattern string, re, body *syntax.Regexp, leadBoundary bool) *prefixPlan {
	full, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	if prefix, _ := full.LiteralPrefix(); prefix != "" {
		return nil
	}
	// buildPlan declined a pattern matching the empty input, but `\b[0-9]*`
	// matches "" at every boundary of a non-empty one, and no first byte
	// marks those starts.
	if canBeEmpty(body) {
		return nil
	}
	var first [256]bool
	if !firstBytes(body, &first) {
		return nil
	}
	n := 0
	for c, ok := range first {
		if !ok {
			continue
		}
		n++
		if isSpaceByte(byte(c)) || (leadBoundary && !isWordByte(byte(c))) {
			return nil
		}
	}
	if n == 0 || n > maxFirstBytes {
		return nil
	}
	anchored, err := regexp.Compile(`^(?:` + pattern + `)`)
	if err != nil {
		return nil
	}
	p := &prefixPlan{first: &first, anchored: anchored, leadBoundary: leadBoundary, maxLen: maxBytes(re)}
	var shape []*[256]bool
	fixedShape(body, &shape)
	if len(shape) > 1 {
		p.follow = shape[1:]
	}
	return p
}

// fixedShape appends to shape the bytes every match of re can have at each
// of its leading positions, for as long as each such position is one ASCII
// byte in every match, and reports whether that holds to re's end, so a
// caller may go on to what follows. Every set appended is a position no
// match can skip or widen: a literal or an ASCII class, inside captures and
// concatenations, and the first of a `+`. re is simplified, so `C{2,4}` is
// already `CC(?:CC?)?` and its two mandatory copies are reached as a
// concatenation. Anything else ends the shape.
func fixedShape(re *syntax.Regexp, shape *[]*[256]bool) bool {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return false
		}
		for _, r := range re.Rune {
			if r >= utf8.RuneSelf {
				return false
			}
			var set [256]bool
			set[r] = true
			*shape = append(*shape, &set)
		}
		return true
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return false
		}
		var set [256]bool
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi >= utf8.RuneSelf {
				return false
			}
			for c := lo; c <= hi; c++ {
				set[c] = true
			}
		}
		*shape = append(*shape, &set)
		return true
	case syntax.OpCapture:
		return fixedShape(re.Sub[0], shape)
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if !fixedShape(sub, shape) {
				return false
			}
		}
		return true
	case syntax.OpPlus:
		fixedShape(re.Sub[0], shape)
		return false
	}
	return false
}

// firstBytes adds to set every byte a match of re can start with, or reports
// false when that cannot be stated exactly as ASCII bytes. Widening is safe,
// as for literals: a byte that cannot start a match costs a failed match.
func firstBytes(re *syntax.Regexp, set *[256]bool) bool {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 || re.Flags&syntax.FoldCase != 0 || re.Rune[0] >= utf8.RuneSelf {
			return false
		}
		set[re.Rune[0]] = true
		return true
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return false
		}
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi >= utf8.RuneSelf {
				return false
			}
			for c := lo; c <= hi; c++ {
				set[c] = true
			}
		}
		return true
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		return firstBytes(re.Sub[0], set)
	case syntax.OpRepeat:
		return re.Max != 0 && firstBytes(re.Sub[0], set)
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !firstBytes(sub, set) {
				return false
			}
		}
		return true
	case syntax.OpConcat:
		// The first non-optional element ends the set; everything optional
		// before it can be skipped, so its first bytes are starts too.
		for _, sub := range re.Sub {
			if !firstBytes(sub, set) {
				return false
			}
			if !canBeEmpty(sub) {
				return true
			}
		}
		return false
	}
	return false
}

// canBeEmpty reports whether re can match without consuming input. Only the
// operators firstBytes accepts need an answer; anything else is reported as
// possibly empty, which makes firstBytes keep going and then decline.
func canBeEmpty(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral, syntax.OpCharClass:
		return false
	case syntax.OpCapture, syntax.OpPlus:
		return canBeEmpty(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min == 0 || canBeEmpty(re.Sub[0])
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if !canBeEmpty(sub) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if canBeEmpty(sub) {
				return true
			}
		}
		return false
	}
	return true
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// stripLeadingBoundary returns the pattern without a leading `\b`, and whether
// there was one. The form `\b` + rest at the top of the pattern (through
// capture groups) is recognised, and so is an alternation every branch of
// which opens with `\b`: SEC-254's `(?:\bkind:…|\bdata:…)`, which the parser
// does not factor. A boundary is a property of the position, so a match at s
// of any branch needs `\b` at s, and given it the pattern is the alternation
// of what follows. `\b` inside some alternatives only, or `\B`, leaves the
// pattern as it is, and leadingLiterals then declines it.
func stripLeadingBoundary(re *syntax.Regexp) (*syntax.Regexp, bool) {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op == syntax.OpAlternate {
		subs := make([]*syntax.Regexp, len(re.Sub))
		for i, sub := range re.Sub {
			rest, ok := stripLeadingBoundary(sub)
			if !ok {
				return re, false
			}
			subs[i] = rest
		}
		return &syntax.Regexp{Op: syntax.OpAlternate, Flags: re.Flags, Sub: subs}, true
	}
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 || re.Sub[0].Op != syntax.OpWordBoundary {
		return re, false
	}
	rest := &syntax.Regexp{Op: syntax.OpConcat, Flags: re.Flags, Sub: re.Sub[1:]}
	if len(rest.Sub) == 1 {
		return rest.Sub[0], true
	}
	return rest, true
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
	case syntax.OpCharClass:
		// `[Ss]` is one letter in either case: searched case-insensitively,
		// which widens it by at most the fold outliers (and usable refuses a
		// file containing one).
		if c, ok := casePair(re.Rune); ok {
			return []literalPrefix{{text: string(c), fold: true}}, true
		}
		// A few ASCII characters, `["']` in AI-002's `f["']`, are one literal
		// each: after a literal they extend it into as many alternatives.
		var out []literalPrefix
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				if r >= utf8.RuneSelf || len(out) == maxClassLiterals {
					return nil, false
				}
				out = append(out, literalPrefix{text: string(r)})
			}
		}
		return out, len(out) > 0
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
		if !isSingleLiteral(re.Sub[0]) || len(re.Sub) < 2 {
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

// maxClassLiterals bounds the characters a class may have to be taken as
// that many literals.
const maxClassLiterals = 4

// maxBytes bounds the bytes a match of re can span, or -1 when it cannot be
// bounded.
func maxBytes(re *syntax.Regexp) int {
	const unbounded = -1
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune) * utf8.UTFMax
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax
	case syntax.OpCapture, syntax.OpQuest:
		return maxBytes(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		if maxBytes(re.Sub[0]) == 0 {
			return 0
		}
		return unbounded
	case syntax.OpRepeat:
		n := maxBytes(re.Sub[0])
		if n == 0 {
			return 0
		}
		if n < 0 || re.Max < 0 {
			return unbounded
		}
		return n * re.Max
	case syntax.OpConcat, syntax.OpAlternate:
		total := 0
		for _, sub := range re.Sub {
			n := maxBytes(sub)
			if n < 0 {
				return unbounded
			}
			if re.Op == syntax.OpConcat {
				total += n
			} else {
				total = max(total, n)
			}
		}
		return total
	}
	return 0 // empty match and assertions
}

// isSingleLiteral reports an element that matches exactly the text
// leadingLiterals returns for it: a literal, or a case-pair class.
func isSingleLiteral(re *syntax.Regexp) bool {
	if re.Op == syntax.OpLiteral {
		return true
	}
	_, ok := casePair(re.Rune)
	return re.Op == syntax.OpCharClass && ok
}

// casePair reports a class that is one ASCII letter in both cases, possibly
// with the letter's fold outlier (Go adds it under (?i)), and returns the
// letter in lower case.
func casePair(ranges []rune) (byte, bool) {
	var rs []rune
	for i := 0; i+1 < len(ranges); i += 2 {
		for r := ranges[i]; r <= ranges[i+1]; r++ {
			if len(rs) == 3 {
				return 0, false
			}
			rs = append(rs, r)
		}
	}
	if len(rs) < 2 || rs[0] < 'A' || rs[0] > 'Z' || rs[1] != rs[0]+'a'-'A' {
		return 0, false
	}
	if len(rs) == 3 && string(rs[2]) != outlierOf(byte(rs[1])) {
		return 0, false
	}
	return byte(rs[1]), true
}

func outlierOf(c byte) string {
	switch c {
	case 'k':
		return "\u212a"
	case 's':
		return "\u017f"
	}
	return ""
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
func (p *prefixPlan) usable(content []byte) bool { return p.usableIn(nil, content) }

func (p *prefixPlan) usableIn(lits *fileLiterals, content []byte) bool {
	if p.lead != nil && !lits.validUTF8(content) {
		return false
	}
	for _, lp := range p.prefixes {
		if lp.fold {
			return !lits.hasFoldOutlier(content)
		}
	}
	return true
}

// fileLiterals remembers, for one file, the answers every plan asks of it:
// where each literal occurs, whether the file holds a fold outlier, whether it
// is valid UTF-8. Rules share literals -- `(?i)apiversion:` leads 37 IaC
// rules, and 689 of crewAI's 1,770 literal searches per file repeat one
// another's -- so each is searched once per file rather than once per rule
// (#736). With an index, the literals it holds are found together, in one
// pass over the file (see literalindex.go). A nil *fileLiterals computes every
// answer afresh.
type fileLiterals struct {
	index       *literalIndex
	indexed     [][]int // index.occurrences, once some plan has asked
	occurrences map[literalPrefix][]int
	outlier     tristate
	lower       tristate // holds a lowerOutlier
	valid       tristate
}

type tristate uint8

const (
	unknown tristate = iota
	no
	yes
)

func (l *fileLiterals) indexAll(content []byte, lp literalPrefix) []int {
	if l == nil {
		return indexAll(content, lp)
	}
	if n, ok := l.index.lookup(lp); ok {
		if l.indexed == nil {
			l.indexed = l.index.occurrences(content)
		}
		return l.indexed[n]
	}
	if at, ok := l.occurrences[lp]; ok {
		return at
	}
	if l.occurrences == nil {
		l.occurrences = map[literalPrefix][]int{}
	}
	at := indexAll(content, lp)
	l.occurrences[lp] = at
	return at
}

func (l *fileLiterals) hasFoldOutlier(content []byte) bool {
	if l == nil || l.outlier == unknown {
		found := no
		for _, o := range foldOutliers {
			if bytes.Contains(content, o) {
				found = yes
				break
			}
		}
		if l == nil {
			return found == yes
		}
		l.outlier = found
	}
	return l.outlier == yes
}

// keywordsPresent reports, for each keyword of l.index.keywords, whether it
// occurs in bytes.ToLower(content); nil when the one pass cannot say, and
// the caller asks the keyword index itself.
func (l *fileLiterals) keywordsPresent(content []byte) []bool {
	x := l.index
	if x == nil || x.kwLit == nil {
		return nil
	}
	if l.lower == unknown {
		l.lower = no
		for _, o := range lowerOutliers {
			if bytes.Contains(content, o) {
				l.lower = yes
				break
			}
		}
	}
	if l.lower == yes {
		return nil
	}
	if l.indexed == nil {
		l.indexed = x.occurrences(content)
	}
	p := make([]bool, len(x.kwLit))
	for n, id := range x.kwLit {
		if id >= 0 {
			p[n] = len(l.indexed[id]) > 0
		} else {
			p[n] = asciiFoldContains(content, x.keywords.keywords[n])
		}
	}
	return p
}

func (l *fileLiterals) validUTF8(content []byte) bool {
	if l == nil || l.valid == unknown {
		v := no
		if utf8.Valid(content) {
			v = yes
		}
		if l == nil {
			return v == yes
		}
		l.valid = v
	}
	return l.valid == yes
}

// match returns what re.FindAllSubmatchIndex(content, -1) would, or ok=false
// when the full scan should run instead: the plan is not exact for this
// content, or would cost more than the scan.
//
// Each candidate costs an anchored match, which runs until the pattern cannot
// continue. For a pattern like `(?i)(agent|bot)\s*.*?\b(auto|self)…` that is
// the rest of the line, so a file whose long lines hold many candidates --
// recorded API responses, minified bundles -- costs candidates times line
// length (808ms against the scan's 44ms on one crewAI cassette). The estimate
// charges each candidate the rest of its line, or the pattern's longest match
// when that is shorter, and the scan runs when that exceeds the file's length.
// Both paths return the same locations; this only picks the cheaper.
func (p *prefixPlan) match(content []byte, submatch bool) ([][]int, bool) {
	return p.matchIn(nil, content, submatch)
}

// matchIn is match sharing lits with the other rules scanning this file.
func (p *prefixPlan) matchIn(lits *fileLiterals, content []byte, submatch bool) ([][]int, bool) {
	if !p.usableIn(lits, content) {
		return nil, false
	}
	var starts []int
	if p.first != nil {
		var ok bool
		if starts, ok = p.firstCandidates(content, len(content)/maxFirstDensity+1); !ok {
			return nil, false
		}
	} else {
		starts = p.candidates(lits, content)
		if p.line {
			starts = lineStarts(content, starts)
		}
	}
	if p.cost(content, starts) > len(content) {
		return nil, false
	}
	return p.findAllFrom(content, starts, submatch), true
}

// firstCandidates returns the offsets of the plan's first bytes, skipping
// those `\b` rules out by the byte before. It gives up -- false, take the
// scan -- once there are more than limit (-1: no limit). match passes one in
// maxFirstDensity bytes: each candidate costs a call into regexp, so past that
// the plan is no cheaper, and a file of digits would otherwise build a
// candidate list as long as itself.
func (p *prefixPlan) firstCandidates(content []byte, limit int) ([]int, bool) {
	var out []int
	for i, c := range content {
		if !p.first[c] || (p.leadBoundary && i > 0 && isWordByte(content[i-1])) || !p.followsAt(content, i) {
			continue
		}
		if len(out) == limit {
			return nil, false
		}
		out = append(out, i)
	}
	return out, true
}

// followsAt reports whether the bytes after a first byte at i are of the
// plan's follow sets; a file ending first leaves positions no match can skip.
func (p *prefixPlan) followsAt(content []byte, i int) bool {
	if i+len(p.follow) >= len(content) {
		return len(p.follow) == 0
	}
	for k, set := range p.follow {
		if !set[content[i+1+k]] {
			return false
		}
	}
	return true
}

// maxFirstDensity: the first-byte path is used while at most one byte in this
// many is a candidate.
const maxFirstDensity = 16

// cost estimates the bytes the anchored matches from starts will read.
func (p *prefixPlan) cost(content []byte, starts []int) int {
	total, eol := 0, -1
	for _, s := range starts {
		if eol < s {
			eol = nextByte(content, s, '\n')
			if eol < 0 {
				eol = len(content)
			}
		}
		n := eol - s
		if p.maxLen >= 0 && p.maxLen < n {
			n = p.maxLen
		}
		if p.lead != nil {
			n += p.lead.backBytes()
		}
		total += n
		if total > len(content) {
			return total
		}
	}
	return total
}

// findAll is match without the cost check, for tests.
func (p *prefixPlan) findAll(lits *fileLiterals, content []byte, submatch bool) [][]int {
	if p.first != nil {
		starts, _ := p.firstCandidates(content, -1)
		return p.findAllFrom(content, starts, submatch)
	}
	starts := p.candidates(lits, content)
	if p.line {
		starts = lineStarts(content, starts)
	}
	return p.findAllFrom(content, starts, submatch)
}

// findAllFrom returns what re.FindAllSubmatchIndex(content, -1) would, using
// the plan's candidate starts. submatch=false returns only the whole-match
// pairs, like FindAllIndex. Callers check usable first.
func (p *prefixPlan) findAllFrom(content []byte, starts []int, submatch bool) [][]int {
	if p.lead != nil {
		return p.lead.findAll(p, content, starts, submatch)
	}
	var out [][]int
	resume := 0
	for _, s := range starts {
		if s < resume {
			continue
		}
		if p.leadBoundary && s > 0 && isWordByte(content[s-1]) {
			continue // `\b` does not hold here, so no match starts here
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

// findAll is prefixPlan.findAll for a pattern that opens with a run: rest is
// the plan for what follows the run.
func (l *leadRun) findAll(rest *prefixPlan, content []byte, starts []int, submatch bool) [][]int {
	var out [][]int
	resume := 0
	for _, t := range starts {
		if t < resume || !rest.anchored.Match(content[t:]) {
			continue
		}
		s := l.runStart(content, t, resume)
		if l.boundary && s > 0 && isWordByte(content[s-1]) {
			continue // no start this literal could have has `\b` before it
		}
		loc := l.anchored.FindSubmatchIndex(content[s:])
		if loc == nil {
			continue // unreachable: R matches at t and content[s:t] is the run
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

// runStart walks back from t over the runs, last first, each over at most its
// max runes of its class and none before floor, and returns where the first
// run begins.
func (l *leadRun) runStart(content []byte, t, floor int) int {
	s := t
	for i := len(l.runs) - 1; i >= 0; i-- {
		run := l.runs[i]
		for n := 0; (run.max < 0 || n < run.max) && s > floor; n++ {
			r, size := utf8.DecodeLastRune(content[floor:s])
			if !inClass(r, run.class) {
				break
			}
			s -= size
		}
	}
	return s
}

// backBytes bounds the bytes runStart walks back over.
func (l *leadRun) backBytes() int {
	total := 0
	for _, run := range l.runs {
		if run.max < 0 {
			return total // unbounded: the rest of the line already dominates
		}
		total += run.max * utf8.UTFMax
	}
	return total
}

// classWithin reports whether every rune of class a is in class b. Parsed
// classes are sorted with adjacent ranges merged, so each range of a must lie
// inside one range of b.
func classWithin(a, b []rune) bool {
	for i := 0; i+1 < len(a); i += 2 {
		inside := false
		for j := 0; j+1 < len(b); j += 2 {
			if a[i] >= b[j] && a[i+1] <= b[j+1] {
				inside = true
				break
			}
		}
		if !inside {
			return false
		}
	}
	return true
}

func inClass(r rune, ranges []rune) bool {
	for i := 0; i+1 < len(ranges); i += 2 {
		if r >= ranges[i] && r <= ranges[i+1] {
			return true
		}
	}
	return false
}

// candidates returns every offset where one of the plan's literals begins, in
// ascending order.
func (p *prefixPlan) candidates(lits *fileLiterals, content []byte) []int {
	seen := map[int]struct{}{}
	var out []int
	for _, lp := range p.prefixes {
		for _, at := range lits.indexAll(content, lp) {
			if p.after != nil {
				if end := at + len(lp.text); end >= len(content) || !p.after[content[end]] {
					continue // the rest of the pattern cannot start here
				}
			}
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
	// Case-insensitive ASCII: walk the occurrences of each case of one byte of
	// the needle (IndexByte is vectorised), keeping the next position of each
	// so neither is rescanned, and confirm the window around it with
	// EqualFold. Every occurrence has that byte at the same offset, so each is
	// found exactly once and in order. The byte is the needle's rarest, not its
	// first: `secret` is walked from its `c`, not from every `s` and `S` in
	// the file (#736).
	k := rarestByte(needle)
	lo, up := needle[k], needle[k]
	if lo >= 'a' && lo <= 'z' {
		up = lo - 'a' + 'A'
	}
	nextLo := nextByte(content, k, lo)
	nextUp := nextLo
	if up != lo {
		nextUp = nextByte(content, k, up)
	}
	for nextLo >= 0 || nextUp >= 0 {
		i := nextLo
		if i < 0 || (nextUp >= 0 && nextUp < i) {
			i = nextUp
		}
		if start := i - k; start+len(needle) <= len(content) && bytes.EqualFold(content[start:start+len(needle)], needle) {
			out = append(out, start)
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

// byteRank orders bytes by how often they occur in source and config files,
// most often first; a byte not listed ranks after all that are. Letters are
// listed in lower case and rank for both cases. It only picks which byte of
// a needle to search for, so a poor guess costs time, never a result.
var byteRank = func() (rank [256]int) {
	const common = " e\nt\"a.o_si:rn,l/-c=d()u\tp0m'1h2g{}fb#[]y;3w4v5<>89x67k*+jq@z&|?!%$\\~^`"
	for c := range rank {
		rank[c] = len(common)
	}
	for i := len(common) - 1; i >= 0; i-- {
		rank[common[i]] = i
		if c := common[i]; c >= 'a' && c <= 'z' {
			rank[c-'a'+'A'] = i
		}
	}
	return rank
}()

// rarestByte returns the offset of the needle's least common byte, the first
// such when several tie.
func rarestByte(needle []byte) int {
	k := 0
	for i := 1; i < len(needle); i++ {
		if byteRank[needle[i]] > byteRank[needle[k]] {
			k = i
		}
	}
	return k
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
