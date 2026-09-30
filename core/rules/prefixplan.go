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
// literal, so it is found from the literal too (see leadRun).
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
		return nil
	}
	body, leadBoundary := stripLeadingBoundary(re)
	prefixes, ok := leadingLiterals(body)
	if !ok || len(prefixes) == 0 {
		return buildLeadPlan(pattern)
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
			return nil // a one-character literal is too common to narrow anything
		}
	}
	anchored, err := regexp.Compile(`^(?:` + pattern + `)`)
	if err != nil {
		return nil
	}
	return &prefixPlan{prefixes: prefixes, anchored: anchored, leadBoundary: leadBoundary, maxLen: maxBytes(re)}
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
	var runs []classRun
	for len(runs) < 2 && len(runs) < len(re.Sub)-1 {
		run := re.Sub[len(runs)]
		if run.Op != syntax.OpRepeat || run.Min != 0 || run.Sub[0].Op != syntax.OpCharClass {
			break
		}
		if len(runs) > 0 && !classWithin(runs[0].class, run.Sub[0].Rune) {
			return nil
		}
		runs = append(runs, classRun{class: run.Sub[0].Rune, max: run.Max})
	}
	if len(runs) == 0 {
		return nil
	}
	rest := &syntax.Regexp{Op: syntax.OpConcat, Flags: re.Flags, Sub: re.Sub[len(runs):]}
	if len(rest.Sub) == 1 {
		rest = rest.Sub[0]
	}
	p := buildPlan(rest.String())
	// A rest that opens with `\b` would be checked against the byte before the
	// run, not before the literal; one that has its own run is not this shape.
	if p == nil || p.leadBoundary || p.lead != nil {
		return nil
	}
	anchored, err := regexp.Compile(`^(?:` + pattern + `)`)
	if err != nil {
		return nil
	}
	return &prefixPlan{
		prefixes: p.prefixes,
		anchored: p.anchored,
		maxLen:   maxBytes(re),
		lead:     &leadRun{runs: runs, anchored: anchored},
	}
}

// stripLeadingBoundary returns the pattern without a leading `\b`, and whether
// there was one. Only the form `\b` + rest at the top of the pattern (through
// capture groups) is recognised; `\b` inside some alternatives only, or `\B`,
// leaves the pattern as it is, and leadingLiterals then declines it.
func stripLeadingBoundary(re *syntax.Regexp) (*syntax.Regexp, bool) {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
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
		return nil, false
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
func (p *prefixPlan) usable(content []byte) bool {
	if p.lead != nil && !utf8.Valid(content) {
		return false
	}
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
	if !p.usable(content) {
		return nil, false
	}
	starts := p.candidates(content)
	if p.cost(content, starts) > len(content) {
		return nil, false
	}
	return p.findAllFrom(content, starts, submatch), true
}

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
func (p *prefixPlan) findAll(content []byte, submatch bool) [][]int {
	return p.findAllFrom(content, p.candidates(content), submatch)
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
