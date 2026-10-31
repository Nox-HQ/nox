package rules

import "bytes"

// One pass for every plan's literals.
//
// A plan finds its candidates by searching the file for each of its literals
// (see prefixplan.go). Even with each literal searched once per file
// (fileLiterals), crewAI's scan made 1,255,315 searches, each reading the file
// from the start: 5.7 s of the engine's 33 s. literalIndex finds every
// literal of every plan in one pass instead, the way keywordIndex answers the
// keyword pre-filters: each literal of three or more bytes is filed under a
// hash of its first three bytes, lower-cased; the pass hashes each three-byte
// window of the file, lower-cased, and where the hash is one some literal has,
// compares those literals in full. Over crewAI that pass took 2.0 s and found
// every occurrence of all 1,332 literals (#736).
//
// It returns what indexAll returns: every occurrence, overlapping ones
// included, in ascending order. A case-sensitive literal is compared byte for
// byte, a case-insensitive one ASCII-case-insensitively, which is what
// indexAll's EqualFold decides wherever a plan is used: a file holding a fold
// outlier takes the full scan (usableIn) and never asks. Literals under three
// bytes, and literals no plan of the rule set had, are searched one at a time.
//
// The same pass answers the keyword pre-filters. They were a second pass of
// their own (keywordindex.go) over a lower-cased copy of the file: 2.9 s of
// crewAI's scan, against 0.35 s for adding the keywords to this one. Each
// keyword of three or more bytes is held as a case-insensitive literal.
type literalIndex struct {
	rules int // len(RuleSet.Rules()) when built
	lits  []literalPrefix
	id    map[literalPrefix]int32
	seen  [indexBuckets / 64]uint64
	start [indexBuckets + 1]int32 // bucket b holds ids[start[b]:start[b+1]]
	ids   []int32

	// keywords is the rule set's keyword index; kwLit gives, per keyword,
	// its position in lits, or -1 for one under three bytes. nil when some
	// keyword is not ASCII, which this pass cannot answer for.
	keywords *keywordIndex
	kwLit    []int32
}

func newLiteralIndex(rules []*Rule) *literalIndex {
	x := &literalIndex{rules: len(rules), id: map[literalPrefix]int32{}}
	for _, r := range rules {
		var pattern string
		switch r.MatcherType {
		case "regex":
			pattern = r.Pattern
		case "absence":
			pattern = r.AbsenceAnchor
		}
		if pattern == "" {
			continue
		}
		plan := planFor(pattern)
		if plan == nil {
			continue
		}
		for _, lp := range plan.prefixes {
			if _, ok := x.id[lp]; ok || len(lp.text) < 3 {
				continue
			}
			x.id[lp] = int32(len(x.lits))
			x.lits = append(x.lits, lp)
		}
	}
	x.addKeywords(newKeywordIndex(rules))
	var counts [indexBuckets]int32
	for _, lp := range x.lits {
		counts[lp.bucket()]++
	}
	for b := range indexBuckets {
		x.start[b+1] = x.start[b] + counts[b]
	}
	x.ids = make([]int32, x.start[indexBuckets])
	fill := x.start
	for n, lp := range x.lits {
		b := lp.bucket()
		x.ids[fill[b]] = int32(n)
		fill[b]++
		x.seen[b/64] |= 1 << (b % 64)
	}
	return x
}

func (x *literalIndex) addKeywords(kw *keywordIndex) {
	x.keywords = kw
	kwLit := make([]int32, len(kw.keywords))
	for n, k := range kw.keywords {
		if !isASCII(string(k)) {
			return
		}
		kwLit[n] = -1
		if len(k) < 3 {
			continue
		}
		lp := literalPrefix{text: string(k), fold: true}
		id, ok := x.id[lp]
		if !ok {
			id = int32(len(x.lits))
			x.id[lp] = id
			x.lits = append(x.lits, lp)
		}
		kwLit[n] = id
	}
	x.kwLit = kwLit
}

func (lp literalPrefix) bucket() uint32 {
	t := lp.text
	return trigramBucket(asciiLower(t[0]), asciiLower(t[1]), asciiLower(t[2]))
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// lookup returns lp's position in x.lits; false for a nil index or a literal
// it does not hold.
func (x *literalIndex) lookup(lp literalPrefix) (int32, bool) {
	if x == nil {
		return 0, false
	}
	n, ok := x.id[lp]
	return n, ok
}

// occurrences finds every indexed literal in content, indexed like x.lits.
func (x *literalIndex) occurrences(content []byte) [][]int {
	occ := make([][]int, len(x.lits))
	for i := 0; i+2 < len(content); i++ {
		b := trigramBucket(asciiLower(content[i]), asciiLower(content[i+1]), asciiLower(content[i+2]))
		if x.seen[b/64]&(1<<(b%64)) == 0 {
			continue
		}
		for _, n := range x.ids[x.start[b]:x.start[b+1]] {
			if x.lits[n].at(content, i) {
				occ[n] = append(occ[n], i)
			}
		}
	}
	return occ
}

// at reports whether the literal occurs at offset i of content.
func (lp literalPrefix) at(content []byte, i int) bool {
	t := lp.text
	if len(content)-i < len(t) {
		return false
	}
	w := content[i : i+len(t)]
	if !lp.fold {
		return string(w) == t
	}
	for j := range len(t) {
		if asciiLower(w[j]) != t[j] {
			return false
		}
	}
	return true
}

// lowerOutliers are the two non-ASCII runes bytes.ToLower turns into ASCII
// letters: LATIN CAPITAL LETTER I WITH DOT ABOVE into i, KELVIN SIGN into k.
// The keyword pre-filter asked whether a keyword occurs in the lower-cased
// file, so "Key" spelled with a Kelvin sign holds the keyword "key"; an ASCII
// comparison would not find it. In a file holding neither, an ASCII keyword
// occurs in the lower-cased file exactly where it occurs, ASCII case ignored,
// in the file itself: lowering changes no other ASCII byte and creates no
// other.
var lowerOutliers = [][]byte{[]byte("\u0130"), []byte("\u212a")}

// asciiFoldContains reports whether lower-cased k occurs in content, ASCII
// case ignored. Only a position holding k's first byte, in either case, can
// start an occurrence, so those are found with bytes.IndexByte and tried in
// order. The next position of each case is kept until it is passed, so
// neither is searched for twice and the scan stays linear. k is non-empty.
func asciiFoldContains(content, k []byte) bool {
	if len(content) < len(k) {
		return false
	}
	lp := literalPrefix{text: string(k), fold: true}
	starts := content[:len(content)-len(k)+1]
	lo, up := k[0], asciiUpper(k[0])
	nextLo := indexByteFrom(starts, lo, 0)
	nextUp := len(starts)
	if up != lo {
		nextUp = indexByteFrom(starts, up, 0)
	}
	for {
		i := min(nextLo, nextUp)
		if i == len(starts) {
			return false
		}
		if lp.at(content, i) {
			return true
		}
		if i == nextLo {
			nextLo = indexByteFrom(starts, lo, i+1)
		} else {
			nextUp = indexByteFrom(starts, up, i+1)
		}
	}
}

// indexByteFrom returns the first position at or after from holding c, or
// len(b) when there is none.
func indexByteFrom(b []byte, c byte, from int) int {
	if j := bytes.IndexByte(b[from:], c); j >= 0 {
		return from + j
	}
	return len(b)
}

func asciiUpper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}
