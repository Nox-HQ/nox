package rules

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
type literalIndex struct {
	rules int // len(RuleSet.Rules()) when built
	lits  []literalPrefix
	id    map[literalPrefix]int32
	seen  [indexBuckets / 64]uint64
	start [indexBuckets + 1]int32 // bucket b holds ids[start[b]:start[b+1]]
	ids   []int32
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
