package rules

import (
	"bytes"
	"strings"
)

// One pass for every keyword pre-filter.
//
// Each rule's pre-filter asks whether any of its keywords occurs in the file.
// Asked rule by rule, that is a bytes.Contains per keyword per file -- 2,163
// keywords over 1,393 rules, most of them absent, so most of those calls read
// the whole file. On the 2026-09-30 llama_index profile it was 11% of scan
// CPU, all of it spent re-reading the same bytes.
//
// keywordIndex answers the same question for every keyword in one pass. Each
// keyword of three or more bytes is filed under a hash of its first three;
// the pass hashes each three-byte window of the file and, where the hash is
// one some keyword has, compares those keywords in full. Shorter keywords are
// still looked up with bytes.Contains. A keyword counts as present exactly
// when bytes.Contains would say so: the hash only chooses which keywords to
// compare, it never decides.
type keywordIndex struct {
	rules    int       // len(RuleSet.Rules()) when built
	keywords [][]byte  // distinct, lower-cased
	byRule   [][]int32 // per rule position, its keywords' indices
	short    []int32   // keywords under three bytes
	seen     [indexBuckets / 64]uint64
	start    [indexBuckets + 1]int32 // bucket b holds ids[start[b]:start[b+1]]
	ids      []int32
}

const indexBuckets = 1 << 16

func trigramBucket(a, b, c byte) uint32 {
	return (uint32(a)<<16 | uint32(b)<<8 | uint32(c)) * 2654435761 >> 16 & (indexBuckets - 1)
}

func newKeywordIndex(rules []*Rule) *keywordIndex {
	x := &keywordIndex{rules: len(rules), byRule: make([][]int32, len(rules))}
	id := map[string]int32{}
	for i, r := range rules {
		for _, kw := range r.Keywords {
			k := strings.ToLower(kw)
			n, ok := id[k]
			if !ok {
				n = int32(len(x.keywords))
				id[k] = n
				x.keywords = append(x.keywords, []byte(k))
			}
			x.byRule[i] = append(x.byRule[i], n)
		}
	}
	var counts [indexBuckets]int32
	for n, k := range x.keywords {
		if len(k) < 3 {
			x.short = append(x.short, int32(n))
			continue
		}
		counts[trigramBucket(k[0], k[1], k[2])]++
	}
	for b := range indexBuckets {
		x.start[b+1] = x.start[b] + counts[b]
	}
	x.ids = make([]int32, x.start[indexBuckets])
	fill := x.start
	for n, k := range x.keywords {
		if len(k) < 3 {
			continue
		}
		b := trigramBucket(k[0], k[1], k[2])
		x.ids[fill[b]] = int32(n)
		fill[b]++
		x.seen[b/64] |= 1 << (b % 64)
	}
	return x
}

// present reports, for each keyword, whether it occurs in contentLower.
func (x *keywordIndex) present(contentLower []byte) []bool {
	p := make([]bool, len(x.keywords))
	for _, n := range x.short {
		p[n] = bytes.Contains(contentLower, x.keywords[n])
	}
	c := contentLower
	for i := 0; i+2 < len(c); i++ {
		b := trigramBucket(c[i], c[i+1], c[i+2])
		if x.seen[b/64]&(1<<(b%64)) == 0 {
			continue
		}
		for _, n := range x.ids[x.start[b]:x.start[b+1]] {
			if !p[n] && bytes.HasPrefix(c[i:], x.keywords[n]) {
				p[n] = true
			}
		}
	}
	return p
}

// anyPresent reports whether any keyword of the rule at position i occurs.
func (x *keywordIndex) anyPresent(present []bool, i int) bool {
	for _, n := range x.byRule[i] {
		if present[n] {
			return true
		}
	}
	return false
}
