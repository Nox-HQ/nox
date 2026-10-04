package main

import (
	"math/rand"
	"regexp/syntax"
	"strings"
	"unicode"
)

// The detector-side generator. It explores the DETECTOR's paths: every
// top-level alternative, every quantifier at its minimum and at its bound (or
// past its minimum when unbounded), with characters drawn from the edges and
// the interior of each class. This is the regex analogue of path coverage,
// and it is allowed to read the detector because it only proposes inputs.
// The reference judges them.

type genMode int

const (
	modeMin genMode = iota
	modeMax
	modeRandom
)

func detectorSamples(pattern string, r *rand.Rand) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()
	var roots []*syntax.Regexp
	if top := unwrapCapture(re); top.Op == syntax.OpAlternate {
		roots = top.Sub
	} else {
		roots = []*syntax.Regexp{re}
	}
	seen := map[string]bool{}
	var out []string
	for _, root := range roots {
		for _, m := range []genMode{modeMin, modeMax, modeRandom, modeRandom, modeRandom} {
			var b strings.Builder
			gen(&b, root, m, r)
			s := b.String()
			if !seen[s] && s != "" {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func unwrapCapture(re *syntax.Regexp) *syntax.Regexp {
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	return re
}

func gen(b *strings.Builder, re *syntax.Regexp, m genMode, r *rand.Rand) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, c := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 && m == modeRandom && r.Intn(2) == 0 {
				c = unicode.SimpleFold(c)
			}
			b.WriteRune(c)
		}
	case syntax.OpCharClass:
		b.WriteRune(pickClass(re.Rune, m, r))
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		b.WriteByte(byte('!' + r.Intn(94)))
	case syntax.OpCapture:
		gen(b, re.Sub[0], m, r)
	case syntax.OpConcat:
		for _, s := range re.Sub {
			gen(b, s, m, r)
		}
	case syntax.OpAlternate:
		i := 0
		if m == modeRandom {
			i = r.Intn(len(re.Sub))
		} else if m == modeMax {
			i = len(re.Sub) - 1
		}
		gen(b, re.Sub[i], m, r)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		lo, hi := re.Min, re.Max
		switch re.Op {
		case syntax.OpStar:
			lo, hi = 0, -1
		case syntax.OpPlus:
			lo, hi = 1, -1
		case syntax.OpQuest:
			lo, hi = 0, 1
		}
		n := lo
		switch m {
		case modeMax:
			if hi >= 0 {
				n = hi
			} else {
				n = lo + 8
			}
		case modeRandom:
			span := 8
			if hi >= 0 {
				span = hi - lo
			}
			if span > 0 {
				n = lo + r.Intn(span+1)
			}
		}
		for i := 0; i < n; i++ {
			gen(b, re.Sub[0], m, r)
		}
	}
	// Empty-width assertions (\b, ^, $) emit nothing: the host supplies the
	// surrounding characters.
}

// pickClass chooses a printable ASCII rune from a class: the lowest in min
// mode, the highest in max mode, uniformly otherwise.
func pickClass(ranges []rune, m genMode, r *rand.Rand) rune {
	var cands []rune
	for i := 0; i+1 < len(ranges); i += 2 {
		for c := ranges[i]; c <= ranges[i+1] && c < 0x7f; c++ {
			if c >= 0x20 || c == '\n' || c == '\t' {
				cands = append(cands, c)
			}
		}
	}
	if len(cands) == 0 {
		return 'a'
	}
	switch m {
	case modeMin:
		return cands[0]
	case modeMax:
		return cands[len(cands)-1]
	}
	return cands[r.Intn(len(cands))]
}
