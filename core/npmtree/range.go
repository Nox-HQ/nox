package npmtree

import (
	"strconv"
	"strings"
)

// npmVersion is a release version. Pre-release and build tags are not
// represented: a fixed version nox plans is a release. A range bound that
// names a pre-release is still read, exactly (satisfiesPrereleaseBound),
// because the answer for a release version does not depend on the tag.
type npmVersion [3]int

func parseNPMVersion(s string) (npmVersion, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return npmVersion{}, false
	}
	var v npmVersion
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return npmVersion{}, false
		}
		v[i] = n
	}
	return v, true
}

func (a npmVersion) cmp(b npmVersion) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// satisfiesNPMRange reports whether version v lies inside an npm semver range.
// The second result is false when the range is written in a form this does not
// read (a dist-tag, a URL, an alias): the caller must then not conclude the
// fix is reachable.
func satisfiesNPMRange(v npmVersion, rng string) (in, known bool) {
	rng = strings.TrimSpace(rng)
	if rng == "" {
		return true, true // npm treats an empty range as "*"
	}
	anyKnown := false
	for _, set := range strings.Split(rng, "||") {
		ok, k := satisfiesComparatorSet(v, set)
		if !k {
			return false, false
		}
		anyKnown = true
		if ok {
			return true, true
		}
	}
	return false, anyKnown
}

// satisfiesComparatorSet evaluates one whitespace-separated AND of comparators,
// after expanding hyphen ranges, carets, tildes and x-ranges.
func satisfiesComparatorSet(v npmVersion, set string) (in, known bool) {
	fields := strings.Fields(set)
	if len(fields) == 0 {
		return true, true
	}
	// "a - b" is a hyphen range.
	var comps []string
	for i := 0; i < len(fields); i++ {
		if i+2 < len(fields) && fields[i+1] == "-" {
			comps = append(comps, ">="+fields[i], "<="+fields[i+2])
			i += 2
			continue
		}
		// "> 1.0.0" written with a space between operator and version.
		if isBareOperator(fields[i]) && i+1 < len(fields) {
			comps = append(comps, fields[i]+fields[i+1])
			i++
			continue
		}
		comps = append(comps, fields[i])
	}
	for _, c := range comps {
		ok, k := satisfiesComparator(v, c)
		if !k {
			return false, false
		}
		if !ok {
			return false, true
		}
	}
	return true, true
}

func isBareOperator(s string) bool {
	switch s {
	case ">", ">=", "<", "<=", "=", "^", "~":
		return true
	}
	return false
}

// partial is a possibly-incomplete version: 1, 1.2, 1.2.3, 1.x, *.
type partial struct {
	n     [3]int
	count int // how many leading components are numbers
}

func parsePartial(s string) (partial, bool) {
	s = strings.TrimPrefix(s, "v")
	if s == "" || s == "*" || s == "x" || s == "X" {
		return partial{}, true
	}
	if strings.ContainsAny(s, "-+") {
		return partial{}, false // pre-release or build metadata
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return partial{}, false
	}
	var p partial
	for i, part := range parts {
		if part == "x" || part == "X" || part == "*" {
			break
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return partial{}, false
		}
		p.n[i] = n
		p.count = i + 1
	}
	return p, true
}

func satisfiesComparator(v npmVersion, c string) (in, known bool) {
	op := ""
	for _, o := range []string{">=", "<=", ">", "<", "=", "^", "~"} {
		if strings.HasPrefix(c, o) {
			op, c = o, c[len(o):]
			break
		}
	}
	// Build metadata has no precedence (semver 10): 1.2.3+build is 1.2.3.
	if i := strings.IndexByte(c, '+'); i >= 0 {
		c = c[:i]
	}
	if base, tag, tagged := strings.Cut(c, "-"); tagged {
		return satisfiesPrereleaseBound(v, op, base, tag)
	}
	p, ok := parsePartial(c)
	if !ok {
		return false, false
	}
	lo := npmVersion(p.n)
	switch op {
	case "", "=":
		return inPartial(v, p), true
	case ">=":
		return v.cmp(lo) >= 0, true
	case "<=":
		return v.cmp(upperExclusive(p)) < 0, true
	case ">":
		return v.cmp(upperExclusive(p)) >= 0, true
	case "<":
		return v.cmp(lo) < 0, true
	case "~":
		if p.count == 0 {
			return true, true
		}
		hi := npmVersion{p.n[0], p.n[1] + 1, 0}
		if p.count == 1 {
			hi = npmVersion{p.n[0] + 1, 0, 0}
		}
		return v.cmp(lo) >= 0 && v.cmp(hi) < 0, true
	case "^":
		return v.cmp(lo) >= 0 && v.cmp(caretCeiling(p)) < 0, true
	}
	return false, false
}

// satisfiesPrereleaseBound evaluates a comparator whose version carries a
// pre-release tag, X.Y.Z-tag, against a release version v. It is exact, not
// a guess: no release lies between X.Y.Z-tag and X.Y.Z, so for a release
//
//	v >= X.Y.Z-tag and v > X.Y.Z-tag  are  v >= X.Y.Z
//	v <  X.Y.Z-tag and v <= X.Y.Z-tag are  v <  X.Y.Z
//	v =  X.Y.Z-tag                     never holds
//
// and a caret or tilde keeps its ordinary ceiling. Dropping the tag would be
// wrong for >, <= and =, which is why each operator is spelled out. The vite
// ecosystem writes peer ranges as ^6.0.0-0; read as unknown, they made nox
// report vite 6.4.1 as held below 6.4.5 by ranges that allow it.
func satisfiesPrereleaseBound(v npmVersion, op, base, tag string) (in, known bool) {
	b, ok := parseNPMVersion(base)
	if !ok || tag == "" {
		return false, false // a tag on a partial (^1.2-beta) is not a form npm defines
	}
	switch op {
	case ">=", ">":
		return v.cmp(b) >= 0, true
	case "<", "<=":
		return v.cmp(b) < 0, true
	case "", "=":
		return false, true
	case "^":
		return v.cmp(b) >= 0 && v.cmp(caretCeiling(partial{n: b, count: 3})) < 0, true
	case "~":
		return v.cmp(b) >= 0 && v.cmp(npmVersion{b[0], b[1] + 1, 0}) < 0, true
	}
	return false, false
}

// inPartial reports whether v matches a partial version exactly on the
// components it names.
func inPartial(v npmVersion, p partial) bool {
	for i := 0; i < p.count; i++ {
		if v[i] != p.n[i] {
			return false
		}
	}
	return true
}

// upperExclusive is the first version after everything the partial covers:
// <=1.2 means <1.3.0.
func upperExclusive(p partial) npmVersion {
	switch p.count {
	case 0:
		return npmVersion{1 << 30, 0, 0}
	case 1:
		return npmVersion{p.n[0] + 1, 0, 0}
	case 2:
		return npmVersion{p.n[0], p.n[1] + 1, 0}
	}
	return npmVersion{p.n[0], p.n[1], p.n[2] + 1}
}

// caretCeiling is the exclusive upper bound of ^p: the next version that
// changes the left-most non-zero component.
func caretCeiling(p partial) npmVersion {
	switch {
	case p.count == 0:
		return npmVersion{1 << 30, 0, 0}
	case p.n[0] > 0 || p.count == 1:
		return npmVersion{p.n[0] + 1, 0, 0}
	case p.n[1] > 0 || p.count == 2:
		return npmVersion{0, p.n[1] + 1, 0}
	}
	return npmVersion{0, 0, p.n[2] + 1}
}
