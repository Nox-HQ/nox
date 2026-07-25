package main

import (
	"math"
	"sort"
	"strings"
)

// candidate is a package name an LLM is plausibly likely to emit, together with
// a prior in [0,1] estimating that emission likelihood INDEPENDENT of whether
// the name is registered. Registration is decided later by the checker; final
// risk (scorer.go) combines the two. Keeping the prior separate lets the
// harness spend its request budget on the highest-likelihood names.
type candidate struct {
	name       string
	ecosystem  string  // "pypi" | "npm"
	pattern    string  // composition | typo | obvious
	prior      float64 // [0,1]
	neighborOf string  // real stem it derives from ("" if none)
	reason     string
}

// typoPlausibility scales a typo prior by how likely the variant is to be what
// a MODEL actually writes, as opposed to a purely mechanical human fat-finger.
// Slopsquatting is about model output, so semantic-looking variants
// (plural/singular, separator swaps) rank far above a dropped first letter.
var typoPlausibility = map[string]float64{
	"sep":       0.95, // hyphen<->underscore, separator removal
	"plural":    0.90, // pluralise / de-pluralise
	"transpose": 0.60, // adjacent swap in the interior
	"omit":      0.45, // dropped character
	"double":    0.40, // doubled character
	"first":     0.25, // anything mangling the first char (rare in LLMs)
}

// popularityWeight maps a stem's rank in its seed list to a weight in
// [0.5,1.0]: earlier in the list == more popular == an LLM reaches for it more.
func popularityWeight(stem string, seedList []string) float64 {
	idx := -1
	for i, s := range seedList {
		if s == stem {
			idx = i
			break
		}
	}
	if idx < 0 {
		return 0.6
	}
	n := math.Max(1, float64(len(seedList)-1))
	return 1.0 - 0.5*(float64(idx)/n)
}

type typoVariant struct {
	name string
	kind string
	why  string
}

// typoNeighbours returns edit-distance-~1 neighbours of a stem.
func typoNeighbours(stem string) []typoVariant {
	var out []typoVariant
	s := []rune(stem)

	// adjacent-character transposition
	for i := 0; i < len(s)-1; i++ {
		if s[i] == s[i+1] {
			continue
		}
		v := string(s[:i]) + string(s[i+1]) + string(s[i]) + string(s[i+2:])
		kind := "transpose"
		if i == 0 {
			kind = "first"
		}
		out = append(out, typoVariant{v, kind, "transposed adjacent chars"})
	}
	// single-character omission
	for i := 0; i < len(s); i++ {
		v := string(s[:i]) + string(s[i+1:])
		if len([]rune(v)) >= 3 {
			kind := "omit"
			if i == 0 {
				kind = "first"
			}
			out = append(out, typoVariant{v, kind, "omitted a char"})
		}
	}
	// double a single character
	for i := 0; i < len(s); i++ {
		v := string(s[:i]) + string(s[i]) + string(s[i:])
		kind := "double"
		if i == 0 {
			kind = "first"
		}
		out = append(out, typoVariant{v, kind, "doubled a char"})
	}
	// hyphen<->underscore swaps and separator removal
	if strings.Contains(stem, "-") {
		out = append(out,
			typoVariant{strings.ReplaceAll(stem, "-", "_"), "sep", "hyphen->underscore"},
			typoVariant{strings.ReplaceAll(stem, "-", ""), "sep", "hyphen removed"},
		)
	}
	if strings.Contains(stem, "_") {
		out = append(out, typoVariant{strings.ReplaceAll(stem, "_", "-"), "sep", "underscore->hyphen"})
	}
	// singular/plural
	if strings.HasSuffix(stem, "s") {
		out = append(out, typoVariant{strings.TrimSuffix(stem, "s"), "plural", "de-pluralised"})
	} else {
		out = append(out, typoVariant{stem + "s", "plural", "pluralised"})
	}

	// dedup, drop identity, trim separators
	seen := map[string]struct{}{}
	uniq := out[:0:0]
	for _, tv := range out {
		v := strings.Trim(tv.name, "-_")
		if v == stem || v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		tv.name = v
		uniq = append(uniq, tv)
	}
	return uniq
}

type composed struct {
	name string
	sub  string
	why  string
}

// compose returns compositional variants of a stem (stem-suffix, prefix-stem).
func compose(stem string) []composed {
	var out []composed
	for _, suf := range suffixes {
		out = append(out, composed{stem + "-" + suf, "suffix", "popular stem + '-" + suf + "'"})
	}
	for _, pre := range prefixes {
		out = append(out, composed{pre + "-" + stem, "prefix", "'" + pre + "-' + popular stem"})
	}
	return out
}

// generateCandidates deterministically produces the full candidate set (no
// network, no randomness). A candidate that collides with a real seed name is
// dropped; when the same name arises from multiple derivations, the
// highest-prior explanation wins.
func generateCandidates() []candidate {
	realSeeds := map[string]struct{}{}
	for _, n := range pypiSeeds {
		realSeeds["pypi\x00"+n] = struct{}{}
	}
	for _, n := range npmSeeds {
		realSeeds["npm\x00"+n] = struct{}{}
	}

	cands := map[string]candidate{}
	add := func(c candidate) {
		key := c.ecosystem + "\x00" + c.name
		if _, isReal := realSeeds[key]; isReal {
			return
		}
		if cur, ok := cands[key]; !ok || c.prior > cur.prior {
			cands[key] = c
		}
	}

	for _, es := range []struct {
		eco   string
		seeds []string
	}{{"pypi", pypiSeeds}, {"npm", npmSeeds}} {
		for _, stem := range es.seeds {
			w := popularityWeight(stem, es.seeds)
			for _, tv := range typoNeighbours(stem) {
				plaus := typoPlausibility[tv.kind]
				prior := round3(0.30 + 0.45*plaus*w)
				add(candidate{
					name: tv.name, ecosystem: es.eco, pattern: "typo",
					prior: prior, neighborOf: stem,
					reason: "edit-distance-1 typo of '" + stem + "' (" + tv.why + ")",
				})
			}
			for _, cp := range compose(stem) {
				base := 0.30
				if cp.sub == "suffix" {
					base = 0.42
				}
				add(candidate{
					name: cp.name, ecosystem: es.eco, pattern: "composition",
					prior: round3(base + 0.30*w), neighborOf: stem,
					reason: "compositional: " + cp.why,
				})
			}
		}
	}

	for _, on := range obviousNames {
		add(candidate{
			name: on.name, ecosystem: on.eco, pattern: "obvious",
			prior: 0.78, neighborOf: "",
			reason: "'obvious API' name an LLM invents for a common task",
		})
	}

	out := make([]candidate, 0, len(cands))
	for _, c := range cands {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].prior != out[j].prior {
			return out[i].prior > out[j].prior
		}
		if out[i].ecosystem != out[j].ecosystem {
			return out[i].ecosystem < out[j].ecosystem
		}
		return out[i].name < out[j].name
	})
	return out
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }
