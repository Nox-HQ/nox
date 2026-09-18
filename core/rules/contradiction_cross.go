package rules

import (
	"fmt"
	"math"
	"regexp"
	"sort"
)

// CrossContradiction records one rule advising a value that another rule
// reports as a defect.
//
// The invariant is the same one RemediationContradiction enforces, extended
// across the catalogue: following nox's own advice must not produce another
// nox finding. An operator who does exactly what a remediation says and gets a
// new finding for it has been given advice the tool itself disagrees with.
//
// AI-023 and AI-041 were such a pair and shipped together for months. AI-023
// advised "Use top_p of 0.7-0.95 for balanced output"; AI-041 fired on
// `top_p: 0.95`. Nobody noticed. The pair was resolved incidentally when
// AI-041 was withdrawn in v1.36.0 for an unrelated reason — which is the
// argument for checking mechanically rather than hoping someone reads two
// rules side by side.
type CrossContradiction struct {
	// Adviser is the rule whose remediation endorses the value.
	Adviser string
	// Flagger is the rule that reports that value as a defect.
	Flagger string
	// Param is the parameter both are talking about.
	Param string
	// Endorsement is the remediation substring the range was read from.
	Endorsement string
	// Value is a value inside the endorsed range that Flagger matches, and
	// Assignment is the assignment that reproduces it.
	Value      string
	Assignment string
}

// CrossContradictions reports every pair where one rule's remediation endorses
// a value another rule's pattern flags.
//
// # Why this is measured by construction rather than inferred
//
// The obvious implementation reads the flagged range out of the flagging
// rule's regex — deciding that `0\.[0-6][0-9]?` means [0.0, 0.69]. That is
// range inference over regex source, it is wrong in ways that are hard to see,
// and being wrong means either inventing a contradiction or missing one.
//
// So no inference: values are sampled from the ENDORSED range, written out as
// real assignments, and run through the flagging rule's own compiled pattern.
// If the pattern matches, the pattern matches — there is nothing left to be
// mistaken about. This caught an error in the first hand-written account of
// the AI-023/AI-041 pair, which named the wrong rule as the adviser.
//
// Output is sorted and de-duplicated on (Adviser, Flagger, Param): one pair is
// one finding however many spellings of the assignment reproduce it.
func CrossContradictions(rs []*Rule) []CrossContradiction {
	params := pinnedParams(rs)
	patterns := compiledPatterns(rs)

	seen := map[string]bool{}
	var out []CrossContradiction
	for _, adviser := range rs {
		if adviser.Remediation == "" {
			continue
		}
		for _, p := range params {
			for _, rg := range endorsedRanges(adviser.Remediation, p) {
				for _, v := range sampleRange(rg.low, rg.high) {
					for _, assignment := range assignmentSpellings(p, v) {
						for _, flagger := range rs {
							if flagger.ID == adviser.ID {
								continue
							}
							re, ok := patterns[flagger.ID]
							if !ok || !re.MatchString(assignment) {
								continue
							}
							key := adviser.ID + "\x00" + flagger.ID + "\x00" + p
							if seen[key] {
								continue
							}
							seen[key] = true
							out = append(out, CrossContradiction{
								Adviser:     adviser.ID,
								Flagger:     flagger.ID,
								Param:       p,
								Endorsement: rg.text,
								Value:       formatSample(v),
								Assignment:  assignment,
							})
						}
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Adviser != out[j].Adviser {
			return out[i].Adviser < out[j].Adviser
		}
		if out[i].Flagger != out[j].Flagger {
			return out[i].Flagger < out[j].Flagger
		}
		return out[i].Param < out[j].Param
	})
	return out
}

// pinnedParams is the vocabulary of parameter names any rule keys on, sorted.
// A remediation is only searched for ranges belonging to a parameter some rule
// actually pins, which keeps the search over prose bounded by the catalogue
// rather than by the English language.
func pinnedParams(rs []*Rule) []string {
	set := map[string]bool{}
	for _, r := range rs {
		ps, _, ok := r.PinnedAssignment()
		if !ok {
			continue
		}
		for _, p := range ps {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func compiledPatterns(rs []*Rule) map[string]*regexp.Regexp {
	out := make(map[string]*regexp.Regexp, len(rs))
	for _, r := range rs {
		if r.Pattern == "" {
			continue
		}
		// A pattern that does not compile cannot match anything, which
		// CheckCoherence already refuses; skipping is right here either way.
		if re, err := regexp.Compile(r.Pattern); err == nil {
			out[r.ID] = re
		}
	}
	return out
}

// crossSamples is how many points inside an endorsed range are tried.
//
// The endpoints alone are not enough: a flagging rule may cover only part of
// the endorsed range, and the pair is real if ANY endorsed value is flagged.
// Eleven points is dense enough to catch a band covering a tenth of the range
// and cheap enough not to matter — the whole search runs in well under a
// second over 1,496 rules, because only a handful of remediations endorse a
// range at all.
const crossSamples = 11

func sampleRange(lo, hi float64) []float64 {
	if lo >= hi {
		return []float64{round4(lo)}
	}
	step := (hi - lo) / float64(crossSamples-1)
	seen := make(map[float64]bool, crossSamples)
	out := make([]float64, 0, crossSamples)
	for i := 0; i < crossSamples; i++ {
		v := round4(lo + step*float64(i))
		if i == crossSamples-1 {
			v = round4(hi) // the endpoint exactly, not lo+10*step
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// round4 keeps sampled values readable.
//
// The evidence this check hands a maintainer is an assignment they are meant
// to paste and reproduce, and `top_p: 0.9249999999999999` — which is what
// 0.7 + 2*0.025 evaluates to — is not that. Four decimal places is finer than
// any tuning parameter in the catalogue is written to, so rounding cannot move
// a sample out of a band that a real config could land in.
func round4(v float64) float64 { return math.Round(v*1e4) / 1e4 }

func formatSample(v float64) string { return fmt.Sprintf("%g", v) }

// assignmentSpellings writes a parameter assignment the ways the catalogue's
// own patterns expect to see one: YAML, an equals sign with and without
// spaces, and a quoted JSON key.
func assignmentSpellings(param string, v float64) []string {
	s := formatSample(v)
	return []string{
		param + ": " + s,
		param + " = " + s,
		param + "=" + s,
		`"` + param + `": ` + s,
	}
}
