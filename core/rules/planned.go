package rules

import "regexp"

// PlannedRegexp is a compiled pattern whose Match goes through the
// literal-prefix plan (see prefixplan.go) when the plan is exact for the
// content and cheaper than the scan, and through regexp otherwise. It is for
// the hand-written pattern tables outside the rule engine: on crewAI the AI
// inventory's eighteen framework patterns, alternations of import statements
// with no common literal, cost 17s of a 186s scan as full-file regexp scans
// (#736).
//
// It answers exactly what regexp.Match answers: the plan returns what FindAll
// returns, and FindAll finds something exactly when Match is true.
type PlannedRegexp struct {
	re   *regexp.Regexp
	plan *prefixPlan
}

// MustCompilePlanned compiles pattern like regexp.MustCompile and builds its
// literal-prefix plan, if it has one.
func MustCompilePlanned(pattern string) *PlannedRegexp {
	return &PlannedRegexp{re: regexp.MustCompile(pattern), plan: planFor(pattern)}
}

// Match reports whether content contains any match of the pattern.
func (p *PlannedRegexp) Match(content []byte) bool {
	if p.plan != nil {
		if locs, ok := p.plan.match(content, false); ok {
			return len(locs) > 0
		}
	}
	return p.re.Match(content)
}

// FindAllSubmatchIndex returns what regexp's FindAllSubmatchIndex(content,
// -1) returns, through the plan when it is exact for the content and cheaper
// than the scan.
func (p *PlannedRegexp) FindAllSubmatchIndex(content []byte) [][]int {
	if p.plan != nil {
		if locs, ok := p.plan.match(content, true); ok {
			return locs
		}
	}
	return p.re.FindAllSubmatchIndex(content, -1)
}

// HasPlan reports whether the pattern has a literal-prefix plan at all.
func (p *PlannedRegexp) HasPlan() bool { return p.plan != nil }

// String returns the source pattern.
func (p *PlannedRegexp) String() string { return p.re.String() }
