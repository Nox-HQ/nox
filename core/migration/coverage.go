// Package migration measures how far each rule family has actually moved to
// evidence-native reporting.
//
// Track J asks for rule families to be migrated "according to observed
// value/risk, not alphabetically". That ordering cannot be chosen from a list
// of rule counts, and it cannot be chosen from intuition either — the one
// intervention that has moved a number so far was checksum verification, and
// the one that was predicted to and did not was recording more heuristics.
// So this measures.
//
// # What counts as migrated
//
// Not "has claims". Every finding has claims, because the scan records an
// observation for each one; a metric that is true by construction measures
// nothing. What counts is a claim STRONGER than a pattern match.
//
// That threshold is not arbitrary. Confidence aggregation takes the strongest
// supporting claim, and heuristics are the bottom of the ladder, so a family
// that can only ever produce heuristics cannot lift a finding off the floor
// however many claims it files. Three heuristics are still a heuristic. A
// family is migrated when it can say something a regex cannot.
package migration

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
)

// FamilyCoverage is one rule family's position in the migration.
type FamilyCoverage struct {
	// Family is the rule ID prefix — SEC, IAC, AI, TAINT.
	Family string `json:"family"`
	// Findings is how many the scan reported from this family.
	Findings int `json:"findings"`
	// Corroborated is how many carry a claim beyond the bare observation that
	// the rule fired. It shows effort; it does not show strength.
	Corroborated int `json:"corroborated"`
	// AboveHeuristic is how many carry a claim above heuristic strength from
	// any source, including the observation itself.
	//
	// Read it with Earned, not instead of it. reasoning.ObservationKind gives
	// TAINT and VULN findings KindStatic on the strength of their rule prefix,
	// which is defensible — dataflow analysis and a version-range match are not
	// pattern matches — but it is a classification decision rather than
	// evidence work. A metric that counted it as migration would show those two
	// families finished on the day the switch was written.
	AboveHeuristic int `json:"above_heuristic"`
	// Earned is the number that tracks migration: findings with an
	// above-heuristic claim that is NOT the automatic observation. Something
	// looked at the candidate and established a fact a regex could not.
	Earned int `json:"earned_above_heuristic"`
	// Strongest is the strongest claim kind this family produced anywhere in
	// the scan, which is the family's actual ceiling on this corpus.
	Strongest string `json:"strongest_kind"`
}

// Migrated reports whether anything in this family has ESTABLISHED something a
// regex could not — not whether its observations are classified generously.
func (f FamilyCoverage) Migrated() bool { return f.Earned > 0 }

// ClassifiedAbove reports whether the family's observation claim itself sits
// above heuristic. It is worth knowing separately: such a family starts higher
// without anybody having looked harder, and its findings will read as
// better-evidenced than a migrated family's until the migration catches up.
func (f FamilyCoverage) ClassifiedAbove() bool {
	return f.AboveHeuristic > 0 && f.Earned == 0
}

// Report is the migration state across every family a scan exercised.
type Report struct {
	Families []FamilyCoverage `json:"families"`
	// Findings and AboveHeuristic are the totals, so a reader gets the headline
	// before the breakdown.
	Findings       int `json:"findings"`
	AboveHeuristic int `json:"above_heuristic"`
	Earned         int `json:"earned_above_heuristic"`
}

// LedgerFor is how the caller supplies the evidence about a finding. It is a
// function rather than a map so this package does not need to know how subjects
// are derived — that derivation lives in one place and must not be duplicated.
type LedgerFor func(findings.Finding) evidence.Ledger

// Measure builds the report from a scan's findings and their evidence.
func Measure(fs []findings.Finding, ledgerFor LedgerFor) Report {
	byFamily := map[string]*FamilyCoverage{}
	strongest := map[string]int{}

	for _, f := range fs {
		fam := Family(f.RuleID)
		c := byFamily[fam]
		if c == nil {
			c = &FamilyCoverage{Family: fam}
			byFamily[fam] = c
		}
		c.Findings++

		l := ledgerFor(f)
		var corroborated, above, earned bool
		for _, claim := range l.Claims {
			if !claim.Live() {
				continue
			}
			if claim.Kind != evidence.KindHeuristic {
				above = true
				if !isBareObservation(claim, f.RuleID) {
					earned = true
				}
			}
			// The observation claim says only that the rule fired. Anything
			// else is the analyzer having looked at something.
			if !isBareObservation(claim, f.RuleID) {
				corroborated = true
			}
			if s := claim.Kind.Strength(); s > strongest[fam] {
				strongest[fam] = s
				c.Strongest = string(claim.Kind)
			}
		}
		if corroborated {
			c.Corroborated++
		}
		if above {
			c.AboveHeuristic++
		}
		if earned {
			c.Earned++
		}
	}

	var out Report
	for _, c := range byFamily {
		out.Families = append(out.Families, *c)
		out.Findings += c.Findings
		out.AboveHeuristic += c.AboveHeuristic
		out.Earned += c.Earned
	}
	sort.Slice(out.Families, func(i, j int) bool {
		if out.Families[i].Findings != out.Families[j].Findings {
			return out.Families[i].Findings > out.Families[j].Findings
		}
		return out.Families[i].Family < out.Families[j].Family
	})
	return out
}

// Family returns a rule ID's family prefix.
func Family(ruleID string) string {
	if i := strings.Index(ruleID, "-"); i > 0 {
		return ruleID[:i]
	}
	if ruleID == "" {
		return "(unnamed)"
	}
	return ruleID
}

// isBareObservation reports whether a claim says only that the rule fired.
//
// Matched on the statement the scan writes, which is fragile in exactly one
// direction: if that wording changes, this over-counts corroboration and the
// number looks better than it is. TestBareObservationIsRecognised holds it to
// the real statement so the two cannot drift apart silently.
func isBareObservation(c evidence.Claim, ruleID string) bool {
	return c.Statement == "rule "+ruleID+" matched at this location"
}
