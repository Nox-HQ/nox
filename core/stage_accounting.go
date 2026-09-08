package core

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
)

// StageCount is one rule family's account of what the scan did with the
// candidates it generated.
//
// It is the answer to a question nobody could ask before: how much of what a
// family produced survived, and what removed the rest. A family that generates
// a thousand candidates and refutes none is doing no refinement; one that
// refutes nine in ten is doing most of its work after the match. Neither is
// visible from a finding count, because both produce findings.
//
// The counts partition the family's candidates exactly — Promoted + Refuted +
// Withheld + Unresolved equals Candidates — so a number that does not add up is
// a bug in the accounting rather than a judgement call.
type StageCount struct {
	// Family is the rule-ID prefix: SEC, IAC, TAINT, AI.
	Family string `json:"family"`
	// Candidates is how many distinct subjects the family made claims about.
	Candidates int `json:"candidates"`
	// Promoted became a reported finding.
	Promoted int `json:"promoted"`
	// Refuted were removed by EVIDENCE: a match inside a comment, a placeholder
	// value, a companion found in another file. This is the number that says
	// whether a family refines at all.
	Refuted int `json:"refuted"`
	// Withheld were removed by CONFIGURATION or by deduplication — a decision
	// that says nothing about whether the finding was true. Counted apart from
	// Refuted because collapsing them would make a family that dedupes look
	// like one that reasons.
	Withheld int `json:"withheld"`
	// Unresolved were considered and neither reported nor removed. A non-zero
	// value here is worth looking at: it means the pipeline recorded a claim
	// about something that then went nowhere.
	Unresolved int `json:"unresolved"`
}

// StageAccounting summarises what each rule family produced and what became of
// it, from the reasoning ledger and the findings that survived.
//
// Nil when the scan recorded no reasoning: a refuted candidate never becomes a
// finding, so the ledger is the only place it exists, and an accounting derived
// without one would report every family as refuting nothing — which is the
// specific wrong answer this exists to detect.
//
// Deliberately NOT timed. Latency is on the milestone's list and cannot go in
// the artifact: findings.json is byte-identical across runs by contract, and a
// duration is different every time. Cost belongs on stderr or in a benchmark,
// not in a file whose reproducibility is a guarantee.
func StageAccounting(store *reasoning.Store, fs *findings.FindingSet) []StageCount {
	if store == nil || store.Len() == 0 {
		return nil
	}
	reported := map[evidence.Subject]bool{}
	if fs != nil {
		for _, f := range fs.Findings() {
			reported[SubjectForFinding(f)] = true
		}
	}

	byFamily := map[string]*StageCount{}
	for _, s := range store.Subjects() {
		fam := familyOf(s)
		c := byFamily[fam]
		if c == nil {
			c = &StageCount{Family: fam}
			byFamily[fam] = c
		}
		c.Candidates++
		if reported[s] {
			c.Promoted++
			continue
		}
		// The order is the meaning. A candidate with a refuting claim was
		// removed on evidence even if configuration also touched it; one with
		// only an Unknown-polarity claim was withheld, which is not a
		// statement about whether it was true.
		var refuted, withheld bool
		for _, claim := range store.About(s).Claims {
			switch {
			case claim.Refutes():
				refuted = true
			case claim.Polarity == evidence.PolarityUnknown:
				withheld = true
			}
		}
		switch {
		case refuted:
			c.Refuted++
		case withheld:
			c.Withheld++
		default:
			c.Unresolved++
		}
	}

	out := make([]StageCount, 0, len(byFamily))
	for _, c := range byFamily {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

// familyOf extracts the rule-family prefix from a candidate subject's ID, which
// reasoning.Candidate formats as "<ruleID>@<path>:<line>:<col>".
//
// Rule IDs are "<FAMILY>-<number>", so the prefix is everything before the
// first hyphen. A subject that is not a candidate — a flow, a package — has no
// family and is grouped under its kind rather than being dropped, because a
// count that silently omits subjects is not an account.
func familyOf(s evidence.Subject) string {
	if s.Kind != evidence.SubjectCandidate {
		return string(s.Kind)
	}
	id := s.ID
	if i := strings.Index(id, "@"); i > 0 {
		id = id[:i]
	}
	if i := strings.Index(id, "-"); i > 0 {
		return id[:i]
	}
	return id
}
