// Package hypothesize turns a finished scan into the active-testing questions
// its findings raise.
//
// It is a package of its own, above both, for a reason the dependency graph has
// to keep rather than a comment: core (the scan pipeline) must not be able to
// import core/attack. TestTheScanCannotReachTheAttackPackage enforces that by
// reading the imports, and its wording is the point — "a scanner that can
// unknowingly attack what it is pointed at is unsafe to run in most places nox
// should be ubiquitous".
//
// So this sits outside the pipeline and runs after it. It takes a ScanResult
// that has already been produced and computes over it. Nothing here can execute
// during a scan, because nothing in a scan can reach it.
//
// One implementation rather than one per adapter: the CLI, the MCP server and
// the LSP all need the same handoff, and three copies of it would disagree the
// first time one changed.
package hypothesize

import (
	"github.com/nox-hq/nox-core/evidence"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/adjudicate"
	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/findings"
)

// From turns a scan's findings into the active-testing questions they raise: what an attacker would have to do, what would settle it, and what nox
// does not know.
//
// It is milestone 8.1, and it is the passive half of a handoff that already
// existed in two pieces. `nox attack plan` could build these, but only from
// artifacts on disk — so getting the scan's evidence onto a hypothesis meant
// `nox scan --evidence-out`, then `nox attack plan --evidence`, with the two
// rejoined by fingerprint. Two commands, two files, and a join that can only
// carry what the artifact happens to record.
//
// Built in-process it carries more, and the difference is not cosmetic. The
// artifact records capability counts per SCAN, so unknownsFromArtifact hands
// every hypothesis the same scan-wide list and says so. Here the coverage is
// per-subject — that is what milestone 2.2 built — so each hypothesis states
// the questions still open about ITS OWN subject. "Nothing established taint
// for this finding" is actionable; "taint answered 30 subjects somewhere in
// this scan" is not.
//
// Nothing here executes anything. BuildPlan is pure computation over findings
// and an inventory, which is what keeps Gate E intact: `nox scan` remains
// read-only, and every verb that touches a target still lives behind
// `nox attack ... --authorize`.
func From(r *nox.ScanResult, root, now string) (*attack.Plan, error) {
	if r == nil {
		return attack.BuildPlan(attack.PlanInput{Root: root, Now: now})
	}
	var ff []findings.Finding
	if r.Findings != nil {
		// Every finding, not only the active ones. BuildPlan applies the
		// active-findings rule itself and records each waived finding as a
		// SkipNote — filtering here would drop them out of that account, and
		// the plan is meant to say why each finding did or did not raise a
		// question.
		ff = r.Findings.Findings()
	}
	return attack.BuildPlan(attack.PlanInput{
		Root:      root,
		Findings:  ff,
		Inventory: r.AIInventory,
		Now:       now,
		Evidence:  evidenceFor(r),
		Unknowns:  UnknownsFor(r),
	})
}

// evidenceForHypotheses returns the subject and ledger a hypothesis should
// carry for a finding, straight from this scan's store.
//
// Nil when the scan recorded no reasoning, which BuildPlan reads as "no
// evidence" rather than as an empty one. A hypothesis carrying an empty ledger
// it was told to expect is honest; one carrying an empty ledger because nobody
// asked for reasoning would look like a scan that established nothing.
func evidenceFor(r *nox.ScanResult) func(findings.Finding) (evidence.Subject, evidence.Ledger) {
	if r.Reasoning == nil {
		return nil
	}
	return func(f findings.Finding) (evidence.Subject, evidence.Ledger) {
		s := nox.SubjectForFinding(f)
		return s, r.Reasoning.About(s)
	}
}

// UnknownsFor returns a lookup of the open questions about one subject,
// cheapest first — the reason a hypothesis is a hypothesis and not a conclusion.
//
// Per-subject, unlike the artifact-driven path, which can only report scan-wide
// counts. adjudicate.MissingEvidence answers from the same coverage the
// capability matrix and `nox why` read, so a hypothesis and an explanation
// cannot disagree about what was left unanswered.
// It is exported so a test can assert the per-subject property directly;
// callers should use From, which wires it.
func UnknownsFor(r *nox.ScanResult) func(evidence.Subject) []string {
	if r.Coverage == nil {
		return nil
	}
	return func(s evidence.Subject) []string {
		gaps := adjudicate.MissingEvidence(r.Coverage, r.Capabilities, s)
		if len(gaps) == 0 {
			return nil
		}
		out := make([]string, 0, len(gaps))
		for _, g := range gaps {
			// Whether anything COULD answer it is the difference between a
			// next step and a standing limit, so it is stated rather than left
			// for the reader to look up.
			suffix := " (nothing on this installation can answer it)"
			if g.Available {
				suffix = ""
			}
			out = append(out, string(g.Capability)+": "+g.Question+suffix)
		}
		return out
	}
}
