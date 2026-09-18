package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/rules"
)

// `nox rule-review` points a maintainer at rule propositions worth re-reading.
// It does not score them, rank them, suppress them, retire them or change
// them, and that restraint is the design rather than an unfinished edge.
//
// The motivating history: twice while auditing this catalogue a cleanup that
// was obviously right on inspection measured wrong on the corpus. Requiring
// entropy context for private-key rules would have lost a real RSA key.
// Merging the 29 vendor rule pairs that looked like duplicates would have
// deleted credential spellings that only one member of each pair covered. A
// tool that had ranked those as "remove me" would have been confidently
// wrong, because the evidence that overturned them was not in any of the
// signals below — it was in running the change against real repositories.
//
// So this command answers "which propositions deserve a human read", and the
// human answers everything after that. Contrast `nox calibrate`, which
// deliberately DOES prescribe: it emits severity overrides an operator can
// paste. Calibration is reversible config in one project. Retiring a rule is
// not, which is why #670 and #671 had to teach nox to explain a withdrawal
// years after the release that made it.
//
// The three signals are reported in separate sections and are never combined.
// A rule listed under all three is a rule to inspect, not a rule that is
// three times as bad; a combined number would be a ranking, and there is no
// evidence yet that the three are commensurable.
//
// Two of the three are INGESTED rather than computed here, because nox already
// measures them and a second implementation would be a second answer:
//
//	single_construct   scripts/metamorphic/sweep.py triage report
//	prevalence collapse `nox bench --json` rule_prevalence
//
// Only the third — a remediation that endorses the value its own rule flags —
// is computed, from the built-in catalogue, because nothing measured it
// before. See rules.Contradiction and docs/design/rule-review-candidates.md.
func runRuleReview(args []string) int {
	fs := flag.NewFlagSet("rule-review", flag.ContinueOnError)
	var (
		benchPath string
		sweepPath string
		output    string
		asJSON    bool
		showAll   bool
	)
	fs.StringVar(&benchPath, "bench", "", "path to a `nox bench --json` report (supplies the prevalence-collapse signal)")
	fs.StringVar(&sweepPath, "sweep", "", "path to a scripts/metamorphic/sweep.py triage report (supplies the single-construct signal)")
	fs.StringVar(&output, "output", "", "destination path (defaults to stdout)")
	fs.BoolVar(&asJSON, "json", false, "emit the report as JSON")
	fs.BoolVar(&showAll, "all", false, "show every measured collapse row, not just those at or above the default factor")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	report := RuleReviewReport{Schema: ruleReviewSchema}
	report.Sources.Catalog = len(catalog.Rules())

	report.Contradictions = contradictionCandidates()
	report.CrossContradictions = crossContradictionCandidates()

	if benchPath != "" {
		rows, err := collapseCandidates(benchPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		report.Sources.Bench = benchPath
		// Every measured row is kept in the report's own accounting; the
		// threshold decides only which are shown.
		report.CollapsesMeasured = len(rows)
		report.CollapseFactorShown = defaultCollapseFactor
		report.CollapseCopiesShown = defaultCollapseCopies
		if showAll {
			report.CollapseFactorShown = 0
			report.CollapseCopiesShown = 0
		}
		report.Collapses = meetsCollapseFloors(rows,
			report.CollapseFactorShown, report.CollapseCopiesShown)
	}
	if sweepPath != "" {
		rows, err := singleConstructCandidates(sweepPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		report.Sources.Sweep = sweepPath
		report.SingleConstruct = rows
	}

	var out []byte
	if asJSON {
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: encoding report: %v\n", err)
			return 2
		}
		out = append(b, '\n') //nolint:gocritic // b is a fresh buffer; the copy is the point
	} else {
		out = []byte(renderRuleReview(&report))
	}
	if output == "" {
		if _, err := os.Stdout.Write(out); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing report: %v\n", err)
			return 2
		}
		return 0
	}
	if err := os.WriteFile(output, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}
	return 0
}

const ruleReviewSchema = "nox-rule-review-candidates/v1"

// defaultCollapseFactor is the copy factor at or above which a collapsing rule
// is shown by default.
//
// It is PRESENTATION, not adjudication. Crossing it says "worth looking at"
// and says nothing about whether the rule is defective; the factor itself is
// the canonical measurement and every measured row is still computed, counted
// and reachable with --all.
//
// 2 was chosen from the labelled run over docs/benchmarks/2026-09-15: of the
// 19 rules that collapse at all, 7 carried information and 12 were dismissible
// from the factor column alone — three of them near unity (SEC-161 at 1.009 is
// six duplicated lines out of 673) and six with counts too small to read
// (2->1, 3->1, 4->2). A cutoff of 2 keeps all 7 informative rows.
//
// Changing this number changes what a maintainer is shown first and nothing
// else. It is deliberately a constant rather than an expression inside
// collapseCandidates so that future catalogue evidence can move it without
// touching the signal.
const defaultCollapseFactor = 2.0

// defaultCollapseCopies is the number of duplicated lines a rule must have
// before its factor is worth reading.
//
// The factor alone cannot tell a 2x built from 260 findings apart from one
// built from 4. SEC-509 collapses 2 findings to 1 site — a factor of exactly
// 2.000 from a single duplicated line — and sat beside AI-031's 260-to-20 as
// though the two were comparable.
//
// So a row must clear BOTH bars, and they are complementary rather than
// redundant: the factor is proportional and excludes the high-volume
// near-unity rules (SEC-161 is 673 findings over 667 sites, six duplicates in
// total), while this one is absolute and excludes the tiny ones. Neither
// catches the other's case.
//
// 3 is chosen from a sensitivity sweep over docs/benchmarks/2026-09-15 rather
// than picked. Of the 11 rules at factor >= 2, EVERY copies floor from 3 to 36
// selects the same 8 rows, and every findings floor from 5 to 53 selects those
// same 8 — two differently motivated bars agreeing across an order of
// magnitude each. A parameter with a plateau that wide is not tuned, which is
// what makes it safe to set from a single corpus.
//
// Counting copies rather than findings is the more honest of the two: copies
// ARE the quantity the signal is about, so the floor lands on the measurement
// instead of on a proxy for it. "One duplicated line is not evidence of copy
// multiplication" needs no corpus to justify.
//
// Deliberately NOT tuned to produce 7 rows. Reaching 7 needs a findings floor
// of exactly 54 — SEC-801 has 53 — which is a cliff with no plateau on either
// side, the shape of a number fitted to a wanted answer. 8 is where the
// evidence actually separates.
const defaultCollapseCopies = 3

// RuleReviewReport is the stable shape of the candidate report.
//
// The three signal lists are siblings and stay siblings. There is deliberately
// no total, no score and no severity: adding one would answer a question this
// analysis has not earned the right to answer.
type RuleReviewReport struct {
	Schema  string `json:"schema"`
	Sources struct {
		Catalog int    `json:"catalog_rules"`
		Bench   string `json:"bench,omitempty"`
		Sweep   string `json:"sweep,omitempty"`
	} `json:"sources"`

	Contradictions      []ContradictionCandidate      `json:"remediation_contradicts_trigger"`
	CrossContradictions []CrossContradictionCandidate `json:"remediation_advises_what_another_flags"`

	// Collapses holds the rows SHOWN. CollapsesMeasured is how many collapsed
	// at all, and CollapseFactorShown is the cutoff that separated them, so a
	// reader can always tell a short list from a filtered one. Zero means
	// nothing was withheld.
	Collapses           []CollapseCandidate `json:"prevalence_collapses,omitempty"`
	CollapsesMeasured   int                 `json:"prevalence_collapses_measured,omitempty"`
	CollapseFactorShown float64             `json:"prevalence_collapse_factor_shown,omitempty"`
	CollapseCopiesShown int                 `json:"prevalence_collapse_copies_shown,omitempty"`

	SingleConstruct []SingleConstructRow `json:"single_construct,omitempty"`
}

// meetsCollapseFloors filters rows for presentation. It never recomputes
// anything: the measurement is whatever collapseCandidates found, and this only
// decides which of those rows a maintainer is shown first.
//
// Both bars must be cleared. They are complementary — proportional and
// absolute — and a row passing one while failing the other is exactly the case
// each exists to withhold.
func meetsCollapseFloors(rows []CollapseCandidate, factor float64, copies int) []CollapseCandidate {
	out := make([]CollapseCandidate, 0, len(rows))
	for _, r := range rows {
		if r.Factor >= factor && r.Findings-r.Authored >= copies {
			out = append(out, r)
		}
	}
	return out
}

// ContradictionCandidate is a rule whose remediation recommends a range
// containing the value its own trigger requires.
type ContradictionCandidate struct {
	Rule        string  `json:"rule"`
	Param       string  `json:"param"`
	Flagged     string  `json:"flagged_value"`
	EndorsedLow float64 `json:"endorsed_low"`
	EndorsedHi  float64 `json:"endorsed_high"`
	Endorsement string  `json:"endorsement"`
	Remediation string  `json:"remediation"`
}

// CollapseCandidate is a rule whose raw finding count overstates the number of
// lines someone actually wrote.
type CollapseCandidate struct {
	Rule     string  `json:"rule"`
	Findings int     `json:"findings"`
	Authored int     `json:"authored_occurrences"`
	Repos    int     `json:"repos"`
	Factor   float64 `json:"copy_factor"`
}

// SingleConstructRow is a rule the metamorphic sweep only ever exercised in
// one place.
type SingleConstructRow struct {
	Rule      string   `json:"rule"`
	FireCount int      `json:"fire_count"`
	SeedCount int      `json:"seed_count"`
	Seeds     []string `json:"seeds,omitempty"`
}

// CrossContradictionCandidate is one rule advising a value another rule flags.
type CrossContradictionCandidate struct {
	Adviser     string `json:"adviser"`
	Flagger     string `json:"flagger"`
	Param       string `json:"param"`
	Endorsement string `json:"endorsement"`
	Assignment  string `json:"assignment"`
}

func crossContradictionCandidates() []CrossContradictionCandidate {
	out := []CrossContradictionCandidate{}
	for _, c := range rules.CrossContradictions(catalog.Rules()) {
		out = append(out, CrossContradictionCandidate{
			Adviser:     c.Adviser,
			Flagger:     c.Flagger,
			Param:       c.Param,
			Endorsement: c.Endorsement,
			Assignment:  c.Assignment,
		})
	}
	return out
}

func contradictionCandidates() []ContradictionCandidate {
	out := []ContradictionCandidate{}
	for _, r := range catalog.Rules() {
		c, ok := r.RemediationContradiction()
		if !ok {
			continue
		}
		out = append(out, ContradictionCandidate{
			Rule:        r.ID,
			Param:       c.Param,
			Flagged:     c.Flagged,
			EndorsedLow: c.Low,
			EndorsedHi:  c.High,
			Endorsement: c.Endorsement,
			Remediation: r.Remediation,
		})
	}
	return out
}

// collapseCandidates lists every rule whose authored-occurrence count is
// strictly below its raw finding count.
//
// There is no threshold, on purpose. A threshold is a judgement about how much
// multiplication is too much, and picking one here would be the scoring this
// command does not do. Measured on docs/benchmarks/2026-09-15, 96 of 115 rules
// with prevalence data collapse not at all and never appear; of the 19 that do,
// the factor column separates SEC-161 at 1.01 from AI-031 at 13.0 far better
// than any cutoff would.
func collapseCandidates(path string) ([]CollapseCandidate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bench report %s: %w", path, err)
	}
	var report BenchReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parsing bench report %s: %w", path, err)
	}
	if len(report.RulePrevalence) == 0 {
		return nil, fmt.Errorf("%s carries no rule_prevalence; re-run `nox bench --json` with a corpus", path)
	}
	out := []CollapseCandidate{}
	for id, p := range report.RulePrevalence {
		if p.Sites <= 0 || p.Sites >= p.Findings {
			continue
		}
		out = append(out, CollapseCandidate{
			Rule:     id,
			Findings: p.Findings,
			Authored: p.Sites,
			Repos:    p.Repos,
			Factor:   float64(p.Findings) / float64(p.Sites),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out, nil
}

// sweepTriage is the part of the metamorphic sweep's report this reads.
type sweepTriage struct {
	Suspicious []struct {
		RuleID    string   `json:"ruleid"`
		Signals   []string `json:"signals"`
		FireCount int      `json:"fire_count"`
		SeedCount int      `json:"seed_count"`
		Seeds     []string `json:"seeds"`
	} `json:"suspicious_rules"`
}

// singleConstructCandidates reads the sweep's own triage rather than
// recomputing it.
//
// `flips_under_edit`, the sweep's other signal, is deliberately not carried
// here: it is a confirmed rule BUG with a minimal reproduction attached, and
// the sweep already fails on a new one. Re-listing it as something to think
// about would demote a red gate into a suggestion.
func singleConstructCandidates(path string) ([]SingleConstructRow, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading sweep triage %s: %w", path, err)
	}
	var triage sweepTriage
	if err := json.Unmarshal(raw, &triage); err != nil {
		return nil, fmt.Errorf("parsing sweep triage %s: %w", path, err)
	}
	out := []SingleConstructRow{}
	for _, s := range triage.Suspicious {
		for _, sig := range s.Signals {
			if sig != "single_construct" {
				continue
			}
			out = append(out, SingleConstructRow{
				Rule:      s.RuleID,
				FireCount: s.FireCount,
				SeedCount: s.SeedCount,
				Seeds:     s.Seeds,
			})
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out, nil
}
