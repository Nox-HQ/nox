// Package advisory decides what happens when a scan finds a dependency
// advisory that was not there last time.
//
// A scheduled scan exists to notice a vulnerability disclosed weeks after the
// code that depends on it was written. Noticing is the easy half. The half this
// package owns is the decision that follows: report it, prepare a fix, or carry
// the fix as far as the repository's own rules allow. That decision is a policy
// the operator sets, and it is made here as a pure function of the findings, the
// previous run and the policy, so the same inputs always produce the same
// answer and an operator can read why.
//
// Three rules shape it, each the opposite of a failure this project has already
// had:
//
//   - The default is the least autonomous level. Writing no policy never opens
//     a pull request, let alone merges one.
//   - Undetermined is not "not affected". An advisory nox could not place
//     against the code is treated as possibly affecting it, and the reason says
//     the question went unanswered. Only a refuted rung (not_impacting) lowers
//     an advisory, and it lowers it to "reported with the reason", never to
//     silence.
//   - "New" must be established, not assumed. With no previous run to compare
//     against, nothing is called new and nothing is acted on; with a scan that
//     could not finish looking, nothing is acted on either. Acting on either
//     would open a pull request for every advisory in the repository, or merge
//     on the strength of a lookup that never completed.
//
// The package is pure: no I/O, no clock, no network. Merging is not performed
// here at all. The result says whether a merge is permitted; the CI platform's
// own branch protection decides whether it happens.
package advisory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
)

// ruleID is the finding rule that carries dependency advisories.
const ruleID = "VULN-001"

// Level is how far nox may carry a newly disclosed advisory. It is a ceiling
// the operator sets, not a promise: each advisory goes only as far as its own
// gate allows.
type Level string

// The levels, least autonomous first.
const (
	Report    Level = "report"
	Prepare   Level = "prepare"
	Remediate Level = "remediate"
)

func (l Level) rank() int {
	switch l {
	case Report:
		return 1
	case Prepare:
		return 2
	case Remediate:
		return 3
	}
	return 0
}

// Action is what is decided for one advisory, or for the run as a whole.
type Action string

// The actions. ActionNone is an advisory nothing is owed for: already known or
// already waived.
const (
	ActionNone      Action = "none"
	ActionReport    Action = "report"
	ActionPrepare   Action = "prepare"
	ActionRemediate Action = "remediate"
)

func (a Action) rank() int {
	switch a {
	case ActionReport:
		return 1
	case ActionPrepare:
		return 2
	case ActionRemediate:
		return 3
	}
	return 0
}

// Relevance is how far the applicability argument got for one advisory,
// weakest first. It reuses the vocabulary of the applicability ladder so an
// operator reads the same words in the finding and in the policy.
type Relevance string

// The relevance classes. RelNotImpacting is outside the ordering: a refuted
// advisory satisfies no threshold.
const (
	// RelUndetermined: the climb stopped below symbol_used because it could not
	// be established, not because anything was refuted.
	RelUndetermined Relevance = "undetermined"
	// RelSymbolUsed: the affected package is linked or imported by this build.
	RelSymbolUsed Relevance = "symbol_used"
	// RelCallReachable: a call path reaches the affected code.
	RelCallReachable Relevance = "call_reachable"
	// RelNotImpacting: a rung was deterministically refuted.
	RelNotImpacting Relevance = "not_impacting"
)

func (r Relevance) rank() int {
	switch r {
	case RelUndetermined:
		return 1
	case RelSymbolUsed:
		return 2
	case RelCallReachable:
		return 3
	}
	return 0
}

// Novelty says whether an advisory is new, and if not, why not.
type Novelty string

// The novelty classes.
const (
	// NoveltyNew: active, and absent from the previous run.
	NoveltyNew Novelty = "new"
	// NoveltyKnown: active, and already present in the previous run.
	NoveltyKnown Novelty = "known"
	// NoveltyWaived: baselined, or waived through VEX. A person already decided.
	NoveltyWaived Novelty = "waived"
	// NoveltyUnestablished: there was no previous run to compare against.
	NoveltyUnestablished Novelty = "unestablished"
)

// Settings is the .nox.yaml `advisories` block.
type Settings struct {
	// Policy is the ceiling: report (default), prepare or remediate.
	Policy string `yaml:"policy"`
	// Prepare gates which new advisories get a remediation pull request.
	Prepare Gate `yaml:"prepare"`
	// Remediate gates which of those may also be auto-merged.
	Remediate RemediateGate `yaml:"remediate"`
}

// Gate is a threshold an advisory must meet to be carried to a level.
type Gate struct {
	// MinSeverity is critical, high, medium or low.
	MinSeverity string `yaml:"min_severity"`
	// MinRelevance is undetermined, symbol_used or call_reachable.
	MinRelevance string `yaml:"min_relevance"`
}

// RemediateGate is the stricter gate for auto-merge.
type RemediateGate struct {
	Gate `yaml:",inline"`
	// MaxBump is the largest version move that counts as safe: patch or minor.
	// A major bump is never safe to merge unattended and cannot be allowed.
	MaxBump string `yaml:"max_bump"`
}

// Policy is Settings with defaults applied and values validated.
type Policy struct {
	Level   Level
	Prepare gate
	Merge   gate
	// MaxBump is the largest move the Merge gate accepts.
	MaxBump fix.Bump
}

type gate struct {
	minSeverity  findings.Severity
	minRelevance Relevance
}

// Defaults. The prepare gate is permissive on purpose: preparing a pull request
// asks a person to review, so doing it for anything not refuted costs little.
// The merge gate is not: it requires evidence the code uses the package.
const (
	defaultPrepareSeverity  = findings.SeverityLow
	defaultPrepareRelevance = RelUndetermined
	defaultMergeSeverity    = findings.SeverityHigh
	defaultMergeRelevance   = RelSymbolUsed
	defaultMaxBump          = fix.BumpMinor
)

// Resolve applies defaults and validates. An invalid value is an error rather
// than a quiet fallback: a misspelt `policy: remediate` that silently became
// `report` would look like a working configuration that never acts.
func (s Settings) Resolve() (Policy, error) {
	p := Policy{Level: Report, MaxBump: defaultMaxBump}

	switch Level(strings.ToLower(strings.TrimSpace(s.Policy))) {
	case "", Report:
		p.Level = Report
	case Prepare:
		p.Level = Prepare
	case Remediate:
		p.Level = Remediate
	default:
		return p, fmt.Errorf("advisories.policy %q is not one of report, prepare, remediate", s.Policy)
	}

	var err error
	if p.Prepare, err = resolveGate("advisories.prepare", s.Prepare, defaultPrepareSeverity, defaultPrepareRelevance); err != nil {
		return p, err
	}
	if p.Merge, err = resolveGate("advisories.remediate", s.Remediate.Gate, defaultMergeSeverity, defaultMergeRelevance); err != nil {
		return p, err
	}
	switch strings.ToLower(strings.TrimSpace(s.Remediate.MaxBump)) {
	case "":
	case "patch":
		p.MaxBump = fix.BumpPatch
	case "minor":
		p.MaxBump = fix.BumpMinor
	default:
		return p, fmt.Errorf("advisories.remediate.max_bump %q must be patch or minor: a major bump is never merged unattended", s.Remediate.MaxBump)
	}
	return p, nil
}

func resolveGate(name string, g Gate, defSev findings.Severity, defRel Relevance) (gate, error) {
	out := gate{minSeverity: defSev, minRelevance: defRel}
	switch sev := findings.Severity(strings.ToLower(strings.TrimSpace(g.MinSeverity))); sev {
	case "":
	case findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium, findings.SeverityLow:
		out.minSeverity = sev
	default:
		return out, fmt.Errorf("%s.min_severity %q is not one of critical, high, medium, low", name, g.MinSeverity)
	}
	switch rel := Relevance(strings.ToLower(strings.TrimSpace(g.MinRelevance))); rel {
	case "":
	case RelUndetermined, RelSymbolUsed, RelCallReachable:
		out.minRelevance = rel
	case RelNotImpacting:
		return out, fmt.Errorf("%s.min_relevance cannot be not_impacting: an advisory shown not to affect this build is reported, never acted on", name)
	default:
		return out, fmt.Errorf("%s.min_relevance %q is not one of undetermined, symbol_used, call_reachable", name, g.MinRelevance)
	}
	return out, nil
}

// Input is everything a decision depends on.
type Input struct {
	// Findings are the current scan's findings, waived ones included: their
	// Status says so, and a waived advisory must be seen to be waived.
	Findings []findings.Finding
	// Previous are the last run's findings. Only meaningful with HavePrevious.
	Previous []findings.Finding
	// HavePrevious distinguishes "last run had no advisories" from "there was no
	// last run". The first is a comparison; the second is not.
	HavePrevious bool
	// Incomplete, when non-empty, says why this scan could not finish looking.
	Incomplete string
	Policy     Policy
}

// Decision is the outcome for one advisory.
type Decision struct {
	Advisory  string    `json:"advisory"`
	Aliases   []string  `json:"aliases,omitempty"`
	Ecosystem string    `json:"ecosystem"`
	Package   string    `json:"package"`
	Version   string    `json:"version"`
	FixedIn   string    `json:"fixed_in,omitempty"`
	Severity  string    `json:"severity"`
	Relevance Relevance `json:"relevance"`
	Novelty   Novelty   `json:"novelty"`
	Action    Action    `json:"action"`
	// Reason says why, in the operator's terms, including what was not
	// established.
	Reason string `json:"reason"`

	index int
}

// Result is the decision for a whole run.
type Result struct {
	Policy Level `json:"policy"`
	// Action is the strongest decision across advisories.
	Action Action `json:"action"`
	// AutoMerge is true only when every advisory in the pull request qualified
	// for remediate. It permits a merge; it does not perform one.
	AutoMerge bool `json:"automerge"`
	// PreviousRun is whether a previous run was available to compare against.
	PreviousRun bool `json:"previous_run"`
	// Incomplete is why the scan could not be trusted to have found everything.
	Incomplete string     `json:"incomplete,omitempty"`
	Decisions  []Decision `json:"decisions"`
	// Prepare are the positions, in Input.Findings, of the advisories that go
	// into the remediation pull request.
	Prepare []int `json:"-"`
}

// Counts tallies decisions by novelty and action.
func (r Result) Counts() (newN, knownN, waivedN int) {
	for i := range r.Decisions {
		switch r.Decisions[i].Novelty {
		case NoveltyNew:
			newN++
		case NoveltyKnown:
			knownN++
		case NoveltyWaived:
			waivedN++
		case NoveltyUnestablished:
		}
	}
	return newN, knownN, waivedN
}

// Evaluate decides what to do about each advisory in the scan.
func Evaluate(in Input) Result {
	res := Result{Policy: in.Policy.Level, Action: ActionNone, PreviousRun: in.HavePrevious, Incomplete: in.Incomplete}
	seen := knownSet(in.Previous)

	var candidates []int
	for i := range in.Findings {
		f := &in.Findings[i]
		if f.RuleID != ruleID || f.Metadata["vuln_id"] == "" {
			continue
		}
		d := describe(f, i)
		d.Novelty = noveltyOf(f, seen, in.HavePrevious)
		switch d.Novelty {
		case NoveltyWaived:
			d.Action = ActionNone
			d.Reason = fmt.Sprintf("Already %s; a person decided this one", waiverWord(f.Status))
		case NoveltyKnown:
			d.Action = ActionNone
			d.Reason = "Already present in the previous run; reported then."
		case NoveltyUnestablished:
			d.Action = ActionReport
			d.Reason = "No previous run to compare against, so whether this is new cannot be established; " +
				"reported, nothing is acted on until a run exists to compare with. " + relevanceSentence(f, d.Relevance)
		case NoveltyNew:
			d.Action = ActionReport
			candidates = append(candidates, len(res.Decisions))
		}
		res.Decisions = append(res.Decisions, d)
	}

	switch {
	case in.Incomplete != "":
		for _, c := range candidates {
			res.Decisions[c].Reason = "New, but this scan could not finish looking (" + in.Incomplete +
				"), so nothing is acted on. " + relevanceSentence(&in.Findings[res.Decisions[c].index], res.Decisions[c].Relevance)
		}
	case in.Policy.Level.rank() > Report.rank():
		res.Prepare = decideActions(&res, in, candidates)
	default:
		for _, c := range candidates {
			d := &res.Decisions[c]
			d.Reason = "New advisory; policy is report, so it is reported and nothing else. " +
				relevanceSentence(&in.Findings[d.index], d.Relevance)
		}
	}

	finalise(&res, in)
	return res
}

// decideActions assigns prepare/remediate to the candidates that earn it and
// returns the finding positions that belong in the pull request.
func decideActions(res *Result, in Input, candidates []int) []int {
	// Gate each candidate on severity, relevance and the existence of a fix.
	var eligible []int
	for _, c := range candidates {
		d := &res.Decisions[c]
		f := &in.Findings[d.index]
		why := relevanceSentence(f, d.Relevance)
		switch {
		case d.Relevance == RelNotImpacting:
			d.Reason = "New advisory, but " + strings.ToLower(why[:1]) + why[1:]
		case findings.SeverityRank(findings.Severity(d.Severity)) > findings.SeverityRank(in.Policy.Prepare.minSeverity):
			d.Reason = fmt.Sprintf("New advisory below the prepare severity gate (severity %s, need %s). %s",
				d.Severity, in.Policy.Prepare.minSeverity, why)
		case d.Relevance.rank() < in.Policy.Prepare.minRelevance.rank():
			d.Reason = fmt.Sprintf("New advisory below the prepare relevance gate (relevance %s, need %s). %s",
				d.Relevance, in.Policy.Prepare.minRelevance, why)
		case d.FixedIn == "":
			d.Reason = "New advisory with no fixed version published, so there is nothing to prepare. " + why
		default:
			eligible = append(eligible, c)
		}
	}

	// Plan once over the eligible set. The planner is the one `nox fix` uses, so
	// the pull request contains exactly the moves it would make, and a package
	// with several advisories moves once, to the highest fix.
	subset := make([]findings.Finding, len(eligible))
	for i, c := range eligible {
		subset[i] = in.Findings[res.Decisions[c].index]
	}
	plan := fix.PlanUpgrades(subset, fix.Options{})
	moved := map[int]fix.UpgradeAction{}
	for _, a := range plan.Actions {
		for _, p := range a.Findings {
			moved[p] = a
		}
	}

	var prepare []int
	for i, c := range eligible {
		d := &res.Decisions[c]
		f := &in.Findings[d.index]
		why := relevanceSentence(f, d.Relevance)
		mv, ok := moved[i]
		if !ok {
			d.Reason = unplannedReason(subset[i], plan, i) + " " + why
			continue
		}
		d.Action = ActionPrepare
		prepare = append(prepare, d.index)
		bump := fix.BumpKind(mv.From, mv.To)
		move := fmt.Sprintf("%s %s -> %s (%s)", mv.Package, mv.From, mv.To, bump)
		d.Reason = "New advisory; prepared as a pull request: " + move + ". " + why

		if in.Policy.Level != Remediate {
			continue
		}
		if why2 := mergeBlocker(d, in.Policy, bump); why2 != "" {
			d.Reason += " Not eligible to merge: " + why2 + "."
			continue
		}
		d.Action = ActionRemediate
		d.Reason += " Meets the remediate gate; may merge once the repository's required checks pass."
	}
	sort.Ints(prepare)
	return prepare
}

// mergeBlocker returns why an already-prepared advisory may not be merged
// unattended, or "" when it may.
func mergeBlocker(d *Decision, p Policy, bump fix.Bump) string {
	switch {
	case findings.SeverityRank(findings.Severity(d.Severity)) > findings.SeverityRank(p.Merge.minSeverity):
		return fmt.Sprintf("severity %s is below the remediate gate (%s)", d.Severity, p.Merge.minSeverity)
	case d.Relevance.rank() < p.Merge.minRelevance.rank():
		return fmt.Sprintf("relevance %s is below the remediate gate (%s); nothing established that this build uses the package", d.Relevance, p.Merge.minRelevance)
	case bump == fix.BumpUnknown:
		return "the size of the version move could not be determined"
	case bumpRank(bump) > bumpRank(p.MaxBump):
		return fmt.Sprintf("a %s bump exceeds max_bump %s", bump, p.MaxBump)
	}
	return ""
}

func bumpRank(b fix.Bump) int {
	switch b {
	case fix.BumpPatch:
		return 1
	case fix.BumpMinor:
		return 2
	}
	return 3
}

// unplannedReason explains why the shared planner declined an advisory that
// passed the gates.
func unplannedReason(f findings.Finding, plan fix.Plan, pos int) string {
	for _, h := range plan.Held {
		for _, p := range h.Findings {
			if p == pos {
				return fmt.Sprintf("New advisory whose fix crosses a major version (%s %s -> %s); a person must take that bump, so it is reported.",
					h.Package, h.From, h.To)
			}
		}
	}
	if _, ok := fix.SupportedEcosystem(f.Metadata["ecosystem"]); !ok {
		return fmt.Sprintf("New advisory in the %s ecosystem, which nox fix cannot drive, so it is reported.", f.Metadata["ecosystem"])
	}
	return "New advisory whose fixed version is not a forward upgrade nox can plan, so it is reported."
}

// finalise derives the run-level action and the merge permission.
func finalise(res *Result, in Input) {
	sort.SliceStable(res.Decisions, func(i, j int) bool {
		a, b := res.Decisions[i], res.Decisions[j]
		if ra, rb := findings.SeverityRank(findings.Severity(a.Severity)), findings.SeverityRank(findings.Severity(b.Severity)); ra != rb {
			return ra < rb
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Advisory != b.Advisory {
			return a.Advisory < b.Advisory
		}
		return a.Version < b.Version
	})

	allSafe := len(res.Prepare) > 0
	for i := range res.Decisions {
		d := res.Decisions[i]
		if d.Action.rank() > res.Action.rank() {
			res.Action = d.Action
		}
	}
	inPR := map[int]bool{}
	for _, p := range res.Prepare {
		inPR[p] = true
	}
	for i := range res.Decisions {
		d := res.Decisions[i]
		if inPR[d.index] && d.Action != ActionRemediate {
			allSafe = false
		}
	}
	res.AutoMerge = allSafe && in.Policy.Level == Remediate && in.Incomplete == ""
}

// describe fills the identity and severity of a decision from a finding.
func describe(f *findings.Finding, idx int) Decision {
	m := f.Metadata
	d := Decision{
		Advisory:  m["vuln_id"],
		Ecosystem: m["ecosystem"],
		Package:   m["package"],
		Version:   m["version"],
		FixedIn:   m["fixed_in"],
		Severity:  string(f.Severity),
		Relevance: relevanceOf(f),
		index:     idx,
	}
	for _, a := range strings.Split(m["aliases"], ",") {
		if a = strings.TrimSpace(a); a != "" {
			d.Aliases = append(d.Aliases, a)
		}
	}
	sort.Strings(d.Aliases)
	// A candidate nobody has published is not an advisory anyone can upgrade
	// away from, whatever fixed_in says. It is reported and left there.
	if m["theoretical"] == "true" {
		d.FixedIn = ""
	}
	return d
}

// relevanceOf reads the applicability fields the dependency analyzer records.
//
// Undetermined, absent and unrecognised all land on RelUndetermined. They are
// "nobody established otherwise", and the only value that may lower an
// advisory is the explicit not_impacting outcome.
func relevanceOf(f *findings.Finding) Relevance {
	m := f.Metadata
	if m["applicability"] == "not_impacting" {
		return RelNotImpacting
	}
	switch m["applicability_reached"] {
	case "call_reachable", "attacker_reachable":
		if m["applicability"] == "impacting" {
			return RelCallReachable
		}
		return RelSymbolUsed
	case "symbol_used":
		return RelSymbolUsed
	}
	return RelUndetermined
}

// relevanceSentence states what was and was not established, in words that
// cannot be read as a clearance.
func relevanceSentence(f *findings.Finding, r Relevance) string {
	m := f.Metadata
	switch r {
	case RelNotImpacting:
		return "This build was shown not to be affected (" + m["applicability_stopped_at"] + " was refuted); reported with that reason, not acted on."
	case RelCallReachable:
		return "A call path reaches the affected code."
	case RelSymbolUsed:
		return "The affected package is linked by this build; whether anything calls it was not established."
	}
	stopped, because := m["applicability_stopped_at"], m["applicability_because"]
	if stopped == "" {
		return "Relevance could not be determined (no applicability analysis recorded); treated as possibly affected, not as safe."
	}
	return fmt.Sprintf("Relevance could not be determined (%s was not established: %s); treated as possibly affected, not as safe.", stopped, because)
}

func waiverWord(s findings.Status) string {
	switch s {
	case findings.StatusBaselined:
		return "baselined"
	case findings.StatusVEXNotAffected:
		return "waived as not affected (VEX)"
	case findings.StatusVEXFixed:
		return "marked fixed (VEX)"
	}
	return "suppressed"
}

// noveltyOf classifies one advisory.
func noveltyOf(f *findings.Finding, seen map[string]struct{}, havePrevious bool) Novelty {
	if !f.Status.IsActive() {
		return NoveltyWaived
	}
	if !havePrevious {
		return NoveltyUnestablished
	}
	for _, id := range advisoryIDs(f) {
		if _, ok := seen[idKey(f, id)]; ok {
			return NoveltyKnown
		}
	}
	return NoveltyNew
}

// knownSet indexes every id an earlier run reported, per package.
//
// Keyed by ecosystem, package and advisory id, and not by version or
// fingerprint. A fingerprint hashes the message, which carries the advisory's
// summary and the applicability sentence; either changing would make last
// week's advisory look newly disclosed. And an advisory still hitting a package
// that was upgraded within the vulnerable range is the same advisory.
func knownSet(prev []findings.Finding) map[string]struct{} {
	out := map[string]struct{}{}
	for i := range prev {
		f := &prev[i]
		if f.RuleID != ruleID || f.Metadata["vuln_id"] == "" {
			continue
		}
		for _, id := range advisoryIDs(f) {
			out[idKey(f, id)] = struct{}{}
		}
	}
	return out
}

// IDs returns every identifier an advisory finding answers to: its vuln id and
// its aliases (GHSA and CVE for the same flaw). ok is false for a finding that
// is not a dependency advisory. It is the one definition of advisory identity,
// shared with core/change so "the same advisory" means the same thing in the
// two places that ask.
func IDs(f *findings.Finding) (ids []string, ok bool) {
	if f.RuleID != ruleID || f.Metadata["vuln_id"] == "" {
		return nil, false
	}
	return advisoryIDs(f), true
}

func advisoryIDs(f *findings.Finding) []string {
	ids := []string{f.Metadata["vuln_id"]}
	for _, a := range strings.Split(f.Metadata["aliases"], ",") {
		if a = strings.TrimSpace(a); a != "" {
			ids = append(ids, a)
		}
	}
	return ids
}

func idKey(f *findings.Finding, id string) string {
	return f.Metadata["ecosystem"] + "|" + f.Metadata["package"] + "|" + strings.ToUpper(id)
}
