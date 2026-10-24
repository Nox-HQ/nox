package remediate

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/findings"
)

// Status is what a re-run of the checks showed about one change.
type Status string

// The statuses. Only StatusFixed claims success, and it is reached one way:
// the check that produced the finding ran again, to completion, and did not
// report it.
const (
	StatusFixed        Status = "verified_fixed"
	StatusStillPresent Status = "still_present"
	StatusNewFinding   Status = "new_finding_introduced"
	// StatusNotVerified is "the check could not run again", which is not a
	// pass. It is the status that keeps an offline run, or a failed
	// vulnerability lookup, from reading as a clean result.
	StatusNotVerified Status = "not_verified"
	// StatusNotApplied is a change that did not happen, so there is nothing
	// to verify.
	StatusNotApplied Status = "not_applied"
)

// Attempt is what happened when the CLI tried to apply an item.
type Attempt struct {
	// N is the plan item's number.
	N       int
	Applied bool
	// Error says why it was not applied.
	Error string
}

// Outcome is the verified result for one plan item.
type Outcome struct {
	N      int    `json:"n"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	// Targeted is how many findings the change was meant to clear, and
	// Remaining how many of them the re-run still reports.
	Targeted  int `json:"targeted"`
	Remaining int `json:"remaining"`
	// New are findings the re-run reports that the original scan did not, on
	// the package or files the change touched.
	New []string `json:"new,omitempty"`
}

// Counts tallies outcomes by status.
type Counts struct {
	Fixed        int `json:"verified_fixed"`
	StillPresent int `json:"still_present"`
	NewFinding   int `json:"new_finding_introduced"`
	NotVerified  int `json:"not_verified"`
	NotApplied   int `json:"not_applied"`
}

// Report is the result of verifying a set of changes.
type Report struct {
	Outcomes []Outcome `json:"outcomes"`
	Counts   Counts    `json:"counts"`
	// Rechecked names the checks that were run again.
	Rechecked []string `json:"rechecked"`
	// NewElsewhere are findings the re-run reports that the original scan did
	// not and that no change touched.
	NewElsewhere []string `json:"new_elsewhere,omitempty"`
	// Untouched are the plan items nothing was attempted for.
	Untouched []int `json:"untouched,omitempty"`
}

// Rescan is the outcome of running some checks again.
type Rescan struct {
	// Active are the findings the re-run reports; All also holds the ones a
	// baseline or waiver suppressed.
	Active []findings.Finding
	All    []findings.Finding
	// Unchecked maps each scope that did not complete to why. A scope absent
	// from it ran to completion.
	Unchecked map[nox.Scope]string
}

// Rescanner runs the given scopes again over the project. A nil scope list
// means a full scan.
type Rescanner func(ctx context.Context, scopes []nox.Scope) (Rescan, error)

// CoreRescanner re-runs checks with the same engine `nox scan` uses. With
// offline set it makes no network call, and so cannot look vulnerabilities up
// again: dependency changes are then reported as not verified.
func CoreRescanner(root string, offline bool) Rescanner {
	return func(ctx context.Context, scopes []nox.Scope) (Rescan, error) {
		opts := nox.ScanOptions{Offline: offline}
		if scopes != nil {
			opts.Scopes = nox.OnlyScopes(scopes...)
		}
		res, err := nox.RunScanContext(ctx, root, opts)
		if err != nil {
			return Rescan{}, err
		}
		rs := Rescan{
			Active:    res.Findings.ActiveFindings(),
			All:       res.Findings.Findings(),
			Unchecked: map[nox.Scope]string{},
		}
		for _, s := range scopesOrAll(scopes) {
			if reason := incomplete(res, s, offline); reason != "" {
				rs.Unchecked[s] = reason
			}
		}
		return rs, nil
	}
}

func scopesOrAll(scopes []nox.Scope) []nox.Scope {
	if scopes != nil {
		return scopes
	}
	return []nox.Scope{nox.ScopeSecrets, nox.ScopeCode, nox.ScopeDeps, nox.ScopeIaC, nox.ScopeAI, nox.ScopeData, nox.ScopeSupplyChain}
}

// depsFailures are the degradations that mean the dependency check could not
// say what it normally says.
var depsFailures = map[string]bool{"osv_lookup": true, "lockfile_parse": true, "vuln_data_load": true}

// incomplete says why a scope's re-run cannot be trusted, or "" when it can.
func incomplete(res *nox.ScanResult, s nox.Scope, offline bool) string {
	if !res.Scope.Has(s) {
		return "the " + scopeLabel(s) + " check did not run"
	}
	if s != nox.ScopeDeps {
		return ""
	}
	if offline {
		return "this run is offline, so known vulnerabilities cannot be looked up again; re-run without --offline to check"
	}
	for _, d := range res.Degradations {
		if depsFailures[string(d.Kind)] && d.Blocks() {
			return "the dependency check did not complete (" + strings.TrimSuffix(d.Impact, ".") + ")"
		}
	}
	return ""
}

var scopeLabels = map[nox.Scope]string{
	nox.ScopeSecrets:     "secrets",
	nox.ScopeCode:        "application code",
	nox.ScopeDeps:        "dependency",
	nox.ScopeIaC:         "infrastructure configuration",
	nox.ScopeAI:          "AI integration",
	nox.ScopeData:        "sensitive-data",
	nox.ScopeSupplyChain: "supply chain",
}

func scopeLabel(s nox.Scope) string {
	if l, ok := scopeLabels[s]; ok {
		return l
	}
	return string(s)
}

// Verify runs again the checks that produced the targeted findings and reports,
// per applied change, what they now show.
//
// before is the finding list the plan was built from. The re-run is the only
// evidence a change worked: a package manager that exits 0, a file that was
// written, a version that moved -- none of those says the finding is gone. So a
// change is verified fixed only when its scope's checks ran to completion and
// did not report any of the findings it targeted. A check that could not run
// is reported as such; it is never a pass.
func Verify(ctx context.Context, plan Plan, before []findings.Finding, attempts []Attempt, scan Rescanner) Report {
	rep := Report{Outcomes: []Outcome{}}
	attempted := map[int]Attempt{}
	for _, a := range attempts {
		attempted[a.N] = a
	}
	for i := range plan.Items {
		if _, ok := attempted[plan.Items[i].N]; !ok {
			rep.Untouched = append(rep.Untouched, plan.Items[i].N)
		}
	}

	var applied []*Item
	for i := range plan.Items {
		it := &plan.Items[i]
		a, ok := attempted[it.N]
		switch {
		case !ok:
		case a.Applied:
			applied = append(applied, it)
		default:
			rep.Outcomes = append(rep.Outcomes, Outcome{
				N: it.N, Title: it.Title, Status: StatusNotApplied, Targeted: it.Findings, Remaining: it.Findings,
				Detail: "Not applied: " + a.Error + ". Its findings are unchanged.",
			})
		}
	}

	if len(applied) > 0 {
		scopes := rescanScopes(applied)
		rep.Rechecked = scopeNames(scopes)
		rs, err := scan(ctx, scopes)
		if err != nil {
			for _, it := range applied {
				rep.Outcomes = append(rep.Outcomes, notVerified(it, "the re-run failed: "+err.Error()))
			}
		} else {
			v := newVerifier(before, rs)
			for _, it := range applied {
				rep.Outcomes = append(rep.Outcomes, v.outcome(it))
			}
			rep.NewElsewhere = v.unclaimed()
		}
	}
	sort.SliceStable(rep.Outcomes, func(i, j int) bool { return rep.Outcomes[i].N < rep.Outcomes[j].N })
	for i := range rep.Outcomes {
		rep.Counts.add(rep.Outcomes[i].Status)
	}
	return rep
}

func (c *Counts) add(s Status) {
	switch s {
	case StatusFixed:
		c.Fixed++
	case StatusStillPresent:
		c.StillPresent++
	case StatusNewFinding:
		c.NewFinding++
	case StatusNotVerified:
		c.NotVerified++
	case StatusNotApplied:
		c.NotApplied++
	}
}

// itemScopes are the scopes an item's rules belong to. ok is false when a rule
// belongs to none (a custom rule), which no narrowed re-run can be trusted to
// include.
func itemScopes(it *Item) (scopes []nox.Scope, ok bool) {
	seen := map[nox.Scope]bool{}
	for _, r := range it.Rules {
		s, found := nox.ScopeOfRule(r)
		if !found {
			return nil, false
		}
		if !seen[s] {
			seen[s] = true
			scopes = append(scopes, s)
		}
	}
	return scopes, true
}

// rescanScopes is the union of the applied items' scopes, or nil (everything)
// when any item has a rule no scope owns.
func rescanScopes(items []*Item) []nox.Scope {
	seen := map[nox.Scope]bool{}
	var out []nox.Scope
	for _, it := range items {
		ss, ok := itemScopes(it)
		if !ok {
			return nil
		}
		for _, s := range ss {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func scopeNames(ss []nox.Scope) []string {
	if ss == nil {
		return []string{"full"}
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = scopeLabel(s)
	}
	return out
}

func notVerified(it *Item, why string) Outcome {
	return Outcome{
		N: it.N, Title: it.Title, Status: StatusNotVerified, Targeted: it.Findings, Remaining: it.Findings,
		Detail: "Could not verify: " + why + ". Nothing is claimed about whether it is fixed.",
	}
}

// verifier compares a re-run with the findings it is meant to have cleared.
type verifier struct {
	byFP        map[string]*findings.Finding
	beforeID    map[string]bool
	beforeLoose map[string]bool
	rescan      Rescan
	activeID    map[string][]*findings.Finding
	suppressed  map[string]bool
	claimed     map[string]bool
}

func newVerifier(before []findings.Finding, rs Rescan) *verifier {
	v := &verifier{
		byFP:        map[string]*findings.Finding{},
		beforeID:    map[string]bool{},
		beforeLoose: map[string]bool{},
		rescan:      rs,
		activeID:    map[string][]*findings.Finding{},
		suppressed:  map[string]bool{},
		claimed:     map[string]bool{},
	}
	for i := range before {
		f := &before[i]
		v.byFP[f.Fingerprint] = f
		v.beforeID[identity(f)] = true
		v.beforeLoose[looseKey(f)] = true
	}
	for i := range rs.Active {
		f := &rs.Active[i]
		v.activeID[identity(f)] = append(v.activeID[identity(f)], f)
	}
	for i := range rs.All {
		f := &rs.All[i]
		if _, active := v.activeID[identity(f)]; !active {
			v.suppressed[identity(f)] = true
		}
	}
	return v
}

// identity names a finding across a change that rewrites what its fingerprint
// is made of. A dependency finding's fingerprint carries the installed version,
// so upgrading to a release the advisory still affects gives the same
// vulnerability a new fingerprint; comparing fingerprints would then report it
// gone. The advisory in the package at the manifest is what stays the same.
func identity(f *findings.Finding) string {
	if id := f.Metadata["vuln_id"]; id != "" && f.Metadata["package"] != "" {
		return strings.Join([]string{f.RuleID, f.Location.FilePath, f.Metadata["ecosystem"], f.Metadata["package"], id}, "|")
	}
	return f.Fingerprint
}

// looseKey is what a finding says, without the parts a change can move. It is
// how a finding that merely re-fingerprinted is told from one that is new.
func looseKey(f *findings.Finding) string {
	if id := f.Metadata["vuln_id"]; id != "" && f.Metadata["package"] != "" {
		return identity(f)
	}
	return f.RuleID + "|" + f.Location.FilePath + "|" + f.Message
}

func (v *verifier) outcome(it *Item) Outcome {
	if scopes, ok := itemScopes(it); ok {
		for _, s := range scopes {
			if why, bad := v.rescan.Unchecked[s]; bad {
				return notVerified(it, why)
			}
		}
	} else {
		for _, why := range v.rescan.Unchecked {
			return notVerified(it, why)
		}
	}

	o := Outcome{N: it.N, Title: it.Title, Targeted: it.Findings}
	var remaining []*findings.Finding
	suppressed := 0
	seen := map[string]bool{}
	for _, fp := range it.Fingerprints {
		f := v.byFP[fp]
		if f == nil {
			continue
		}
		id := identity(f)
		if seen[id] {
			continue
		}
		seen[id] = true
		remaining = append(remaining, v.activeID[id]...)
		if v.suppressed[id] {
			suppressed++
		}
	}
	o.Remaining = len(remaining) + suppressed
	o.New = v.newRelated(it)

	switch {
	case len(o.New) > 0:
		o.Status = StatusNewFinding
		o.Detail = fmt.Sprintf("The change introduced %s. %s", count(len(o.New), "finding the original scan did not report", "findings the original scan did not report"), remainingNote(o.Remaining, o.Targeted))
	case o.Remaining > 0:
		o.Status = StatusStillPresent
		o.Detail = stillPresentDetail(it, remaining, suppressed, o)
	default:
		o.Status = StatusFixed
		o.Detail = "The re-run no longer reports " + allOf(o.Targeted) + " this change targeted."
	}
	return o
}

// allOf says "the finding" or "any of the N findings".
func allOf(n int) string {
	if n == 1 {
		return "the finding"
	}
	return fmt.Sprintf("any of the %d findings", n)
}

func remainingNote(remaining, targeted int) string {
	switch {
	case remaining == 0 && targeted == 1:
		return "The finding it targeted is gone."
	case remaining == 0:
		return fmt.Sprintf("All %d findings it targeted are gone.", targeted)
	case targeted == 1:
		return "The finding it targeted is still reported."
	case remaining == targeted:
		return fmt.Sprintf("All %d findings it targeted are still reported.", targeted)
	}
	return fmt.Sprintf("%d of the %d findings it targeted are still reported.", remaining, targeted)
}

func stillPresentDetail(it *Item, remaining []*findings.Finding, suppressed int, o Outcome) string {
	d := strings.TrimSuffix(remainingNote(o.Remaining, o.Targeted), ".") + " after the change"
	if it.Upgrade != nil && len(remaining) > 0 {
		var ids []string
		for _, f := range remaining {
			ids = appendUnique(ids, f.Metadata["vuln_id"])
		}
		sort.Strings(ids)
		verb := "still affect"
		if len(ids) == 1 {
			verb = "still affects"
		}
		d += fmt.Sprintf(": %s is at %s, and %s %s that version (%s)",
			it.Upgrade.Package, remaining[0].Metadata["version"], count(len(ids), "advisory", "advisories"), verb, shortList(ids))
	}
	if suppressed > 0 {
		d += fmt.Sprintf("; %d of them are now suppressed by a baseline or waiver, which hides a finding without fixing it", suppressed)
	}
	return d + "."
}

func shortList(ss []string) string {
	const shown = 3
	if len(ss) <= shown {
		return strings.Join(ss, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(ss[:shown], ", "), len(ss)-shown)
}

// newRelated lists findings the re-run reports that the original scan did not,
// on the package or the files this item touched. Each is claimed, so it is not
// repeated as unattached.
func (v *verifier) newRelated(it *Item) []string {
	files := map[string]bool{}
	for _, fp := range it.Fingerprints {
		if f := v.byFP[fp]; f != nil {
			files[f.Location.FilePath] = true
		}
	}
	var out []string
	for i := range v.rescan.Active {
		f := &v.rescan.Active[i]
		if v.beforeID[identity(f)] || v.beforeLoose[looseKey(f)] {
			continue
		}
		related := false
		if it.Upgrade != nil {
			related = f.Metadata["package"] == it.Upgrade.Package && path.Dir(f.Location.FilePath) == path.Dir(it.Upgrade.Manifest)
		} else {
			related = files[f.Location.FilePath]
		}
		if related {
			out = append(out, describe(f))
			v.claimed[identity(f)+"|"+f.Fingerprint] = true
		}
	}
	sort.Strings(out)
	return out
}

// unclaimed lists the new findings no change accounts for.
func (v *verifier) unclaimed() []string {
	var out []string
	for i := range v.rescan.Active {
		f := &v.rescan.Active[i]
		if v.beforeID[identity(f)] || v.beforeLoose[looseKey(f)] || v.claimed[identity(f)+"|"+f.Fingerprint] {
			continue
		}
		out = append(out, describe(f))
	}
	sort.Strings(out)
	return out
}

// describe is a finding in one line.
func describe(f *findings.Finding) string {
	if id := f.Metadata["vuln_id"]; id != "" && f.Metadata["package"] != "" {
		return fmt.Sprintf("%s %s in %s@%s", f.RuleID, id, f.Metadata["package"], f.Metadata["version"])
	}
	if f.Location.StartLine > 0 {
		return fmt.Sprintf("%s at %s:%d", f.RuleID, f.Location.FilePath, f.Location.StartLine)
	}
	return fmt.Sprintf("%s in %s", f.RuleID, f.Location.FilePath)
}
