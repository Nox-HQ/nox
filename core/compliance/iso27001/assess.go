package iso27001

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// Status describes the EVIDENCE nox holds for a control, never the control.
//
// There is deliberately no value that reads as "this control is met": a scanner
// cannot know that, because an Annex A control is satisfied by an organisation
// operating a process. Adding such a value is the change TestNoStatusClaimsMet
// exists to stop.
type Status string

const (
	// SupportingEvidence means every check behind the control ran, was
	// complete, and has nothing open. The evidence supports the control; the
	// control's Limits still list what it does not show.
	SupportingEvidence Status = "supporting_evidence"
	// OpenIssues means the checks ran and found issues still open.
	OpenIssues Status = "open_issues"
	// LimitedEvidence means nox holds some evidence but only at one remove, or
	// part of the checks behind it did not run or did not complete.
	LimitedEvidence Status = "limited_evidence"
	// NotEvidenced means the scan holds no evidence for the control, either
	// because none is possible from a repository or because the checks did not
	// run.
	NotEvidenced Status = "not_evidenced"
)

// Evidence is one cited piece of technical evidence for a control.
type Evidence struct {
	// Artifact is the scan output the claim comes from (its base name).
	Artifact string `json:"artifact"`
	// Statement is the claim, in words, with the counts it rests on.
	Statement string `json:"statement"`
	// Findings and Waived count active findings and findings that are
	// baselined, suppressed or VEX-cleared, among those this evidence selects.
	Findings int `json:"findings"`
	Waived   int `json:"waived"`
	// Rules lists the distinct rule IDs behind the counts, sorted.
	Rules []string `json:"rules,omitempty"`
}

// Control is the assessment of one Annex A control.
type Control struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Theme    string     `json:"theme"`
	Status   Status     `json:"status"`
	Evidence []Evidence `json:"evidence"`
	// Gaps are what is missing from THIS run: checks that did not run, outputs
	// that were not provided, capabilities that never answered.
	Gaps []string `json:"gaps,omitempty"`
	// Limits are what this evidence can never show, whatever the run found.
	Limits []string `json:"limits"`
	// Organizational lists the IDs of the OrgItems the control depends on.
	Organizational []string `json:"organizational_evidence"`
}

// Meta identifies the document. Its shape is the one every nox JSON report
// carries, which is also how a later scan recognises this file as nox's own
// output and does not read it back as source.
type Meta struct {
	SchemaVersion string `json:"schema_version"`
	ToolName      string `json:"tool_name"`
	ToolVersion   string `json:"tool_version"`
	Report        string `json:"report"`
	Standard      string `json:"standard"`
}

// Provenance says what the assessment was derived from.
type Provenance struct {
	// ScanToolVersion and ScanGeneratedAt come from findings.json, so they
	// describe the scan, not the moment the assessment was written.
	ScanToolVersion string `json:"scan_tool_version"`
	ScanGeneratedAt string `json:"scan_generated_at"`
	ScanOffline     bool   `json:"scan_offline"`
	// ScopesScanned and ScopesNotScanned come from findings.json; empty
	// NotScanned means a full scan.
	ScopesScanned    []string `json:"scopes_scanned"`
	ScopesNotScanned []string `json:"scopes_not_scanned,omitempty"`
	Degradations     int      `json:"degradations"`
	// Commit is the repository revision when the assessment was generated; the
	// scan may have run at an earlier one.
	Commit    string     `json:"commit,omitempty"`
	Artifacts []Artifact `json:"artifacts"`
}

// Summary counts controls by the status of their evidence.
type Summary struct {
	Controls           int `json:"controls"`
	SupportingEvidence int `json:"supporting_evidence"`
	OpenIssues         int `json:"open_issues"`
	LimitedEvidence    int `json:"limited_evidence"`
	NotEvidenced       int `json:"not_evidenced"`
}

// Assessment is the complete, serialisable result.
type Assessment struct {
	Meta       Meta       `json:"meta"`
	Notice     string     `json:"notice"`
	Provenance Provenance `json:"provenance"`
	Summary    Summary    `json:"summary"`
	Controls   []Control  `json:"controls"`
	// Organizational is the checklist of evidence a repository cannot show.
	Organizational []OrgItem `json:"organizational_evidence_required"`
}

// Notice is printed in every rendering. It avoids the vocabulary of
// certification on purpose: nothing here is a verdict.
const Notice = "This is technical evidence from an automated scan, offered as supporting material for an " + Standard +
	" assessment. It does not decide whether any control is implemented or effective, it is not an audit, and it is not a " +
	"certificate. Each statement cites the scan output it comes from; each control lists what that evidence cannot show."

// ShortNotice is the one-line form of Notice, for the terminal.
const ShortNotice = "Supporting evidence only: nox does not decide whether any control is implemented or effective."

// ControlIDs returns the Annex A control numbers this package maps, in order.
func ControlIDs() []string {
	ids := make([]string, len(controls))
	for i, c := range controls {
		ids[i] = c.id
	}
	return ids
}

// Assess derives the assessment from in. It is a pure function of in.
func Assess(in Input) Assessment {
	ctx := newContext(in)
	out := Assessment{
		Meta: Meta{
			SchemaVersion: "1.0.0", ToolName: "nox", ToolVersion: in.NoxVersion,
			Report: "iso27001-technical-evidence", Standard: Standard,
		},
		Notice:         Notice,
		Provenance:     ctx.provenance(),
		Organizational: orgChecklist(),
	}
	needed := map[string][]string{}
	for _, def := range controls {
		c := ctx.assessControl(def)
		out.Controls = append(out.Controls, c)
		for _, id := range c.Organizational {
			needed[id] = append(needed[id], c.ID)
		}
		out.Summary.add(c.Status)
	}
	for i := range out.Organizational {
		out.Organizational[i].Controls = needed[out.Organizational[i].ID]
	}
	return out
}

func (s *Summary) add(st Status) {
	s.Controls++
	switch st {
	case SupportingEvidence:
		s.SupportingEvidence++
	case OpenIssues:
		s.OpenIssues++
	case LimitedEvidence:
		s.LimitedEvidence++
	default:
		s.NotEvidenced++
	}
}

func orgChecklist() []OrgItem {
	out := make([]OrgItem, len(orgItems))
	copy(out, orgItems)
	return out
}

// context holds what is derived once from the input.
type context struct {
	in      Input
	scanned map[string]bool
	full    bool
	active  []findings.Finding
	waived  []findings.Finding
}

func newContext(in Input) *context {
	c := &context{in: in, scanned: map[string]bool{}, full: in.Report.Meta.Scope == nil}
	if sc := in.Report.Meta.Scope; sc != nil {
		for _, s := range sc.Scanned {
			c.scanned[s] = true
		}
	}
	for _, f := range in.Report.Findings {
		if f.Status.IsActive() {
			c.active = append(c.active, f)
		} else {
			c.waived = append(c.waived, f)
		}
	}
	return c
}

func (c *context) ran(scope string) bool {
	return scope == "" || c.full || c.scanned[scope]
}

func (c *context) provenance() Provenance {
	m := c.in.Report.Meta
	p := Provenance{
		ScanToolVersion: m.ToolVersion, ScanGeneratedAt: m.GeneratedAt, ScanOffline: m.Offline,
		Degradations: len(m.Degradations), Commit: c.in.Commit,
	}
	arts := append([]Artifact(nil), c.in.Artifacts...)
	sortArtifacts(arts)
	p.Artifacts = arts
	if m.Scope != nil {
		p.ScopesScanned = append([]string{}, m.Scope.Scanned...)
		p.ScopesNotScanned = append([]string{}, m.Scope.NotScanned...)
		sort.Strings(p.ScopesScanned)
		sort.Strings(p.ScopesNotScanned)
	} else {
		p.ScopesScanned = []string{"all"}
	}
	return p
}

func (c *context) findingsArtifact() string {
	for _, a := range c.in.Artifacts {
		if a.Kind == "findings" {
			return a.Name
		}
	}
	return "findings.json"
}

// matches reports whether f is selected by the source.
func (s source) matches(f findings.Finding) bool {
	for _, id := range s.ids {
		if f.RuleID == id {
			return true
		}
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(f.RuleID, p) {
			return true
		}
	}
	if len(s.cwes) > 0 {
		cwe := f.Metadata["cwe"]
		for _, w := range s.cwes {
			if cwe == w {
				return true
			}
		}
	}
	return false
}

// tally is the outcome of evaluating one source.
type tally struct {
	evidence   *Evidence
	gap        string
	incomplete bool
	open       int
}

func (c *context) assessControl(def controlDef) Control {
	ctl := Control{
		ID: def.id, Title: def.title, Theme: def.theme,
		Limits: def.limits, Organizational: def.org, Evidence: []Evidence{},
	}
	var held, open int
	incomplete := false
	for _, src := range def.sources {
		t := c.evaluate(src)
		if t.evidence != nil {
			ctl.Evidence = append(ctl.Evidence, *t.evidence)
			held++
		}
		if t.gap != "" {
			ctl.Gaps = append(ctl.Gaps, t.gap)
		}
		incomplete = incomplete || t.incomplete
		open += t.open
	}
	if def.needsCapability != "" && c.answered(def.needsCapability) == 0 {
		ctl.Gaps = append(ctl.Gaps, def.capabilityGap)
		incomplete = true
	}
	ctl.Status = classify(len(def.sources), held, open, incomplete || def.indirect)
	return ctl
}

func classify(sources, held, open int, limited bool) Status {
	switch {
	case sources == 0 || held == 0:
		return NotEvidenced
	case open > 0:
		return OpenIssues
	case limited:
		return LimitedEvidence
	}
	return SupportingEvidence
}

func (c *context) answered(capability string) int {
	n := 0
	for _, cc := range c.in.Report.Meta.Capabilities {
		if cc.Capability == capability {
			n += cc.Answered
		}
	}
	return n
}

func (c *context) evaluate(src source) tally {
	switch src.kind {
	case fromFindings:
		return c.evaluateFindings(src)
	case fromSBOM:
		return c.evaluateSBOM(src)
	case fromAI:
		return c.evaluateAI(src)
	case fromLeads:
		return c.evaluateLeads(src)
	}
	return c.evaluateScanRecord(src)
}

// evaluateLeads names the authorization leads the scan produced. A lead is a
// route worth testing, not a defect, so it is never counted as open; it is a
// gap, because the control cannot be read as evidenced while a lead is
// unconfirmed in either direction.
func (c *context) evaluateLeads(src source) tally {
	n := len(c.in.Report.Leads)
	if n == 0 {
		return tally{}
	}
	return tally{incomplete: true, gap: fmt.Sprintf(
		"%s: %d authorization lead(s) are routes that load a record by a caller-supplied id with no visible ownership check. They are hints, not findings: each needs a two-account test before it counts as a defect or is set aside.", src.label, n)}
}

func (c *context) evaluateFindings(src source) tally {
	if src.additive && (!c.ran(src.scope) || !c.hasMatch(src)) {
		return tally{}
	}
	if !c.ran(src.scope) {
		return tally{gap: fmt.Sprintf("%s did not run: the %q scope was not scanned, so the absence of findings says nothing.", src.label, src.scope), incomplete: true}
	}
	var act, wav []findings.Finding
	for _, f := range c.active {
		if src.matches(f) {
			act = append(act, f)
		}
	}
	for _, f := range c.waived {
		if src.matches(f) {
			wav = append(wav, f)
		}
	}
	t := tally{open: len(act)}
	if len(wav) > 0 {
		t.gap = fmt.Sprintf("%s: %d finding(s) are waived, baselined or VEX-cleared. Each is a decision to accept or defer a risk; the scan does not show who made it or why, and a reviewer will ask.", src.label, len(wav))
		t.incomplete = true
	}
	if len(act)+len(wav) == 0 && !c.subjectPresent(src) {
		t.gap = joinGap(t.gap, fmt.Sprintf("%s found nothing, but the scan outputs do not show that any files of this kind were present. No findings may mean there was nothing to check.", src.label))
		t.incomplete = true
	}
	if src.networkLookup {
		if gap := c.lookupGap(src, len(act)+len(wav)); gap != "" {
			t.gap = joinGap(t.gap, gap)
			t.incomplete = true
		}
	}
	for _, d := range c.in.Report.Meta.Degradations {
		for _, k := range src.degradeKinds {
			if d.Kind == k {
				t.gap = joinGap(t.gap, fmt.Sprintf("%s ran incompletely (%s): %s", src.label, d.Kind, d.Impact))
				t.incomplete = true
			}
		}
	}
	t.evidence = &Evidence{
		Artifact: c.findingsArtifact(), Findings: len(act), Waived: len(wav),
		Statement: findingsStatement(src, act, wav), Rules: distinctRules(act, wav),
	}
	return t
}

func (c *context) hasMatch(src source) bool {
	for _, f := range c.active {
		if src.matches(f) {
			return true
		}
	}
	for _, f := range c.waived {
		if src.matches(f) {
			return true
		}
	}
	return false
}

func joinGap(a, b string) string {
	if a == "" {
		return b
	}
	return a + " " + b
}

// subjectPresent reports whether the outputs show something for the source's
// checks to have examined, which is what makes an empty result mean "checked
// and found nothing" instead of "had nothing to look at".
func (c *context) subjectPresent(src source) bool {
	if src.anywhere {
		return true
	}
	if src.scope == "ai" {
		return c.in.AI != nil && c.in.AI.Components+c.in.AI.Models > 0
	}
	return src.subjectFromSBOM && c.in.SBOM != nil && c.in.SBOM.Components > 0
}

// lookupGap says why an advisory lookup cannot be assumed to have happened.
// Findings prove it did; an offline scan proves it did not; and an empty
// result proves neither, because a scan with the lookup disabled records no
// degradation and looks exactly like a clean one.
func (c *context) lookupGap(src source, found int) string {
	switch {
	case c.in.Report.Meta.Offline:
		return src.label + " did not query its advisory source: the scan ran offline."
	case found == 0:
		return src.label + " reported nothing, but the scan outputs do not record whether the advisory lookup ran (a scan run with --no-osv produces the same output). Confirm it was not disabled."
	}
	return ""
}

func findingsStatement(src source, act, wav []findings.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s ran (scope: %s). ", src.label, scopeLabel(src.scope))
	if len(act) == 0 {
		b.WriteString("No open findings.")
	} else {
		fmt.Fprintf(&b, "%d open finding(s): %s.", len(act), severityCounts(act))
	}
	if n := withMeta(act, "fixed_in"); n > 0 {
		fmt.Fprintf(&b, " %d of them name a version that fixes them.", n)
	}
	if len(wav) > 0 {
		fmt.Fprintf(&b, " Also %d finding(s) baselined, suppressed or VEX-cleared.", len(wav))
	}
	return b.String()
}

func scopeLabel(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

func withMeta(ff []findings.Finding, key string) int {
	n := 0
	for _, f := range ff {
		if f.Metadata[key] != "" {
			n++
		}
	}
	return n
}

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

func severityCounts(ff []findings.Finding) string {
	counts := map[string]int{}
	for _, f := range ff {
		counts[strings.ToLower(string(f.Severity))]++
	}
	var parts []string
	for _, s := range severityOrder {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

func distinctRules(groups ...[]findings.Finding) []string {
	seen := map[string]bool{}
	for _, g := range groups {
		for _, f := range g {
			seen[f.RuleID] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (c *context) evaluateSBOM(src source) tally {
	if !c.ran(src.scope) {
		return tally{gap: "No software bill of materials can describe this scan: the deps scope was not scanned.", incomplete: true}
	}
	s := c.in.SBOM
	if s == nil {
		return tally{gap: "No SBOM was provided with the scan outputs. Produce one with `nox scan . --format json,cdx` and run this command again.", incomplete: true}
	}
	return tally{evidence: &Evidence{
		Artifact:  s.Name,
		Statement: fmt.Sprintf("%s lists %d component(s) in %s format.", src.label, s.Components, s.Format),
	}}
}

func (c *context) evaluateAI(src source) tally {
	if !c.ran(src.scope) {
		return tally{gap: "AI components were not inventoried: the ai scope was not scanned.", incomplete: true}
	}
	a := c.in.AI
	if a == nil {
		return tally{gap: "No ai.inventory.json was provided with the scan outputs; `nox scan` writes one on every run.", incomplete: true}
	}
	st := fmt.Sprintf("%s lists %d component(s) and %d model reference(s)", src.label, a.Components, a.Models)
	if a.UnpinnedModels > 0 {
		st += fmt.Sprintf(", %d of them not pinned to a version", a.UnpinnedModels)
	}
	return tally{evidence: &Evidence{Artifact: a.Name, Statement: st + "."}}
}

func (c *context) evaluateScanRecord(src source) tally {
	m := c.in.Report.Meta
	scope := "all scopes"
	if m.Scope != nil {
		scope = "scopes " + strings.Join(m.Scope.Scanned, ", ")
	}
	return tally{evidence: &Evidence{
		Artifact: c.findingsArtifact(),
		Statement: fmt.Sprintf("%s: a scan by nox %s on %s covered %s with %d active finding(s) in total. It shows a security scan was run, not that one runs on every change.",
			src.label, m.ToolVersion, m.GeneratedAt, scope, len(c.active)),
	}}
}
