// Package change says what CHANGED between two scan states.
//
// A scan answers "what is wrong now". A person reading it a week later, or a
// reviewer reading a pull request, needs the other question: what is wrong now
// that was not before, what was fixed, and what got worse. Without it the new
// items are buried among every pre-existing one, and a one-line lockfile change
// reprints forty old advisories.
//
// This package is the one place that comparison is made, so the CLI, the MCP
// server and the LSP cannot drift into three different notions of "new". It is
// pure: no I/O, no clock, no network; the same two states always produce the
// same delta, in the same order.
//
// Identity decides everything here, and it is chosen per kind of thing:
//
//   - A dependency advisory is identified by manifest, ecosystem, package and
//     advisory id (any of its aliases). Not by fingerprint: the fingerprint
//     hashes the message, which carries the version, so upgrading a package
//     that is still affected would read as one advisory resolved and another
//     appearing. Upgrading within the vulnerable range is the same advisory.
//   - Every other finding is identified by rule, normalised file and message,
//     the line-independent fingerprint, computed here with the V2 algorithm
//     whatever version the scan pinned. A finding that only moved is neither
//     new nor resolved. When one fingerprint occurs several times in a file the
//     counts are exact and the pairing is by order, so which occurrence is
//     reported as resolved is approximate and the number is not.
//   - An authorization lead is identified by route and file. The line it sits
//     on is presentation.
//   - An agent capability is identified by agent, server, tool and capability.
//     An AI component by type and name.
//
// Two rules keep the answer honest. A comparison that cannot be made says so
// (Caveats) instead of reading as "nothing changed": a previous run that did not
// record leads, did not run the AI checks, or did not complete. And a finding
// that is waived or baselined between the runs is reported as waived, never as
// resolved: someone decided to stop looking, which is not the same as a fix.
package change

import (
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/advisory"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/infra"
	"github.com/nox-hq/nox/core/report"
)

// State is one scan, reduced to what a comparison needs. Build it with
// FromReport (a findings.json on disk) or core's FromScan (a scan in memory);
// both yield the same shape, which is what makes `--previous` and `nox diff`
// agree.
type State struct {
	// Label names this state in output: a ref ("main") or "previous run".
	Label string
	// Findings are every finding the scan produced, waived ones included.
	Findings []findings.Finding
	// Leads are the scan's authorization leads.
	Leads []report.Lead
	// LeadsRecorded is whether this state knows its leads. A findings.json
	// written before leads existed does not, and "no leads recorded" must not
	// read as "no leads".
	LeadsRecorded bool
	// Inventory is the AI inventory, or nil when none was recorded.
	Inventory *ai.Inventory
	// Infrastructure is the deployment inventory the scan read, or nil.
	Infrastructure *infra.Inventory
	// InfrastructureRecorded is whether this state knows its infrastructure.
	// A findings.json written before the inventory existed does not, and "no
	// inventory recorded" must not read as "no infrastructure".
	InfrastructureRecorded bool
	// Incomplete lists the checks that did not complete in this scan.
	Incomplete []string
	// Scanned is the scopes a scoped scan covered; nil means a full scan.
	Scanned []string
	// AdvisoryLookup is empty when this scan looked its dependencies up in a
	// vulnerability source, and otherwise says why it did not (offline,
	// --no-osv, a lookup that failed). A scan that did not look reports no
	// advisories because it did not ask, not because there are none, so the
	// advisories of such a scan are never compared.
	AdvisoryLookup string
}

// Why a scan did not look its dependencies up. They are the reasons State
// carries and the words a caveat uses.
const (
	LookupOffline  = "it was offline"
	LookupDisabled = "vulnerability lookups were disabled"
	LookupFailed   = "its vulnerability lookup failed"
)

// FromReport builds a State from a loaded findings.json and, optionally, the
// ai.inventory.json that sat beside it.
func FromReport(rep report.JSONReport, inv *ai.Inventory, label string) State {
	s := State{
		Label:         label,
		Findings:      rep.Findings,
		Leads:         rep.Leads,
		LeadsRecorded: len(rep.LeadChecks) > 0,
		Inventory:     inv,

		Infrastructure:         rep.Infrastructure,
		InfrastructureRecorded: rep.Infrastructure != nil,
	}
	for _, d := range rep.Meta.Degradations {
		if !d.Advisory {
			s.Incomplete = append(s.Incomplete, d.Detail)
		}
		if d.Kind == string(degrade.OSV) {
			s.AdvisoryLookup = LookupFailed
		}
	}
	switch {
	case rep.Meta.Offline:
		s.AdvisoryLookup = LookupOffline
	case rep.Meta.AdvisoryLookup == report.AdvisoryLookupSkipped:
		s.AdvisoryLookup = LookupDisabled
	}
	if rep.Meta.Scope != nil {
		s.Scanned = rep.Meta.Scope.Scanned
	}
	return s
}

// Item is one finding in a delta.
type Item struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Message     string `json:"message"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Package, Version and Advisory are set for a dependency advisory.
	Package  string `json:"package,omitempty"`
	Version  string `json:"version,omitempty"`
	Advisory string `json:"advisory,omitempty"`
}

// SeverityChange is a finding present in both states at a different severity.
type SeverityChange struct {
	Item
	From       string `json:"from"`
	To         string `json:"to"`
	Regression bool   `json:"regression"`
}

// Grant is a tool an agent holds and the capabilities it carries.
type Grant struct {
	Tool         string   `json:"tool"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// AgentChange is what one agent (or MCP server) gained or lost.
type AgentChange struct {
	Agent   string  `json:"agent"`
	Server  string  `json:"server,omitempty"`
	Path    string  `json:"path,omitempty"`
	Added   bool    `json:"added,omitempty"`
	Removed bool    `json:"removed,omitempty"`
	Gained  []Grant `json:"gained,omitempty"`
	Lost    []Grant `json:"lost,omitempty"`
}

// ComponentChange is an AI component that appeared or disappeared.
type ComponentChange struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

// Delta is the difference between two states.
type Delta struct {
	// Since is the label of the earlier state.
	Since string `json:"since"`
	// New are active findings with no counterpart in the earlier state.
	New []Item `json:"new"`
	// Resolved are earlier active findings with no counterpart now.
	Resolved []Item `json:"resolved"`
	// Waived are earlier active findings now baselined, suppressed or cleared
	// by VEX. Someone decided to stop looking; nothing was fixed.
	Waived []Item `json:"waived,omitempty"`
	// SeverityChanged are findings whose severity differs between the states.
	SeverityChanged []SeverityChange `json:"severity_changed,omitempty"`
	// NewLeads and ResolvedLeads are the authorization leads that appeared and
	// disappeared. Leads are hints, never findings.
	NewLeads      []report.Lead `json:"new_leads,omitempty"`
	ResolvedLeads []report.Lead `json:"resolved_leads,omitempty"`
	// Agents are the agents that gained or lost tools or capabilities.
	Agents []AgentChange `json:"agent_changes,omitempty"`
	// ComponentsAdded and ComponentsRemoved are AI components that came or went.
	ComponentsAdded   []ComponentChange `json:"components_added,omitempty"`
	ComponentsRemoved []ComponentChange `json:"components_removed,omitempty"`
	// Infrastructure are the security-relevant properties of deployment
	// resources that got weaker or stronger since the earlier state: the
	// assumptions a change invalidated, which findings alone cannot name
	// because a hardened resource has none. Hints, like leads: never counted
	// as regressions and never findings.
	Infrastructure []infra.Change `json:"infrastructure,omitempty"`
	// Caveats say what could not be compared or may be misleading. A delta with
	// caveats is not a clean bill of health.
	Caveats []string `json:"caveats,omitempty"`
}

// Compare returns what changed from prev to cur.
func Compare(prev, cur State) Delta {
	d := Delta{Since: prev.Label, New: []Item{}, Resolved: []Item{}}
	pf, cf := prev.Findings, cur.Findings
	if prev.AdvisoryLookup != "" || cur.AdvisoryLookup != "" {
		pf, cf = withoutAdvisories(pf), withoutAdvisories(cf)
	}
	compareFindings(&d, pf, cf)
	compareLeads(&d, prev, cur)
	compareInventory(&d, prev, cur)
	compareInfrastructure(&d, prev, cur)
	d.Caveats = append(d.Caveats, caveats(prev, cur)...)
	return d
}

// Empty reports whether nothing changed in anything compared.
func (d Delta) Empty() bool {
	return len(d.New) == 0 && len(d.Resolved) == 0 && len(d.Waived) == 0 &&
		len(d.SeverityChanged) == 0 && len(d.NewLeads) == 0 && len(d.ResolvedLeads) == 0 &&
		len(d.Agents) == 0 && len(d.ComponentsAdded) == 0 && len(d.ComponentsRemoved) == 0 &&
		len(d.Infrastructure) == 0
}

// Regressions counts what got worse in findings: new issues plus severity
// increases. It is what a gate on "this change made things worse" reads.
// Leads and agent changes are hints and are not counted.
func (d Delta) Regressions() int {
	n := len(d.New)
	for _, c := range d.SeverityChanged {
		if c.Regression {
			n++
		}
	}
	return n
}

// ---- findings ---------------------------------------------------------------

// advisoryKeys is the identity of a dependency advisory finding: one key per
// id it answers to, so a GHSA in one run and its CVE alias in another match.
func advisoryKeys(f *findings.Finding) ([]string, bool) {
	ids, ok := advisory.IDs(f)
	if !ok {
		return nil, false
	}
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, f.Location.FilePath+"|"+f.Metadata["ecosystem"]+"|"+f.Metadata["package"]+"|"+strings.ToUpper(id))
	}
	return keys, true
}

// findingKey is the identity of every other finding: rule, normalised file and
// message, with no line. It is the V2 fingerprint computed here so a scan that
// pinned the line-bearing V1 still compares by what the finding says.
func findingKey(f *findings.Finding) string {
	return findings.ComputeFingerprintWith(f.RuleID, f.Location, f.Message, findings.FingerprintV2)
}

func toItem(f *findings.Finding) Item {
	it := Item{
		RuleID: f.RuleID, Severity: string(f.Severity), File: f.Location.FilePath,
		Line: f.Location.StartLine, Message: f.Message, Fingerprint: f.Fingerprint,
	}
	if _, ok := advisory.IDs(f); ok {
		it.Package, it.Version, it.Advisory = f.Metadata["package"], f.Metadata["version"], f.Metadata["vuln_id"]
	}
	return it
}

// withoutAdvisories drops dependency advisories. They are removed from BOTH
// sides when either side did not look them up: the side that did look would
// otherwise read as having gained (or lost) every advisory it has.
func withoutAdvisories(ff []findings.Finding) []findings.Finding {
	out := make([]findings.Finding, 0, len(ff))
	for i := range ff {
		if _, ok := advisory.IDs(&ff[i]); !ok {
			out = append(out, ff[i])
		}
	}
	return out
}

func compareFindings(d *Delta, prev, cur []findings.Finding) {
	prevAdv, prevOther := splitActive(prev)
	curAdvAll, curOtherAll := splitAll(cur)

	// Advisories: matched by any shared id.
	curKeys := map[string]*findings.Finding{}
	for _, f := range curAdvAll {
		keys, _ := advisoryKeys(f)
		for _, k := range keys {
			curKeys[k] = f
		}
	}
	prevKeys := map[string]struct{}{}
	for _, f := range prevAdv {
		keys, _ := advisoryKeys(f)
		matched := (*findings.Finding)(nil)
		for _, k := range keys {
			prevKeys[k] = struct{}{}
			if m, ok := curKeys[k]; ok && matched == nil {
				matched = m
			}
		}
		classifyPair(d, f, matched)
	}
	for _, f := range curAdvAll {
		if !f.Status.IsActive() {
			continue
		}
		keys, _ := advisoryKeys(f)
		known := false
		for _, k := range keys {
			if _, ok := prevKeys[k]; ok {
				known = true
				break
			}
		}
		if !known {
			d.New = append(d.New, toItem(f))
		}
	}

	// Everything else: matched by key, paired by order within a key.
	prevBy := groupByKey(prevOther)
	curBy := groupByKey(curOtherAll)
	for key, ps := range prevBy {
		cs := curBy[key]
		for i, p := range ps {
			var m *findings.Finding
			if i < len(cs) {
				m = cs[i]
			}
			classifyPair(d, p, m)
		}
	}
	for key, cs := range curBy {
		paired := len(prevBy[key])
		for i, c := range cs {
			if i >= paired && c.Status.IsActive() {
				d.New = append(d.New, toItem(c))
			}
		}
	}
	sortItems(d.New)
	sortItems(d.Resolved)
	sortItems(d.Waived)
	sort.Slice(d.SeverityChanged, func(i, j int) bool { return itemLess(d.SeverityChanged[i].Item, d.SeverityChanged[j].Item) })
}

// classifyPair records what became of an earlier active finding p, given the
// current finding m it pairs with (nil when none).
func classifyPair(d *Delta, p, m *findings.Finding) {
	switch {
	case m == nil:
		d.Resolved = append(d.Resolved, toItem(p))
	case !m.Status.IsActive():
		d.Waived = append(d.Waived, toItem(m))
	case m.Severity != p.Severity:
		d.SeverityChanged = append(d.SeverityChanged, SeverityChange{
			Item: toItem(m), From: string(p.Severity), To: string(m.Severity),
			Regression: findings.SeverityRank(m.Severity) < findings.SeverityRank(p.Severity),
		})
	}
}

func splitActive(ff []findings.Finding) (adv, other []*findings.Finding) {
	for i := range ff {
		if !ff[i].Status.IsActive() {
			continue
		}
		if _, ok := advisory.IDs(&ff[i]); ok {
			adv = append(adv, &ff[i])
		} else {
			other = append(other, &ff[i])
		}
	}
	return adv, other
}

func splitAll(ff []findings.Finding) (adv, other []*findings.Finding) {
	for i := range ff {
		if _, ok := advisory.IDs(&ff[i]); ok {
			adv = append(adv, &ff[i])
		} else {
			other = append(other, &ff[i])
		}
	}
	return adv, other
}

func groupByKey(ff []*findings.Finding) map[string][]*findings.Finding {
	out := map[string][]*findings.Finding{}
	for _, f := range ff {
		k := findingKey(f)
		out[k] = append(out[k], f)
	}
	for _, g := range out {
		sort.SliceStable(g, func(i, j int) bool { return g[i].Location.StartLine < g[j].Location.StartLine })
	}
	return out
}

func itemLess(a, b Item) bool {
	if ra, rb := findings.SeverityRank(findings.Severity(a.Severity)), findings.SeverityRank(findings.Severity(b.Severity)); ra != rb {
		return ra < rb
	}
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.Advisory != b.Advisory {
		return a.Advisory < b.Advisory
	}
	return a.Message < b.Message
}

func sortItems(its []Item) {
	sort.SliceStable(its, func(i, j int) bool { return itemLess(its[i], its[j]) })
}

// ---- leads ------------------------------------------------------------------

func leadKey(l report.Lead) string { return l.Category + "|" + l.Route + "|" + l.FilePath }

func compareLeads(d *Delta, prev, cur State) {
	if !prev.LeadsRecorded || !cur.LeadsRecorded {
		return
	}
	pk := map[string]struct{}{}
	for _, l := range prev.Leads {
		pk[leadKey(l)] = struct{}{}
	}
	ck := map[string]struct{}{}
	for _, l := range cur.Leads {
		ck[leadKey(l)] = struct{}{}
		if _, ok := pk[leadKey(l)]; !ok {
			d.NewLeads = append(d.NewLeads, l)
		}
	}
	for _, l := range prev.Leads {
		if _, ok := ck[leadKey(l)]; !ok {
			d.ResolvedLeads = append(d.ResolvedLeads, l)
		}
	}
	sortLeads(d.NewLeads)
	sortLeads(d.ResolvedLeads)
}

func sortLeads(ls []report.Lead) {
	sort.SliceStable(ls, func(i, j int) bool {
		if ls[i].FilePath != ls[j].FilePath {
			return ls[i].FilePath < ls[j].FilePath
		}
		if ls[i].Route != ls[j].Route {
			return ls[i].Route < ls[j].Route
		}
		return ls[i].Line < ls[j].Line
	})
}

// ---- AI inventory -----------------------------------------------------------

// inventoryUsable is whether an inventory can be compared: it exists and the AI
// checks ran. An empty inventory from a scan that did not look says nothing.
func inventoryUsable(inv *ai.Inventory) bool { return inv != nil && len(inv.Checks) > 0 }

type agentKey struct{ agent, server string }

// agentTools indexes an inventory's tool matrix: agent -> tool -> capability set.
func agentTools(inv *ai.Inventory) (tools map[agentKey]map[string]map[string]struct{}, paths map[agentKey]string) {
	tools = map[agentKey]map[string]map[string]struct{}{}
	paths = map[agentKey]string{}
	for _, s := range inv.ToolMatrix {
		k := agentKey{s.Agent, s.Server}
		if tools[k] == nil {
			tools[k] = map[string]map[string]struct{}{}
			paths[k] = s.Path
		}
		for _, t := range s.Tools {
			if tools[k][t] == nil {
				tools[k][t] = map[string]struct{}{}
			}
			for _, c := range s.Capabilities[t] {
				tools[k][t][c] = struct{}{}
			}
		}
	}
	return tools, paths
}

func compareInventory(d *Delta, prev, cur State) {
	if !inventoryUsable(prev.Inventory) || !inventoryUsable(cur.Inventory) {
		return
	}
	compareComponents(d, prev.Inventory, cur.Inventory)

	pt, _ := agentTools(prev.Inventory)
	ct, cpaths := agentTools(cur.Inventory)
	for k, tools := range ct {
		ch := AgentChange{Agent: k.agent, Server: k.server, Path: cpaths[k]}
		old, existed := pt[k]
		ch.Added = !existed
		ch.Gained = grantsAdded(tools, old)
		ch.Lost = grantsAdded(old, tools)
		if ch.Added || len(ch.Gained) > 0 || len(ch.Lost) > 0 {
			d.Agents = append(d.Agents, ch)
		}
	}
	pt2, ppaths := agentTools(prev.Inventory)
	for k, tools := range pt2 {
		if _, ok := ct[k]; !ok {
			d.Agents = append(d.Agents, AgentChange{
				Agent: k.agent, Server: k.server, Path: ppaths[k], Removed: true, Lost: grantsAdded(tools, nil),
			})
		}
	}
	sort.SliceStable(d.Agents, func(i, j int) bool {
		if d.Agents[i].Agent != d.Agents[j].Agent {
			return d.Agents[i].Agent < d.Agents[j].Agent
		}
		return d.Agents[i].Server < d.Agents[j].Server
	})
}

// grantsAdded returns what is in now and not in before: tools that are new, and
// capabilities that are new on a tool that existed.
func grantsAdded(now, before map[string]map[string]struct{}) []Grant {
	var out []Grant
	names := make([]string, 0, len(now))
	for t := range now {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		old, had := before[t]
		var caps []string
		for c := range now[t] {
			if _, ok := old[c]; !had || !ok {
				caps = append(caps, c)
			}
		}
		sort.Strings(caps)
		if !had || len(caps) > 0 {
			out = append(out, Grant{Tool: t, Capabilities: caps})
		}
	}
	return out
}

func compareComponents(d *Delta, prev, cur *ai.Inventory) {
	key := func(c ai.Component) string { return c.Type + "|" + c.Name }
	pk, ck := map[string]struct{}{}, map[string]struct{}{}
	for _, c := range prev.Components {
		pk[key(c)] = struct{}{}
	}
	for _, c := range cur.Components {
		ck[key(c)] = struct{}{}
		if _, ok := pk[key(c)]; !ok {
			d.ComponentsAdded = append(d.ComponentsAdded, ComponentChange{Type: c.Type, Name: c.Name, Path: c.Path})
		}
	}
	for _, c := range prev.Components {
		if _, ok := ck[key(c)]; !ok {
			d.ComponentsRemoved = append(d.ComponentsRemoved, ComponentChange{Type: c.Type, Name: c.Name, Path: c.Path})
		}
	}
	less := func(s []ComponentChange) {
		sort.SliceStable(s, func(i, j int) bool {
			if s[i].Type != s[j].Type {
				return s[i].Type < s[j].Type
			}
			return s[i].Name < s[j].Name
		})
	}
	less(d.ComponentsAdded)
	less(d.ComponentsRemoved)
}

// ---- infrastructure ---------------------------------------------------------

// compareInfrastructure names the properties of resources present in both
// states that got weaker or stronger. Both states must have recorded their
// infrastructure; otherwise caveats says why nothing is compared.
func compareInfrastructure(d *Delta, prev, cur State) {
	if !prev.InfrastructureRecorded || !cur.InfrastructureRecorded {
		return
	}
	d.Infrastructure = infra.Compare(prev.Infrastructure, cur.Infrastructure)
}

// ---- caveats ----------------------------------------------------------------

func caveats(prev, cur State) []string {
	var out []string
	if len(prev.Incomplete) > 0 {
		out = append(out, "The earlier scan did not complete every check ("+strings.Join(prev.Incomplete, "; ")+
			"); items it could not look for may be reported as new.")
	}
	if len(cur.Incomplete) > 0 {
		out = append(out, "This scan did not complete every check ("+strings.Join(cur.Incomplete, "; ")+
			"); items it could not look for are not reported as resolved, but may be missing.")
	}
	switch {
	case prev.AdvisoryLookup != "" && cur.AdvisoryLookup != "":
		out = append(out, "Dependency advisories were not compared: the previous scan did not look up advisories ("+
			prev.AdvisoryLookup+") and neither did this one ("+cur.AdvisoryLookup+").")
	case prev.AdvisoryLookup != "":
		out = append(out, "Dependency advisories were not compared: the previous scan did not look up advisories ("+
			prev.AdvisoryLookup+"), so every advisory this scan found would read as new.")
	case cur.AdvisoryLookup != "":
		out = append(out, "Dependency advisories were not compared: this scan did not look up advisories ("+
			cur.AdvisoryLookup+"), so every advisory the previous scan found would read as resolved.")
	}
	if !sameScopes(prev.Scanned, cur.Scanned) {
		out = append(out, "The two scans covered different scopes ("+scopeWords(prev.Scanned)+" before, "+
			scopeWords(cur.Scanned)+" now); findings outside the narrower scope are not comparable.")
	}
	if !prev.LeadsRecorded && len(cur.Leads) > 0 {
		out = append(out, "Authorization and authentication leads were not compared: the earlier findings.json did not record them. "+
			"This scan has "+strconv.Itoa(len(cur.Leads))+".")
	}
	if !prev.InfrastructureRecorded && cur.Infrastructure != nil && !cur.Infrastructure.Empty() {
		out = append(out, "Infrastructure assumptions were not compared: the earlier findings.json did not record the "+
			"deployment inventory (it predates it, or the earlier tree had no infrastructure files). "+
			"This scan read "+strconv.Itoa(len(cur.Infrastructure.Resources))+" resources.")
	}
	if cur.Inventory != nil && !inventoryUsable(prev.Inventory) && (len(cur.Inventory.Components) > 0 || len(cur.Inventory.ToolMatrix) > 0) {
		out = append(out, "AI components and agent capabilities were not compared: the earlier scan has no AI inventory "+
			"(pass the ai.inventory.json from the same run alongside the findings).")
	}
	return out
}

func sameScopes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func scopeWords(s []string) string {
	if s == nil {
		return "all scopes"
	}
	x := append([]string(nil), s...)
	sort.Strings(x)
	return strings.Join(x, ", ")
}
