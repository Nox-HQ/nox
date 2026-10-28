package threatmodel

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/infra"
)

// ElementRef names an element that appeared or disappeared.
type ElementRef struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// FlowRef names a flow that appeared or disappeared.
type FlowRef struct {
	ID       string `json:"id"`
	From     string `json:"from"`
	To       string `json:"to"`
	Label    string `json:"label"`
	Boundary string `json:"boundary"`
}

// BoundaryRef names a trust boundary that appeared or disappeared.
type BoundaryRef struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// CellChange is a STRIDE cell, on an element present in both models, whose
// evidence differs.
type CellChange struct {
	Element  string   `json:"element"`
	Name     string   `json:"name"`
	Category Category `json:"category"`
	From     Status   `json:"from"`
	To       Status   `json:"to"`
	// Added and Removed are the evidence that is new and the evidence that is
	// gone, as stable keys (rule and file, or the statement), never line numbers.
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// Delta is what changed between two models. It reports a change in what nox
// can evidence. It does not say the system got better or worse.
type Delta struct {
	// Previous identifies the model it was compared against.
	PreviousScanGeneratedAt string `json:"previous_scan_generated_at,omitempty"`
	PreviousCommit          string `json:"previous_commit,omitempty"`

	ElementsAdded     []ElementRef  `json:"elements_added,omitempty"`
	ElementsRemoved   []ElementRef  `json:"elements_removed,omitempty"`
	FlowsAdded        []FlowRef     `json:"flows_added,omitempty"`
	FlowsRemoved      []FlowRef     `json:"flows_removed,omitempty"`
	BoundariesAdded   []BoundaryRef `json:"boundaries_added,omitempty"`
	BoundariesRemoved []BoundaryRef `json:"boundaries_removed,omitempty"`
	CellsChanged      []CellChange  `json:"cells_changed,omitempty"`
	// PropertiesChanged are the security-relevant properties of deployment
	// resources, present in both models, that got weaker or stronger: the
	// assumptions the change invalidated or established. A resource that exists
	// in both is never reported as added.
	PropertiesChanged []infra.Change `json:"properties_changed,omitempty"`

	// Caveats say what could not be compared. A comparison that cannot be made
	// must not read as "nothing changed".
	Caveats []string `json:"caveats,omitempty"`
}

// Empty reports whether nothing changed in what could be compared.
func (d Delta) Empty() bool {
	return len(d.ElementsAdded) == 0 && len(d.ElementsRemoved) == 0 &&
		len(d.FlowsAdded) == 0 && len(d.FlowsRemoved) == 0 &&
		len(d.BoundariesAdded) == 0 && len(d.BoundariesRemoved) == 0 &&
		len(d.CellsChanged) == 0 && len(d.PropertiesChanged) == 0
}

// kindInput says which input an element kind depends on, so a model built
// without that input is not read as having lost the elements.
func kindInput(e Element) string {
	switch e.Kind {
	case KindRoute:
		return "routes"
	case KindAgent, KindMCPServer, KindMCPClient, KindModel:
		return "ai_inventory"
	case KindService, KindDependencies:
		return "sbom"
	case KindDataStore:
		if e.Attributes["basis"] == "dependency" {
			return "sbom"
		}
	}
	if strings.HasPrefix(e.ID, "deploy:") {
		return "infrastructure"
	}
	return ""
}

// Compare says what changed from prev to cur. Identity is the element ID, which
// carries no line number, so an element that only moved is neither added nor
// removed; a cell is compared on the stable keys of its evidence, so a finding
// that moved a few lines is not a change.
func Compare(prev, cur Model) Delta {
	d := Delta{
		PreviousScanGeneratedAt: prev.Provenance.ScanGeneratedAt,
		PreviousCommit:          prev.Provenance.Commit,
	}
	skip := map[string]bool{}
	if prev.Meta.SchemaVersion != cur.Meta.SchemaVersion {
		d.Caveats = append(d.Caveats, "The previous model uses schema "+prev.Meta.SchemaVersion+" and this one "+cur.Meta.SchemaVersion+"; fields added since may make the comparison show changes that are not changes in the system.")
	}
	pc, cc := prev.Provenance.Coverage, cur.Provenance.Coverage
	if !pc.Routes && cc.Routes {
		skip["routes"] = true
		d.Caveats = append(d.Caveats, "The previous model recorded no routes (it may predate route recording), so routes were not compared.")
	}
	if pc.Routes && !cc.Routes {
		d.Caveats = append(d.Caveats, "This model records no routes where the previous one did: either they were removed or this scan read none.")
	}
	if pc.AIInventory != cc.AIInventory {
		skip["ai_inventory"] = true
		d.Caveats = append(d.Caveats, "The AI inventory was provided to only one of the two models, so AI agents, tools, models and MCP servers were not compared.")
	}
	if pc.Infrastructure != cc.Infrastructure {
		skip["infrastructure"] = true
		d.Caveats = append(d.Caveats, "The deployment inventory was recorded for only one of the two models (the earlier findings.json may predate it), so deployment resources were not compared; they are not reported as new or gone.")
	}
	if pc.SBOM != cc.SBOM {
		skip["sbom"] = true
		d.Caveats = append(d.Caveats, "An SBOM was provided to only one of the two models, so dependency-derived data stores and services were not compared.")
	}
	if strings.Join(prev.Provenance.ScopesNotScanned, ",") != strings.Join(cur.Provenance.ScopesNotScanned, ",") {
		d.Caveats = append(d.Caveats, "The two scans covered different scopes, so some differences below come from what was looked at and not from the system.")
	}

	pe, ce := indexElements(prev, skip), indexElements(cur, skip)
	for _, id := range sortedElementIDs(ce) {
		if _, ok := pe[id]; !ok && reported(ce[id]) {
			d.ElementsAdded = append(d.ElementsAdded, refOf(ce[id]))
		}
	}
	for _, id := range sortedElementIDs(pe) {
		if _, ok := ce[id]; !ok && reported(pe[id]) {
			d.ElementsRemoved = append(d.ElementsRemoved, refOf(pe[id]))
		}
	}

	pf, cf := indexFlows(prev, pe), indexFlows(cur, ce)
	for _, id := range sortedFlowIDs(cf) {
		if _, ok := pf[id]; !ok {
			d.FlowsAdded = append(d.FlowsAdded, flowRef(cf[id], ce))
		}
	}
	for _, id := range sortedFlowIDs(pf) {
		if _, ok := cf[id]; !ok {
			d.FlowsRemoved = append(d.FlowsRemoved, flowRef(pf[id], pe))
		}
	}

	pb, cb := boundariesOf(prev, pf), boundariesOf(cur, cf)
	for _, id := range sortedStringKeys(cb) {
		if _, ok := pb[id]; !ok {
			d.BoundariesAdded = append(d.BoundariesAdded, BoundaryRef{ID: id, Label: cb[id]})
		}
	}
	for _, id := range sortedStringKeys(pb) {
		if _, ok := cb[id]; !ok {
			d.BoundariesRemoved = append(d.BoundariesRemoved, BoundaryRef{ID: id, Label: pb[id]})
		}
	}

	d.CellsChanged = compareCells(prev, cur, pe, ce)
	if !skip["infrastructure"] {
		d.PropertiesChanged = propertyDelta(prev, cur)
	}
	return d
}

// reported reports whether an element appearing or disappearing is itself
// news. Actors and host capabilities exist only as the ends of flows, so their
// arrival is reported through the flow and the boundary that brought them.
func reported(e Element) bool { return e.Kind != KindActor && e.Kind != KindCapability }

func flowRef(f Flow, elems map[string]Element) FlowRef {
	return FlowRef{ID: f.ID, From: elems[f.From].Name, To: elems[f.To].Name, Label: f.Label, Boundary: f.Boundary}
}

func refOf(e Element) ElementRef { return ElementRef{ID: e.ID, Kind: e.Kind, Name: e.Name} }

func indexElements(m Model, skip map[string]bool) map[string]Element {
	out := map[string]Element{}
	for _, e := range m.Elements {
		if skip[kindInput(e)] {
			continue
		}
		out[e.ID] = e
	}
	return out
}

// indexFlows keeps the flows whose two ends are both compared elements.
func indexFlows(m Model, elems map[string]Element) map[string]Flow {
	out := map[string]Flow{}
	for _, f := range m.Flows {
		_, fromKnown := elems[f.From]
		_, toKnown := elems[f.To]
		if !fromKnown || !toKnown {
			continue
		}
		out[f.ID] = f
	}
	return out
}

// boundariesOf derives the boundaries from the compared flows, so a boundary
// that exists only through a flow that was not compared is not reported.
func boundariesOf(m Model, flows map[string]Flow) map[string]string {
	label := map[string]string{}
	for _, b := range m.Boundaries {
		label[b.ID] = b.Label
	}
	out := map[string]string{}
	for _, f := range flows {
		out[f.Boundary] = label[f.Boundary]
	}
	return out
}

func compareCells(prev, cur Model, pe, ce map[string]Element) []CellChange {
	prow := map[string]Row{}
	for _, r := range prev.STRIDE {
		prow[r.Element] = r
	}
	var out []CellChange
	for _, r := range cur.STRIDE {
		old, ok := prow[r.Element]
		if !ok {
			continue
		}
		if _, known := pe[r.Element]; !known {
			continue
		}
		oldCells := map[Category]Cell{}
		for _, c := range old.Cells {
			oldCells[c.Category] = c
		}
		for _, c := range r.Cells {
			oc, ok := oldCells[c.Category]
			if !ok {
				continue
			}
			added, removed := diffKeys(evidenceKeys(oc.Evidence), evidenceKeys(c.Evidence))
			if len(added) == 0 && len(removed) == 0 && oc.Status == c.Status {
				continue
			}
			out = append(out, CellChange{
				Element: r.Element, Name: ce[r.Element].Name, Category: c.Category,
				From: oc.Status, To: c.Status, Added: added, Removed: removed,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Element != out[j].Element {
			return out[i].Element < out[j].Element
		}
		return categoryIndex(out[i].Category) < categoryIndex(out[j].Category)
	})
	return out
}

func categoryIndex(c Category) int {
	for i, x := range Categories {
		if x == c {
			return i
		}
	}
	return len(Categories)
}

func evidenceKeys(ev []Evidence) map[string]bool {
	out := map[string]bool{}
	for _, e := range ev {
		out[e.stableKey()] = true
	}
	return out
}

func diffKeys(old, cur map[string]bool) (added, removed []string) {
	for k := range cur {
		if !old[k] {
			added = append(added, k)
		}
	}
	for k := range old {
		if !cur[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func sortedElementIDs(m map[string]Element) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedFlowIDs(m map[string]Flow) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// WithChanges returns the model with its changes against prev recorded.
func (m Model) WithChanges(prev Model) Model {
	d := Compare(prev, m)
	m.Changes = &d
	return m
}
