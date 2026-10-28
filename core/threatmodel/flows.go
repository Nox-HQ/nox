package threatmodel

import (
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/findings"
)

// Fixed boundary identifiers. Tool and taint boundaries carry a suffix naming
// the effect they reach.
const (
	boundaryRequest    = "request"
	boundaryExposure   = "exposure"
	boundaryPrompt     = "prompt"
	boundaryDispatch   = "tool-dispatch"
	boundaryDataAccess = "data-access"
	boundaryService    = "third-party"
	boundaryModelCall  = "model-call"
	boundaryMCP        = "tool:mcp-server"
)

type boundaryDef struct {
	label    string
	from, to Zone
}

// fixedBoundaries are the boundaries whose meaning does not depend on a
// suffix. Each is a place where something less trusted reaches something more
// trusted, in the direction of the flow.
var fixedBoundaries = map[string]boundaryDef{
	boundaryRequest:    {"untrusted caller → route", ZoneUntrusted, ZoneApplication},
	boundaryExposure:   {"internet → exposed deployment resource", ZoneUntrusted, ZoneDeploy},
	boundaryPrompt:     {"untrusted input → LLM prompt", ZoneUntrusted, ZoneModel},
	boundaryDispatch:   {"model output → agent tool dispatch", ZoneModel, ZoneApplication},
	boundaryDataAccess: {"application → data store", ZoneApplication, ZoneData},
	boundaryService:    {"application → third-party service", ZoneApplication, ZoneThirdParty},
	boundaryModelCall:  {"application → model provider", ZoneApplication, ZoneModel},
	boundaryMCP:        {"model output → MCP server tool", ZoneModel, ZoneThirdParty},
}

func (b *builder) addFlow(from, to, boundary, label string, ev ...Evidence) {
	if from == "" || to == "" || len(ev) == 0 {
		return
	}
	id := from + " -> " + to + " [" + boundary + "]"
	f, ok := b.flows[id]
	if !ok {
		f = &Flow{ID: id, From: from, To: to, Boundary: boundary, Label: label}
		b.flows[id] = f
	}
	f.Evidence = append(f.Evidence, ev...)
}

// connect builds every flow the scan joins, after the elements exist.
func (b *builder) connect() {
	b.requestFlows()
	b.exposureFlows()
	b.promptFlows()
	b.toolFlows()
	b.mcpFlows()
	b.applicationFlows()
	b.taintFlows()
}

// requestFlows: an untrusted caller reaches every route.
func (b *builder) requestFlows() {
	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		if e.Kind != KindRoute {
			continue
		}
		b.ensureActor("actor:caller", "Callers (untrusted input)")
		label := "request reaches " + e.Name
		if e.Attributes["authentication_middleware"] == "none visible" {
			label += " (no authentication middleware visible)"
		} else if a := e.Attributes["authentication_middleware"]; a != "" && a != "not recorded" {
			label += " (authentication middleware: " + a + ")"
		}
		b.addFlow("actor:caller", id, boundaryRequest, label, e.Evidence...)
	}
}

// exposureFlows: a deployment resource that a finding says is reachable from
// outside is reached from the internet.
func (b *builder) exposureFlows() {
	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		if len(e.exposedBy) == 0 {
			continue
		}
		b.add(Element{
			ID: "actor:internet", Kind: KindActor, Name: "Internet (untrusted)", Zone: ZoneUntrusted,
			Evidence: []Evidence{{Artifact: artFindings, Statement: "origin of untrusted traffic; present because a deployment resource is reachable from it"}},
		})
		b.addFlow("actor:internet", id, boundaryExposure, e.Name+" is reachable from outside", e.exposedBy...)
	}
}

// promptFlows: untrusted input reaches an LLM prompt call, and the prompt
// call's output reaches the agent registered beside it. The attack graph owns
// the definition of both (which findings assert untrusted input reaches a
// prompt, and what links a prompt call to an agent); this reads its edges so
// the two documents cannot disagree.
func (b *builder) promptFlows() {
	g := attack.BuildGraph(b.active, b.in.Inventory)
	nodes := map[string]attack.AttackNode{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	byFingerprint := map[string]findings.Finding{}
	for _, f := range b.active {
		byFingerprint[f.Fingerprint] = f
	}
	for _, e := range g.Edges {
		from, to := nodes[e.From], nodes[e.To]
		switch {
		case from.Kind == attack.NodeEntryPoint && to.Kind == attack.NodeModel && e.Kind == attack.EdgeDataFlow:
			b.promptFlow(from, e, byFingerprint)
		case from.Kind == attack.NodeModel && to.Kind == attack.NodeAgent && e.Kind == attack.EdgeDataFlow:
			b.dispatchFlow(from, to, e, byFingerprint)
		}
	}
}

func fingerprintEvidence(e attack.AttackEdge, byFP map[string]findings.Finding) []Evidence {
	var out []Evidence
	for _, ne := range e.Evidence {
		if f, ok := byFP[ne.Ref]; ok {
			out = append(out, findingEvidence([]findings.Finding{f}, false))
		}
	}
	return out
}

// promptTarget returns the model element for a prompt call in file: the model
// the inventory names there, or a generic prompt-call element when it names
// none.
func (b *builder) promptTargets(file string, line int) []string {
	var ids []string
	for _, id := range sortedIDs(b.elems) {
		if e := b.elems[id]; e.Kind == KindModel && e.files[file] {
			ids = append(ids, id)
		}
	}
	if len(ids) > 0 {
		return ids
	}
	id := "model:prompt-call@" + file
	b.add(Element{
		ID: id, Kind: KindModel, Name: "LLM prompt call in " + file, Zone: ZoneModel, Location: loc(file, line),
		Evidence: []Evidence{{Artifact: artFindings, Ref: loc(file, line), Statement: "a finding places an LLM prompt call here; the inventory names no model for the file"}},
	}, file)
	return []string{id}
}

func (b *builder) promptFlow(entry attack.AttackNode, e attack.AttackEdge, byFP map[string]findings.Finding) {
	file := entry.FilePath
	line := entryLine(entry.ID)
	ev := fingerprintEvidence(e, byFP)
	if len(ev) == 0 {
		return
	}
	from := "actor:caller"
	b.ensureActor(from, "Callers (untrusted input)")
	if r := b.routeFor(file, line); r != nil {
		from = r.ID
	}
	for _, to := range b.promptTargets(file, line) {
		b.addFlow(from, to, boundaryPrompt, "untrusted input reaches the LLM prompt call at "+loc(file, line), ev...)
	}
}

func (b *builder) dispatchFlow(model, agent attack.AttackNode, e attack.AttackEdge, byFP map[string]findings.Finding) {
	ev := fingerprintEvidence(e, byFP)
	if len(ev) == 0 {
		return
	}
	var agentID string
	for _, id := range sortedIDs(b.elems) {
		el := b.elems[id]
		if el.Kind == KindAgent && el.files[agent.FilePath] && el.Attributes["agent"] == agent.Label {
			agentID = id
			break
		}
	}
	if agentID == "" {
		return
	}
	for _, from := range b.promptTargets(model.FilePath, entryLine(model.ID)) {
		b.addFlow(from, agentID, boundaryDispatch,
			"model output drives the agent's tool calls (prompt call and agent are registered in the same file; nox does not trace the call)", ev...)
	}
}

// entryLine parses the line out of an attack-graph node ID of the form
// kind:path:line.
func entryLine(id string) int {
	i := strings.LastIndex(id, ":")
	if i < 0 {
		return 0
	}
	n, _ := strconv.Atoi(id[i+1:])
	return n
}

// toolFlows: an agent's tools reach the effects their capabilities name. A tool
// whose capability nox does not recognise is its own flow, never dropped.
func (b *builder) toolFlows() {
	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		if e.Kind != KindAgent {
			continue
		}
		type reach struct {
			effect capEffect
			tools  []string
			caps   map[string]bool
		}
		reaches := map[string]*reach{}
		var unclassified []string
		for _, t := range e.toolNames {
			caps := e.toolCaps[t]
			if len(caps) == 0 {
				unclassified = append(unclassified, t)
				continue
			}
			for _, c := range caps {
				eff, ok := capabilityEffects[c]
				if !ok {
					eff = capEffect{id: c, name: c, label: c}
				}
				r := reaches[eff.id]
				if r == nil {
					r = &reach{effect: eff, caps: map[string]bool{}}
					reaches[eff.id] = r
				}
				r.tools = appendUnique(r.tools, t)
				r.caps[c] = true
			}
		}
		ev := Evidence{Artifact: artInventory, Ref: e.Location, Statement: "tool registration in the AI inventory"}
		for _, effID := range sortedKeys(reaches) {
			r := reaches[effID]
			target := b.ensureCapability(r.effect.id, r.effect.name, ev)
			sort.Strings(r.tools)
			bid := "tool:" + r.effect.id
			b.addFlow(id, target.ID, bid,
				"model output may invoke "+strings.Join(r.tools, ", ")+" ("+strings.Join(sortedBool(r.caps), ", ")+")",
				Evidence{Artifact: artInventory, Ref: e.Location, Statement: "agent registers tool(s) " + strings.Join(r.tools, ", ") + " with capability " + strings.Join(sortedBool(r.caps), ", ")})
		}
		if len(unclassified) > 0 {
			sort.Strings(unclassified)
			target := b.ensureCapability("unclassified", "Effect nox could not classify", ev)
			b.addFlow(id, target.ID, "tool:unclassified",
				"model output may invoke "+strings.Join(unclassified, ", ")+" (capability not classified)",
				Evidence{Artifact: artInventory, Ref: e.Location, Statement: "agent registers tool(s) " + strings.Join(unclassified, ", ") + " with no capability nox recognises"})
		}
	}
}

// mcpFlows: an MCP client reaches the servers its configuration names.
func (b *builder) mcpFlows() {
	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		if e.Kind != KindMCPServer {
			continue
		}
		path := e.Location
		b.addFlow("mcp-client:"+path, id, boundaryMCP,
			"model output may call tools on "+e.Name, e.Evidence...)
	}
}

// applicationFlows: the application reaches the data stores, services and
// model providers its dependencies and model references name. The evidence is
// that a package or reference is present, which shows the application can talk
// to the thing, and the label says no more than that.
func (b *builder) applicationFlows() {
	if _, ok := b.elems["app"]; !ok {
		return
	}
	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		switch {
		case e.Kind == KindDataStore && e.Attributes["basis"] == "dependency":
			b.addFlow("app", id, boundaryDataAccess, "a package for "+e.Name+" is in the dependency set", e.Evidence...)
		case e.Kind == KindService:
			b.addFlow("app", id, boundaryService, "a package for "+e.Name+" is in the dependency set", e.Evidence...)
		case e.Kind == KindModel && e.Attributes["model"] != "":
			b.addFlow("app", id, boundaryModelCall, "the application calls model "+e.Attributes["model"], e.Evidence...)
		}
	}
}

// taintFlows: a taint finding says a value from an untrusted source reaches a
// dangerous sink. The flow runs from the route the finding sits in (or from the
// untrusted callers when it sits in none) to the effect the sink reaches.
func (b *builder) taintFlows() {
	for _, f := range b.active {
		class := f.Metadata["vuln_class"]
		if !strings.HasPrefix(f.RuleID, "TAINT") || class == "" || class == "prompt_injection" {
			continue
		}
		eff, ok := taintEffects[class]
		if !ok {
			continue
		}
		ev := findingEvidence([]findings.Finding{f}, false)
		target := b.ensureCapability(eff.capID, eff.name, Evidence{Artifact: artFindings, Ref: ev.Ref, Statement: "reached by a taint finding"})
		from := "actor:caller"
		b.ensureActor(from, "Callers (untrusted input)")
		if r := b.routeFor(f.Location.FilePath, f.Location.StartLine); r != nil {
			from = r.ID
		}
		bid := "taint:" + class
		b.addFlow(from, target.ID, bid,
			"untrusted input ("+f.Metadata["source_kind"]+") reaches a "+eff.label+" sink", ev)
	}
}

// boundaries derives the boundary list from the flows: a boundary exists
// because a flow crosses it.
func (b *builder) boundaries() []Boundary {
	counts := map[string]int{}
	for _, f := range b.flows {
		counts[f.Boundary]++
	}
	var out []Boundary
	for id, n := range counts {
		out = append(out, boundaryFor(id, n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func boundaryFor(id string, n int) Boundary {
	if d, ok := fixedBoundaries[id]; ok {
		return Boundary{ID: id, Label: d.label, From: d.from, To: d.to, Flows: n}
	}
	switch {
	case strings.HasPrefix(id, "tool:"):
		label := effectLabel(strings.TrimPrefix(id, "tool:"))
		return Boundary{ID: id, Label: "model output → " + label, From: ZoneModel, To: ZoneHost, Flows: n}
	case strings.HasPrefix(id, "taint:"):
		class := strings.TrimPrefix(id, "taint:")
		label := class
		if eff, ok := taintEffects[class]; ok {
			label = eff.label
		}
		return Boundary{ID: id, Label: "untrusted input → " + label, From: ZoneUntrusted, To: ZoneHost, Flows: n}
	}
	return Boundary{ID: id, Label: id, Flows: n}
}

func effectLabel(id string) string {
	for _, e := range capabilityEffects {
		if e.id == id {
			return e.label
		}
	}
	if id == "unclassified" {
		return "tool with a capability nox could not classify"
	}
	return id
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
