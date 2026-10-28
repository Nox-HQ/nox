package threatmodel

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/infra"
)

// This file derives deployment elements from the inventory a scan recorded
// (findings.json "infrastructure"), not from the findings alone.
//
// Findings only describe what is wrong. A bucket whose public access is blocked
// has none, so a model built from findings had no element for it, and a later
// model built after the block was removed reported a "new data store" that
// existed all along. An element is the resource; the findings attach to it.

// classCandidates lists, for a rule's kind of resource, the inventory classes a
// finding of that rule can be about, most specific first. A rule about a
// container image fires on a Dockerfile and on a Kubernetes workload alike.
func (r iacRow) classCandidates() []string {
	switch r.kind {
	case KindIngress:
		return []string{infra.ClassIngress}
	case KindWorkload:
		return []string{infra.ClassWorkload, infra.ClassImage}
	case KindImage:
		return []string{infra.ClassImage, infra.ClassWorkload}
	case KindNetworkRule:
		return []string{infra.ClassNetworkRule}
	case KindDataStore:
		if r.sub == "bucket" {
			return []string{infra.ClassBucket}
		}
		return []string{infra.ClassDatabase}
	}
	return nil
}

// kindOfClass maps an inventory class to the element kind it is shown as.
func kindOfClass(class string) (kind string, zone Zone) {
	switch class {
	case infra.ClassBucket, infra.ClassDatabase:
		return KindDataStore, ZoneData
	case infra.ClassIngress:
		return KindIngress, ZoneDeploy
	case infra.ClassImage:
		return KindImage, ZoneDeploy
	case infra.ClassNetworkRule:
		return KindNetworkRule, ZoneDeploy
	}
	return KindWorkload, ZoneDeploy
}

func classLabel(r infra.Resource) string {
	switch r.Class {
	case infra.ClassBucket:
		return "Storage bucket"
	case infra.ClassDatabase:
		return "Database instance"
	case infra.ClassIngress:
		return "Ingress"
	case infra.ClassImage:
		return "Container image"
	case infra.ClassNetworkRule:
		return "Network rule"
	}
	return "Workload"
}

// resourceName names the element after the resource the document names.
func resourceName(r infra.Resource) string {
	name := classLabel(r)
	if r.Kind != "Dockerfile" {
		n := r.Name
		if r.Namespace != "" {
			n = r.Namespace + "/" + n
		}
		name += " " + n
	}
	return name + " (" + r.File + ")"
}

// resourceElementID is the stable identity of a resource's element: its class
// and the resource's own identity, never a line.
func resourceElementID(r infra.Resource) string {
	return "deploy:" + r.Class + ":" + r.ID()
}

func (b *builder) collectResources() {
	inv := b.in.Report.Infrastructure
	if inv == nil {
		return
	}
	for i := range inv.Resources {
		r := inv.Resources[i]
		kind, zone := kindOfClass(r.Class)
		attrs := map[string]string{
			"file": r.File, "kind": r.Kind, "name": r.Name, "class": r.Class, "basis": "inventory",
		}
		if r.Namespace != "" {
			attrs["namespace"] = r.Namespace
		}
		e := b.add(Element{
			ID: resourceElementID(r), Kind: kind, Name: resourceName(r), Zone: zone,
			Location: loc(r.File, r.Line), Attributes: attrs,
			Properties: copyProps(r.Properties),
			Evidence: []Evidence{{
				Artifact: artFindings, Ref: loc(r.File, r.Line),
				Statement: r.Display() + " is declared in " + r.File + "; its properties were read from the configuration",
			}},
		}, r.File)
		e.resource = &inv.Resources[i]
		b.infraPerFile[r.File]++
		b.resources[r.File] = append(b.resources[r.File], e)
	}
	for file := range b.resources {
		list := b.resources[file]
		sort.SliceStable(list, func(i, j int) bool { return list[i].resource.Line < list[j].resource.Line })
	}
	b.attachResourceFindings()
}

func copyProps(p map[string]string) map[string]string {
	if len(p) == 0 {
		return nil
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// attachResourceFindings adds each finding to the evidence of the resource it
// is about, and records the exposure the finding claims.
func (b *builder) attachResourceFindings() {
	type key struct {
		elem, rule string
		waived     bool
	}
	groups := map[key][]findings.Finding{}
	var order []key
	for _, list := range [][]findings.Finding{b.active, b.waived} {
		for _, f := range list {
			e := b.resourceFor(f)
			if e == nil {
				continue
			}
			k := key{e.ID, f.RuleID, !f.Status.IsActive()}
			if _, ok := groups[k]; !ok {
				order = append(order, k)
			}
			groups[k] = append(groups[k], f)
		}
	}
	for _, k := range order {
		g := groups[k]
		e := b.elems[k.elem]
		ev := findingEvidence(g, k.waived)
		if !hasEvidence(e.Evidence, ev) {
			e.Evidence = append(e.Evidence, ev)
		}
		if iacRules[k.rule].exposes {
			e.exposedBy = append(e.exposedBy, ev)
		}
	}
}

// resourceFor returns the inventory element an infrastructure finding is about.
// The rule names the kind of resource; among that kind in the finding's file,
// the finding belongs to the last resource declared at or above its line, or to
// the first when it sits above all of them (a document-level finding). Nil when
// the rule is not an infrastructure rule or the file holds no such resource, in
// which case the finding falls back to the element derived from the rule.
func (b *builder) resourceFor(f findings.Finding) *elem {
	row, ok := iacRules[f.RuleID]
	if !ok {
		return nil
	}
	list := b.resources[f.Location.FilePath]
	for _, class := range row.classCandidates() {
		var pick *elem
		for _, e := range list {
			if e.resource.Class != class {
				continue
			}
			if pick == nil || e.resource.Line <= f.Location.StartLine {
				pick = e
			}
		}
		if pick != nil {
			return pick
		}
	}
	return nil
}

// propertyDelta compares the properties of the deployment resources present in
// both models.
func propertyDelta(prev, cur Model) []infra.Change {
	return infra.Compare(inventoryOfModel(prev), inventoryOfModel(cur))
}

// inventoryOfModel rebuilds the resources a model's elements were derived from.
func inventoryOfModel(m Model) *infra.Inventory {
	inv := &infra.Inventory{Version: infra.SchemaVersion}
	for _, e := range m.Elements {
		if e.Attributes["basis"] != "inventory" || strings.TrimSpace(e.Attributes["kind"]) == "" {
			continue
		}
		inv.Resources = append(inv.Resources, infra.Resource{
			Kind: e.Attributes["kind"], Name: e.Attributes["name"], Namespace: e.Attributes["namespace"],
			File: e.Attributes["file"], Class: e.Attributes["class"], Properties: e.Properties,
		})
	}
	return inv
}
