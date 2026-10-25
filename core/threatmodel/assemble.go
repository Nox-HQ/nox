package threatmodel

import "sort"

// Build derives the model from in. It is a pure function of in: it reads no
// clock, no file and no network, and no map iteration order reaches the output.
func Build(in Input) Model {
	b := newBuilder(in)
	b.collect()
	b.connect()

	rows, unattributed := b.rows()
	sortRows(rows)

	m := Model{
		Meta: Meta{
			SchemaVersion: SchemaVersion, ToolName: "nox", ToolVersion: in.NoxVersion, Report: ReportKind,
		},
		Notice:     Notice,
		Provenance: provenance(in),
		Elements:   b.elementList(),
		Boundaries: b.boundaries(),
		Flows:      b.flowList(),
		STRIDE:     rows,
		Questions:  b.questions(),
		Limits:     b.limits(),
	}
	m.Summary = summarize(m, unattributed)
	return m
}

func provenance(in Input) Provenance {
	rep := in.Report
	arts := append([]Artifact(nil), in.Artifacts...)
	sortArtifacts(arts)
	p := Provenance{
		ScanToolVersion: rep.Meta.ToolVersion,
		ScanGeneratedAt: rep.Meta.GeneratedAt,
		ScanOffline:     rep.Meta.Offline,
		Commit:          in.Commit,
		Artifacts:       arts,
		Coverage: Coverage{
			Routes:      len(rep.Routes) > 0,
			AIInventory: in.Inventory != nil,
			SBOM:        in.SBOM != nil,
		},
	}
	for _, d := range rep.Meta.Degradations {
		if !d.Advisory {
			p.Degradations++
		}
	}
	if sc := rep.Meta.Scope; sc != nil {
		p.ScopesScanned = append([]string{}, sc.Scanned...)
		p.ScopesNotScanned = append([]string(nil), sc.NotScanned...)
		sort.Strings(p.ScopesScanned)
		sort.Strings(p.ScopesNotScanned)
	} else {
		p.ScopesScanned = []string{"all"}
	}
	return p
}

func (b *builder) elementList() []Element {
	out := make([]Element, 0, len(b.elems))
	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		el := e.Element
		sortEvidenceByRef(el.Evidence)
		if len(el.Attributes) == 0 {
			el.Attributes = nil
		}
		out = append(out, el)
	}
	return out
}

func sortEvidenceByRef(ev []Evidence) {
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].Ref != ev[j].Ref {
			return ev[i].Ref < ev[j].Ref
		}
		return ev[i].Statement < ev[j].Statement
	})
}

func (b *builder) flowList() []Flow {
	ids := make([]string, 0, len(b.flows))
	for id := range b.flows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Flow, 0, len(ids))
	for _, id := range ids {
		f := *b.flows[id]
		sortEvidenceByRef(f.Evidence)
		out = append(out, f)
	}
	return out
}

func summarize(m Model, unattributed int) Summary {
	s := Summary{
		Elements: len(m.Elements), Flows: len(m.Flows), Boundaries: len(m.Boundaries),
		UnattributedFindings: unattributed, Questions: len(m.Questions),
	}
	for _, r := range m.STRIDE {
		for _, c := range r.Cells {
			switch c.Status {
			case OpenIssues:
				s.OpenIssues++
			case LeadsToVerify:
				s.LeadsToVerify++
			case LimitedEvidence:
				s.LimitedEvidence++
			default:
				s.NotEvidenced++
			}
		}
	}
	return s
}
