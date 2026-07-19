package plugin

import (
	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/graph"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// --- Proto → Go conversion ---

// pluginRuleNamespace prefixes the rule ID fed into the fingerprint hash for
// plugin-supplied findings, keeping their digests disjoint from core findings'.
const pluginRuleNamespace = "plugin:"

// ProtoFindingToGo converts a protobuf Finding to the domain Finding type.
// pluginName identifies the plugin that produced the finding and is required:
// it namespaces the fingerprint (see pluginFingerprint).
func ProtoFindingToGo(pf *pluginv1.Finding, pluginName string) findings.Finding {
	if pf == nil {
		return findings.Finding{}
	}
	loc := ProtoLocationToGo(pf.GetLocation())
	f := findings.Finding{
		ID:          pf.GetId(),
		RuleID:      pf.GetRuleId(),
		Severity:    ProtoSeverityToGo(pf.GetSeverity()),
		Confidence:  ProtoConfidenceToGo(pf.GetConfidence()),
		Location:    loc,
		Message:     pf.GetMessage(),
		Fingerprint: pluginFingerprint(pluginName, pf, loc),
	}
	if m := pf.GetMetadata(); len(m) > 0 {
		f.Metadata = make(map[string]string, len(m))
		for k, v := range m {
			f.Metadata[k] = v
		}
	}
	return f
}

// pluginFingerprint derives the fingerprint nox stores for a plugin-supplied
// finding.
//
// Plugin findings are merged into the same FindingSet as core findings, which
// dedupes first-wins by fingerprint, and baseline/VEX suppression keys on the
// same value. Storing the plugin's claimed fingerprint verbatim therefore hands
// every plugin a forgery primitive: collide with a core finding to suppress it,
// or match a baselined entry to hide itself. Hashing the plugin's name into the
// digest confines each plugin to its own fingerprint space.
//
// The claimed fingerprint is demoted to hash input, never used as the output,
// so a plugin keeps control over which of *its own* findings are considered the
// same across runs — that is what makes plugin findings baseline-able — without
// any say over collisions outside its namespace.
func pluginFingerprint(pluginName string, pf *pluginv1.Finding, loc findings.Location) string {
	// A plugin that supplies no fingerprint still needs a stable identity, so
	// its message stands in. The fp:/msg: tags keep the two cases from aliasing
	// (a claimed fingerprint that happens to equal another finding's message).
	seed := "fp:" + pf.GetFingerprint()
	if pf.GetFingerprint() == "" {
		seed = "msg:" + pf.GetMessage()
	}
	// Reuse the core scheme so plugin fingerprints inherit its determinism and
	// path normalisation, and so a fingerprint-version bump moves both in step.
	return findings.ComputeFingerprint(pluginRuleNamespace+pluginName+":"+pf.GetRuleId(), loc, seed)
}

// ProtoLocationToGo converts a protobuf Location to the domain Location type.
// A nil proto Location returns a zero-value Location.
func ProtoLocationToGo(pl *pluginv1.Location) findings.Location {
	if pl == nil {
		return findings.Location{}
	}
	return findings.Location{
		FilePath:    pl.GetFilePath(),
		StartLine:   int(pl.GetStartLine()),
		EndLine:     int(pl.GetEndLine()),
		StartColumn: int(pl.GetStartColumn()),
		EndColumn:   int(pl.GetEndColumn()),
	}
}

// ProtoSeverityToGo maps a protobuf Severity enum to the domain Severity string.
func ProtoSeverityToGo(ps pluginv1.Severity) findings.Severity {
	switch ps {
	case pluginv1.Severity_SEVERITY_CRITICAL:
		return findings.SeverityCritical
	case pluginv1.Severity_SEVERITY_HIGH:
		return findings.SeverityHigh
	case pluginv1.Severity_SEVERITY_MEDIUM:
		return findings.SeverityMedium
	case pluginv1.Severity_SEVERITY_LOW:
		return findings.SeverityLow
	case pluginv1.Severity_SEVERITY_INFO:
		return findings.SeverityInfo
	default:
		return findings.SeverityInfo
	}
}

// ProtoConfidenceToGo maps a protobuf Confidence enum to the domain Confidence string.
func ProtoConfidenceToGo(pc pluginv1.Confidence) findings.Confidence {
	switch pc {
	case pluginv1.Confidence_CONFIDENCE_HIGH:
		return findings.ConfidenceHigh
	case pluginv1.Confidence_CONFIDENCE_MEDIUM:
		return findings.ConfidenceMedium
	case pluginv1.Confidence_CONFIDENCE_LOW:
		return findings.ConfidenceLow
	default:
		return findings.ConfidenceLow
	}
}

// ProtoPackageToGo converts a protobuf Package to the domain Package type.
func ProtoPackageToGo(pp *pluginv1.Package) deps.Package {
	if pp == nil {
		return deps.Package{}
	}
	return deps.Package{
		Name:      pp.GetName(),
		Version:   pp.GetVersion(),
		Ecosystem: pp.GetEcosystem(),
	}
}

// ProtoAIComponentToGo converts a protobuf AIComponent to the domain Component type.
func ProtoAIComponentToGo(pac *pluginv1.AIComponent) ai.Component {
	if pac == nil {
		return ai.Component{}
	}
	c := ai.Component{
		Name: pac.GetName(),
		Type: pac.GetType(),
		Path: pac.GetPath(),
	}
	if d := pac.GetDetails(); len(d) > 0 {
		c.Details = make(map[string]string, len(d))
		for k, v := range d {
			c.Details[k] = v
		}
	}
	return c
}

// --- Go → Proto conversion ---

// GoFindingToProto converts a domain Finding to its protobuf representation.
func GoFindingToProto(f *findings.Finding) *pluginv1.Finding {
	pf := &pluginv1.Finding{
		Id:          f.ID,
		RuleId:      f.RuleID,
		Severity:    GoSeverityToProto(f.Severity),
		Confidence:  GoConfidenceToProto(f.Confidence),
		Location:    GoLocationToProto(f.Location),
		Message:     f.Message,
		Fingerprint: f.Fingerprint,
	}
	if len(f.Metadata) > 0 {
		pf.Metadata = make(map[string]string, len(f.Metadata))
		for k, v := range f.Metadata {
			pf.Metadata[k] = v
		}
	}
	return pf
}

// GoLocationToProto converts a domain Location to its protobuf representation.
func GoLocationToProto(l findings.Location) *pluginv1.Location {
	return &pluginv1.Location{
		FilePath:    l.FilePath,
		StartLine:   int32(l.StartLine),
		EndLine:     int32(l.EndLine),
		StartColumn: int32(l.StartColumn),
		EndColumn:   int32(l.EndColumn),
	}
}

// GoSeverityToProto maps a domain Severity string to the protobuf Severity enum.
func GoSeverityToProto(s findings.Severity) pluginv1.Severity {
	switch s {
	case findings.SeverityCritical:
		return pluginv1.Severity_SEVERITY_CRITICAL
	case findings.SeverityHigh:
		return pluginv1.Severity_SEVERITY_HIGH
	case findings.SeverityMedium:
		return pluginv1.Severity_SEVERITY_MEDIUM
	case findings.SeverityLow:
		return pluginv1.Severity_SEVERITY_LOW
	case findings.SeverityInfo:
		return pluginv1.Severity_SEVERITY_INFO
	default:
		return pluginv1.Severity_SEVERITY_UNSPECIFIED
	}
}

// GoConfidenceToProto maps a domain Confidence string to the protobuf Confidence enum.
func GoConfidenceToProto(c findings.Confidence) pluginv1.Confidence {
	switch c {
	case findings.ConfidenceHigh:
		return pluginv1.Confidence_CONFIDENCE_HIGH
	case findings.ConfidenceMedium:
		return pluginv1.Confidence_CONFIDENCE_MEDIUM
	case findings.ConfidenceLow:
		return pluginv1.Confidence_CONFIDENCE_LOW
	default:
		return pluginv1.Confidence_CONFIDENCE_UNSPECIFIED
	}
}

// GoPackageToProto converts a domain Package to its protobuf representation.
func GoPackageToProto(p deps.Package) *pluginv1.Package {
	return &pluginv1.Package{
		Name:      p.Name,
		Version:   p.Version,
		Ecosystem: p.Ecosystem,
	}
}

// GoAIComponentToProto converts a domain Component to its protobuf representation.
func GoAIComponentToProto(c ai.Component) *pluginv1.AIComponent {
	pac := &pluginv1.AIComponent{
		Name: c.Name,
		Type: c.Type,
		Path: c.Path,
	}
	if len(c.Details) > 0 {
		pac.Details = make(map[string]string, len(c.Details))
		for k, v := range c.Details {
			pac.Details[k] = v
		}
	}
	return pac
}

// --- Graph conversion ---

// ProtoNodeKindToGo maps a protobuf NodeKind to the domain NodeKind string.
func ProtoNodeKindToGo(pk pluginv1.NodeKind) graph.NodeKind {
	switch pk {
	case pluginv1.NodeKind_NODE_KIND_RESOURCE:
		return graph.NodeKindResource
	case pluginv1.NodeKind_NODE_KIND_FUNCTION:
		return graph.NodeKindFunction
	case pluginv1.NodeKind_NODE_KIND_DATA:
		return graph.NodeKindData
	case pluginv1.NodeKind_NODE_KIND_SERVICE:
		return graph.NodeKindService
	case pluginv1.NodeKind_NODE_KIND_POLICY:
		return graph.NodeKindPolicy
	default:
		return graph.NodeKindUnspecified
	}
}

// GoNodeKindToProto maps a domain NodeKind to the protobuf NodeKind enum.
func GoNodeKindToProto(k graph.NodeKind) pluginv1.NodeKind {
	switch k {
	case graph.NodeKindResource:
		return pluginv1.NodeKind_NODE_KIND_RESOURCE
	case graph.NodeKindFunction:
		return pluginv1.NodeKind_NODE_KIND_FUNCTION
	case graph.NodeKindData:
		return pluginv1.NodeKind_NODE_KIND_DATA
	case graph.NodeKindService:
		return pluginv1.NodeKind_NODE_KIND_SERVICE
	case graph.NodeKindPolicy:
		return pluginv1.NodeKind_NODE_KIND_POLICY
	default:
		return pluginv1.NodeKind_NODE_KIND_UNSPECIFIED
	}
}

// ProtoEdgeKindToGo maps a protobuf EdgeKind to the domain EdgeKind string.
func ProtoEdgeKindToGo(pk pluginv1.EdgeKind) graph.EdgeKind {
	switch pk {
	case pluginv1.EdgeKind_EDGE_KIND_DEPENDS_ON:
		return graph.EdgeKindDependsOn
	case pluginv1.EdgeKind_EDGE_KIND_CALLS:
		return graph.EdgeKindCalls
	case pluginv1.EdgeKind_EDGE_KIND_FLOWS_TO:
		return graph.EdgeKindFlowsTo
	case pluginv1.EdgeKind_EDGE_KIND_EXPOSES:
		return graph.EdgeKindExposes
	case pluginv1.EdgeKind_EDGE_KIND_REFERENCES:
		return graph.EdgeKindReferences
	default:
		return graph.EdgeKindUnspecified
	}
}

// GoEdgeKindToProto maps a domain EdgeKind to the protobuf EdgeKind enum.
func GoEdgeKindToProto(k graph.EdgeKind) pluginv1.EdgeKind {
	switch k {
	case graph.EdgeKindDependsOn:
		return pluginv1.EdgeKind_EDGE_KIND_DEPENDS_ON
	case graph.EdgeKindCalls:
		return pluginv1.EdgeKind_EDGE_KIND_CALLS
	case graph.EdgeKindFlowsTo:
		return pluginv1.EdgeKind_EDGE_KIND_FLOWS_TO
	case graph.EdgeKindExposes:
		return pluginv1.EdgeKind_EDGE_KIND_EXPOSES
	case graph.EdgeKindReferences:
		return pluginv1.EdgeKind_EDGE_KIND_REFERENCES
	default:
		return pluginv1.EdgeKind_EDGE_KIND_UNSPECIFIED
	}
}

// ProtoGraphToGo converts a protobuf Graph to the domain Graph type.
func ProtoGraphToGo(pg *pluginv1.Graph) graph.Graph {
	if pg == nil {
		return graph.Graph{}
	}
	g := graph.Graph{
		Name:        pg.GetName(),
		Description: pg.GetDescription(),
	}
	for _, pn := range pg.GetNodes() {
		n := graph.Node{
			ID:       pn.GetId(),
			Kind:     ProtoNodeKindToGo(pn.GetKind()),
			Label:    pn.GetLabel(),
			FilePath: pn.GetFilePath(),
		}
		if p := pn.GetProperties(); len(p) > 0 {
			n.Properties = make(map[string]string, len(p))
			for k, v := range p {
				n.Properties[k] = v
			}
		}
		g.Nodes = append(g.Nodes, n)
	}
	for _, pe := range pg.GetEdges() {
		e := graph.Edge{
			Source: pe.GetSource(),
			Target: pe.GetTarget(),
			Kind:   ProtoEdgeKindToGo(pe.GetKind()),
			Label:  pe.GetLabel(),
		}
		if p := pe.GetProperties(); len(p) > 0 {
			e.Properties = make(map[string]string, len(p))
			for k, v := range p {
				e.Properties[k] = v
			}
		}
		g.Edges = append(g.Edges, e)
	}
	return g
}

// GoGraphToProto converts a domain Graph to its protobuf representation.
func GoGraphToProto(g *graph.Graph) *pluginv1.Graph {
	if g == nil {
		return nil
	}
	pg := &pluginv1.Graph{
		Name:        g.Name,
		Description: g.Description,
	}
	for _, n := range g.Nodes {
		pn := &pluginv1.GraphNode{
			Id:       n.ID,
			Kind:     GoNodeKindToProto(n.Kind),
			Label:    n.Label,
			FilePath: n.FilePath,
		}
		if len(n.Properties) > 0 {
			pn.Properties = make(map[string]string, len(n.Properties))
			for k, v := range n.Properties {
				pn.Properties[k] = v
			}
		}
		pg.Nodes = append(pg.Nodes, pn)
	}
	for _, e := range g.Edges {
		pe := &pluginv1.GraphEdge{
			Source: e.Source,
			Target: e.Target,
			Kind:   GoEdgeKindToProto(e.Kind),
			Label:  e.Label,
		}
		if len(e.Properties) > 0 {
			pe.Properties = make(map[string]string, len(e.Properties))
			for k, v := range e.Properties {
				pe.Properties[k] = v
			}
		}
		pg.Edges = append(pg.Edges, pe)
	}
	return pg
}

// --- Enrichment conversion ---

// ProtoEnrichmentToGo converts a protobuf Enrichment to the domain Enrichment type.
func ProtoEnrichmentToGo(pe *pluginv1.Enrichment) findings.Enrichment {
	if pe == nil {
		return findings.Enrichment{}
	}
	e := findings.Enrichment{
		FindingFingerprint: pe.GetFindingFingerprint(),
		Kind:               pe.GetKind(),
		Title:              pe.GetTitle(),
		Body:               pe.GetBody(),
		Confidence:         ProtoConfidenceToGo(pe.GetConfidence()),
		Source:             pe.GetSource(),
	}
	if m := pe.GetMetadata(); len(m) > 0 {
		e.Metadata = make(map[string]string, len(m))
		for k, v := range m {
			e.Metadata[k] = v
		}
	}
	return e
}

// GoEnrichmentToProto converts a domain Enrichment to its protobuf representation.
func GoEnrichmentToProto(e *findings.Enrichment) *pluginv1.Enrichment {
	if e == nil {
		return nil
	}
	pe := &pluginv1.Enrichment{
		FindingFingerprint: e.FindingFingerprint,
		Kind:               e.Kind,
		Title:              e.Title,
		Body:               e.Body,
		Confidence:         GoConfidenceToProto(e.Confidence),
		Source:             e.Source,
	}
	if len(e.Metadata) > 0 {
		pe.Metadata = make(map[string]string, len(e.Metadata))
		for k, v := range e.Metadata {
			pe.Metadata[k] = v
		}
	}
	return pe
}

// --- ScanContext conversion ---

// GoScanResultToProtoContext converts core scan results into a proto ScanContext
// for post-scan plugin invocation.
func GoScanResultToProtoContext(r *core.ScanResult) *pluginv1.ScanContext {
	if r == nil {
		return nil
	}
	sc := &pluginv1.ScanContext{}
	if r.Findings != nil {
		ff := r.Findings.Findings()
		for i := range ff {
			sc.Findings = append(sc.Findings, GoFindingToProto(&ff[i]))
		}
	}
	if r.Inventory != nil {
		for _, p := range r.Inventory.Packages() {
			sc.Packages = append(sc.Packages, GoPackageToProto(p))
		}
	}
	if r.AIInventory != nil {
		for _, c := range r.AIInventory.Components {
			sc.AiComponents = append(sc.AiComponents, GoAIComponentToProto(c))
		}
	}
	return sc
}
