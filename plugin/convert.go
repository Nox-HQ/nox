package plugin

import (
	"fmt"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/graph"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

// --- Proto → Go conversion ---

// ProtoFindingToGo converts a protobuf Finding to the domain Finding type.
//
// pluginName identifies the plugin that produced the finding; it namespaces the
// fingerprint so a plugin cannot reach outside its own findings. See
// pluginFingerprint.
//
// workspaceRoot is the directory the plugin was pointed at. Plugins commonly
// report absolute paths, so the location is made relative to it BEFORE the
// fingerprint is computed. Without that, a plugin finding's fingerprint moved
// with the checkout directory and could not be baselined anywhere the path was
// not byte-identical — every CI runner, every git-worktree gate, any two
// developers (#454). Pass "" to skip normalisation.
func ProtoFindingToGo(pf *pluginv1.Finding, pluginName, workspaceRoot string) findings.Finding {
	if pf == nil {
		return findings.Finding{}
	}
	f := findings.Finding{
		ID:         pf.GetId(),
		RuleID:     pf.GetRuleId(),
		Severity:   ProtoSeverityToGo(pf.GetSeverity()),
		Confidence: ProtoConfidenceToGo(pf.GetConfidence()),
		Location:   ProtoLocationToGo(pf.GetLocation()),
		Message:    pf.GetMessage(),
	}
	f.Location.FilePath = repoRelativePath(f.Location.FilePath, workspaceRoot)
	f.Fingerprint = pluginFingerprint(pluginName, pf.GetRuleId(), pf.GetFingerprint(), f)
	if m := pf.GetMetadata(); len(m) > 0 {
		f.Metadata = make(map[string]string, len(m))
		for k, v := range m {
			f.Metadata[k] = v
		}
	}
	return f
}

// repoRelativePath rewrites an absolute plugin-reported path to one relative to
// root, so a finding identifies a file in the repository rather than a location
// on the machine that scanned it.
//
// It delegates to sdk.RelativePath, the helper plugin authors are told to use,
// so the host and the plugins agree on what a repo-relative path is. Two
// implementations of this drifted once already: this one returned native
// separators while the SDK's returned slashes, which on Windows gave a plugin
// finding `internal\svc\handler.go` where every other nox path is
// `internal/svc/handler.go`. That made the fingerprint differ between Windows
// and Linux for the same file in the same repository — the #454 bug again,
// across operating systems instead of across directories — and left
// forward-slash exclude patterns unable to match plugin paths.
func repoRelativePath(path, root string) string {
	return sdk.RelativePath(root, path)
}

// pluginFingerprint derives the fingerprint stored for a plugin finding.
//
// A plugin's claimed fingerprint cannot be used as-is. Plugin findings merge
// into the same FindingSet as core findings and are then deduplicated
// first-wins, and baseline and VEX suppression key on the same value. A plugin
// could therefore claim a fingerprint matching a core finding and erase it, or
// claim one matching a baselined finding and hide itself.
//
// So the value is recomputed host-side using the core scheme — which keeps
// determinism, path normalisation and fingerprint-version parity — with the
// rule ID namespaced by plugin name. The plugin's claim is demoted to hash
// input, tagged so a claimed fingerprint and a message can never alias. That
// preserves the one legitimate use of the claim: deciding which of a plugin's
// own findings are "the same" across runs, so they stay baseline-able.
func pluginFingerprint(pluginName, ruleID, claimed string, f findings.Finding) string {
	// Length-prefixed rather than delimited.
	//
	// A delimiter is only unambiguous if it cannot appear in the components,
	// and nothing enforces that here: the plugin name comes from the plugin's
	// own GetManifest response and the rule ID from the finding it emitted, so
	// both are attacker-controlled. A colon separator collided outright
	// ("acme" + "sql:injection" versus "acme:sql" + "injection"), and moving to
	// NUL only made the same collision require a NUL-bearing name — proto3
	// strings are UTF-8, which permits NUL. Length prefixes remove the class:
	// no choice of name or rule ID can produce another pair's encoding.
	namespaced := fmt.Sprintf("plugin\x00%d:%s\x00%d:%s",
		len(pluginName), pluginName, len(ruleID), ruleID)

	identity := "msg:" + f.Message
	if claimed != "" {
		identity = "fp:" + claimed
	}

	return findings.ComputeFingerprint(namespaced, f.Location, identity)
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

// AttributedResponse pairs a plugin response with the name of the plugin that
// produced it.
//
// The response message itself carries no producer identity, but the host needs
// it at merge time to namespace fingerprints — see pluginFingerprint. Carrying
// it alongside is simpler than widening the wire format, and keeps the
// attribution authoritative: it comes from the host's own registry rather than
// from anything the plugin says about itself.
type AttributedResponse struct {
	PluginName string
	Response   *pluginv1.InvokeToolResponse
}
