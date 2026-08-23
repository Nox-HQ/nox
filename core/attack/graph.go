package attack

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/graph"
)

// graphSchemaVersion identifies the attack-graph document format. It is
// versioned separately from the plan because a consumer may read the graph
// alone (via MCP) without the surrounding plan.
const graphSchemaVersion = "attack-graph/1"

// Why an attack-specific graph type instead of core/graph.Graph:
//
// core/graph is nox's generic plugin-emission graph. Its vocabulary is five
// node kinds (resource, function, data, service, policy) and five edge kinds
// (depends_on, calls, flows_to, exposes, references). None of those express the
// facts this graph exists to carry: an authorization boundary is not a policy
// node, "agent A delegates to agent B" is not "calls", and "the app trusts this
// MCP server's output" is not "references". Collapsing delegation, invocation
// and trust into one generic edge would destroy exactly the distinction that
// makes an attack path meaningful. core/graph also carries no JSON tags, and
// this graph is serialised into the plan document alongside snake_case fields.
//
// So the vocabulary is attack-specific, but the reuse is real: every node and
// edge kind here is a plain string type, so ToGraph projects losslessly onto
// core/graph.Graph and Validate delegates to its structural checks rather than
// reimplementing them. Renderers that consume core/graph keep working.
//
// The Attack* prefix on the exported types is deliberate for the same reason.
// revive reads attack.AttackGraph as stutter, but this package sits next to
// core/graph, whose Graph, Node and Edge mean something else entirely, and the
// PRD-facing API names these types. Dropping the prefix would trade a lint nit
// for real ambiguity, so the four declarations carry a nolint.

// NodeKind classifies a vertex of the attack graph. The kinds are the things an
// attacker moves through or aims at, not the things a build system depends on.
type NodeKind string

// Attack-graph node kinds.
const (
	// NodeEntryPoint is a place untrusted input enters the system.
	NodeEntryPoint NodeKind = "entry_point"
	// NodeModel is an LLM prompt call or a referenced model.
	NodeModel NodeKind = "model"
	// NodeAgent is an agent context that holds a set of tools.
	NodeAgent NodeKind = "agent"
	// NodeMCPServer is an MCP server exposing tools to an agent.
	NodeMCPServer NodeKind = "mcp_server"
	// NodeTool is a single registered tool.
	NodeTool NodeKind = "tool"
	// NodeResource is a readable store: a filesystem, a secret store.
	NodeResource NodeKind = "resource"
	// NodeDatabase is a database reachable through a tool.
	NodeDatabase NodeKind = "database"
	// NodeNetworkSink is an egress channel: HTTP, webhook, email.
	NodeNetworkSink NodeKind = "network_sink"
	// NodeIdentity is a principal or credential the system authenticates as.
	NodeIdentity NodeKind = "identity"
	// NodeAuthzBoundary is a control that is supposed to gate a privileged act.
	NodeAuthzBoundary NodeKind = "authz_boundary"
	// NodeAsset is a privileged capability or a thing of value.
	NodeAsset NodeKind = "asset"
)

// EdgeKind classifies a relationship between two attack-graph nodes. The kind is
// load-bearing and deliberately not collapsible: "agent A can invoke tool B" and
// "agent A delegates to agent B" are different security facts with different
// remediations, and a graph that merges them cannot tell an operator which grant
// to revoke.
type EdgeKind string

// Attack-graph edge kinds.
const (
	// EdgeDataFlow is content moving from one node into another.
	EdgeDataFlow EdgeKind = "data_flow"
	// EdgeInvokes is one node causing another to execute.
	EdgeInvokes EdgeKind = "invokes"
	// EdgeDelegates is one agent handing work to another agent.
	EdgeDelegates EdgeKind = "delegates_to"
	// EdgeTrusts is one node accepting another's output as authoritative.
	EdgeTrusts EdgeKind = "trusts"
	// EdgeAuthorizes is a control relation: an identity or approval gate that
	// governs a capability. It is recorded but never traversed (see traversable).
	EdgeAuthorizes EdgeKind = "authorizes"
	// EdgeReaches is plain reachability where no finer kind is known.
	EdgeReaches EdgeKind = "reaches"
)

// Evidence kinds. Every node and edge names the scan artifact it came from.
const (
	// EvidenceKindFinding grounds a node in a static finding fingerprint.
	EvidenceKindFinding = "finding"
	// EvidenceKindComponent grounds a node in an AI inventory component.
	EvidenceKindComponent = "inventory_component"
	// EvidenceKindToolGrant grounds a node in a tool registration.
	EvidenceKindToolGrant = "tool_registration"
	// EvidenceKindModelRef grounds a node in a model provenance record.
	EvidenceKindModelRef = "model_reference"
	// EvidenceKindConnection grounds a node in the inventory connection graph.
	EvidenceKindConnection = "inventory_connection"
)

// NodeEvidence is the scan artifact a node or edge is grounded in. It exists
// because a fabricated attack graph is worse than no attack graph: it produces
// confident, wrong hypotheses. Nothing enters the graph without one of these.
type NodeEvidence struct {
	// Kind is one of the EvidenceKind* constants.
	Kind string `json:"kind"`
	// Ref identifies the artifact: a fingerprint, a file path, a name.
	Ref string `json:"ref"`
	// Detail carries human-readable context.
	Detail string `json:"detail,omitempty"`
}

// AttackNode is one vertex of the attack graph.
//
//nolint:revive // the Attack* prefix is deliberate; see the note above.
type AttackNode struct {
	// ID is a stable, deterministic identifier.
	ID string `json:"id"`
	// Kind classifies the node.
	Kind NodeKind `json:"kind"`
	// Label is a human-readable description.
	Label string `json:"label"`
	// FilePath is where the node was observed, when known.
	FilePath string `json:"file_path,omitempty"`
	// Sensitive marks a node that is itself worth reaching (a secret, a file
	// store, a database). A path that terminates here is a disclosure path.
	Sensitive bool `json:"sensitive,omitempty"`
	// Privileged marks a capability whose abuse is itself the objective (shell
	// execution, egress, a payment). A path that terminates here is an abuse
	// path.
	Privileged bool `json:"privileged,omitempty"`
	// Capabilities are ai.CapabilityTag values carried by a tool node.
	Capabilities []string `json:"capabilities,omitempty"`
	// Attributes carries extra grounded detail (an agent name, a config path).
	Attributes map[string]string `json:"attributes,omitempty"`
	// Evidence is what this node is grounded in. Never empty.
	Evidence []NodeEvidence `json:"evidence"`
}

// AttackEdge is one directed relationship of the attack graph.
//
//nolint:revive // the Attack* prefix is deliberate; see the note above.
type AttackEdge struct {
	// ID is a stable, deterministic identifier derived from the endpoints and
	// the kind.
	ID string `json:"id"`
	// From is the source node ID.
	From string `json:"from"`
	// To is the target node ID.
	To string `json:"to"`
	// Kind classifies the relationship.
	Kind EdgeKind `json:"kind"`
	// Label is a human-readable description of the relationship.
	Label string `json:"label"`
	// Evidence is what this edge is grounded in. Never empty.
	Evidence []NodeEvidence `json:"evidence"`
}

// PathTruncation records that a bounded enumeration stopped early. A capped
// result that renders as if it were complete is a bug: an operator who reads
// "3 attack paths" must be able to tell whether that is the answer or the
// budget. Nil means the last enumeration was exhaustive within its bounds.
type PathTruncation struct {
	// DepthLimit is the maximum number of hops that were explored.
	DepthLimit int `json:"depth_limit"`
	// PathLimit is the maximum number of paths that could be returned.
	PathLimit int `json:"path_limit"`
	// DepthCapped reports that at least one branch was abandoned at DepthLimit
	// with traversable edges still unexplored.
	DepthCapped bool `json:"depth_capped"`
	// PathCapped reports that enumeration stopped because PathLimit was hit.
	PathCapped bool `json:"path_capped"`
	// Reason states in plain language what was left out.
	Reason string `json:"reason"`
}

// AttackPath is one walk from an entry point to a sensitive asset or a
// privileged capability.
//
//nolint:revive // the Attack* prefix is deliberate; see the note above.
type AttackPath struct {
	// ID is a stable identifier derived from the traversed edges.
	ID string `json:"id"`
	// EntryID is the entry-point node the path starts at.
	EntryID string `json:"entry_id"`
	// TerminalID is the node the path ends at.
	TerminalID string `json:"terminal_id"`
	// Nodes are the node IDs in order, entry first.
	Nodes []string `json:"nodes"`
	// Edges are the traversed edge IDs; len(Edges) == len(Nodes)-1.
	Edges []string `json:"edges"`
	// Steps is the path rendered in the plan's PathStep vocabulary so a
	// hypothesis can carry it verbatim.
	Steps []PathStep `json:"steps"`
}

// CutEdge is a proposed intervention: an edge whose removal breaks attack paths.
// PRD §20 prioritises removing edges over recommending prompt changes, because
// revoking a grant is verifiable and rewording a system prompt is not.
type CutEdge struct {
	// EdgeID is the edge to remove.
	EdgeID string `json:"edge_id"`
	// From is the source node ID.
	From string `json:"from"`
	// To is the target node ID.
	To string `json:"to"`
	// Kind classifies the relationship being cut.
	Kind EdgeKind `json:"kind"`
	// PathsBroken is how many of the supplied paths traverse this edge.
	PathsBroken int `json:"paths_broken"`
	// Action is the concrete operator instruction.
	Action string `json:"action"`
}

// AttackGraph is the target-aware model of the scanned system: what an attacker
// can enter through, what they can move through, and what they can reach.
//
//nolint:revive // the Attack* prefix is deliberate; see the note above.
type AttackGraph struct {
	// SchemaVersion identifies the document format.
	SchemaVersion string `json:"schema_version"`
	// Nodes are the graph vertices, sorted by ID.
	Nodes []AttackNode `json:"nodes"`
	// Edges are the graph relationships, sorted by ID.
	Edges []AttackEdge `json:"edges"`
	// Truncation records the bounds of the most recent path enumeration, or nil
	// if that enumeration was exhaustive.
	Truncation *PathTruncation `json:"truncation,omitempty"`
	// Cuts are the highest-value interventions for the most recently enumerated
	// path set. Populated by whoever ran the enumeration, not by BuildGraph.
	Cuts []CutEdge `json:"cut_edges,omitempty"`
	// Notes record inputs that could not be grounded into the graph, so a
	// dropped connection is visible rather than silent.
	Notes []string `json:"notes,omitempty"`
}

// Path enumeration bounds. Real agent topologies are small, but a pathological
// config (a fan-out of hundreds of tools, mutual delegation) makes simple-path
// enumeration exponential, so both dimensions are capped.
const (
	// DefaultMaxPathDepth is the hop budget used when a caller passes maxDepth
	// <= 0. The longest grounded route this builder produces is entry -> model
	// -> agent -> mcp server -> tool -> resource -> tool -> sink (7 hops); the
	// remainder is headroom for delegation chains.
	DefaultMaxPathDepth = 12
	// MaxEnumeratedPaths caps how many paths a single enumeration returns.
	MaxEnumeratedPaths = 256
)

// traversable reports whether an attacker can move along this edge kind.
// Authorization edges are control relations, not attack steps: an approval gate
// governing a tool does not let an attacker reach that tool, so traversing it
// would invent movement that does not exist. Trust edges are traversable
// because accepting another node's output as authoritative is precisely how
// indirect injection propagates.
func traversable(k EdgeKind) bool {
	switch k {
	case EdgeDataFlow, EdgeInvokes, EdgeDelegates, EdgeTrusts, EdgeReaches:
		return true
	case EdgeAuthorizes:
		return false
	default:
		return false
	}
}

// edgeID builds a deterministic, readable edge identifier.
func edgeID(from string, kind EdgeKind, to string) string {
	return from + " -[" + string(kind) + "]-> " + to
}

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

// graphBuilder accumulates nodes and edges keyed by ID so repeated evidence
// merges into one vertex instead of duplicating it.
type graphBuilder struct {
	nodes map[string]*AttackNode
	edges map[string]*AttackEdge
	notes map[string]bool
}

func newGraphBuilder() *graphBuilder {
	return &graphBuilder{
		nodes: map[string]*AttackNode{},
		edges: map[string]*AttackEdge{},
		notes: map[string]bool{},
	}
}

// addNode inserts or merges a node. Merging is how one agent that appears in
// both the component list and the tool matrix stays a single vertex carrying
// both pieces of evidence.
func (b *graphBuilder) addNode(n AttackNode) {
	ex, ok := b.nodes[n.ID]
	if !ok {
		cp := n
		cp.Evidence = mergeEvidence(nil, n.Evidence)
		cp.Capabilities = mergeStrings(nil, n.Capabilities)
		b.nodes[n.ID] = &cp
		return
	}
	ex.Evidence = mergeEvidence(ex.Evidence, n.Evidence)
	ex.Capabilities = mergeStrings(ex.Capabilities, n.Capabilities)
	ex.Sensitive = ex.Sensitive || n.Sensitive
	ex.Privileged = ex.Privileged || n.Privileged
	if ex.Label == "" {
		ex.Label = n.Label
	}
	if ex.FilePath == "" {
		ex.FilePath = n.FilePath
	}
	for k, v := range n.Attributes {
		if ex.Attributes == nil {
			ex.Attributes = map[string]string{}
		}
		if _, dup := ex.Attributes[k]; !dup {
			ex.Attributes[k] = v
		}
	}
}

// addEdge inserts or merges an edge.
func (b *graphBuilder) addEdge(from string, kind EdgeKind, to, label string, ev ...NodeEvidence) {
	id := edgeID(from, kind, to)
	if ex, ok := b.edges[id]; ok {
		ex.Evidence = mergeEvidence(ex.Evidence, ev)
		return
	}
	b.edges[id] = &AttackEdge{
		ID: id, From: from, To: to, Kind: kind, Label: label,
		Evidence: mergeEvidence(nil, ev),
	}
}

func (b *graphBuilder) note(s string) { b.notes[s] = true }

// build emits the finished graph with every collection sorted, and drops any
// edge whose endpoints did not survive (recording a note rather than leaving a
// dangling reference).
func (b *graphBuilder) build() *AttackGraph {
	g := &AttackGraph{
		SchemaVersion: graphSchemaVersion,
		Nodes:         make([]AttackNode, 0, len(b.nodes)),
		Edges:         make([]AttackEdge, 0, len(b.edges)),
	}
	ids := make([]string, 0, len(b.nodes))
	for id := range b.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		g.Nodes = append(g.Nodes, *b.nodes[id])
	}

	eids := make([]string, 0, len(b.edges))
	for id := range b.edges {
		eids = append(eids, id)
	}
	sort.Strings(eids)
	for _, id := range eids {
		e := b.edges[id]
		if b.nodes[e.From] == nil || b.nodes[e.To] == nil {
			b.note(fmt.Sprintf("dropped edge %q: an endpoint has no grounded node", id))
			continue
		}
		g.Edges = append(g.Edges, *e)
	}

	notes := make([]string, 0, len(b.notes))
	for n := range b.notes {
		notes = append(notes, n)
	}
	sort.Strings(notes)
	if len(notes) > 0 {
		g.Notes = notes
	}
	return g
}

// principalIndex maps the several ways a finding or a hypothesis refers to an
// agent onto the agent's node ID.
type principalIndex struct {
	// bySeed keys on shortID(label, configPath), which is exactly how BuildPlan
	// derives a tool hypothesis ID, so a hypothesis can find its own agent.
	bySeed map[string]string
	// byName keys on the agent label; a name claimed by two nodes maps to "" so
	// an ambiguous reference resolves to nothing rather than to a guess.
	byName map[string]string
	// byPath keys on the config/source file the agent was declared in.
	byPath map[string][]string
}

func newPrincipalIndex() *principalIndex {
	return &principalIndex{
		bySeed: map[string]string{},
		byName: map[string]string{},
		byPath: map[string][]string{},
	}
}

func (p *principalIndex) put(name, path, nodeID string) {
	if name != "" {
		if ex, ok := p.byName[name]; ok && ex != nodeID {
			p.byName[name] = ""
		} else {
			p.byName[name] = nodeID
		}
	}
	if path != "" {
		p.bySeed[shortID(name, path)] = nodeID
		for _, ex := range p.byPath[path] {
			if ex == nodeID {
				return
			}
		}
		p.byPath[path] = append(p.byPath[path], nodeID)
	}
}

func (p *principalIndex) name(n string) (string, bool) {
	id, ok := p.byName[n]
	return id, ok && id != ""
}

// BuildGraph derives the attack graph from a scan's findings and AI inventory.
// Every node traces back to a finding, an inventory component, a model
// reference, a tool registration, or a connection the scan actually observed;
// nothing is inferred from what a system of this shape usually looks like.
// Nil or empty inputs yield an empty, valid graph.
func BuildGraph(ff []findings.Finding, inv *ai.Inventory) *AttackGraph {
	b := newGraphBuilder()
	principals := newPrincipalIndex()

	if inv != nil {
		addInventoryComponents(b, inv, principals)
		addModelReferences(b, inv)
		addToolMatrix(b, inv, principals)
	}
	addInjectionFindings(b, ff, principals)
	if inv != nil {
		addConnections(b, inv, principals)
	}
	return b.build()
}

// addInventoryComponents adds the agents and MCP servers the inventory listed
// directly, so an agent that registers no tools is still a vertex delegation
// edges can attach to.
func addInventoryComponents(b *graphBuilder, inv *ai.Inventory, p *principalIndex) {
	comps := append([]ai.Component(nil), inv.Components...)
	sort.Slice(comps, func(i, j int) bool {
		if comps[i].Type != comps[j].Type {
			return comps[i].Type < comps[j].Type
		}
		if comps[i].Name != comps[j].Name {
			return comps[i].Name < comps[j].Name
		}
		return comps[i].Path < comps[j].Path
	})
	for _, c := range comps {
		if c.Name == "" {
			continue
		}
		ev := NodeEvidence{Kind: EvidenceKindComponent, Ref: c.Path, Detail: c.Type + " " + c.Name}
		switch c.Type {
		case "agent":
			id := "agent:" + c.Name
			b.addNode(AttackNode{
				ID: id, Kind: NodeAgent, Label: c.Name, FilePath: c.Path,
				Attributes: map[string]string{"path": c.Path},
				Evidence:   []NodeEvidence{ev},
			})
			p.put(c.Name, c.Path, id)
		case "mcp_config", "mcp_server":
			id := "mcp:" + c.Name
			b.addNode(AttackNode{
				ID: id, Kind: NodeMCPServer, Label: c.Name, FilePath: c.Path,
				Attributes: map[string]string{"path": c.Path},
				Evidence:   []NodeEvidence{ev},
			})
			p.put(c.Name, c.Path, id)
		}
	}
}

// addModelReferences adds model vertices and, where the reference names an auth
// environment variable, the identity that authorizes calls to it. The identity
// is sensitive: it is a credential, and reaching it is an objective in itself.
func addModelReferences(b *graphBuilder, inv *ai.Inventory) {
	refs := append([]ai.ModelReference(nil), inv.ModelProvenance...)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Name != refs[j].Name {
			return refs[i].Name < refs[j].Name
		}
		return refs[i].Path < refs[j].Path
	})
	for _, r := range refs {
		if r.Name == "" {
			continue
		}
		ev := NodeEvidence{Kind: EvidenceKindModelRef, Ref: r.Path, Detail: r.Name}
		modelID := "model:" + r.Name
		attrs := map[string]string{"pinned": fmt.Sprintf("%t", r.Pinned)}
		if r.Registry != "" {
			attrs["registry"] = r.Registry
		}
		b.addNode(AttackNode{
			ID: modelID, Kind: NodeModel, Label: r.Name, FilePath: r.Path,
			Attributes: attrs, Evidence: []NodeEvidence{ev},
		})
		if r.AuthEnvVar != "" {
			idID := "identity:" + r.AuthEnvVar
			b.addNode(AttackNode{
				ID: idID, Kind: NodeIdentity, Label: r.AuthEnvVar, FilePath: r.Path,
				Sensitive: true, Evidence: []NodeEvidence{ev},
			})
			b.addEdge(idID, EdgeAuthorizes, modelID,
				fmt.Sprintf("credential %s authorizes calls to model %s", r.AuthEnvVar, r.Name), ev)
		}
	}
}

// terminalSpec describes the vertex a capability tag terminates in.
type terminalSpec struct {
	idPart     string
	kind       NodeKind
	label      string
	sensitive  bool
	privileged bool
	edge       EdgeKind
	// source marks a store the tool READS from. A source is where an
	// exfiltration chain begins; a non-source is where it ends.
	source bool
}

// capabilityTerminals maps ai.CapabilityTag onto the thing the capability
// actually touches. The taxonomy is ai's, not a parallel one.
var capabilityTerminals = map[ai.CapabilityTag]terminalSpec{
	ai.CapFileRead:     {"res:filesystem", NodeResource, "filesystem readable by %s", true, false, EdgeReaches, true},
	ai.CapReadSecret:   {"res:secrets", NodeResource, "secret store readable by %s", true, false, EdgeReaches, true},
	ai.CapDatabaseRead: {"db:read", NodeDatabase, "database readable by %s", true, false, EdgeReaches, true},

	ai.CapHTTPRequest:     {"sink:http", NodeNetworkSink, "outbound HTTP sink reachable by %s", false, true, EdgeDataFlow, false},
	ai.CapWebhookPost:     {"sink:webhook", NodeNetworkSink, "webhook sink reachable by %s", false, true, EdgeDataFlow, false},
	ai.CapEmailSend:       {"sink:email", NodeNetworkSink, "outbound email reachable by %s", false, true, EdgeDataFlow, false},
	ai.CapShellExec:       {"asset:shell", NodeAsset, "shell execution as %s", false, true, EdgeInvokes, false},
	ai.CapFileWrite:       {"asset:file-write", NodeAsset, "filesystem writes by %s", false, true, EdgeInvokes, false},
	ai.CapDatabaseWrite:   {"db:write", NodeDatabase, "database writes by %s", false, true, EdgeInvokes, false},
	ai.CapGitPush:         {"asset:git-push", NodeAsset, "repository pushes by %s", false, true, EdgeInvokes, false},
	ai.CapCloudIAMModify:  {"asset:cloud-iam", NodeAsset, "cloud IAM changes by %s", false, true, EdgeInvokes, false},
	ai.CapPaymentInitiate: {"asset:payment", NodeAsset, "payment initiation by %s", false, true, EdgeInvokes, false},
}

// addToolMatrix turns each tool permission set into a principal, its tools, and
// the stores and capabilities those tools touch.
func addToolMatrix(b *graphBuilder, inv *ai.Inventory, p *principalIndex) {
	sets := append([]ai.ToolPermissionSet(nil), inv.ToolMatrix...)
	sort.Slice(sets, func(i, j int) bool {
		if sets[i].Agent != sets[j].Agent {
			return sets[i].Agent < sets[j].Agent
		}
		if sets[i].Server != sets[j].Server {
			return sets[i].Server < sets[j].Server
		}
		return sets[i].Path < sets[j].Path
	})
	for _, set := range sets {
		addToolSet(b, set, p)
	}
}

// addToolSet adds one permission set. It is a separate function because the
// per-set scoping is the whole point: a read tool and an egress tool chain only
// when they belong to the SAME set, never across two agents that happen to hold
// complementary grants.
func addToolSet(b *graphBuilder, set ai.ToolPermissionSet, p *principalIndex) {
	label := set.Agent
	if label == "" {
		label = set.Server
	}
	if label == "" {
		return
	}
	ev := NodeEvidence{Kind: EvidenceKindToolGrant, Ref: set.Path, Detail: label}

	principalID := "agent:" + label
	principalKind := NodeAgent
	if set.Agent == "" {
		principalID = "mcp:" + label
		principalKind = NodeMCPServer
	}
	b.addNode(AttackNode{
		ID: principalID, Kind: principalKind, Label: label, FilePath: set.Path,
		Attributes: map[string]string{"path": set.Path},
		Evidence:   []NodeEvidence{ev},
	})
	p.put(label, set.Path, principalID)

	// An agent that reaches its tools through a named MCP server keeps that hop
	// in the graph: the server is a distinct trust domain and a distinct cut.
	toolHolder := principalID
	if set.Agent != "" && set.Server != "" {
		serverID := "mcp:" + set.Server
		b.addNode(AttackNode{
			ID: serverID, Kind: NodeMCPServer, Label: set.Server, FilePath: set.Path,
			Attributes: map[string]string{"path": set.Path},
			Evidence:   []NodeEvidence{ev},
		})
		p.put(set.Server, set.Path, serverID)
		b.addEdge(principalID, EdgeInvokes, serverID,
			fmt.Sprintf("agent %s invokes MCP server %s", label, set.Server), ev)
		toolHolder = serverID
	}

	tools := append([]string(nil), set.Tools...)
	sort.Strings(tools)

	var sources, egress []string // terminal node IDs / tool node IDs in this set
	var privilegedTools []string

	for _, tool := range tools {
		if tool == "" {
			continue
		}
		toolID := "tool:" + toolHolder + ":" + tool
		tags := capabilityTags(tool, set.Capabilities[tool])
		tagStrings := make([]string, 0, len(tags))
		for _, t := range tags {
			tagStrings = append(tagStrings, string(t))
		}
		desc := set.Descriptions[tool]
		attrs := map[string]string{"path": set.Path}
		if desc != "" {
			attrs["description"] = desc
		}
		b.addNode(AttackNode{
			ID: toolID, Kind: NodeTool, Label: tool, FilePath: set.Path,
			Capabilities: tagStrings, Attributes: attrs,
			Evidence: []NodeEvidence{ev},
		})
		b.addEdge(toolHolder, EdgeInvokes, toolID,
			fmt.Sprintf("%s may invoke tool %s", label, tool), ev)

		for _, tag := range tags {
			switch tag {
			case ai.CapUntrustedInput:
				// A tool tagged untrusted_input_path ingests attacker-controlled
				// content: that is an entry point, grounded in the registration.
				entryID := "entry:tool:" + toolID
				b.addNode(AttackNode{
					ID: entryID, Kind: NodeEntryPoint, FilePath: set.Path,
					Label:    fmt.Sprintf("untrusted content ingested by tool %s", tool),
					Evidence: []NodeEvidence{ev},
				})
				b.addEdge(entryID, EdgeDataFlow, toolID,
					fmt.Sprintf("untrusted content flows into tool %s", tool), ev)
				continue
			case ai.CapHumanApproval:
				// Handled once per set below, after the privileged tools it
				// would govern are known.
				continue
			}
			spec, ok := capabilityTerminals[tag]
			if !ok {
				continue
			}
			termID := spec.idPart + ":" + principalID
			b.addNode(AttackNode{
				ID: termID, Kind: spec.kind, Label: fmt.Sprintf(spec.label, label),
				Sensitive: spec.sensitive, Privileged: spec.privileged,
				Attributes: map[string]string{"agent": label},
				Evidence:   []NodeEvidence{ev},
			})
			b.addEdge(toolID, spec.edge, termID,
				fmt.Sprintf("tool %s %s %s", tool, verbFor(spec.edge), spec.idPart), ev)
			if spec.source {
				sources = appendUnique(sources, termID)
			} else {
				egress = appendUnique(egress, toolID)
				privilegedTools = appendUnique(privilegedTools, toolID)
			}
		}
	}

	// The exfiltration chain. A read tool's result lands in the same context
	// that holds the egress tool; that co-location is exactly the AI-AGENT-*
	// lattice fact, and it is recorded per set so it is never fabricated across
	// two agents. It is deliberately NOT claimed as an observed taint flow: the
	// label says what the evidence supports.
	for _, src := range sources {
		for _, out := range egress {
			b.addEdge(src, EdgeDataFlow, out,
				fmt.Sprintf("content read by %s is available to egress tool %s in the same tool context",
					label, strings.TrimPrefix(out, "tool:"+toolHolder+":")), ev)
		}
	}

	// A human-approval tool in the set is a control covering that set's
	// privileged tools. It is recorded with authorizes edges, which paths never
	// traverse: an approval gate is not a way in.
	if hasTag(set, tools, ai.CapHumanApproval) {
		authzID := "authz:" + principalID
		b.addNode(AttackNode{
			ID: authzID, Kind: NodeAuthzBoundary,
			Label:      fmt.Sprintf("human approval gate declared for %s", label),
			FilePath:   set.Path,
			Attributes: map[string]string{"agent": label},
			Evidence:   []NodeEvidence{ev},
		})
		for _, t := range privilegedTools {
			if t == "" {
				continue
			}
			b.addEdge(authzID, EdgeAuthorizes, t,
				fmt.Sprintf("approval gate governs %s", strings.TrimPrefix(t, "tool:"+toolHolder+":")), ev)
		}
	}
}

// hasTag reports whether any tool in the set carries the given capability tag.
func hasTag(set ai.ToolPermissionSet, tools []string, want ai.CapabilityTag) bool {
	for _, t := range tools {
		for _, tag := range capabilityTags(t, set.Capabilities[t]) {
			if tag == want {
				return true
			}
		}
	}
	return false
}

// verbFor renders an edge kind as a verb for edge labels.
func verbFor(k EdgeKind) string {
	switch k {
	case EdgeReaches:
		return "reads from"
	case EdgeDataFlow:
		return "writes into"
	case EdgeInvokes:
		return "performs"
	case EdgeDelegates:
		return "delegates to"
	case EdgeTrusts:
		return "trusts"
	case EdgeAuthorizes:
		return "authorizes"
	default:
		return "reaches"
	}
}

// addInjectionFindings turns each statically-flagged "untrusted input reaches an
// LLM prompt" finding into an entry point, the prompt call it reaches, and the
// system prompt that call protects.
//
// Only injection findings become entry points. A finding of any other class is
// evidence of a weakness, not evidence that attacker-controlled data enters
// here, and promoting it would put unreachable roots into every path search.
func addInjectionFindings(b *graphBuilder, ff []findings.Finding, p *principalIndex) {
	inj := injectionFindings(ff)
	for i := range inj {
		f := inj[i]
		ev := NodeEvidence{Kind: EvidenceKindFinding, Ref: f.Fingerprint, Detail: f.RuleID}
		loc := fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.StartLine)

		entryLabel := f.Metadata["route"]
		if entryLabel == "" {
			entryLabel = "untrusted request field at " + loc
		}
		entryID := "entry:" + loc
		modelID := "model:" + loc

		b.addNode(AttackNode{
			ID: entryID, Kind: NodeEntryPoint, Label: entryLabel, FilePath: f.Location.FilePath,
			Attributes: map[string]string{"rule_id": f.RuleID},
			Evidence:   []NodeEvidence{ev},
		})
		b.addNode(AttackNode{
			ID: modelID, Kind: NodeModel, Label: "LLM prompt call at " + loc,
			FilePath: f.Location.FilePath, Evidence: []NodeEvidence{ev},
		})
		b.addEdge(entryID, EdgeDataFlow, modelID, "untrusted input reaches the prompt call", ev)

		b.addNode(AttackNode{
			ID: "asset:system-prompt", Kind: NodeAsset,
			Label: "the model's confidential system instruction", Sensitive: true,
			Evidence: []NodeEvidence{ev},
		})
		b.addEdge(modelID, EdgeReaches, "asset:system-prompt",
			"the prompt call holds the confidential system instruction", ev)

		// Link the prompt call to an agent only on evidence: the finding names
		// the agent, or the prompt call lives in the same file that registers
		// the agent's tools (the same file-scoped context convention the agent
		// lattice analyzer uses). Absent either, the subgraphs stay
		// disconnected and Paths honestly reports no route.
		if agent := f.Metadata["agent"]; agent != "" {
			if id, ok := p.name(agent); ok {
				b.addEdge(modelID, EdgeDataFlow, id,
					fmt.Sprintf("model output drives agent %s (named by %s)", agent, f.RuleID), ev)
				continue
			}
			b.note(fmt.Sprintf("finding %s names agent %q, which no inventory component matches", f.Fingerprint, agent))
		}
		for _, id := range p.byPath[f.Location.FilePath] {
			b.addEdge(modelID, EdgeDataFlow, id,
				// nox:ignore AI-006 -- graph edge label, not a log line: id is an inventory component ID and "prompt call" is prose; no prompt or response text is formatted here
				fmt.Sprintf("the prompt call and %s are registered in the same file", id), ev)
		}
	}
}

// connectionEdgeKind maps an inventory connection type onto an edge kind. The
// default is plain reachability, never a stronger claim than the type supports.
func connectionEdgeKind(t string) EdgeKind {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "tool_access":
		return EdgeInvokes
	case "model_call":
		return EdgeInvokes
	case "data_flow":
		return EdgeDataFlow
	case "delegate", "delegates", "delegation", "handoff", "sub_agent", "a2a":
		return EdgeDelegates
	case "trust", "trusts":
		return EdgeTrusts
	case "authorize", "authorizes", "grant", "authz":
		return EdgeAuthorizes
	default:
		return EdgeReaches
	}
}

// addConnections replays the inventory's own connection graph. An endpoint that
// no existing node matches becomes an agent vertex grounded in the connection
// itself: the connection was parsed out of a real config, so the name is
// evidence. An ambiguous endpoint is dropped with a note rather than guessed.
func addConnections(b *graphBuilder, inv *ai.Inventory, p *principalIndex) {
	conns := append([]ai.Connection(nil), inv.ConnectionGraph...)
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].From != conns[j].From {
			return conns[i].From < conns[j].From
		}
		if conns[i].To != conns[j].To {
			return conns[i].To < conns[j].To
		}
		return conns[i].Type < conns[j].Type
	})
	byLabel := map[string][]string{}
	for id, n := range b.nodes {
		byLabel[n.Label] = append(byLabel[n.Label], id)
	}
	for k := range byLabel {
		sort.Strings(byLabel[k])
	}

	resolve := func(name string) (string, bool) {
		if id, ok := p.name(name); ok {
			return id, true
		}
		switch ids := byLabel[name]; len(ids) {
		case 0:
			// Unknown but real: the connection extractor read it out of a
			// config. Create the agent it names.
			id := "agent:" + name
			b.addNode(AttackNode{
				ID: id, Kind: NodeAgent, Label: name,
				Evidence: []NodeEvidence{{Kind: EvidenceKindConnection, Ref: name, Detail: "named by the inventory connection graph"}},
			})
			return id, true
		case 1:
			return ids[0], true
		default:
			return "", false
		}
	}

	for _, c := range conns {
		if c.From == "" || c.To == "" {
			continue
		}
		from, okFrom := resolve(c.From)
		to, okTo := resolve(c.To)
		if !okFrom || !okTo {
			b.note(fmt.Sprintf("dropped connection %q -> %q (%s): an endpoint name is ambiguous", c.From, c.To, c.Type))
			continue
		}
		if from == to {
			continue
		}
		kind := connectionEdgeKind(c.Type)
		ev := NodeEvidence{Kind: EvidenceKindConnection, Ref: c.From + "->" + c.To, Detail: c.Type}
		b.addEdge(from, kind, to, fmt.Sprintf("%s %s %s", c.From, verbFor(kind), c.To), ev)
	}
}

// -----------------------------------------------------------------------------
// Capability classification
// -----------------------------------------------------------------------------

// capabilityTags returns the ai.CapabilityTag values for one tool. Tags the
// inventory already recorded win outright: they came from the same extractor
// that produced the AI-AGENT-* lattice findings. When a permission set carries
// no tags for a tool — an MCP config that lists names only, an older inventory —
// the name is classified with the same coarse vocabulary ai.classifyToolName
// uses. That function is unexported, so it is mirrored here rather than a
// second, divergent taxonomy being invented; the token list is deliberately a
// little broader so this agrees with plan.go's toolCapabilities and the graph
// never contradicts the hypotheses built beside it.
func capabilityTags(name string, recorded []string) []ai.CapabilityTag {
	if len(recorded) > 0 {
		tags := make([]ai.CapabilityTag, 0, len(recorded))
		for _, r := range recorded {
			if r != "" {
				tags = append(tags, ai.CapabilityTag(r))
			}
		}
		sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })
		return tags
	}
	low := strings.ToLower(name)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(low, s) {
				return true
			}
		}
		return false
	}
	var tags []ai.CapabilityTag
	if has("shell", "exec", "run_command", "runcommand", "subprocess", "bash", "system_call") {
		tags = append(tags, ai.CapShellExec)
	}
	switch {
	case has("read_file", "readfile", "fs_read", "fsread", "file_read", "fileread", "open_file", "openfile", "cat_file", "list_files", "listfiles", "ls_dir", "lsdir"):
		tags = append(tags, ai.CapFileRead)
	case has("write_file", "writefile", "fs_write", "fswrite", "file_write", "filewrite", "save_file", "savefile", "append_file", "delete_file", "rm_file"):
		tags = append(tags, ai.CapFileWrite)
	}
	switch {
	case has("webhook", "slack_send", "discord_send", "notify_webhook"):
		tags = append(tags, ai.CapWebhookPost)
	case has("email", "smtp"):
		tags = append(tags, ai.CapEmailSend)
	case has("http", "fetch", "url", "web_request", "scrape"):
		tags = append(tags, ai.CapHTTPRequest)
	}
	switch {
	case has("db_read", "dbread", "sql_query", "sqlquery", "select_query"):
		tags = append(tags, ai.CapDatabaseRead)
	case has("db_write", "dbwrite", "sql_insert", "sql_update", "sql_delete", "exec_sql", "execsql"):
		tags = append(tags, ai.CapDatabaseWrite)
	}
	switch {
	case has("git_push", "gitpush", "push_repo", "pushrepo"):
		tags = append(tags, ai.CapGitPush)
	case has("read_secret", "readsecret", "get_secret", "getsecret", "vault_read", "vaultread", "secrets_get"):
		tags = append(tags, ai.CapReadSecret)
	}
	switch {
	case has("iam_attach", "iam_create_policy", "iam_put_policy", "create_role", "attach_role_policy"):
		tags = append(tags, ai.CapCloudIAMModify)
	case has("stripe_charge", "create_charge", "payment_create", "init_payment", "charge_card"):
		tags = append(tags, ai.CapPaymentInitiate)
	case has("human_approval", "request_approval", "ask_human", "wait_human"):
		tags = append(tags, ai.CapHumanApproval)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })
	return tags
}

// -----------------------------------------------------------------------------
// Traversal
// -----------------------------------------------------------------------------

// nodeIndex maps node ID to node. It is rebuilt on each call rather than cached
// so a graph that arrived by JSON round-trip behaves identically to one just
// built.
func (g *AttackGraph) nodeIndex() map[string]AttackNode {
	idx := make(map[string]AttackNode, len(g.Nodes))
	for _, n := range g.Nodes {
		idx[n.ID] = n
	}
	return idx
}

// adjacency returns outgoing edges per node, in the graph's sorted edge order.
func (g *AttackGraph) adjacency() map[string][]AttackEdge {
	out := make(map[string][]AttackEdge, len(g.Nodes))
	for _, e := range g.Edges {
		out[e.From] = append(out[e.From], e)
	}
	return out
}

// isTerminal reports whether a path that ends here is worth reporting.
func isTerminal(n AttackNode) bool { return n.Sensitive || n.Privileged }

// Paths returns attack paths from any entry point to any sensitive asset or
// privileged capability, bounded by maxDepth. A maxDepth of zero or less uses
// DefaultMaxPathDepth. Enumeration is also capped at MaxEnumeratedPaths; when
// either bound bites, g.Truncation says so.
func (g *AttackGraph) Paths(maxDepth int) []AttackPath {
	idx := g.nodeIndex()
	return g.enumerate(maxDepth, func(id string) bool { return isTerminal(idx[id]) })
}

// PathsTo returns paths that terminate at a specific node, bounded by maxDepth.
// The same truncation reporting applies.
func (g *AttackGraph) PathsTo(targetID string, maxDepth int) []AttackPath {
	return g.enumerate(maxDepth, func(id string) bool { return id == targetID })
}

// enumerate walks every simple path from every entry point, recording those whose
// current node satisfies keep.
//
// Paths are simple — a node never repeats within one path — which is what makes
// termination unconditional on real agent topologies, where mutual delegation
// (A delegates to B, B delegates back to A) is common and a naive walk would
// loop forever. It also means a genuine there-and-back-again route is not
// reported; that is the deliberate trade, and the alternative (bounded repeats)
// buys combinatorial blowup for paths no operator would act on.
func (g *AttackGraph) enumerate(maxDepth int, keep func(nodeID string) bool) []AttackPath {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxPathDepth
	}
	g.Truncation = nil
	idx := g.nodeIndex()
	adj := g.adjacency()

	var results []AttackPath
	depthCapped, pathCapped := false, false

	nodePath := make([]string, 0, maxDepth+1)
	edgePath := make([]string, 0, maxDepth)
	onPath := map[string]bool{}

	var walk func(cur string, depth int)
	walk = func(cur string, depth int) {
		if pathCapped {
			return
		}
		if len(nodePath) > 1 && keep(cur) {
			results = append(results, newAttackPath(idx, nodePath, edgePath))
			if len(results) >= MaxEnumeratedPaths {
				pathCapped = true
				return
			}
		}
		if depth >= maxDepth {
			for _, e := range adj[cur] {
				if traversable(e.Kind) && !onPath[e.To] {
					depthCapped = true
					break
				}
			}
			return
		}
		for _, e := range adj[cur] {
			if !traversable(e.Kind) || onPath[e.To] {
				continue
			}
			onPath[e.To] = true
			nodePath = append(nodePath, e.To)
			edgePath = append(edgePath, e.ID)
			walk(e.To, depth+1)
			nodePath = nodePath[:len(nodePath)-1]
			edgePath = edgePath[:len(edgePath)-1]
			delete(onPath, e.To)
			if pathCapped {
				return
			}
		}
	}

	// g.Nodes is sorted by ID, so entry points are visited in a fixed order and
	// the result slice is deterministic without a post-sort.
	for _, n := range g.Nodes {
		if n.Kind != NodeEntryPoint {
			continue
		}
		nodePath = append(nodePath[:0], n.ID)
		edgePath = edgePath[:0]
		onPath = map[string]bool{n.ID: true}
		walk(n.ID, 0)
		if pathCapped {
			break
		}
	}

	if depthCapped || pathCapped {
		g.Truncation = &PathTruncation{
			DepthLimit:  maxDepth,
			PathLimit:   MaxEnumeratedPaths,
			DepthCapped: depthCapped,
			PathCapped:  pathCapped,
			Reason:      truncationReason(depthCapped, pathCapped, maxDepth),
		}
	}
	return results
}

// truncationReason spells out what was left out, so a reader is never told a
// capped enumeration was complete.
func truncationReason(depthCapped, pathCapped bool, maxDepth int) string {
	switch {
	case depthCapped && pathCapped:
		return fmt.Sprintf("enumeration stopped at %d paths and at least one branch was abandoned at %d hops; this result is a subset of the reachable paths",
			MaxEnumeratedPaths, maxDepth)
	case pathCapped:
		return fmt.Sprintf("enumeration stopped at the %d-path budget; further paths exist and were not enumerated", MaxEnumeratedPaths)
	default:
		return fmt.Sprintf("at least one branch was abandoned at the %d-hop depth limit; longer paths were not explored", maxDepth)
	}
}

// newAttackPath snapshots the current walk into an AttackPath.
func newAttackPath(idx map[string]AttackNode, nodePath, edgePath []string) AttackPath {
	nodes := append([]string(nil), nodePath...)
	edges := append([]string(nil), edgePath...)
	steps := make([]PathStep, 0, len(nodes))
	for _, id := range nodes {
		n := idx[id]
		steps = append(steps, PathStep{Kind: stepKind(n.Kind), ID: n.ID, Label: n.Label})
	}
	return AttackPath{
		ID:         "path-" + shortID(edges...),
		EntryID:    nodes[0],
		TerminalID: nodes[len(nodes)-1],
		Nodes:      nodes,
		Edges:      edges,
		Steps:      steps,
	}
}

// stepKind projects an attack-graph node kind onto the plan's PathStep
// vocabulary. The PathStep vocabulary is coarser, so identities, boundaries and
// stores all render as "asset"; the node ID in the step keeps the precise
// identity recoverable from the graph.
func stepKind(k NodeKind) string {
	switch k {
	case NodeEntryPoint:
		return StepEntryPoint
	case NodeModel:
		return StepModel
	case NodeAgent:
		return StepAgent
	case NodeMCPServer:
		return StepMCPServer
	case NodeTool:
		return StepTool
	case NodeNetworkSink:
		return StepSink
	default:
		return StepAsset
	}
}

// CutEdges returns the edges whose removal breaks the most attack paths — the
// smallest intervention that reduces reachability. Results are sorted by how
// many paths each edge carries, so the head of the slice is the highest-value
// cut. Edges no supplied path traverses are not returned: cutting them would
// change nothing.
func (g *AttackGraph) CutEdges(paths []AttackPath) []CutEdge {
	counts := map[string]int{}
	for _, p := range paths {
		// One path may traverse the same edge only once (paths are simple), so a
		// plain increment counts paths, not traversals.
		for _, id := range p.Edges {
			counts[id]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	idx := g.nodeIndex()
	out := make([]CutEdge, 0, len(counts))
	for _, e := range g.Edges {
		n, ok := counts[e.ID]
		if !ok {
			continue
		}
		out = append(out, CutEdge{
			EdgeID:      e.ID,
			From:        e.From,
			To:          e.To,
			Kind:        e.Kind,
			PathsBroken: n,
			Action:      cutAction(idx, e),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PathsBroken != out[j].PathsBroken {
			return out[i].PathsBroken > out[j].PathsBroken
		}
		return out[i].EdgeID < out[j].EdgeID
	})
	return out
}

// cutAction renders a concrete operator instruction for removing an edge.
func cutAction(idx map[string]AttackNode, e AttackEdge) string {
	from, to := idx[e.From], idx[e.To]
	fromLabel, toLabel := from.Label, to.Label
	if fromLabel == "" {
		fromLabel = e.From
	}
	if toLabel == "" {
		toLabel = e.To
	}
	switch e.Kind {
	case EdgeInvokes:
		if to.Kind == NodeTool {
			if caps := strings.Join(to.Capabilities, ", "); caps != "" {
				return fmt.Sprintf("revoke %s's %s grant (tool %q)", fromLabel, caps, toLabel)
			}
			return fmt.Sprintf("revoke %s's grant on tool %q", fromLabel, toLabel)
		}
		return fmt.Sprintf("stop %s from performing %s", fromLabel, toLabel)
	case EdgeDelegates:
		return fmt.Sprintf("remove the delegation from %s to %s", fromLabel, toLabel)
	case EdgeTrusts:
		return fmt.Sprintf("stop %s treating %s output as trusted", fromLabel, toLabel)
	case EdgeReaches:
		return fmt.Sprintf("remove %s's access to %s", fromLabel, toLabel)
	case EdgeDataFlow:
		return fmt.Sprintf("stop %s flowing into %s", fromLabel, toLabel)
	case EdgeAuthorizes:
		return fmt.Sprintf("revoke the authorization %s holds over %s", fromLabel, toLabel)
	default:
		return fmt.Sprintf("remove the %s relationship from %s to %s", e.Kind, fromLabel, toLabel)
	}
}

// RemoveEdge returns a copy of the graph without the named edge. It exists so a
// caller can verify a CutEdge claim by re-running Paths rather than trusting the
// count.
func (g *AttackGraph) RemoveEdge(id string) *AttackGraph {
	cp := &AttackGraph{
		SchemaVersion: g.SchemaVersion,
		Nodes:         append([]AttackNode(nil), g.Nodes...),
		Edges:         make([]AttackEdge, 0, len(g.Edges)),
		Notes:         append([]string(nil), g.Notes...),
	}
	for _, e := range g.Edges {
		if e.ID == id {
			continue
		}
		cp.Edges = append(cp.Edges, e)
	}
	return cp
}

// -----------------------------------------------------------------------------
// Interop and validation
// -----------------------------------------------------------------------------

// ToGraph projects the attack graph onto nox's generic graph domain type. The
// projection is lossless for structure: attack node and edge kinds are carried
// through as-is, since graph.NodeKind and graph.EdgeKind are open string types.
func (g *AttackGraph) ToGraph() *graph.Graph {
	out := &graph.Graph{
		Name:        "attack-graph",
		Description: "attack-oriented model of the scanned system",
		Nodes:       make([]graph.Node, 0, len(g.Nodes)),
		Edges:       make([]graph.Edge, 0, len(g.Edges)),
	}
	for _, n := range g.Nodes {
		out.Nodes = append(out.Nodes, graph.Node{
			ID: n.ID, Kind: graph.NodeKind(n.Kind), Label: n.Label,
			FilePath: n.FilePath, Properties: n.Attributes,
		})
	}
	for _, e := range g.Edges {
		out.Edges = append(out.Edges, graph.Edge{
			Source: e.From, Target: e.To, Kind: graph.EdgeKind(e.Kind), Label: e.Label,
		})
	}
	return out
}

// Validate reports structural problems. Endpoint and ID checks are delegated to
// core/graph rather than reimplemented; the grounding check is attack-specific,
// because an ungrounded node is the one defect that makes this graph actively
// misleading rather than merely incomplete.
func (g *AttackGraph) Validate() []string {
	errs := g.ToGraph().Validate()
	for _, n := range g.Nodes {
		if len(n.Evidence) == 0 {
			errs = append(errs, fmt.Sprintf("node %q has no grounding evidence", n.ID))
		}
	}
	for _, e := range g.Edges {
		if len(e.Evidence) == 0 {
			errs = append(errs, fmt.Sprintf("edge %q has no grounding evidence", e.ID))
		}
	}
	return errs
}

// -----------------------------------------------------------------------------
// Plan integration
// -----------------------------------------------------------------------------

// attachGraphPaths rewrites each hypothesis path to a real walk over g where one
// exists. Where the graph has no end-to-end route, the hypothesis keeps the
// scenario's generic shape and its rationale says so — a synthesized path
// presented as an observed one would be the exact fabrication this graph exists
// to prevent.
//
// It also records the cut edges for the enumerated path set, so the plan carries
// the intervention that shrinks reachability rather than only the attacks.
func attachGraphPaths(g *AttackGraph, hyps []Hypothesis) {
	if g == nil {
		return
	}
	// One enumeration, filtered in memory: calling PathsTo per hypothesis would
	// overwrite g.Truncation with the bounds of whichever call ran last.
	paths := g.Paths(0)
	g.Cuts = g.CutEdges(paths)

	idx := g.nodeIndex()
	seeds := map[string]string{} // shortID(label, path) -> principal node ID
	for _, n := range g.Nodes {
		if n.Kind != NodeAgent && n.Kind != NodeMCPServer {
			continue
		}
		if p := n.Attributes["path"]; p != "" {
			seeds[shortID(n.Label, p)] = n.ID
		}
	}

	for i := range hyps {
		h := &hyps[i]
		var match *AttackPath
		switch h.ScenarioID {
		case ScenarioPIDirect, ScenarioPIIndirect:
			match = bestPath(paths, func(p AttackPath) bool {
				return p.TerminalID == "asset:system-prompt" &&
					entryGroundedIn(idx, p.EntryID, h.FindingFingerprints)
			})
		case ScenarioToolUnauth:
			agentID := seeds[hypothesisSeed(h.ID)]
			match = bestPath(paths, func(p AttackPath) bool {
				return agentID != "" && pathContains(p, agentID) && idx[p.TerminalID].Privileged &&
					idx[p.TerminalID].Kind != NodeNetworkSink
			})
		case ScenarioExfilFSNet:
			agentID := seeds[hypothesisSeed(h.ID)]
			match = bestPath(paths, func(p AttackPath) bool {
				return agentID != "" && pathContains(p, agentID) && idx[p.TerminalID].Kind == NodeNetworkSink
			})
		}
		if match == nil {
			h.Rationale += " No end-to-end path for this hypothesis exists in the scan's attack graph, so the path below is the scenario's generic shape, not an observed route."
			continue
		}
		h.Path = match.Steps
		h.Rationale += fmt.Sprintf(" The path below is a real route in the scan's attack graph (%s, %d hops).", match.ID, len(match.Edges))
	}
}

// hypothesisSeed extracts the trailing shortID from a hypothesis identifier of
// the form "hyp-<scenario>-<seed>".
func hypothesisSeed(id string) string {
	if i := strings.LastIndex(id, "-"); i >= 0 {
		return id[i+1:]
	}
	return ""
}

// entryGroundedIn reports whether the entry node cites one of the fingerprints.
func entryGroundedIn(idx map[string]AttackNode, entryID string, fingerprints []string) bool {
	n, ok := idx[entryID]
	if !ok {
		return false
	}
	for _, ev := range n.Evidence {
		if ev.Kind != EvidenceKindFinding {
			continue
		}
		for _, fp := range fingerprints {
			if ev.Ref == fp {
				return true
			}
		}
	}
	return false
}

func pathContains(p AttackPath, nodeID string) bool {
	for _, id := range p.Nodes {
		if id == nodeID {
			return true
		}
	}
	return false
}

// bestPath returns the shortest matching path, breaking ties on ID so the choice
// is deterministic.
func bestPath(paths []AttackPath, match func(AttackPath) bool) *AttackPath {
	var best *AttackPath
	for i := range paths {
		p := paths[i]
		if !match(p) {
			continue
		}
		if best == nil || len(p.Edges) < len(best.Edges) ||
			(len(p.Edges) == len(best.Edges) && p.ID < best.ID) {
			cp := p
			best = &cp
		}
	}
	return best
}

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------

// mergeEvidence unions two evidence lists, deduplicated and sorted.
func mergeEvidence(a, b []NodeEvidence) []NodeEvidence {
	seen := map[NodeEvidence]bool{}
	out := make([]NodeEvidence, 0, len(a)+len(b))
	for _, e := range append(append([]NodeEvidence(nil), a...), b...) {
		if seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Ref != out[j].Ref {
			return out[i].Ref < out[j].Ref
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

// mergeStrings unions two string slices, deduplicated and sorted.
func mergeStrings(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string(nil), a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func appendUnique(dst []string, s string) []string {
	for _, ex := range dst {
		if ex == s {
			return dst
		}
	}
	return append(dst, s)
}
