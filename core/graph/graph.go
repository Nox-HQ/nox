// Package graph provides domain types for representing relationship graphs
// emitted by plugins. Graphs model cross-resource dependencies, data flows,
// call chains, and other structural relationships discovered during analysis.
package graph

import "fmt"

// NodeKind classifies graph nodes.
type NodeKind string

// NodeKind constants for classifying graph vertices.
const (
	NodeKindUnspecified NodeKind = ""
	NodeKindResource    NodeKind = "resource"
	NodeKindFunction    NodeKind = "function"
	NodeKindData        NodeKind = "data"
	NodeKindService     NodeKind = "service"
	NodeKindPolicy      NodeKind = "policy"
)

// EdgeKind classifies graph edges.
type EdgeKind string

// EdgeKind constants for classifying graph relationships.
const (
	EdgeKindUnspecified EdgeKind = ""
	EdgeKindDependsOn   EdgeKind = "depends_on"
	EdgeKindCalls       EdgeKind = "calls"
	EdgeKindFlowsTo     EdgeKind = "flows_to"
	EdgeKindExposes     EdgeKind = "exposes"
	EdgeKindReferences  EdgeKind = "references"
)

// Node represents a vertex in a relationship graph.
type Node struct {
	ID         string
	Kind       NodeKind
	Label      string
	FilePath   string
	Properties map[string]string
}

// Edge represents a directed edge between two graph nodes.
type Edge struct {
	Source     string // source node ID
	Target     string // target node ID
	Kind       EdgeKind
	Label      string
	Properties map[string]string
}

// Graph is a labeled collection of nodes and edges.
type Graph struct {
	Name        string
	Description string
	Nodes       []Node
	Edges       []Edge
}

// NodeIDs returns a set of all node IDs in the graph.
func (g *Graph) NodeIDs() map[string]bool {
	ids := make(map[string]bool, len(g.Nodes))
	for _, n := range g.Nodes {
		ids[n.ID] = true
	}
	return ids
}

// Validate checks structural invariants: all edge endpoints must reference
// existing nodes, and all nodes must have non-empty IDs.
func (g *Graph) Validate() []string {
	var errs []string
	ids := g.NodeIDs()
	for i, n := range g.Nodes {
		if n.ID == "" {
			errs = append(errs, fmt.Sprintf("node[%d]: id must not be empty", i))
		}
	}
	for i, e := range g.Edges {
		if !ids[e.Source] {
			errs = append(errs, fmt.Sprintf("edge[%d]: source %q not in nodes", i, e.Source))
		}
		if !ids[e.Target] {
			errs = append(errs, fmt.Sprintf("edge[%d]: target %q not in nodes", i, e.Target))
		}
	}
	return errs
}
