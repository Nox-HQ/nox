package graph

import (
	"testing"
)

func TestGraph_NodeIDs(t *testing.T) {
	g := Graph{
		Name: "test",
		Nodes: []Node{
			{ID: "a", Kind: NodeKindResource, Label: "VPC"},
			{ID: "b", Kind: NodeKindService, Label: "API"},
		},
	}

	ids := g.NodeIDs()
	if len(ids) != 2 {
		t.Fatalf("expected 2 IDs, got %d", len(ids))
	}
	if !ids["a"] || !ids["b"] {
		t.Errorf("expected ids a and b, got %v", ids)
	}
}

func TestGraph_Validate_Valid(t *testing.T) {
	g := Graph{
		Name: "deps",
		Nodes: []Node{
			{ID: "n1", Kind: NodeKindResource, Label: "S3"},
			{ID: "n2", Kind: NodeKindResource, Label: "Lambda"},
		},
		Edges: []Edge{
			{Source: "n1", Target: "n2", Kind: EdgeKindDependsOn},
		},
	}

	errs := g.Validate()
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestGraph_Validate_MissingNodeID(t *testing.T) {
	g := Graph{
		Name: "bad",
		Nodes: []Node{
			{ID: "", Kind: NodeKindResource, Label: "noID"},
		},
	}

	errs := g.Validate()
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
}

func TestGraph_Validate_DanglingEdge(t *testing.T) {
	g := Graph{
		Name: "dangling",
		Nodes: []Node{
			{ID: "n1", Kind: NodeKindFunction, Label: "main"},
		},
		Edges: []Edge{
			{Source: "n1", Target: "n2", Kind: EdgeKindCalls},
		},
	}

	errs := g.Validate()
	if len(errs) != 1 {
		t.Fatalf("expected 1 error for dangling target, got %d: %v", len(errs), errs)
	}
}

func TestNodeKind_Constants(t *testing.T) {
	kinds := []NodeKind{
		NodeKindUnspecified,
		NodeKindResource,
		NodeKindFunction,
		NodeKindData,
		NodeKindService,
		NodeKindPolicy,
	}
	seen := make(map[NodeKind]bool)
	for _, k := range kinds {
		if seen[k] && k != NodeKindUnspecified {
			t.Errorf("duplicate NodeKind: %q", k)
		}
		seen[k] = true
	}
}

func TestEdgeKind_Constants(t *testing.T) {
	kinds := []EdgeKind{
		EdgeKindUnspecified,
		EdgeKindDependsOn,
		EdgeKindCalls,
		EdgeKindFlowsTo,
		EdgeKindExposes,
		EdgeKindReferences,
	}
	seen := make(map[EdgeKind]bool)
	for _, k := range kinds {
		if seen[k] && k != EdgeKindUnspecified {
			t.Errorf("duplicate EdgeKind: %q", k)
		}
		seen[k] = true
	}
}

func TestNode_Properties(t *testing.T) {
	n := Node{
		ID:         "n1",
		Kind:       NodeKindResource,
		Label:      "test",
		FilePath:   "main.tf",
		Properties: map[string]string{"type": "aws_s3_bucket"},
	}
	if n.Properties["type"] != "aws_s3_bucket" {
		t.Errorf("expected property type=aws_s3_bucket, got %q", n.Properties["type"])
	}
}

func TestEdge_Properties(t *testing.T) {
	e := Edge{
		Source:     "a",
		Target:     "b",
		Kind:       EdgeKindFlowsTo,
		Label:      "user-data",
		Properties: map[string]string{"sensitivity": "high"},
	}
	if e.Properties["sensitivity"] != "high" {
		t.Errorf("expected property sensitivity=high, got %q", e.Properties["sensitivity"])
	}
}
