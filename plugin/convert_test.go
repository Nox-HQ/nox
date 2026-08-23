package plugin

import (
	"reflect"
	"testing"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/graph"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

func TestProtoSeverityToGo(t *testing.T) {
	tests := []struct {
		proto pluginv1.Severity
		want  findings.Severity
	}{
		{pluginv1.Severity_SEVERITY_CRITICAL, findings.SeverityCritical},
		{pluginv1.Severity_SEVERITY_HIGH, findings.SeverityHigh},
		{pluginv1.Severity_SEVERITY_MEDIUM, findings.SeverityMedium},
		{pluginv1.Severity_SEVERITY_LOW, findings.SeverityLow},
		{pluginv1.Severity_SEVERITY_INFO, findings.SeverityInfo},
		{pluginv1.Severity_SEVERITY_UNSPECIFIED, findings.SeverityInfo},
	}
	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			got := ProtoSeverityToGo(tt.proto)
			if got != tt.want {
				t.Errorf("ProtoSeverityToGo(%v) = %q, want %q", tt.proto, got, tt.want)
			}
		})
	}
}

func TestGoSeverityToProto(t *testing.T) {
	tests := []struct {
		goSev findings.Severity
		want  pluginv1.Severity
	}{
		{findings.SeverityCritical, pluginv1.Severity_SEVERITY_CRITICAL},
		{findings.SeverityHigh, pluginv1.Severity_SEVERITY_HIGH},
		{findings.SeverityMedium, pluginv1.Severity_SEVERITY_MEDIUM},
		{findings.SeverityLow, pluginv1.Severity_SEVERITY_LOW},
		{findings.SeverityInfo, pluginv1.Severity_SEVERITY_INFO},
		{findings.Severity("unknown"), pluginv1.Severity_SEVERITY_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(string(tt.goSev), func(t *testing.T) {
			got := GoSeverityToProto(tt.goSev)
			if got != tt.want {
				t.Errorf("GoSeverityToProto(%q) = %v, want %v", tt.goSev, got, tt.want)
			}
		})
	}
}

func TestProtoConfidenceToGo(t *testing.T) {
	tests := []struct {
		proto pluginv1.Confidence
		want  findings.Confidence
	}{
		{pluginv1.Confidence_CONFIDENCE_HIGH, findings.ConfidenceHigh},
		{pluginv1.Confidence_CONFIDENCE_MEDIUM, findings.ConfidenceMedium},
		{pluginv1.Confidence_CONFIDENCE_LOW, findings.ConfidenceLow},
		{pluginv1.Confidence_CONFIDENCE_UNSPECIFIED, findings.ConfidenceLow},
	}
	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			got := ProtoConfidenceToGo(tt.proto)
			if got != tt.want {
				t.Errorf("ProtoConfidenceToGo(%v) = %q, want %q", tt.proto, got, tt.want)
			}
		})
	}
}

func TestGoConfidenceToProto(t *testing.T) {
	tests := []struct {
		goVal findings.Confidence
		want  pluginv1.Confidence
	}{
		{findings.ConfidenceHigh, pluginv1.Confidence_CONFIDENCE_HIGH},
		{findings.ConfidenceMedium, pluginv1.Confidence_CONFIDENCE_MEDIUM},
		{findings.ConfidenceLow, pluginv1.Confidence_CONFIDENCE_LOW},
		{findings.Confidence("unknown"), pluginv1.Confidence_CONFIDENCE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(string(tt.goVal), func(t *testing.T) {
			got := GoConfidenceToProto(tt.goVal)
			if got != tt.want {
				t.Errorf("GoConfidenceToProto(%q) = %v, want %v", tt.goVal, got, tt.want)
			}
		})
	}
}

func TestProtoLocationToGo_Nil(t *testing.T) {
	got := ProtoLocationToGo(nil)
	want := findings.Location{}
	if got != want {
		t.Errorf("ProtoLocationToGo(nil) = %+v, want zero value", got)
	}
}

func TestLocationRoundTrip(t *testing.T) {
	original := findings.Location{
		FilePath:    "src/main.go",
		StartLine:   10,
		EndLine:     20,
		StartColumn: 5,
		EndColumn:   30,
	}
	proto := GoLocationToProto(original)
	roundTrip := ProtoLocationToGo(proto)

	if roundTrip != original {
		t.Errorf("Location round-trip failed:\n  original:  %+v\n  roundTrip: %+v", original, roundTrip)
	}
}

func TestFindingRoundTrip(t *testing.T) {
	original := findings.Finding{
		ID:         "finding-1",
		RuleID:     "SEC-001",
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location: findings.Location{
			FilePath:    "src/auth.go",
			StartLine:   42,
			EndLine:     42,
			StartColumn: 10,
			EndColumn:   50,
		},
		Message:     "Hardcoded secret detected",
		Fingerprint: "abc123",
		Metadata:    map[string]string{"cwe": "CWE-798", "source": "secrets-analyzer"},
	}

	proto := GoFindingToProto(&original)
	roundTrip := ProtoFindingToGo(proto, "test-plugin", "")

	if roundTrip.ID != original.ID {
		t.Errorf("ID mismatch: %q vs %q", roundTrip.ID, original.ID)
	}
	if roundTrip.RuleID != original.RuleID {
		t.Errorf("RuleID mismatch: %q vs %q", roundTrip.RuleID, original.RuleID)
	}
	if roundTrip.Severity != original.Severity {
		t.Errorf("Severity mismatch: %q vs %q", roundTrip.Severity, original.Severity)
	}
	if roundTrip.Confidence != original.Confidence {
		t.Errorf("Confidence mismatch: %q vs %q", roundTrip.Confidence, original.Confidence)
	}
	if roundTrip.Location != original.Location {
		t.Errorf("Location mismatch: %+v vs %+v", roundTrip.Location, original.Location)
	}
	if roundTrip.Message != original.Message {
		t.Errorf("Message mismatch: %q vs %q", roundTrip.Message, original.Message)
	}
	// Fingerprint is deliberately NOT round-tripped. Non-preservation is the
	// security property: a fingerprint arriving from a plugin is recomputed
	// host-side and namespaced, so a plugin cannot collide with a core finding
	// and suppress it via dedup, or match a baselined finding to hide itself.
	if roundTrip.Fingerprint == original.Fingerprint {
		t.Error("Fingerprint was preserved verbatim; it must be recomputed host-side")
	}
	if roundTrip.Fingerprint == "" {
		t.Error("Fingerprint should be recomputed, not blanked")
	}
	if !reflect.DeepEqual(roundTrip.Metadata, original.Metadata) {
		t.Errorf("Metadata mismatch: %v vs %v", roundTrip.Metadata, original.Metadata)
	}
}

func TestProtoFindingToGo_Nil(t *testing.T) {
	got := ProtoFindingToGo(nil, "test-plugin", "")
	if got.ID != "" || got.RuleID != "" {
		t.Errorf("ProtoFindingToGo(nil) should return zero value, got %+v", got)
	}
}

func TestFindingRoundTrip_EmptyMetadata(t *testing.T) {
	original := findings.Finding{
		ID:       "finding-2",
		RuleID:   "SEC-002",
		Severity: findings.SeverityLow,
	}

	proto := GoFindingToProto(&original)
	roundTrip := ProtoFindingToGo(proto, "test-plugin", "")

	if roundTrip.ID != original.ID {
		t.Errorf("ID mismatch: %q vs %q", roundTrip.ID, original.ID)
	}
	if roundTrip.Metadata != nil {
		t.Errorf("empty metadata should remain nil, got %v", roundTrip.Metadata)
	}
}

func TestPackageRoundTrip(t *testing.T) {
	original := deps.Package{
		Name:      "express",
		Version:   "4.18.2",
		Ecosystem: "npm",
	}

	proto := GoPackageToProto(original)
	roundTrip := ProtoPackageToGo(proto)

	if roundTrip != original {
		t.Errorf("Package round-trip failed:\n  original:  %+v\n  roundTrip: %+v", original, roundTrip)
	}
}

func TestProtoPackageToGo_Nil(t *testing.T) {
	got := ProtoPackageToGo(nil)
	if got != (deps.Package{}) {
		t.Errorf("ProtoPackageToGo(nil) should return zero value, got %+v", got)
	}
}

func TestAIComponentRoundTrip(t *testing.T) {
	original := ai.Component{
		Name:    "summarizer",
		Type:    "agent",
		Path:    "agents/summarizer.yaml",
		Details: map[string]string{"model": "gpt-4", "framework": "langchain"},
	}

	proto := GoAIComponentToProto(original)
	roundTrip := ProtoAIComponentToGo(proto)

	if roundTrip.Name != original.Name {
		t.Errorf("Name mismatch: %q vs %q", roundTrip.Name, original.Name)
	}
	if roundTrip.Type != original.Type {
		t.Errorf("Type mismatch: %q vs %q", roundTrip.Type, original.Type)
	}
	if roundTrip.Path != original.Path {
		t.Errorf("Path mismatch: %q vs %q", roundTrip.Path, original.Path)
	}
	if !reflect.DeepEqual(roundTrip.Details, original.Details) {
		t.Errorf("Details mismatch: %v vs %v", roundTrip.Details, original.Details)
	}
}

func TestAIComponentRoundTrip_NilDetails(t *testing.T) {
	original := ai.Component{
		Name: "simple",
		Type: "prompt",
		Path: "prompts/simple.txt",
	}

	proto := GoAIComponentToProto(original)
	roundTrip := ProtoAIComponentToGo(proto)

	if roundTrip.Name != original.Name {
		t.Errorf("Name mismatch: %q vs %q", roundTrip.Name, original.Name)
	}
	if roundTrip.Details != nil {
		t.Errorf("nil details should remain nil, got %v", roundTrip.Details)
	}
}

func TestProtoAIComponentToGo_Nil(t *testing.T) {
	got := ProtoAIComponentToGo(nil)
	if got.Name != "" || got.Type != "" || got.Path != "" || got.Details != nil {
		t.Errorf("ProtoAIComponentToGo(nil) should return zero value, got %+v", got)
	}
}

// --- Graph conversion tests ---

func TestNodeKindRoundTrip(t *testing.T) {
	tests := []struct {
		proto pluginv1.NodeKind
		want  graph.NodeKind
	}{
		{pluginv1.NodeKind_NODE_KIND_RESOURCE, graph.NodeKindResource},
		{pluginv1.NodeKind_NODE_KIND_FUNCTION, graph.NodeKindFunction},
		{pluginv1.NodeKind_NODE_KIND_DATA, graph.NodeKindData},
		{pluginv1.NodeKind_NODE_KIND_SERVICE, graph.NodeKindService},
		{pluginv1.NodeKind_NODE_KIND_POLICY, graph.NodeKindPolicy},
		{pluginv1.NodeKind_NODE_KIND_UNSPECIFIED, graph.NodeKindUnspecified},
	}
	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			goVal := ProtoNodeKindToGo(tt.proto)
			if goVal != tt.want {
				t.Errorf("ProtoNodeKindToGo(%v) = %q, want %q", tt.proto, goVal, tt.want)
			}
			roundTrip := GoNodeKindToProto(goVal)
			if roundTrip != tt.proto {
				t.Errorf("GoNodeKindToProto(%q) = %v, want %v", goVal, roundTrip, tt.proto)
			}
		})
	}
}

func TestEdgeKindRoundTrip(t *testing.T) {
	tests := []struct {
		proto pluginv1.EdgeKind
		want  graph.EdgeKind
	}{
		{pluginv1.EdgeKind_EDGE_KIND_DEPENDS_ON, graph.EdgeKindDependsOn},
		{pluginv1.EdgeKind_EDGE_KIND_CALLS, graph.EdgeKindCalls},
		{pluginv1.EdgeKind_EDGE_KIND_FLOWS_TO, graph.EdgeKindFlowsTo},
		{pluginv1.EdgeKind_EDGE_KIND_EXPOSES, graph.EdgeKindExposes},
		{pluginv1.EdgeKind_EDGE_KIND_REFERENCES, graph.EdgeKindReferences},
		{pluginv1.EdgeKind_EDGE_KIND_UNSPECIFIED, graph.EdgeKindUnspecified},
	}
	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			goVal := ProtoEdgeKindToGo(tt.proto)
			if goVal != tt.want {
				t.Errorf("ProtoEdgeKindToGo(%v) = %q, want %q", tt.proto, goVal, tt.want)
			}
			roundTrip := GoEdgeKindToProto(goVal)
			if roundTrip != tt.proto {
				t.Errorf("GoEdgeKindToProto(%q) = %v, want %v", goVal, roundTrip, tt.proto)
			}
		})
	}
}

func TestGraphRoundTrip(t *testing.T) {
	original := graph.Graph{
		Name:        "resource-deps",
		Description: "IaC resource dependency graph",
		Nodes: []graph.Node{
			{
				ID:         "vpc-1",
				Kind:       graph.NodeKindResource,
				Label:      "aws_vpc.main",
				FilePath:   "main.tf",
				Properties: map[string]string{"provider": "aws"},
			},
			{
				ID:       "subnet-1",
				Kind:     graph.NodeKindResource,
				Label:    "aws_subnet.public",
				FilePath: "network.tf",
			},
		},
		Edges: []graph.Edge{
			{
				Source:     "subnet-1",
				Target:     "vpc-1",
				Kind:       graph.EdgeKindDependsOn,
				Label:      "vpc_id",
				Properties: map[string]string{"field": "vpc_id"},
			},
		},
	}

	proto := GoGraphToProto(&original)
	roundTrip := ProtoGraphToGo(proto)

	if roundTrip.Name != original.Name {
		t.Errorf("Name: %q vs %q", roundTrip.Name, original.Name)
	}
	if roundTrip.Description != original.Description {
		t.Errorf("Description: %q vs %q", roundTrip.Description, original.Description)
	}
	if len(roundTrip.Nodes) != len(original.Nodes) {
		t.Fatalf("Nodes count: %d vs %d", len(roundTrip.Nodes), len(original.Nodes))
	}
	for i := range original.Nodes {
		if roundTrip.Nodes[i].ID != original.Nodes[i].ID {
			t.Errorf("Node[%d].ID: %q vs %q", i, roundTrip.Nodes[i].ID, original.Nodes[i].ID)
		}
		if roundTrip.Nodes[i].Kind != original.Nodes[i].Kind {
			t.Errorf("Node[%d].Kind: %q vs %q", i, roundTrip.Nodes[i].Kind, original.Nodes[i].Kind)
		}
		if roundTrip.Nodes[i].Label != original.Nodes[i].Label {
			t.Errorf("Node[%d].Label: %q vs %q", i, roundTrip.Nodes[i].Label, original.Nodes[i].Label)
		}
		if roundTrip.Nodes[i].FilePath != original.Nodes[i].FilePath {
			t.Errorf("Node[%d].FilePath: %q vs %q", i, roundTrip.Nodes[i].FilePath, original.Nodes[i].FilePath)
		}
		if !reflect.DeepEqual(roundTrip.Nodes[i].Properties, original.Nodes[i].Properties) {
			t.Errorf("Node[%d].Properties: %v vs %v", i, roundTrip.Nodes[i].Properties, original.Nodes[i].Properties)
		}
	}
	if len(roundTrip.Edges) != len(original.Edges) {
		t.Fatalf("Edges count: %d vs %d", len(roundTrip.Edges), len(original.Edges))
	}
	e := roundTrip.Edges[0]
	if e.Source != "subnet-1" || e.Target != "vpc-1" {
		t.Errorf("Edge: source=%q target=%q", e.Source, e.Target)
	}
	if e.Kind != graph.EdgeKindDependsOn {
		t.Errorf("Edge.Kind: %q", e.Kind)
	}
	if !reflect.DeepEqual(e.Properties, original.Edges[0].Properties) {
		t.Errorf("Edge.Properties: %v vs %v", e.Properties, original.Edges[0].Properties)
	}
}

func TestProtoGraphToGo_Nil(t *testing.T) {
	got := ProtoGraphToGo(nil)
	if got.Name != "" || len(got.Nodes) != 0 || len(got.Edges) != 0 {
		t.Errorf("ProtoGraphToGo(nil) should return zero value, got %+v", got)
	}
}

// --- Enrichment conversion tests ---

func TestEnrichmentRoundTrip(t *testing.T) {
	original := findings.Enrichment{
		FindingFingerprint: "fp-abc123",
		Kind:               "triage",
		Title:              "False positive",
		Body:               "This is a **false positive** because the key is a test key.",
		Metadata:           map[string]string{"reason": "test_file", "auto": "true"},
		Confidence:         findings.ConfidenceHigh,
		Source:             "ai-triage",
	}

	proto := GoEnrichmentToProto(&original)
	roundTrip := ProtoEnrichmentToGo(proto)

	if roundTrip.FindingFingerprint != original.FindingFingerprint {
		t.Errorf("FindingFingerprint: %q vs %q", roundTrip.FindingFingerprint, original.FindingFingerprint)
	}
	if roundTrip.Kind != original.Kind {
		t.Errorf("Kind: %q vs %q", roundTrip.Kind, original.Kind)
	}
	if roundTrip.Title != original.Title {
		t.Errorf("Title: %q vs %q", roundTrip.Title, original.Title)
	}
	if roundTrip.Body != original.Body {
		t.Errorf("Body: %q vs %q", roundTrip.Body, original.Body)
	}
	if !reflect.DeepEqual(roundTrip.Metadata, original.Metadata) {
		t.Errorf("Metadata: %v vs %v", roundTrip.Metadata, original.Metadata)
	}
	if roundTrip.Confidence != original.Confidence {
		t.Errorf("Confidence: %q vs %q", roundTrip.Confidence, original.Confidence)
	}
	if roundTrip.Source != original.Source {
		t.Errorf("Source: %q vs %q", roundTrip.Source, original.Source)
	}
}

func TestProtoEnrichmentToGo_Nil(t *testing.T) {
	got := ProtoEnrichmentToGo(nil)
	if got.FindingFingerprint != "" || got.Kind != "" || got.Metadata != nil {
		t.Errorf("ProtoEnrichmentToGo(nil) should return zero value, got %+v", got)
	}
}

func TestEnrichmentRoundTrip_EmptyMetadata(t *testing.T) {
	original := findings.Enrichment{
		FindingFingerprint: "fp-1",
		Kind:               "explanation",
		Source:             "explainer",
	}

	proto := GoEnrichmentToProto(&original)
	roundTrip := ProtoEnrichmentToGo(proto)

	if roundTrip.FindingFingerprint != original.FindingFingerprint {
		t.Errorf("FindingFingerprint: %q vs %q", roundTrip.FindingFingerprint, original.FindingFingerprint)
	}
	if roundTrip.Metadata != nil {
		t.Errorf("empty metadata should remain nil, got %v", roundTrip.Metadata)
	}
}

// --- ScanContext conversion tests ---

func TestGoScanResultToProtoContext(t *testing.T) {
	result := &core.ScanResult{
		Findings:    findings.NewFindingSet(),
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}
	result.Findings.Add(findings.Finding{
		ID:          "f-1",
		RuleID:      "SEC-001",
		Severity:    findings.SeverityHigh,
		Message:     "test",
		Fingerprint: "fp1",
	})
	result.Inventory.Add(deps.Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"})
	result.AIInventory.Add(ai.Component{Name: "gpt-4", Type: "model", Path: "config.yaml"})

	sc := GoScanResultToProtoContext(result)

	if len(sc.GetFindings()) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(sc.GetFindings()))
	}
	if sc.GetFindings()[0].GetRuleId() != "SEC-001" {
		t.Errorf("finding rule_id = %q", sc.GetFindings()[0].GetRuleId())
	}
	if len(sc.GetPackages()) != 1 {
		t.Fatalf("expected 1 package, got %d", len(sc.GetPackages()))
	}
	if sc.GetPackages()[0].GetName() != "lodash" {
		t.Errorf("package name = %q", sc.GetPackages()[0].GetName())
	}
	if len(sc.GetAiComponents()) != 1 {
		t.Fatalf("expected 1 AI component, got %d", len(sc.GetAiComponents()))
	}
	if sc.GetAiComponents()[0].GetName() != "gpt-4" {
		t.Errorf("AI component name = %q", sc.GetAiComponents()[0].GetName())
	}
}

func TestGoScanResultToProtoContext_Nil(t *testing.T) {
	sc := GoScanResultToProtoContext(nil)
	if sc != nil {
		t.Errorf("expected nil ScanContext for nil ScanResult, got %+v", sc)
	}
}

func TestGoGraphToProto_Nil(t *testing.T) {
	got := GoGraphToProto(nil)
	if got != nil {
		t.Errorf("GoGraphToProto(nil) should return nil, got %+v", got)
	}
}

func TestGoEnrichmentToProto_Nil(t *testing.T) {
	got := GoEnrichmentToProto(nil)
	if got != nil {
		t.Errorf("GoEnrichmentToProto(nil) should return nil, got %+v", got)
	}
}

// --- fingerprint trust boundary ---

// TestProtoFindingToGo_DoesNotTrustClaimedFingerprint pins the core property:
// whatever a plugin claims, the stored value is derived host-side.
func TestProtoFindingToGo_DoesNotTrustClaimedFingerprint(t *testing.T) {
	t.Parallel()

	claimed := "0000000000000000000000000000000000000000000000000000000000000000"
	f := ProtoFindingToGo(&pluginv1.Finding{
		RuleId:      "PLG-001",
		Message:     "something",
		Fingerprint: claimed,
	}, "some-plugin", "")

	if f.Fingerprint == claimed {
		t.Fatal("the plugin's claimed fingerprint was stored verbatim")
	}
	if f.Fingerprint == "" {
		t.Fatal("expected a recomputed fingerprint, got empty")
	}
}

// TestProtoFindingToGo_FingerprintIsolatedPerPlugin shows two plugins cannot
// collide even when they claim the identical fingerprint for identical content
// — which is what made cross-plugin and plugin-vs-core suppression possible.
func TestProtoFindingToGo_FingerprintIsolatedPerPlugin(t *testing.T) {
	t.Parallel()

	proto := &pluginv1.Finding{RuleId: "PLG-001", Message: "same", Fingerprint: "identical"}

	a := ProtoFindingToGo(proto, "plugin-a", "")
	b := ProtoFindingToGo(proto, "plugin-b", "")

	if a.Fingerprint == b.Fingerprint {
		t.Error("two plugins claiming the same fingerprint collided; namespacing is not applied")
	}
}

// TestProtoFindingToGo_FingerprintDeterministic guards nox's reproducibility
// guarantee: identical input must yield an identical fingerprint across runs.
func TestProtoFindingToGo_FingerprintDeterministic(t *testing.T) {
	t.Parallel()

	proto := &pluginv1.Finding{
		RuleId:      "PLG-001",
		Message:     "stable",
		Fingerprint: "claimed",
		Location:    &pluginv1.Location{FilePath: "a/b.go", StartLine: 4},
	}

	first := ProtoFindingToGo(proto, "plugin-a", "")
	second := ProtoFindingToGo(proto, "plugin-a", "")

	if first.Fingerprint != second.Fingerprint {
		t.Errorf("fingerprint is not deterministic: %q vs %q", first.Fingerprint, second.Fingerprint)
	}
}

// TestProtoFindingToGo_DistinctFindingsStayDistinct confirms namespacing does
// not over-collapse: a plugin's own findings must remain individually
// addressable, or they could not be baselined or waived separately.
func TestProtoFindingToGo_DistinctFindingsStayDistinct(t *testing.T) {
	t.Parallel()

	one := ProtoFindingToGo(&pluginv1.Finding{
		RuleId: "PLG-001", Message: "first", Fingerprint: "fp-1",
	}, "plugin-a", "")
	two := ProtoFindingToGo(&pluginv1.Finding{
		RuleId: "PLG-001", Message: "second", Fingerprint: "fp-2",
	}, "plugin-a", "")

	if one.Fingerprint == two.Fingerprint {
		t.Error("two distinct findings from one plugin share a fingerprint")
	}
}

// TestProtoFindingToGo_ComputesFingerprintWhenAbsent covers the plugin that
// supplies no fingerprint at all — it must still get a stable one, and it must
// not alias with a plugin that claimed its message as a fingerprint.
func TestProtoFindingToGo_ComputesFingerprintWhenAbsent(t *testing.T) {
	t.Parallel()

	absent := ProtoFindingToGo(&pluginv1.Finding{RuleId: "PLG-001", Message: "text"}, "plugin-a", "")
	if absent.Fingerprint == "" {
		t.Fatal("expected a computed fingerprint when the plugin supplied none")
	}

	claimedAsMessage := ProtoFindingToGo(&pluginv1.Finding{
		RuleId: "PLG-001", Message: "text", Fingerprint: "text",
	}, "plugin-a", "")
	if absent.Fingerprint == claimedAsMessage.Fingerprint {
		t.Error("a claimed fingerprint aliased with an absent one; the hash inputs are not tagged")
	}
}

// TestProtoFindingToGo_NamespaceDelimiterIsNotInjectable is the regression test
// for a collision that defeated fingerprint namespacing.
//
// The namespace was built as "plugin:<name>:<ruleID>", so a plugin could pick a
// name ending in a colon-prefixed fragment and collide with another plugin's
// rule ID: "acme" + "sql:injection" and "acme:sql" + "injection" both flatten
// to the same string. Colliding lets one plugin suppress another's finding via
// first-wins dedup, or hide behind a baselined entry.
func TestProtoFindingToGo_NamespaceDelimiterIsNotInjectable(t *testing.T) {
	t.Parallel()

	loc := &pluginv1.Location{FilePath: "app/db.go", StartLine: 10}

	victim := ProtoFindingToGo(&pluginv1.Finding{
		RuleId: "sql:injection", Message: "m", Fingerprint: "fp", Location: loc,
	}, "acme", "")
	attacker := ProtoFindingToGo(&pluginv1.Finding{
		RuleId: "injection", Message: "m", Fingerprint: "fp", Location: loc,
	}, "acme:sql", "")

	if victim.Fingerprint == attacker.Fingerprint {
		t.Error("delimiter injection produced a fingerprint collision across plugins")
	}
}

// TestProtoFindingToGo_NamespaceSurvivesSeparatorsInNames covers the general
// property rather than the one known payload: no combination of separator
// characters in the plugin name or rule ID may cause two distinct plugins to
// share a fingerprint.
func TestProtoFindingToGo_NamespaceSurvivesSeparatorsInNames(t *testing.T) {
	t.Parallel()

	loc := &pluginv1.Location{FilePath: "a.go", StartLine: 1}
	seen := make(map[string]string)

	for _, tc := range []struct{ plugin, rule string }{
		{"a", "b:c"},
		{"a:b", "c"},
		{"a", "b/c"},
		{"a/b", "c"},
		{"a", "b c"},
		{"a b", "c"},
		{"a", "b\x00c"},
		{"plugin:a", "b"},
	} {
		f := ProtoFindingToGo(&pluginv1.Finding{
			RuleId: tc.rule, Message: "m", Fingerprint: "fp", Location: loc,
		}, tc.plugin, "")

		key := tc.plugin + " / " + tc.rule
		if prev, dup := seen[f.Fingerprint]; dup {
			t.Errorf("collision between %q and %q", prev, key)
		}
		seen[f.Fingerprint] = key
	}
}

// TestProtoFindingToGo_NamespaceIsUnambiguousForAnyInput is the general form of
// the namespace-collision guard.
//
// Two earlier attempts used a delimiter — ':' then NUL — each justified by the
// claim that the character could not appear in a plugin name or rule ID.
// Nothing enforced that claim: both values are attacker-controlled, and proto3
// strings permit NUL. Length-prefixing removes the class rather than raising
// the bar, so this sweeps separator characters instead of testing one payload.
func TestProtoFindingToGo_NamespaceIsUnambiguousForAnyInput(t *testing.T) {
	t.Parallel()

	loc := &pluginv1.Location{FilePath: "a.go", StartLine: 1}
	seen := make(map[string]string)

	pairs := []struct{ plugin, rule string }{
		{"a", "b:c"}, {"a:b", "c"},
		{"a", "b\x00c"}, {"a\x00b", "c"},
		{"a", "1:b"}, {"a1", ":b"},
		{"ab", "c"}, {"a", "bc"},
		{"", "abc"}, {"abc", ""},
		{"plugin", "a"}, {"", "plugin\x00a"},
	}

	for _, tc := range pairs {
		f := ProtoFindingToGo(&pluginv1.Finding{
			RuleId: tc.rule, Message: "m", Fingerprint: "fp", Location: loc,
		}, tc.plugin, "")

		key := tc.plugin + " / " + tc.rule
		if prev, dup := seen[f.Fingerprint]; dup {
			t.Errorf("collision between %q and %q", prev, key)
		}
		seen[f.Fingerprint] = key
	}
}
