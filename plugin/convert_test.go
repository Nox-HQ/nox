package plugin

import (
	"reflect"
	"testing"

	"github.com/felixgeelhaar/hardline/core/analyzers/ai"
	"github.com/felixgeelhaar/hardline/core/analyzers/deps"
	"github.com/felixgeelhaar/hardline/core/findings"
	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
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
		go_   findings.Severity
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
		t.Run(string(tt.go_), func(t *testing.T) {
			got := GoSeverityToProto(tt.go_)
			if got != tt.want {
				t.Errorf("GoSeverityToProto(%q) = %v, want %v", tt.go_, got, tt.want)
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
		go_  findings.Confidence
		want pluginv1.Confidence
	}{
		{findings.ConfidenceHigh, pluginv1.Confidence_CONFIDENCE_HIGH},
		{findings.ConfidenceMedium, pluginv1.Confidence_CONFIDENCE_MEDIUM},
		{findings.ConfidenceLow, pluginv1.Confidence_CONFIDENCE_LOW},
		{findings.Confidence("unknown"), pluginv1.Confidence_CONFIDENCE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(string(tt.go_), func(t *testing.T) {
			got := GoConfidenceToProto(tt.go_)
			if got != tt.want {
				t.Errorf("GoConfidenceToProto(%q) = %v, want %v", tt.go_, got, tt.want)
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
		ID:     "finding-1",
		RuleID: "SEC-001",
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

	proto := GoFindingToProto(original)
	roundTrip := ProtoFindingToGo(proto)

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
	if roundTrip.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint mismatch: %q vs %q", roundTrip.Fingerprint, original.Fingerprint)
	}
	if !reflect.DeepEqual(roundTrip.Metadata, original.Metadata) {
		t.Errorf("Metadata mismatch: %v vs %v", roundTrip.Metadata, original.Metadata)
	}
}

func TestProtoFindingToGo_Nil(t *testing.T) {
	got := ProtoFindingToGo(nil)
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

	proto := GoFindingToProto(original)
	roundTrip := ProtoFindingToGo(proto)

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
