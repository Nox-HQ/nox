package findings

import (
	"testing"
)

func TestEnrichment_BasicConstruction(t *testing.T) {
	e := Enrichment{
		FindingFingerprint: "fp-abc123",
		Kind:               "triage",
		Title:              "Auto-triage: false positive",
		Body:               "This finding is a **false positive** because...",
		Metadata:           map[string]string{"reason": "test_file"},
		Confidence:         ConfidenceHigh,
		Source:             "ai-triage-plugin",
	}

	if e.FindingFingerprint != "fp-abc123" {
		t.Errorf("FindingFingerprint = %q", e.FindingFingerprint)
	}
	if e.Kind != "triage" {
		t.Errorf("Kind = %q", e.Kind)
	}
	if e.Title != "Auto-triage: false positive" {
		t.Errorf("Title = %q", e.Title)
	}
	if e.Body != "This finding is a **false positive** because..." {
		t.Errorf("Body = %q", e.Body)
	}
	if e.Metadata["reason"] != "test_file" {
		t.Errorf("Metadata[reason] = %q", e.Metadata["reason"])
	}
	if e.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q", e.Confidence)
	}
	if e.Source != "ai-triage-plugin" {
		t.Errorf("Source = %q", e.Source)
	}
}

func TestEnrichment_ZeroValue(t *testing.T) {
	var e Enrichment
	if e.FindingFingerprint != "" || e.Kind != "" || e.Title != "" {
		t.Error("zero-value Enrichment should have empty strings")
	}
	if e.Metadata != nil {
		t.Error("zero-value Enrichment should have nil Metadata")
	}
}

func TestEnrichment_KindVariations(t *testing.T) {
	kinds := []string{"triage", "reachability", "explanation"}
	for _, kind := range kinds {
		e := Enrichment{
			FindingFingerprint: "fp-1",
			Kind:               kind,
		}
		if e.Kind != kind {
			t.Errorf("expected kind %q, got %q", kind, e.Kind)
		}
	}
}
