package findings

import (
	"math/rand/v2"
	"reflect"
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

// A plugin may return its enrichments in map order; nox/reachability 0.9.0
// does, and findings.json listed the same eight in a different order on each
// scan of the same tree. The report's order must not depend on the plugin's.
func TestSortEnrichmentsIsIndependentOfInputOrder(t *testing.T) {
	in := []Enrichment{
		{FindingFingerprint: "b", Source: "nox/reachability", Kind: "reachability", Title: "qs"},
		{FindingFingerprint: "a", Source: "nox/triage", Kind: "triage", Title: "t"},
		{FindingFingerprint: "a", Source: "nox/reachability", Kind: "reachability", Title: "body-parser"},
		{FindingFingerprint: "a", Source: "nox/reachability", Kind: "reachability", Title: "body-parser", Body: "second"},
		{FindingFingerprint: "c", Source: "nox/reachability", Kind: "reachability", Title: "path-to-regexp"},
	}
	want := SortEnrichments(append([]Enrichment(nil), in...))
	rng := rand.New(rand.NewPCG(1, 2))
	for range 50 {
		got := append([]Enrichment(nil), in...)
		rng.Shuffle(len(got), func(i, j int) { got[i], got[j] = got[j], got[i] })
		got = SortEnrichments(got)
		for i := range want {
			if !reflect.DeepEqual(got[i], want[i]) {
				t.Fatalf("order depends on input order: %+v vs %+v", got, want)
			}
		}
	}
	if want[0].FindingFingerprint != "a" || want[len(want)-1].FindingFingerprint != "c" {
		t.Fatalf("not ordered by finding: %+v", want)
	}
}
