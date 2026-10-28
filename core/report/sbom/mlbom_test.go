package sbom

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
)

// The AI-BOM had the same blind spot as the console count: a model nox had
// detected never reached sbom.cdx.json, so the ML-BOM of an app calling
// gpt-4o listed only its npm packages. The models come from the inventory's
// DistinctModels, the same set the console counts.

func mlInventory() *ai.Inventory {
	inv := ai.NewInventory()
	inv.AddModels([]ai.ModelReference{
		{Name: "gpt-4o", Registry: "openai", License: "Proprietary (OpenAI)", Path: "b.py"},
		{Name: "gpt-4o", Registry: "openai", Path: "a.py"},
		{Name: "meta-llama/Llama-3-8B", Registry: "huggingface", Version: "abc123", License: "Llama-3", Path: "c.py"},
	})
	return inv
}

func mlCDXDoc(t *testing.T, r *CycloneDXReporter) CDXReport {
	t.Helper()
	data, err := r.Generate(&deps.PackageInventory{})
	if err != nil {
		t.Fatal(err)
	}
	var doc CDXReport
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestCycloneDX_DetectedModelsAreMachineLearningComponents(t *testing.T) {
	doc := mlCDXDoc(t, NewCycloneDXReporter("test").WithAIInventory(mlInventory()))

	var models []CDXComponent
	for _, c := range doc.Components {
		if c.Type == "machine-learning-model" {
			models = append(models, c)
		}
	}
	if len(models) != 2 {
		t.Fatalf("want 2 distinct machine-learning-model components, got %d: %+v", len(models), doc.Components)
	}
	gpt := models[0]
	if gpt.Name != "gpt-4o" || gpt.Publisher != "openai" {
		t.Errorf("first model = %+v, want gpt-4o published by openai", gpt)
	}
	if len(gpt.Licenses) != 1 || gpt.Licenses[0].License.Name != "Proprietary (OpenAI)" {
		t.Errorf("gpt-4o licenses = %+v", gpt.Licenses)
	}
	hf := models[1]
	if hf.PURL != "pkg:huggingface/meta-llama/Llama-3-8B@abc123" {
		t.Errorf("huggingface purl = %q", hf.PURL)
	}
	if gpt.PURL != "" {
		t.Errorf("openai has no purl type; got %q", gpt.PURL)
	}
	if gpt.BOMRef == "" || gpt.BOMRef == hf.BOMRef {
		t.Errorf("bom-refs must be set and unique: %q %q", gpt.BOMRef, hf.BOMRef)
	}
}

func TestCycloneDX_NoAIInventoryMeansNoModelComponents(t *testing.T) {
	for _, r := range []*CycloneDXReporter{
		NewCycloneDXReporter("test"),
		NewCycloneDXReporter("test").WithAIInventory(nil),
		NewCycloneDXReporter("test").WithAIInventory(&ai.Inventory{}),
	} {
		for _, c := range mlCDXDoc(t, r).Components {
			if c.Type == "machine-learning-model" {
				t.Errorf("unexpected model component %+v", c)
			}
		}
	}
}

func TestCycloneDX_ModelComponentsAreDeterministic(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "0")
	a, err := NewCycloneDXReporter("test").WithAIInventory(mlInventory()).Generate(&deps.PackageInventory{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCycloneDXReporter("test").WithAIInventory(mlInventory()).Generate(&deps.PackageInventory{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two generations of the same inventory differ")
	}
}
