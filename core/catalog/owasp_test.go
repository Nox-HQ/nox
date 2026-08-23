package catalog

import (
	"strings"
	"testing"
)

// TestOWASPLLMNumbering pins the 2025 edition numbering. If a future edit
// accidentally renumbers a category (or reverts to the 2023 list), this test
// fails loudly rather than silently shipping a wrong taxonomy.
func TestOWASPLLMNumbering(t *testing.T) {
	want := map[OWASPLLM]string{
		LLM01PromptInjection:         "LLM01",
		LLM02SensitiveInfoDisclosure: "LLM02",
		LLM03SupplyChain:             "LLM03",
		LLM04DataModelPoisoning:      "LLM04",
		LLM05ImproperOutputHandling:  "LLM05",
		LLM06ExcessiveAgency:         "LLM06",
		LLM07SystemPromptLeakage:     "LLM07",
		LLM08VectorEmbedding:         "LLM08",
		LLM09Misinformation:          "LLM09",
		LLM10UnboundedConsumption:    "LLM10",
	}
	for c, code := range want {
		if string(c) != code {
			t.Errorf("category constant = %q, want %q", string(c), code)
		}
	}

	// The 2025 titles for the categories whose meaning changed vs 2023.
	titles := map[OWASPLLM]string{
		LLM02SensitiveInfoDisclosure: "Sensitive Information Disclosure",
		LLM03SupplyChain:             "Supply Chain",
		LLM04DataModelPoisoning:      "Data and Model Poisoning",
		LLM05ImproperOutputHandling:  "Improper Output Handling",
		LLM06ExcessiveAgency:         "Excessive Agency",
		LLM07SystemPromptLeakage:     "System Prompt Leakage",
		LLM08VectorEmbedding:         "Vector and Embedding Weaknesses",
		LLM09Misinformation:          "Misinformation",
		LLM10UnboundedConsumption:    "Unbounded Consumption",
	}
	for c, title := range titles {
		if got := c.Title(); got != title {
			t.Errorf("%s.Title() = %q, want %q", c, got, title)
		}
	}

	if OWASPLLMEdition != "2025" {
		t.Errorf("OWASPLLMEdition = %q, want 2025", OWASPLLMEdition)
	}
}

// TestOWASPLLMAllCategories checks each category is well-formed: Valid, a
// non-empty Title, a Reference URL that carries the code, and a Tag that
// round-trips back to the constant.
func TestOWASPLLMAllCategories(t *testing.T) {
	all := AllOWASPLLM()
	if len(all) != 10 {
		t.Fatalf("AllOWASPLLM() returned %d categories, want 10", len(all))
	}
	for i, c := range all {
		if !c.Valid() {
			t.Errorf("%s.Valid() = false", c)
		}
		if c.Title() == "" {
			t.Errorf("%s.Title() is empty", c)
		}
		ref := c.Reference()
		if !strings.HasPrefix(ref, "https://genai.owasp.org/llmrisk/") {
			t.Errorf("%s.Reference() = %q, unexpected host", c, ref)
		}
		if !strings.Contains(ref, strings.ToLower(string(c))) {
			t.Errorf("%s.Reference() = %q, does not carry the code", c, ref)
		}
		// Tag round-trips: "owasp-llm0N" -> LLM0N.
		wantTag := "owasp-" + strings.ToLower(string(c))
		if got := c.Tag(); got != wantTag {
			t.Errorf("%s.Tag() = %q, want %q", c, got, wantTag)
		}
		if got := LLMTag(c); got != wantTag {
			t.Errorf("LLMTag(%s) = %q, want %q", c, got, wantTag)
		}
		code := OWASPLLM(strings.ToUpper(strings.TrimPrefix(c.Tag(), "owasp-")))
		if code != c {
			t.Errorf("tag round-trip: %q -> %q, want %q", c.Tag(), code, c)
		}
		// Canonical ordering: allOWASPLLM must be LLM01..LLM10 in order.
		if int(c[len(c)-2]-'0')*10+int(c[len(c)-1]-'0') != i+1 {
			t.Errorf("AllOWASPLLM()[%d] = %s, out of canonical order", i, c)
		}
	}
}

// TestOWASPLLMInvalid confirms an unknown code is reported invalid and yields
// empty accessors rather than panicking.
func TestOWASPLLMInvalid(t *testing.T) {
	bad := OWASPLLM("LLM11")
	if bad.Valid() {
		t.Error("LLM11.Valid() = true, want false")
	}
	if bad.Title() != "" {
		t.Errorf("LLM11.Title() = %q, want empty", bad.Title())
	}
	if bad.Reference() != "" {
		t.Errorf("LLM11.Reference() = %q, want empty", bad.Reference())
	}
}

// TestCatalogLLMTagsAreValid2025 is the DRY guard: every owasp-llmNN tag that
// any built-in rule carries must resolve to a valid 2025 category. This keeps
// the analyzers' kebab tags from drifting away from the canonical catalog even
// though (to avoid an import cycle) the analyzers cannot reference the
// constants directly.
func TestCatalogLLMTagsAreValid2025(t *testing.T) {
	saw := false
	for id, meta := range Catalog() {
		for _, tag := range meta.Tags {
			if !strings.HasPrefix(tag, "owasp-llm") {
				continue
			}
			saw = true
			code := OWASPLLM(strings.ToUpper(strings.TrimPrefix(tag, "owasp-")))
			if !code.Valid() {
				t.Errorf("rule %s carries tag %q which is not a valid 2025 OWASP LLM category", id, tag)
			}
		}
	}
	if !saw {
		t.Fatal("no owasp-llm* tags found in catalog; test is not exercising anything")
	}
}
