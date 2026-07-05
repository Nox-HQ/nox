package ai

import "testing"

func TestClassifyModelLicense(t *testing.T) {
	cases := map[string]string{
		"gpt-4o":                                 "Proprietary (OpenAI)",
		"o3-mini":                                "Proprietary (OpenAI)",
		"claude-sonnet-4":                        "Proprietary (Anthropic)",
		"gemini-1.5-pro":                         "Proprietary (Google)",
		"meta-llama/Llama-3-8B":                  "Llama Community License",
		"codellama-13b":                          "Llama Community License",
		"mistralai/Mistral-7B-v0.3":              "Apache-2.0",
		"google/gemma-2-9b":                      "Gemma Terms of Use",
		"microsoft/phi-3-mini":                   "MIT",
		"Qwen/Qwen2.5-7B":                        "Tongyi Qianwen License",
		"sentence-transformers/all-MiniLM-L6-v2": "Apache-2.0",
		"some-unknown-model":                     "",
		"":                                       "",
	}
	for name, want := range cases {
		if got := classifyModelLicense(name); got != want {
			t.Errorf("classifyModelLicense(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestExtractModelReferences_LicenseAndPinned(t *testing.T) {
	src := []byte(`
model = AutoModel.from_pretrained("meta-llama/Llama-3-8B", revision="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
other = pipeline("gpt-4o")
`)
	refs := extractModelReferences("app.py", src)

	byName := map[string]ModelReference{}
	for _, r := range refs {
		byName[r.Name] = r
	}

	llama, ok := byName["meta-llama/Llama-3-8B"]
	if !ok {
		t.Fatalf("expected llama model reference; got %v", refs)
	}
	if llama.License != "Llama Community License" {
		t.Errorf("llama license = %q, want Llama Community License", llama.License)
	}
	if !llama.Pinned {
		t.Errorf("llama pinned via revision hash should be true; hash=%q", llama.Hash)
	}

	gpt, ok := byName["gpt-4o"]
	if !ok {
		t.Fatalf("expected gpt-4o reference; got %v", refs)
	}
	if gpt.License != "Proprietary (OpenAI)" {
		t.Errorf("gpt-4o license = %q, want Proprietary (OpenAI)", gpt.License)
	}
	if gpt.Pinned {
		t.Error("gpt-4o has no revision pin; Pinned should be false")
	}
}
