package ai

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// IsUntrustedRegistry
// ---------------------------------------------------------------------------

func TestIsUntrustedRegistry_TrustedRegistries(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"huggingface", "https://huggingface.co/bert-base-uncased"},
		{"hf.co", "https://hf.co/models/gpt2"},
		{"pytorch hub", "https://download.pytorch.org/models/resnet50.pth"},
		{"tfhub", "https://tfhub.dev/google/bert_en_uncased_L-12"},
		{"kaggle", "https://www.kaggle.com/models/google/bert"},
		{"ollama", "https://registry.ollama.ai/library/llama3"},
		{"azure", "https://models.ai.azure.com/catalog/gpt-4"},
		{"mixed case", "https://HuggingFace.CO/some-model"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsUntrustedRegistry(tt.url) {
				t.Fatalf("expected %q to be trusted, got untrusted", tt.url)
			}
		})
	}
}

func TestIsUntrustedRegistry_UntrustedRegistries(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"random domain", "https://evil-models.example.com/model.bin"},
		{"ip address", "http://192.168.1.100/models/bert.pt"},
		{"localhost", "http://localhost:8080/model.safetensors"},
		{"empty", ""},
		{"unknown registry", "https://my-custom-registry.io/models/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !IsUntrustedRegistry(tt.url) {
				t.Fatalf("expected %q to be untrusted, got trusted", tt.url)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HasHashPin
// ---------------------------------------------------------------------------

func TestHasHashPin_WithHashes(t *testing.T) {
	tests := []struct {
		name      string
		reference string
	}{
		{"sha256", "sha256:abc123def456"},
		{"sha1", "sha1:abc123"},
		{"md5", "md5:abc123def"},
		{"blake2b", "blake2b:0123456789abcdef"},
		{"uppercase", "SHA256:ABC123"},
		{"in context", "model@sha256:abc123def456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !HasHashPin(tt.reference) {
				t.Fatalf("expected HasHashPin(%q) to be true", tt.reference)
			}
		})
	}
}

func TestHasHashPin_WithoutHashes(t *testing.T) {
	tests := []struct {
		name      string
		reference string
	}{
		{"plain model name", "bert-base-uncased"},
		{"version only", "gpt-4-0613"},
		{"empty", ""},
		{"url no hash", "https://huggingface.co/bert"},
		{"partial match no colon", "sha256"},
		{"colon but no hex", "sha256:xyz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if HasHashPin(tt.reference) {
				t.Fatalf("expected HasHashPin(%q) to be false", tt.reference)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AI-019: Model loaded without hash verification
// ---------------------------------------------------------------------------

func TestDetect_ModelWithoutHashVerification(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"from_pretrained", `model = AutoModel.from_pretrained("bert-base-uncased")`},
		{"load_model", `model = load_model("my-model")`},
		{"AutoModel", `model = AutoModel("gpt2")`},
		{"download_model", `download_model("llama-7b")`},
		{"pipeline call", `classifier = pipeline("sentiment-analysis")`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile("train.py", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			f := findingWithRule(results, "AI-019")
			if f == nil {
				t.Fatalf("expected AI-019 finding for %q", tt.name)
			}
			if f.Severity != findings.SeverityHigh {
				t.Fatalf("expected severity high, got %s", f.Severity)
			}
		})
	}
}

func TestNoDetect_ModelWithoutHash_WrongFileType(t *testing.T) {
	a := NewAnalyzer()
	// AI-019 only applies to *.py and *.ipynb files.
	content := []byte(`model = AutoModel.from_pretrained("bert-base-uncased")`)

	results, err := a.ScanFile("config.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-019")
	if f != nil {
		t.Fatal("should not flag AI-019 in a YAML file")
	}
}

// ---------------------------------------------------------------------------
// AI-020: Model from untrusted registry
// ---------------------------------------------------------------------------

func TestDetect_ModelFromUntrustedRegistry(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"from_pretrained http", `model = AutoModel.from_pretrained("https://evil.example.com/model")`},
		{"load_model http", `model = load_model("https://unknown-site.io/bert.bin")`},
		{"model_url assignment", `model_url = "https://random-server.net/weights.pt"`},
		{"download_model http", `download_model("http://192.168.1.100/model.bin")`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile("train.py", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			f := findingWithRule(results, "AI-020")
			if f == nil {
				t.Fatalf("expected AI-020 finding for %q", tt.name)
			}
			if f.Severity != findings.SeverityMedium {
				t.Fatalf("expected severity medium, got %s", f.Severity)
			}
		})
	}
}

func TestDetect_ModelFromTrustedRegistryAlsoMatches(t *testing.T) {
	// Note: AI-020 regex matches any URL in a model loading context.
	// The trusted/untrusted distinction is a helper for post-processing.
	// The regex-based rule will match all URL-based model loads to flag
	// them for review.
	a := NewAnalyzer()
	content := []byte(`model = AutoModel.from_pretrained("https://huggingface.co/bert-base-uncased")`)

	results, err := a.ScanFile("train.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The regex matches the pattern; IsUntrustedRegistry can be used for
	// post-processing but the rule itself fires for all URL-based loads.
	f := findingWithRule(results, "AI-020")
	if f == nil {
		t.Fatal("expected AI-020 finding (regex matches all URL-based model loads)")
	}
}

// ---------------------------------------------------------------------------
// AI-021: Model reference without signature verification
// ---------------------------------------------------------------------------

func TestDetect_ModelFileWithoutSignature(t *testing.T) {
	tests := []struct {
		name    string
		content string
		file    string
	}{
		{"onnx load", `model = ort.load("weights.onnx")`, "inference.py"},
		{"pt load", `model = torch.load("model.pt")`, "train.py"},
		{"pth load", `model = torch.load("checkpoint.pth")`, "train.py"},
		{"h5 load", `model = keras.load("model.h5")`, "train.py"},
		{"pb open", `graph = tf.open("frozen.pb")`, "serve.py"},
		{"safetensors load", `model = load("weights.safetensors")`, "inference.py"},
		{"gguf load", `model = load("model.gguf")`, "serve.py"},
		{"bin load", `model = from_file.open("embeddings.bin")`, "load.py"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile(tt.file, []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			f := findingWithRule(results, "AI-021")
			if f == nil {
				t.Fatalf("expected AI-021 finding for %q", tt.name)
			}
			if f.Severity != findings.SeverityMedium {
				t.Fatalf("expected severity medium, got %s", f.Severity)
			}
		})
	}
}

func TestNoDetect_ModelFileWithoutSignature_NoLoadCall(t *testing.T) {
	a := NewAnalyzer()
	// Just mentioning a model file without a load/open call should not match.
	content := []byte(`# The model is stored at weights.safetensors`)

	results, err := a.ScanFile("readme.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-021")
	if f != nil {
		t.Fatal("should not flag AI-021 without a load/open call")
	}
}

// ---------------------------------------------------------------------------
// Rule existence and metadata
// ---------------------------------------------------------------------------

func TestModelSupplyChainRules_ExistInRuleSet(t *testing.T) {
	a := NewAnalyzer()
	rs := a.Rules()

	for _, id := range []string{"AI-019", "AI-020", "AI-021"} {
		if !rs.HasID(id) {
			t.Errorf("expected rule %s to exist in the rule set", id)
		}
	}
}

func TestModelSupplyChainRules_Metadata(t *testing.T) {
	a := NewAnalyzer()
	rs := a.Rules()

	tests := []struct {
		id       string
		severity findings.Severity
		cwe      string
	}{
		{"AI-019", findings.SeverityHigh, "CWE-494"},
		{"AI-020", findings.SeverityMedium, "CWE-829"},
		{"AI-021", findings.SeverityMedium, "CWE-494"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			rule, ok := rs.ByID(tt.id)
			if !ok {
				t.Fatalf("rule %s not found", tt.id)
			}
			if rule.Severity != tt.severity {
				t.Errorf("expected severity %s for %s, got %s", tt.severity, tt.id, rule.Severity)
			}
			if rule.Metadata["cwe"] != tt.cwe {
				t.Errorf("expected CWE %s for %s, got %s", tt.cwe, tt.id, rule.Metadata["cwe"])
			}
		})
	}
}

func TestModelSupplyChainRules_Tags(t *testing.T) {
	a := NewAnalyzer()
	rs := a.Rules()

	supplyChainRules := rs.ByTag("supply-chain")
	// At minimum, AI-008, AI-014, AI-019, AI-020, AI-021 carry supply-chain tag.
	if len(supplyChainRules) < 4 {
		t.Errorf("expected at least 4 rules with supply-chain tag, got %d", len(supplyChainRules))
	}
}
