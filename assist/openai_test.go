package assist

import "testing"

func TestNewOpenAIProvider_Defaults(t *testing.T) {
	p := NewOpenAIProvider()
	if p.model != "gpt-4o" {
		t.Fatalf("expected default model %q, got %q", "gpt-4o", p.model)
	}
}

func TestNewOpenAIProvider_WithModel(t *testing.T) {
	p := NewOpenAIProvider(WithModel("gpt-4o-mini"))
	if p.model != "gpt-4o-mini" {
		t.Fatalf("expected model %q, got %q", "gpt-4o-mini", p.model)
	}
}

func TestNewOpenAIProvider_WithBaseURL(t *testing.T) {
	// Verify construction succeeds with a custom base URL.
	p := NewOpenAIProvider(WithBaseURL("http://localhost:11434/v1"))
	if p.model != "gpt-4o" {
		t.Fatalf("expected default model, got %q", p.model)
	}
}

func TestNewOpenAIProvider_WithAPIKey(t *testing.T) {
	// Verify construction succeeds with a custom API key.
	p := NewOpenAIProvider(WithAPIKey("test-key"))
	if p.model != "gpt-4o" {
		t.Fatalf("expected default model, got %q", p.model)
	}
}

func TestOpenAIProvider_ImplementsProvider(t *testing.T) {
	var _ Provider = (*OpenAIProvider)(nil)
}
