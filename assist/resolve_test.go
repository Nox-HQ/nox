package assist

import (
	"strings"
	"testing"
)

func TestResolveProvider_DefaultsToOpenAI(t *testing.T) {
	t.Setenv("NOX_AI_PROVIDER", "")
	t.Setenv("NOX_AI_API_KEY", "sk-test")
	t.Setenv("NOX_AI_MODEL", "")
	t.Setenv("NOX_AI_BASE_URL", "")
	t.Setenv("NOX_AI_TEMPERATURE", "")

	cfg, err := ResolveProvider()
	if err != nil {
		t.Fatalf("ResolveProvider error = %v", err)
	}
	if cfg.Name != "openai" {
		t.Errorf("Name = %q, want openai", cfg.Name)
	}
	if cfg.Model != "gpt-4o" {
		t.Errorf("Model = %q, want default gpt-4o", cfg.Model)
	}
	if _, ok := cfg.Provider.(*OpenAIProvider); !ok {
		t.Errorf("Provider type = %T, want *OpenAIProvider", cfg.Provider)
	}
}

func TestResolveProvider_OpenAIRequiresKey(t *testing.T) {
	t.Setenv("NOX_AI_PROVIDER", "openai")
	t.Setenv("NOX_AI_API_KEY", "")
	if _, err := ResolveProvider(); err == nil {
		t.Fatal("expected error when openai key missing")
	}
}

func TestResolveProvider_Anthropic(t *testing.T) {
	t.Setenv("NOX_AI_PROVIDER", "anthropic")
	t.Setenv("NOX_AI_API_KEY", "anthropic-key")
	t.Setenv("NOX_AI_MODEL", "claude-foo")
	t.Setenv("NOX_AI_BASE_URL", "")
	t.Setenv("NOX_AI_TEMPERATURE", "0.4")

	cfg, err := ResolveProvider()
	if err != nil {
		t.Fatalf("ResolveProvider error = %v", err)
	}
	if cfg.Name != "anthropic" || cfg.Model != "claude-foo" {
		t.Errorf("got name=%q model=%q", cfg.Name, cfg.Model)
	}
	a, ok := cfg.Provider.(*AnthropicProvider)
	if !ok {
		t.Fatalf("Provider type = %T, want *AnthropicProvider", cfg.Provider)
	}
	if !a.hasTemp || a.temperature != 0.4 {
		t.Errorf("temperature not propagated: hasTemp=%v val=%v", a.hasTemp, a.temperature)
	}
}

func TestResolveProvider_OllamaUsesOpenAIClient(t *testing.T) {
	t.Setenv("NOX_AI_PROVIDER", "ollama")
	t.Setenv("NOX_AI_API_KEY", "")
	t.Setenv("NOX_AI_MODEL", "mistral")
	t.Setenv("NOX_AI_BASE_URL", "")
	t.Setenv("NOX_AI_TEMPERATURE", "")

	cfg, err := ResolveProvider()
	if err != nil {
		t.Fatalf("ResolveProvider error = %v", err)
	}
	if cfg.Name != "ollama" {
		t.Errorf("Name = %q, want ollama", cfg.Name)
	}
	if cfg.Model != "mistral" {
		t.Errorf("Model = %q, want mistral", cfg.Model)
	}
	if _, ok := cfg.Provider.(*OpenAIProvider); !ok {
		t.Errorf("Provider type = %T, want *OpenAIProvider (ollama via OpenAI-compat)", cfg.Provider)
	}
}

func TestResolveProvider_UnsupportedProvider(t *testing.T) {
	t.Setenv("NOX_AI_PROVIDER", "bedrock")
	t.Setenv("NOX_AI_API_KEY", "x")
	_, err := ResolveProvider()
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	if !strings.Contains(err.Error(), "bedrock") {
		t.Errorf("error should mention provider name, got %v", err)
	}
}

func TestResolveProvider_BadTemperature(t *testing.T) {
	t.Setenv("NOX_AI_PROVIDER", "openai")
	t.Setenv("NOX_AI_API_KEY", "x")
	t.Setenv("NOX_AI_TEMPERATURE", "not-a-number")
	_, err := ResolveProvider()
	if err == nil {
		t.Fatal("expected parse error for invalid temperature")
	}
}
