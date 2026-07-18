package assist

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProviderConfig captures the resolved provider configuration. The model
// field is exposed separately because callers often want to log it.
type ProviderConfig struct {
	Provider Provider
	Name     string
	Model    string
}

// ResolveProvider builds a Provider from NOX_AI_* environment variables.
//
// Recognized variables:
//   - NOX_AI_PROVIDER: openai (default) | anthropic | ollama
//   - NOX_AI_API_KEY:  API key for the chosen provider (Ollama ignores it)
//   - NOX_AI_MODEL:    model id (provider-specific default if unset)
//   - NOX_AI_BASE_URL: override base URL (OpenAI-compatible / custom Anthropic / Ollama)
//   - NOX_AI_TEMPERATURE: float, optional
//
// This is the canonical resolver shared by CLI commands and plugins so all
// nox surfaces honor the same configuration knobs.
func ResolveProvider() (*ProviderConfig, error) {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("NOX_AI_PROVIDER")))
	if name == "" {
		name = "openai"
	}
	apiKey := os.Getenv("NOX_AI_API_KEY")
	model := os.Getenv("NOX_AI_MODEL")
	baseURL := os.Getenv("NOX_AI_BASE_URL")

	temp, hasTemp, err := parseTemperature(os.Getenv("NOX_AI_TEMPERATURE"))
	if err != nil {
		return nil, err
	}

	switch name {
	case "openai":
		if apiKey == "" {
			return nil, fmt.Errorf("NOX_AI_API_KEY is required for openai provider")
		}
		if model == "" {
			model = "gpt-4o"
		}
		opts := []OpenAIOption{WithAPIKey(apiKey), WithModel(model)}
		if baseURL != "" {
			opts = append(opts, WithBaseURL(baseURL))
		}
		if hasTemp {
			opts = append(opts, WithTemperature(temp))
		}
		return &ProviderConfig{Provider: NewOpenAIProvider(opts...), Name: name, Model: model}, nil

	case "anthropic":
		if apiKey == "" {
			return nil, fmt.Errorf("NOX_AI_API_KEY is required for anthropic provider")
		}
		if model == "" {
			model = "claude-sonnet-4-5-20250514"
		}
		opts := []AnthropicOption{WithAnthropicAPIKey(apiKey), WithAnthropicModel(model)}
		if baseURL != "" {
			opts = append(opts, WithAnthropicBaseURL(baseURL))
		}
		if hasTemp {
			opts = append(opts, WithAnthropicTemperature(temp))
		}
		return &ProviderConfig{Provider: NewAnthropicProvider(opts...), Name: name, Model: model}, nil

	case "ollama":
		if model == "" {
			model = "llama3"
		}
		opts := []OllamaOption{WithOllamaModel(model)}
		if baseURL != "" {
			opts = append(opts, WithOllamaBaseURL(baseURL))
		}
		if hasTemp {
			opts = append(opts, WithOllamaTemperature(temp))
		}
		return &ProviderConfig{Provider: NewOllamaProvider(opts...), Name: name, Model: model}, nil

	default:
		return nil, fmt.Errorf("unsupported NOX_AI_PROVIDER %q (supported: openai, anthropic, ollama)", name)
	}
}

func parseTemperature(s string) (temperature float64, ok bool, err error) {
	if strings.TrimSpace(s) == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false, fmt.Errorf("NOX_AI_TEMPERATURE %q is not a valid float: %w", s, err)
	}
	return v, true, nil
}
