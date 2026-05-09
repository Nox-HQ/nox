package assist

import "time"

// NewOllamaProvider returns a Provider that talks to a local Ollama server
// using its OpenAI-compatible /v1 endpoint. Ollama ignores the API key but
// the OpenAI SDK requires a non-empty value, so a placeholder is sent.
//
// Defaults: baseURL "http://localhost:11434/v1", model "llama3", timeout 5m.
func NewOllamaProvider(opts ...OllamaOption) *OpenAIProvider {
	cfg := ollamaConfig{
		baseURL: "http://localhost:11434/v1",
		model:   "llama3",
		timeout: 5 * time.Minute,
	}
	for _, o := range opts {
		o(&cfg)
	}

	openaiOpts := []OpenAIOption{
		WithBaseURL(cfg.baseURL),
		WithModel(cfg.model),
		WithAPIKey("ollama"),
		WithTimeout(cfg.timeout),
	}
	if cfg.hasTemp {
		openaiOpts = append(openaiOpts, WithTemperature(cfg.temperature))
	}
	return NewOpenAIProvider(openaiOpts...)
}

// OllamaOption configures NewOllamaProvider.
type OllamaOption func(*ollamaConfig)

type ollamaConfig struct {
	baseURL     string
	model       string
	timeout     time.Duration
	temperature float64
	hasTemp     bool
}

// WithOllamaBaseURL sets the Ollama base URL (must include /v1 suffix).
func WithOllamaBaseURL(url string) OllamaOption {
	return func(c *ollamaConfig) { c.baseURL = url }
}

// WithOllamaModel sets the model name (e.g. "llama3", "mistral").
func WithOllamaModel(model string) OllamaOption {
	return func(c *ollamaConfig) { c.model = model }
}

// WithOllamaTimeout sets the per-request HTTP timeout.
func WithOllamaTimeout(d time.Duration) OllamaOption {
	return func(c *ollamaConfig) { c.timeout = d }
}

// WithOllamaTemperature sets the sampling temperature.
func WithOllamaTemperature(t float64) OllamaOption {
	return func(c *ollamaConfig) { c.temperature = t; c.hasTemp = true }
}
