package assist

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AnthropicProvider implements Provider against the Anthropic Messages API.
// It sends a minimal HTTP request rather than pulling in an SDK; this keeps
// the assist module's dependency surface small.
type AnthropicProvider struct {
	apiKey      string
	baseURL     string
	model       string
	maxTokens   int
	temperature float64
	hasTemp     bool
	httpClient  *http.Client
}

// AnthropicOption configures an AnthropicProvider.
type AnthropicOption func(*anthropicConfig)

type anthropicConfig struct {
	apiKey      string
	baseURL     string
	model       string
	maxTokens   int
	temperature float64
	hasTemp     bool
	timeout     time.Duration
	httpClient  *http.Client
}

// WithAnthropicAPIKey sets the API key. If empty, the constructor reads
// ANTHROPIC_API_KEY from the environment via the caller.
func WithAnthropicAPIKey(key string) AnthropicOption {
	return func(c *anthropicConfig) { c.apiKey = key }
}

// WithAnthropicModel sets the model id (default "claude-sonnet-4-5-20250514").
func WithAnthropicModel(model string) AnthropicOption {
	return func(c *anthropicConfig) { c.model = model }
}

// WithAnthropicBaseURL overrides the API base URL (default "https://api.anthropic.com/v1").
func WithAnthropicBaseURL(url string) AnthropicOption {
	return func(c *anthropicConfig) { c.baseURL = url }
}

// WithAnthropicMaxTokens sets the response token cap (default 4096).
func WithAnthropicMaxTokens(n int) AnthropicOption {
	return func(c *anthropicConfig) { c.maxTokens = n }
}

// WithAnthropicTemperature sets the sampling temperature.
func WithAnthropicTemperature(t float64) AnthropicOption {
	return func(c *anthropicConfig) { c.temperature = t; c.hasTemp = true }
}

// WithAnthropicTimeout sets the per-request HTTP timeout (default 2 minutes).
func WithAnthropicTimeout(d time.Duration) AnthropicOption {
	return func(c *anthropicConfig) { c.timeout = d }
}

// WithAnthropicHTTPClient injects a custom HTTP client. Useful for tests.
func WithAnthropicHTTPClient(h *http.Client) AnthropicOption {
	return func(c *anthropicConfig) { c.httpClient = h }
}

// NewAnthropicProvider constructs an AnthropicProvider with sensible defaults.
func NewAnthropicProvider(opts ...AnthropicOption) *AnthropicProvider {
	cfg := anthropicConfig{
		baseURL:   "https://api.anthropic.com/v1",
		model:     "claude-sonnet-4-5-20250514",
		maxTokens: 4096,
		timeout:   2 * time.Minute,
	}
	for _, o := range opts {
		o(&cfg)
	}
	client := cfg.httpClient
	if client == nil {
		client = &http.Client{Timeout: cfg.timeout}
	}
	return &AnthropicProvider{
		apiKey:      cfg.apiKey,
		baseURL:     cfg.baseURL,
		model:       cfg.model,
		maxTokens:   cfg.maxTokens,
		temperature: cfg.temperature,
		hasTemp:     cfg.hasTemp,
		httpClient:  client,
	}
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature *float64           `json:"temperature,omitempty"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicResponse struct {
	Content []anthropicContentBlock `json:"content"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Complete sends a Messages API request and returns the assistant text.
func (p *AnthropicProvider) Complete(ctx context.Context, messages []Message) (*Response, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("anthropic provider: missing API key")
	}

	req := anthropicRequest{
		Model:     p.model,
		MaxTokens: p.maxTokens,
	}
	if p.hasTemp {
		t := p.temperature
		req.Temperature = &t
	}
	for _, m := range messages {
		switch m.Role {
		case RoleSystem:
			if req.System != "" {
				req.System += "\n\n"
			}
			req.System += m.Content
		case RoleUser:
			req.Messages = append(req.Messages, anthropicMessage{Role: "user", Content: m.Content})
		case RoleAssistant:
			req.Messages = append(req.Messages, anthropicMessage{Role: "assistant", Content: m.Content})
		default:
			req.Messages = append(req.Messages, anthropicMessage{Role: "user", Content: m.Content})
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic provider: marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("anthropic provider: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic provider: request: %w", err)
	}
	// Response body close on a read-only HTTP response: nothing to report.
	defer func() { _ = resp.Body.Close() }()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("anthropic provider: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("anthropic provider: status %d: %s", resp.StatusCode, string(rawBody))
	}

	var parsed anthropicResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("anthropic provider: parse response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("anthropic provider: %s: %s", parsed.Error.Type, parsed.Error.Message)
	}

	var content string
	for _, c := range parsed.Content {
		if c.Type == "text" {
			content += c.Text
		}
	}
	return &Response{
		Content:          content,
		PromptTokens:     parsed.Usage.InputTokens,
		CompletionTokens: parsed.Usage.OutputTokens,
	}, nil
}
