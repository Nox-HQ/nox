package assist

import (
	"context"
	"fmt"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

// OpenAIProvider implements Provider using the official OpenAI Go SDK.
// It supports any OpenAI-compatible endpoint via WithBaseURL.
type OpenAIProvider struct {
	client openai.Client
	model  string
}

// OpenAIOption configures an OpenAIProvider.
type OpenAIOption func(*openaiConfig)

type openaiConfig struct {
	model   string
	apiKey  string
	baseURL string
	timeout time.Duration
}

// WithModel sets the model name (default: "gpt-4o").
func WithModel(model string) OpenAIOption {
	return func(c *openaiConfig) { c.model = model }
}

// WithAPIKey sets the API key. If empty, the SDK falls back to OPENAI_API_KEY.
func WithAPIKey(key string) OpenAIOption {
	return func(c *openaiConfig) { c.apiKey = key }
}

// WithBaseURL sets a custom base URL, enabling Ollama, vLLM, Azure, or other
// OpenAI-compatible endpoints.
func WithBaseURL(url string) OpenAIOption {
	return func(c *openaiConfig) { c.baseURL = url }
}

// WithTimeout sets the per-request timeout for API calls (default: 2 minutes).
func WithTimeout(d time.Duration) OpenAIOption {
	return func(c *openaiConfig) { c.timeout = d }
}

// NewOpenAIProvider creates an OpenAIProvider with the given options.
func NewOpenAIProvider(opts ...OpenAIOption) *OpenAIProvider {
	cfg := openaiConfig{model: "gpt-4o"}
	for _, o := range opts {
		o(&cfg)
	}

	var clientOpts []option.RequestOption
	if cfg.apiKey != "" {
		clientOpts = append(clientOpts, option.WithAPIKey(cfg.apiKey))
	}
	if cfg.baseURL != "" {
		clientOpts = append(clientOpts, option.WithBaseURL(cfg.baseURL))
	}
	if cfg.timeout > 0 {
		clientOpts = append(clientOpts, option.WithRequestTimeout(cfg.timeout))
	}

	return &OpenAIProvider{
		client: openai.NewClient(clientOpts...),
		model:  cfg.model,
	}
}

// Complete sends a chat completion request to the OpenAI API and returns the
// response content with token usage metadata.
func (p *OpenAIProvider) Complete(ctx context.Context, messages []Message) (*Response, error) {
	params := openai.ChatCompletionNewParams{
		Model:    p.model,
		Messages: toOpenAIMessages(messages),
	}

	completion, err := p.client.Chat.Completions.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("openai chat completion: %w", err)
	}

	if len(completion.Choices) == 0 {
		return nil, fmt.Errorf("openai returned no choices")
	}

	return &Response{
		Content:          completion.Choices[0].Message.Content,
		PromptTokens:     int(completion.Usage.PromptTokens),
		CompletionTokens: int(completion.Usage.CompletionTokens),
	}, nil
}

// toOpenAIMessages converts internal Message values to the SDK union type.
func toOpenAIMessages(msgs []Message) []openai.ChatCompletionMessageParamUnion {
	out := make([]openai.ChatCompletionMessageParamUnion, len(msgs))
	for i, m := range msgs {
		switch m.Role {
		case RoleSystem:
			out[i] = openai.SystemMessage(m.Content)
		case RoleUser:
			out[i] = openai.UserMessage(m.Content)
		case RoleAssistant:
			out[i] = openai.AssistantMessage(m.Content)
		default:
			out[i] = openai.UserMessage(m.Content)
		}
	}
	return out
}
