package main

import (
	"fmt"
	"os"
	"strings"

	plannerllm "github.com/felixgeelhaar/agent-go/contrib/planner-llm"
	"github.com/felixgeelhaar/agent-go/contrib/planner-llm/providers"
)

// resolveProvider creates an LLM provider from NOX_AI_* environment variables.
func resolveProvider() (plannerllm.Provider, string, error) {
	providerName := strings.ToLower(os.Getenv("NOX_AI_PROVIDER"))
	if providerName == "" {
		providerName = "openai"
	}

	apiKey := os.Getenv("NOX_AI_API_KEY")
	model := os.Getenv("NOX_AI_MODEL")
	baseURL := os.Getenv("NOX_AI_BASE_URL")

	switch providerName {
	case "openai":
		if apiKey == "" {
			return nil, "", fmt.Errorf("NOX_AI_API_KEY is required for openai provider")
		}
		if model == "" {
			model = "gpt-4o"
		}
		p := providers.NewOpenAIProvider(providers.OpenAIConfig{
			APIKey:  apiKey,
			BaseURL: baseURL,
			Model:   model,
		})
		return p, model, nil

	case "anthropic":
		if apiKey == "" {
			return nil, "", fmt.Errorf("NOX_AI_API_KEY is required for anthropic provider")
		}
		if model == "" {
			model = "claude-sonnet-4-5-20250514"
		}
		p := providers.NewAnthropicProvider(providers.AnthropicConfig{
			APIKey:  apiKey,
			BaseURL: baseURL,
			Model:   model,
		})
		return p, model, nil

	case "gemini":
		if apiKey == "" {
			return nil, "", fmt.Errorf("NOX_AI_API_KEY is required for gemini provider")
		}
		if model == "" {
			model = "gemini-pro"
		}
		p := providers.NewGeminiProvider(providers.GeminiConfig{
			APIKey: apiKey,
			Model:  model,
		})
		return p, model, nil

	case "ollama":
		if model == "" {
			model = "llama3"
		}
		url := baseURL
		if url == "" {
			url = "http://localhost:11434"
		}
		p := providers.NewOllamaProvider(providers.OllamaConfig{
			BaseURL: url,
			Model:   model,
		})
		return p, model, nil

	case "cohere":
		if apiKey == "" {
			return nil, "", fmt.Errorf("NOX_AI_API_KEY is required for cohere provider")
		}
		if model == "" {
			model = "command-r-plus"
		}
		p := providers.NewCohereProvider(providers.CohereConfig{
			APIKey:  apiKey,
			BaseURL: baseURL,
			Model:   model,
		})
		return p, model, nil

	case "bedrock":
		accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
		secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
		sessionToken := os.Getenv("AWS_SESSION_TOKEN")
		region := os.Getenv("AWS_REGION")
		if accessKey == "" || secretKey == "" {
			return nil, "", fmt.Errorf("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for bedrock provider")
		}
		if model == "" {
			model = "anthropic.claude-3-sonnet-20240229-v1:0"
		}
		p := providers.NewBedrockProvider(providers.BedrockConfig{
			Region:          region,
			AccessKeyID:     accessKey,
			SecretAccessKey: secretKey,
			SessionToken:    sessionToken,
			Model:           model,
		})
		return p, model, nil

	case "copilot":
		token := apiKey
		if token == "" {
			token = os.Getenv("GITHUB_TOKEN")
		}
		if token == "" {
			return nil, "", fmt.Errorf("NOX_AI_API_KEY or GITHUB_TOKEN is required for copilot provider")
		}
		if model == "" {
			model = "gpt-4o"
		}
		p := providers.NewCopilotProvider(providers.CopilotConfig{
			Token:   token,
			BaseURL: baseURL,
			Model:   model,
		})
		return p, model, nil

	default:
		return nil, "", fmt.Errorf("unsupported provider: %s (supported: openai, anthropic, gemini, ollama, cohere, bedrock, copilot)", providerName)
	}
}
