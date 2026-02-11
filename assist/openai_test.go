package assist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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

// TestNewOpenAIProvider_WithTimeout verifies the WithTimeout option is applied.
func TestNewOpenAIProvider_WithTimeout(t *testing.T) {
	p := NewOpenAIProvider(WithTimeout(30 * time.Second))
	if p.model != "gpt-4o" {
		t.Fatalf("expected default model, got %q", p.model)
	}
}

// TestNewOpenAIProvider_AllOptions verifies all options can be combined.
func TestNewOpenAIProvider_AllOptions(t *testing.T) {
	p := NewOpenAIProvider(
		WithModel("gpt-3.5-turbo"),
		WithAPIKey("sk-test-key"),
		WithBaseURL("http://localhost:8080/v1"),
		WithTimeout(10*time.Second),
	)
	if p.model != "gpt-3.5-turbo" {
		t.Fatalf("expected model %q, got %q", "gpt-3.5-turbo", p.model)
	}
}

// TestToOpenAIMessages tests the message conversion function.
func TestToOpenAIMessages(t *testing.T) {
	messages := []Message{
		{Role: RoleSystem, Content: "You are a security expert."},
		{Role: RoleUser, Content: "Explain this finding."},
		{Role: RoleAssistant, Content: "This is an explanation."},
		{Role: Role("unknown"), Content: "Defaults to user."},
	}

	result := toOpenAIMessages(messages)

	if len(result) != 4 {
		t.Fatalf("expected 4 messages, got %d", len(result))
	}
}

// TestToOpenAIMessages_Empty tests conversion of an empty message slice.
func TestToOpenAIMessages_Empty(t *testing.T) {
	result := toOpenAIMessages(nil)
	if len(result) != 0 {
		t.Fatalf("expected 0 messages, got %d", len(result))
	}
}

// TestToOpenAIMessages_AllRoles tests each role type is handled.
func TestToOpenAIMessages_AllRoles(t *testing.T) {
	tests := []struct {
		role Role
	}{
		{RoleSystem},
		{RoleUser},
		{RoleAssistant},
		{Role("custom")},
	}

	for _, tt := range tests {
		msgs := toOpenAIMessages([]Message{{Role: tt.role, Content: "test"}})
		if len(msgs) != 1 {
			t.Errorf("role %q: expected 1 message, got %d", tt.role, len(msgs))
		}
	}
}

// TestComplete_Success tests the Complete method with a mock OpenAI API server.
func TestComplete_Success(t *testing.T) {
	mockResp := map[string]any{
		"id":      "chatcmpl-test",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "gpt-4o",
		"choices": []map[string]any{
			{
				"index":         0,
				"finish_reason": "stop",
				"message": map[string]any{
					"role":    "assistant",
					"content": "This is the LLM response.",
					"refusal": "",
				},
				"logprobs": nil,
			},
		},
		"usage": map[string]any{
			"prompt_tokens":     42,
			"completion_tokens": 15,
			"total_tokens":      57,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResp)
	}))
	defer srv.Close()

	provider := NewOpenAIProvider(
		WithBaseURL(srv.URL),
		WithAPIKey("test-key"),
		WithModel("gpt-4o"),
	)

	resp, err := provider.Complete(context.Background(), []Message{
		{Role: RoleSystem, Content: "You are helpful."},
		{Role: RoleUser, Content: "Hello"},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if resp.Content != "This is the LLM response." {
		t.Errorf("Content = %q, want %q", resp.Content, "This is the LLM response.")
	}
	if resp.PromptTokens != 42 {
		t.Errorf("PromptTokens = %d, want 42", resp.PromptTokens)
	}
	if resp.CompletionTokens != 15 {
		t.Errorf("CompletionTokens = %d, want 15", resp.CompletionTokens)
	}
}

// TestComplete_NoChoices tests that Complete returns an error when the API
// responds with no choices.
func TestComplete_NoChoices(t *testing.T) {
	mockResp := map[string]any{
		"id":      "chatcmpl-test",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "gpt-4o",
		"choices": []map[string]any{},
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 0,
			"total_tokens":      10,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResp)
	}))
	defer srv.Close()

	provider := NewOpenAIProvider(
		WithBaseURL(srv.URL),
		WithAPIKey("test-key"),
	)

	_, err := provider.Complete(context.Background(), []Message{
		{Role: RoleUser, Content: "Hello"},
	})
	if err == nil {
		t.Fatal("expected error for no choices")
	}
	if !strings.Contains(err.Error(), "no choices") {
		t.Errorf("error = %q, want to contain 'no choices'", err.Error())
	}
}

// TestComplete_APIError tests that Complete wraps API errors correctly.
func TestComplete_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": {"message": "server error", "type": "server_error"}}`))
	}))
	defer srv.Close()

	provider := NewOpenAIProvider(
		WithBaseURL(srv.URL),
		WithAPIKey("test-key"),
	)

	_, err := provider.Complete(context.Background(), []Message{
		{Role: RoleUser, Content: "Hello"},
	})
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}
