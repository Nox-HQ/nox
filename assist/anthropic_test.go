package assist

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnthropicProvider_Complete_Success(t *testing.T) {
	var captured anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/messages" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "test-key" {
			t.Errorf("x-api-key = %q, want test-key", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Errorf("anthropic-version = %q, want 2023-06-01", got)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		_, _ = w.Write([]byte(`{
			"content": [{"type":"text","text":"hello there"}],
			"usage": {"input_tokens": 12, "output_tokens": 7}
		}`))
	}))
	defer srv.Close()

	p := NewAnthropicProvider(
		WithAnthropicAPIKey("test-key"),
		WithAnthropicBaseURL(srv.URL),
		WithAnthropicModel("claude-test"),
		WithAnthropicTemperature(0.2),
	)
	resp, err := p.Complete(context.Background(), []Message{
		{Role: RoleSystem, Content: "you are nox"},
		{Role: RoleUser, Content: "ping"},
	})
	if err != nil {
		t.Fatalf("Complete error = %v", err)
	}
	if resp.Content != "hello there" {
		t.Errorf("Content = %q, want %q", resp.Content, "hello there")
	}
	if resp.PromptTokens != 12 || resp.CompletionTokens != 7 {
		t.Errorf("usage = %+v, want 12/7", resp)
	}
	if captured.Model != "claude-test" {
		t.Errorf("Model = %q, want claude-test", captured.Model)
	}
	if captured.System != "you are nox" {
		t.Errorf("System = %q, want %q", captured.System, "you are nox")
	}
	if len(captured.Messages) != 1 || captured.Messages[0].Role != "user" {
		t.Errorf("Messages = %+v, want single user message", captured.Messages)
	}
	if captured.Temperature == nil || *captured.Temperature != 0.2 {
		t.Errorf("Temperature = %v, want 0.2", captured.Temperature)
	}
}

func TestAnthropicProvider_Complete_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"type":"auth","message":"bad key"}}`))
	}))
	defer srv.Close()

	p := NewAnthropicProvider(
		WithAnthropicAPIKey("test"),
		WithAnthropicBaseURL(srv.URL),
	)
	_, err := p.Complete(context.Background(), []Message{{Role: RoleUser, Content: "ping"}})
	if err == nil {
		t.Fatal("expected error from non-2xx response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected status 401 in error, got %v", err)
	}
}

func TestAnthropicProvider_RequiresAPIKey(t *testing.T) {
	p := NewAnthropicProvider()
	_, err := p.Complete(context.Background(), []Message{{Role: RoleUser, Content: "ping"}})
	if err == nil {
		t.Fatal("expected error when API key missing")
	}
}
