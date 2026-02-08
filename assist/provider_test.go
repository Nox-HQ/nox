package assist

import (
	"context"
	"errors"
	"testing"
)

// MockProvider is a configurable test double for the Provider interface.
type MockProvider struct {
	Responses []Response
	Err       error
	Calls     [][]Message
	callIdx   int
}

func (m *MockProvider) Complete(_ context.Context, messages []Message) (*Response, error) {
	m.Calls = append(m.Calls, messages)
	if m.Err != nil {
		return nil, m.Err
	}
	if m.callIdx >= len(m.Responses) {
		return nil, errors.New("mock: no more responses configured")
	}
	resp := m.Responses[m.callIdx]
	m.callIdx++
	return &resp, nil
}

func TestMockProvider_Complete(t *testing.T) {
	mock := &MockProvider{
		Responses: []Response{
			{Content: "hello", PromptTokens: 10, CompletionTokens: 5},
		},
	}

	resp, err := mock.Complete(context.Background(), []Message{
		{Role: RoleUser, Content: "test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "hello" {
		t.Fatalf("expected content %q, got %q", "hello", resp.Content)
	}
	if resp.PromptTokens != 10 {
		t.Fatalf("expected 10 prompt tokens, got %d", resp.PromptTokens)
	}
	if resp.CompletionTokens != 5 {
		t.Fatalf("expected 5 completion tokens, got %d", resp.CompletionTokens)
	}
	if len(mock.Calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(mock.Calls))
	}
}

func TestMockProvider_Error(t *testing.T) {
	mock := &MockProvider{Err: errors.New("api down")}

	_, err := mock.Complete(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "api down" {
		t.Fatalf("expected 'api down', got %q", err.Error())
	}
}

func TestMockProvider_ImplementsProvider(t *testing.T) {
	var _ Provider = (*MockProvider)(nil)
}
