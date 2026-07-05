package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// httpLLMClient is an OpenAI-compatible chat-completions client. It is the only
// component that touches the network; the triage logic depends on the LLMClient
// interface so it can be tested without it.
type httpLLMClient struct {
	endpoint   string
	model      string
	authHeader string // e.g. "Authorization: Bearer sk-..."
	http       *http.Client
}

func newHTTPLLMClient(endpoint, model, authHeader string) *httpLLMClient {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &httpLLMClient{
		endpoint:   endpoint,
		model:      model,
		authHeader: authHeader,
		http:       &http.Client{Timeout: 60 * time.Second},
	}
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// Complete sends the prompt to the configured endpoint and returns the model's
// text reply. Deterministic temperature (0) keeps triage as reproducible as an
// LLM allows.
func (c *httpLLMClient) Complete(ctx context.Context, prompt string) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:       c.model,
		Messages:    []chatMessage{{Role: "user", Content: prompt}},
		Temperature: 0,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authHeader != "" {
		if k, v, ok := strings.Cut(c.authHeader, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("llm endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", fmt.Errorf("decoding llm response: %w", err)
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("llm response had no choices")
	}
	return cr.Choices[0].Message.Content, nil
}
