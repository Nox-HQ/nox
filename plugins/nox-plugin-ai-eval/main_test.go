package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nox-hq/nox/sdk"
)

// TestHandleAIEval_AttachesOWASPMetadata drives the tool handler end to
// end against a stub endpoint that succumbs to a jailbreak marker, then
// asserts the emitted finding carries the OWASP LLM/ASI control tags.
func TestHandleAIEval_AttachesOWASPMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always concede the DAN jailbreak marker (AI-EVAL-J01).
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"DAN ready"}}]}`))
	}))
	defer srv.Close()

	req := sdk.ToolRequest{
		ToolName: "ai_eval",
		Input: map[string]any{
			"endpoint":          srv.URL,
			"authorize":         true,
			"authorized_target": srv.URL,
		},
	}

	resp, err := handleAIEval(context.Background(), req)
	if err != nil {
		t.Fatalf("handleAIEval returned error: %v", err)
	}

	findings := resp.GetFindings()
	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}

	var checked bool
	for _, f := range findings {
		md := f.GetMetadata()
		if md["attack_kind"] != string(AttackJailbreak) {
			continue
		}
		checked = true
		owasp := md["owasp"]
		if !strings.Contains(owasp, "owasp-llm01") || !strings.Contains(owasp, "owasp-asi01") {
			t.Errorf("jailbreak finding owasp metadata = %q, want owasp-llm01 and owasp-asi01", owasp)
		}
	}
	if !checked {
		t.Fatal("no jailbreak finding emitted to assert OWASP metadata on")
	}
}
