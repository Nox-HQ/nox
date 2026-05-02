// Example Go inference service. Demonstrates nox's Go-side LLM SDK
// detection. The model invocation here lands in ai.inventory.json
// alongside the TypeScript frontend's gpt-4o call.

package main

import (
	"context"
	"net/http"
	"os"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

func main() {
	client := anthropic.NewClient(option.WithAPIKey(os.Getenv("ANTHROPIC_API_KEY")))

	http.HandleFunc("/answer", func(w http.ResponseWriter, r *http.Request) {
		question := r.URL.Query().Get("q")

		// nox detects this invocation: anthropic / claude-3-5-sonnet-20241022.
		// Because we use a literal model id, the AIBOM captures the exact
		// version; unpinned models would be flagged by AI-019.
		message, err := client.Messages.New(context.Background(), anthropic.MessageNewParams{
			Model: "claude-3-5-sonnet-20241022",
			Messages: []anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock(question)),
			},
			MaxTokens: 1024,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(message.Content[0].Text))
	})

	_ = http.ListenAndServe(":8080", nil)
}
