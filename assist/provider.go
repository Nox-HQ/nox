package assist

import "context"

// Role identifies the sender of a message in the chat conversation.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is a single entry in the chat conversation sent to the LLM.
type Message struct {
	Role    Role
	Content string
}

// Response holds the LLM's reply along with token usage metadata.
type Response struct {
	Content          string
	PromptTokens     int
	CompletionTokens int
}

// Provider is the interface for LLM backends. Implementations must be safe
// for concurrent use.
type Provider interface {
	Complete(ctx context.Context, messages []Message) (*Response, error)
}
