package taint

// Chat/LLM message roles recognized by the role-aware prompt-injection analysis.
// They are the canonical, lowercased role strings used by the OpenAI/Anthropic
// chat-message schema (`{"role": "...", "content": ...}`) and by the separate
// system= parameter. Only these role placements are reasoned over; any other or
// unreadable role literal is treated as an undetermined role (kept conservatively).
const (
	// PromptRoleSystem and PromptRoleDeveloper are the instruction (trust-bearing)
	// roles. The model is trained to defer to their content, so untrusted input
	// here inverts the trust boundary — a real prompt injection.
	PromptRoleSystem    = "system"
	PromptRoleDeveloper = "developer"
	// PromptRoleUser is the data role. Untrusted input confined to the user role,
	// behind a static system message, is the recommended pattern — not a
	// high-severity injection.
	PromptRoleUser = "user"
	// PromptRoleUnknown marks a prompt sink whose landing role could not be
	// determined (dynamic message construction, indirection the analyzer cannot
	// follow). It is reported on the finding so the conservative verdict is
	// auditable; it never suppresses.
	PromptRoleUnknown = "unknown"
)

// IsPrivilegedPromptRole reports whether role is a trust-bearing instruction role
// (system or developer). Untrusted content landing in a privileged role is the
// genuine prompt injection this analysis must always keep; it is never suppressed.
func IsPrivilegedPromptRole(role string) bool {
	return role == PromptRoleSystem || role == PromptRoleDeveloper
}

// SuppressPromptRole reports whether a tainted value landing in role, at a call
// that also carries a static system message (hasStaticSystem), is the recommended
// data-boundary pattern rather than an injection — i.e. whether the prompt-injection
// finding for this landing should be suppressed.
//
// Policy — deliberately conservative, because for a security tool a missed real
// system-role injection (false negative) is worse than an extra lower-confidence
// finding:
//   - Suppress ONLY when the tainted value lands in the user role AND a static,
//     untainted system message establishes the instruction/data boundary. This is
//     exactly the shape the SDKs recommend and that examples/ai-app/safe.py models.
//   - NEVER suppress a privileged (system/developer) role — that is the injection.
//   - NEVER suppress an unknown/undetermined role, nor a user role that lacks a
//     static system boundary, nor any other role (assistant/tool/function): all are
//     kept so ambiguity and novel shapes fail toward reporting, not silence.
func SuppressPromptRole(role string, hasStaticSystem bool) bool {
	return role == PromptRoleUser && hasStaticSystem
}
