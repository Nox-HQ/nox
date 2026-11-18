package ai

// The directive vocabulary of an injected instruction, written once.
//
// An instruction planted for an agent says the same few things wherever it is
// planted: discard what you were told, hide this from the person you work for,
// move this data out. AGENT-001 and AGENT-004 look for those in the files that
// steer a coding agent; MCP-027 looks for them in the description of an MCP
// tool, which the model reads with the same authority. They are built from
// these constants so the three cannot drift into three slightly different
// ideas of what a concealment directive is.
//
// Each is a fragment of an (?i) RE2 pattern with no anchors, so it composes by
// alternation. What each rule adds around them is its own: the files it scans
// and the region of the file the match must lie in.
const (
	// agentOverrideDirective is "ignore your previous instructions" and its
	// kin: a verb of discarding, within a clause of a scope word and an
	// instruction noun.
	agentOverrideDirective = `\b(ignore|disregard|forget|override|bypass)\b[^\n]{0,50}\b(previous|prior|earlier|above|all|system|safety|your)\b[^\n]{0,30}\b(instruction|prompt|rule|guardrail|guideline|constraint|direction|restriction)s?\b`

	// agentConcealDirective is an order to keep an action from the person the
	// agent works for.
	agentConcealDirective = `(do\s*not|don't|never)\s+(tell|inform|reveal|disclose|mention|notify|warn|alert)\s+(the\s+)?(user|human|operator|developer|owner)`

	// agentExfilVerb and agentLeakVerb are the verbs of moving data out.
	// Words in a rules file; in a tool description "leak" is as often a memory
	// leak being detected as data being leaked, which is why MCP-027 takes
	// only agentExfilVerb.
	agentExfilVerb = `exfiltrate`
	agentLeakVerb  = `leak`

	// agentSendToSink is a send-like verb followed, on the same line, by a
	// destination or a credential noun.
	agentSendToSink = `\b(send|post|upload|forward|transmit)\b[^\n]{0,40}(https?://|webhook|api[_-]?key|secret|token|credential)`

	// mcpSecretExfilDirective is MCP-011's pattern: an exfiltration verb on a
	// secret noun, or a read of a sensitive file. The optional leading
	// negation is part of the match only so a validate hook can veto a
	// refusal ("do not forward credentials").
	mcpSecretExfilDirective = `(?:(?:\bnot|\bnever|n't|\bwithout)\s+)?(?:(?:exfiltrate|send|upload|leak|transmit|post|forward)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~/\.ssh|\.ssh/|id_rsa|\.env\b|/etc/passwd|api[_-]?keys?|secrets?|credentials?|environment\s+variables?|access[_-]?tokens?)|(?:read|cat)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~/\.ssh|\.ssh/|id_rsa|\.env\b|/etc/passwd))`

	// mcpConfigReadDirective is a read of another tool's configuration: the
	// poisoned-tool demonstration reads ~/.cursor/mcp.json, the file that
	// lists every other server and its credentials, and passes it back
	// through a parameter.
	mcpConfigReadDirective = `\b(?:read|cat|open|load|access|include|attach)\s+(?:the\s+)?(?:contents?\s+of\s+)?[^\s'"` + "`" + `]*(?:mcp\.json|claude_desktop_config\.json|mcp_config\.json|\.cursor/|\.claude/|\.aws/credentials|\.netrc|\.npmrc)`
)

// agentRulesOverridePattern is AGENT-001's pattern.
const agentRulesOverridePattern = `(?i)` + agentOverrideDirective

// agentRulesConcealPattern is AGENT-004's pattern: concealment, exfiltration
// verbs, and a send to a sink.
const agentRulesConcealPattern = `(?i)(` + agentConcealDirective + `|\b(` + agentExfilVerb + `|` + agentLeakVerb + `)\b|` + agentSendToSink + `)`
