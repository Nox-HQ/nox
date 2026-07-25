package engine

import (
	"strings"

	"github.com/nox-hq/nox/core/taint"
)

// detectPromptRoles inspects a call's argument text and, when the call is
// chat-message-shaped, returns (a) a map from each variable that appears inside a
// prompt message to the chat role that message occupies, and (b) whether a static
// (untainted) system message is present. It is the substrate that makes the
// prompt-injection rules role-aware: reaching an LLM is necessary but not
// sufficient — WHERE the untrusted value lands (the trust-bearing system role vs
// the data-carrying user role) is the real differentiator.
//
// HOW THE ROLE IS DETERMINED (deterministic, no code execution):
//   - rawArgs (string literals intact) and codeArgs (literals blanked, only real
//     code — including f-string interpolations — surviving) are byte-aligned slices
//     of the SAME call's argument text, so a span located in one view slices the
//     same bytes in the other. The role LITERAL (e.g. "system") is read from the
//     raw view; the interpolated variable identifiers are read from the code view.
//   - The call's top-level arguments are split at bracket depth 0. A messages=[…]
//     (or contents=[…]) keyword whose value is a list literal is parsed into its
//     {…} message objects; for each object the "role" key's string literal gives
//     the role and the object's surviving code identifiers are the variables that
//     land in that role. A system= / system_prompt= / system_instruction= keyword
//     (Anthropic/Gemini) treats its value's identifiers as system-role, and a
//     static string value there counts as a static system message.
//   - A message object whose role is dynamic (no readable string literal) yields no
//     mapping for its variables — they stay undetermined, which the caller keeps
//     conservatively. A messages= value that is a bare variable (dynamic message
//     construction) yields an empty map for the same reason.
//
// PRECEDENCE: a variable that appears in more than one role keeps the most
// privileged (system/developer beats a data role), so a value used in both a
// system and a user message is still judged an injection.
//
// LANGUAGE SCOPE: Python only. The chat-message shape here is the Python SDK form
// (keyword args with `=`, dict literals with `{"role": ...}`). JS/TS and the other
// languages the taint engine supports pass an object literal positionally
// (`create({ messages: [...] })`) with a different punctuation; determining role
// there cleanly is out of reach for this line recognizer, so those languages keep
// their existing role-blind behavior (every reaching value is reported) — a
// deliberate, documented conservative limit, never a downgrade. Returns (nil,
// false) for any non-Python language or any call with no recognizable role
// structure.
func detectPromptRoles(lang langKind, rawArgs, codeArgs string) (map[string]string, bool) {
	if lang != langPython {
		return nil, false // other languages: keep role-blind behavior (see doc).
	}
	// The two views must be byte-aligned for span slicing to be sound; if they are
	// not (should not happen), fail safe by reporting no role structure.
	if len(rawArgs) != len(codeArgs) {
		return nil, false
	}
	// Cheap gate: only chat-message-shaped calls carry these keywords. Avoids
	// parsing every call's arguments.
	if !strings.Contains(codeArgs, "messages") &&
		!strings.Contains(codeArgs, "contents") &&
		!strings.Contains(codeArgs, "system") {
		return nil, false
	}

	roles := map[string]string{}
	staticSystem := false

	for _, slot := range topLevelCommaSpans(codeArgs, 0, len(codeArgs)) {
		name, valStart := keywordAndValueStart(codeArgs, slot.start, slot.end)
		if name == "" {
			continue // positional argument: not a recognized role-bearing keyword.
		}
		switch name {
		case "messages", "contents":
			ss := addMessageListRoles(roles, rawArgs, codeArgs, valStart, slot.end)
			staticSystem = staticSystem || ss
		case "system", "system_prompt", "system_instruction":
			// A separate system parameter (Anthropic/Gemini): its identifiers are
			// system-role, and a purely static string value is a static system
			// boundary.
			ids := freeIdentifiers(langPython, codeArgs[valStart:slot.end])
			for _, id := range ids {
				promoteRole(roles, id, taint.PromptRoleSystem)
			}
			if len(ids) == 0 && strings.TrimSpace(rawArgs[valStart:slot.end]) != "" {
				staticSystem = true
			}
		}
	}

	if len(roles) == 0 && !staticSystem {
		return nil, false
	}
	return roles, staticSystem
}

// promptSinkRole returns the chat role the variable v lands in at a prompt sink,
// per the call's detected role map, or taint.PromptRoleUnknown when v's role could
// not be determined (dynamic construction, non-Python language, unreadable role).
// Unknown is reported on the finding and never suppresses — ambiguity is kept.
func promptSinkRole(info taint.SinkArgInfo, v string) string {
	if role, ok := info.PromptRoles[v]; ok {
		return role
	}
	return taint.PromptRoleUnknown
}

// byteSpan is a half-open [start,end) byte range into an argument string.
type byteSpan struct{ start, end int }

// topLevelCommaSpans splits s[lo:hi) into comma-separated spans at bracket depth 0
// (commas nested inside (), [], or {} do not split). Deterministic; always returns
// at least one span.
func topLevelCommaSpans(s string, lo, hi int) []byteSpan {
	var spans []byteSpan
	depth := 0
	start := lo
	for i := lo; i < hi && i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				spans = append(spans, byteSpan{start, i})
				start = i + 1
			}
		}
	}
	spans = append(spans, byteSpan{start, hi})
	return spans
}

// keywordAndValueStart, for the argument slot code[start:end), returns the keyword
// name and the byte offset (into code) where its value begins, when the slot is a
// keyword argument `name = value` at top level. Returns ("", 0) for a positional
// argument, a comparison, or an empty slot. The `=` must be top level (not inside
// brackets) and a real assignment (not ==, <=, >=, !=).
func keywordAndValueStart(code string, start, end int) (name string, valStart int) {
	depth := 0
	for i := start; i < end; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 {
				continue
			}
			if i+1 < end && code[i+1] == '=' {
				return "", 0 // comparison, not a keyword arg
			}
			if i > start {
				switch code[i-1] {
				case '=', '!', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^':
					return "", 0
				}
			}
			nm := strings.TrimSpace(code[start:i])
			if !isSimpleIdent(nm) {
				return "", 0
			}
			return nm, i + 1
		}
	}
	return "", 0
}

// addMessageListRoles parses a messages=[…] value (raw and code views, byte-aligned)
// and records, for each {role, content} object, the role of every variable it
// carries. It returns whether a static (variable-free) system/developer message was
// found — the data boundary that legitimizes untrusted content in the user role.
// A value that is not a `[…]` list literal (a bare variable: dynamic construction)
// records nothing and returns false, so such calls stay conservatively reported.
func addMessageListRoles(roles map[string]string, raw, code string, valStart, valEnd int) bool {
	// Locate the list literal within the value span.
	open := indexAt(code, '[', valStart, valEnd)
	if open < 0 {
		return false // messages is a variable / not a literal list: dynamic.
	}
	closeIdx := matchBracket(code, open, '[', ']')
	if closeIdx < 0 || closeIdx > valEnd {
		return false
	}
	staticSystem := false
	for _, obj := range topLevelCommaSpans(code, open+1, closeIdx) {
		codeObj := code[obj.start:obj.end]
		rawObj := raw[obj.start:obj.end]
		if strings.TrimSpace(codeObj) == "" {
			continue // trailing comma / empty slot
		}
		role := roleLiteral(rawObj)
		if role == "" {
			continue // dynamic/unreadable role: leave this object's vars undetermined.
		}
		ids := contentIdentifiers(codeObj)
		if len(ids) == 0 {
			// A message with no interpolated variable is static content. A static
			// system/developer message is the instruction/data boundary we look for.
			if taint.IsPrivilegedPromptRole(role) {
				staticSystem = true
			}
			continue
		}
		for _, id := range ids {
			promoteRole(roles, id, role)
		}
	}
	return staticSystem
}

// roleLiteral extracts the value of the "role" key from a raw message-object text
// like `{"role": "system", "content": …}`. It finds the `role` key (an identifier
// immediately followed, after an optional closing quote and spaces, by a colon —
// which distinguishes the key from the word "role" appearing inside content text)
// and returns the next quoted string, lowercased and trimmed. Returns "" when the
// role is absent or dynamic (not a string literal).
func roleLiteral(rawObj string) string {
	n := len(rawObj)
	for i := 0; i+4 <= n; i++ {
		if rawObj[i:i+4] != "role" {
			continue
		}
		// Reject a longer identifier that merely contains "role" (e.g. "roles").
		if i > 0 && isIdentPart(rawObj[i-1]) {
			continue
		}
		if i+4 < n && isIdentPart(rawObj[i+4]) {
			continue
		}
		// After the key, skip an optional closing quote and whitespace; require a
		// colon so this is the KEY position, not the word inside content.
		j := i + 4
		for j < n && (rawObj[j] == '"' || rawObj[j] == '\'' || rawObj[j] == ' ' || rawObj[j] == '\t') {
			j++
		}
		if j >= n || rawObj[j] != ':' {
			continue
		}
		return firstQuotedString(rawObj[j+1:])
	}
	return ""
}

// firstQuotedString returns the contents of the first single- or double-quoted
// string in s, lowercased and trimmed, or "" if the next non-space token is not a
// quoted string (a dynamic role value).
func firstQuotedString(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) || (s[i] != '"' && s[i] != '\'') {
		return "" // dynamic role (a variable/expression), not a literal.
	}
	q := s[i]
	i++
	start := i
	for i < len(s) && s[i] != q {
		i++
	}
	if i >= len(s) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(s[start:i]))
}

// contentIdentifiers returns the variable identifiers surviving in a message
// object's CODE view (string literals — the "role"/"content" keys and any static
// text — already blanked), which are exactly the values interpolated into the
// message content (directly or via an f-string). Deterministic and deduplicated.
func contentIdentifiers(codeObj string) []string {
	return freeIdentifiers(langPython, codeObj)
}

// promoteRole records role for variable v, keeping the most privileged role when v
// appears in more than one message. Precedence: system/developer (privileged) beats
// any non-privileged role; among non-privileged roles a non-user role (assistant/
// tool/function) beats user, so a value used in both user and another role is kept
// (conservatively reported) rather than suppressed as a pure user-role value.
func promoteRole(roles map[string]string, v, role string) {
	cur, ok := roles[v]
	if !ok || rolePriority(role) > rolePriority(cur) {
		roles[v] = role
	}
}

// rolePriority ranks roles so promoteRole keeps the most dangerous placement.
func rolePriority(role string) int {
	switch {
	case taint.IsPrivilegedPromptRole(role):
		return 3
	case role == taint.PromptRoleUser:
		return 1
	default:
		return 2 // assistant/tool/function/other recognized-but-non-user role
	}
}

// indexAt returns the index of the first byte b in s within [lo,hi), or -1.
func indexAt(s string, b byte, lo, hi int) int {
	if hi > len(s) {
		hi = len(s)
	}
	for i := lo; i < hi; i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
