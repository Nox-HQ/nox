package engine

import "strings"

// extractPython turns Python logical lines into unit drafts. Function bodies
// (`def name(...):`) become their own units keyed by name; everything else
// accumulates into the module-level unit (funcName ""). Scoping is by `def`
// only — nested defs and classes fold into the enclosing unit, which is
// conservative (it can only ever merge scopes, never split a real flow) and
// keeps the recognizer simple.
func extractPython(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module

	for _, ll := range lines {
		code := ll.code
		trimmed := strings.TrimSpace(code)
		if trimmed == "" {
			continue
		}
		if name, ok := pyDefName(trimmed); ok {
			u := &unitDraft{funcName: name}
			units = append(units, u)
			cur = u
			continue
		}
		if st, ok := recognizeStatement(langPython, ll); ok {
			cur.stmts = append(cur.stmts, st)
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// pyDefName returns the function name if trimmed is a def header. `async def` is
// handled too. Returns ("", false) for anything else.
func pyDefName(trimmed string) (name string, ok bool) {
	rest := trimmed
	if strings.HasPrefix(rest, "async ") {
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "async "))
	}
	if !strings.HasPrefix(rest, "def ") {
		return "", false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "def "))
	paren := strings.IndexByte(rest, '(')
	if paren <= 0 {
		return "", false
	}
	return strings.TrimSpace(rest[:paren]), true
}
