package engine

import "strings"

// extractJavaScript turns JS/TS logical lines into unit drafts. JavaScript has
// no single lexically-clean function-header shape comparable to Python's `def`
// (function declarations, arrow functions, class methods, and object-literal
// methods all differ), and its bodies are brace-delimited rather than indented.
// Rather than half-parse scopes, this first cut accumulates all recognized
// statements into ONE module unit.
//
// WHY that is acceptable: merging scopes is conservative — it can only ever join
// a source and a sink that live in different functions into one unit, which at
// worst yields a flow that a stricter scoper would not (a false positive), never
// hides a real same-function flow. Because JS handler bodies are typically short
// and self-contained, the practical FP cost is low, and per-function JS scoping
// is called out as a documented limit and a clean follow-up. Python — the
// priority language — gets real per-function units.
func extractJavaScript(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" || isJSStructuralLine(trimmed) {
			continue
		}
		if st, ok := recognizeStatement(langJavaScript, ll); ok {
			module.stmts = append(module.stmts, st)
		}
	}
	return []unitDraft{*module}
}

// isJSStructuralLine reports whether a line is a block/scaffolding line whose
// header identifiers (function name, parameters, control keywords) must not be
// mistaken for a data-flow statement. This keeps `function h(req) {` from being
// read as a call to `h`. It is intentionally coarse — a missed skip only adds a
// harmless non-sink call to the module unit.
func isJSStructuralLine(trimmed string) bool {
	switch trimmed {
	case "{", "}", "})", "});", "};":
		return true
	}
	for _, kw := range []string{"function ", "function(", "if ", "if(", "for ", "for(",
		"while ", "while(", "switch ", "switch(", "class ", "return ", "else"} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	// Arrow-function / method headers ending in `=> {` or `) {`.
	if strings.HasSuffix(trimmed, "{") &&
		(strings.Contains(trimmed, "=>") || strings.Contains(trimmed, ") ")) {
		return true
	}
	return false
}
