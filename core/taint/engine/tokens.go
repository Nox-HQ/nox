package engine

import "sort"

// isIdentStart reports whether b can begin an identifier (letter or underscore;
// '$' allowed for JS).
func isIdentStart(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isIdentPart reports whether b can continue an identifier.
func isIdentPart(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}

// isSimpleIdent reports whether s is a single bare identifier (no dots, no
// brackets, no whitespace) — the only assignment LHS shape we track.
func isSimpleIdent(s string) bool {
	if s == "" {
		return false
	}
	if !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentPart(s[i]) {
			return false
		}
	}
	return !isKeyword(s)
}

// isKeyword reports whether s is a language keyword that must never be treated
// as a variable name (covers both Python and JS; a superset is harmless here).
func isKeyword(s string) bool {
	switch s {
	case "if", "elif", "else", "for", "while", "return", "yield", "def",
		"class", "import", "from", "as", "with", "try", "except", "finally",
		"raise", "pass", "break", "continue", "and", "or", "not", "in", "is",
		"lambda", "global", "nonlocal", "assert", "del", "async", "await",
		"True", "False", "None", "const", "let", "var", "function", "new",
		"typeof", "instanceof", "true", "false", "null", "undefined", "this",
		// Ruby keywords (superset; harmless for Python/JS since these names are
		// not valid identifiers there either or are already covered above).
		"end", "do", "then", "begin", "ensure", "rescue", "when", "case",
		"unless", "until", "elsif", "nil", "self", "module", "next", "redo",
		"retry", "super", "__FILE__", "__LINE__":
		return true
	}
	return false
}

// freeIdentifiers returns the bare variable names read in code: identifiers that
// are NOT the callee of a call (not immediately followed by `(`) and not a dotted
// attribute tail. This is what "reads a variable" means for propagation — a
// tainted var mentioned anywhere in an expression propagates. Deterministic and
// deduplicated.
func freeIdentifiers(_ langKind, code string) []string {
	seen := map[string]struct{}{}
	var out []string
	i := 0
	n := len(code)
	for i < n {
		if !isIdentStart(code[i]) {
			i++
			continue
		}
		start := i
		for i < n && isIdentPart(code[i]) {
			i++
		}
		name := code[start:i]
		// Skip a dotted attribute tail: if preceded by '.', it is an attribute,
		// not a free variable (the receiver at the head of a chain is still
		// recorded, which is harmless — a module name like `os` is never tainted,
		// and a real receiver like `q` in `q.strip()` correctly counts as a read).
		if start > 0 && code[start-1] == '.' {
			continue
		}
		if isKeyword(name) {
			continue
		}
		if _, dup := seen[name]; !dup {
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

// sortStrings sorts a string slice in place (stable, ascending) so statement
// reads and engine output are deterministic.
func sortStrings(s []string) {
	sort.Strings(s)
}
