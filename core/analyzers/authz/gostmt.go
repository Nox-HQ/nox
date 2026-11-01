package authz

import (
	"regexp"
	"strings"
)

// Statement and call-chain helpers shared by the Go and C# readers. Both read
// a lexically masked copy of the file (comments and string bodies are spaces,
// offsets are unchanged), so a bracket or a name found here is code.

// splitStatements cuts [from, to) into statements. A statement ends at a `;`,
// a `{` or a `}` outside parentheses and brackets, and, when newlines is set
// (Go), at a newline outside them unless the line plainly continues. Braces
// inside parentheses stay in their statement, so a call that takes a function
// literal is one statement.
func splitStatements(code string, from, to int, newlines bool) []span {
	var out []span
	depth, start := 0, from
	flush := func(end int) {
		if s := trimSpan(code, span{start, end}); s.end > s.start {
			out = append(out, s)
		}
	}
	for i := from; i < to; i++ {
		switch c := code[i]; c {
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		case ';', '{', '}':
			if depth == 0 {
				flush(i)
				start = i + 1
			}
		case '\n':
			if newlines && depth == 0 && !lineContinues(code, start, i) {
				flush(i)
				start = i + 1
			}
		}
	}
	flush(to)
	return out
}

// lineContinues reports whether the line ending at i is plainly unfinished: it
// ends in an operator, a comma or a dot, or the next line starts with a dot.
func lineContinues(code string, start, i int) bool {
	s := trimSpan(code, span{start, i})
	if s.end <= s.start {
		return false
	}
	return strings.IndexByte(".,+&|=", code[s.end-1]) >= 0
}

// seg is one `.name` or `.name(args)` link of a call chain.
type seg struct {
	name  string
	call  bool
	args  span // between the parentheses
	start int  // offset of name
	end   int  // offset just after the link
}

// parseChain reads s as `a.b(c).d(e)`. ok is false when s is anything else
// (an operator, a literal, a closure) so the caller falls back to scanning.
func parseChain(code string, s span) ([]seg, bool) {
	var out []seg
	i := s.start
	for i < s.end {
		j := i
		for j < s.end && isIdentByte(code[j]) {
			j++
		}
		if j == i {
			return nil, false
		}
		sg := seg{name: code[i:j], start: i, end: j}
		k := j
		for k < s.end && isSpace(code[k]) {
			k++
		}
		if k < s.end && code[k] == '(' {
			c := matchClose(code, k)
			if c < 0 || c >= s.end {
				return nil, false
			}
			sg.call, sg.args, sg.end = true, span{k + 1, c}, c+1
			k = c + 1
			for k < s.end && isSpace(code[k]) {
				k++
			}
		}
		out = append(out, sg)
		if k >= s.end {
			return out, true
		}
		if code[k] != '.' {
			return nil, false
		}
		i = k + 1
		for i < s.end && isSpace(code[i]) {
			i++
		}
	}
	return nil, false
}

// stmtCall is a call found anywhere in a statement.
type stmtCall struct {
	callee string // dotted name before the parenthesis
	start  int    // offset of the callee
	args   span
}

var calleeRe = regexp.MustCompile(`[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*$`)

// findCalls returns every call in s, outermost first, nested ones included.
func findCalls(code string, s span) []stmtCall {
	var out []stmtCall
	for i := s.start; i < s.end; i++ {
		if code[i] != '(' {
			continue
		}
		c := matchClose(code, i)
		if c < 0 || c > s.end {
			continue
		}
		loc := calleeRe.FindStringIndex(code[s.start:i])
		if loc == nil {
			continue
		}
		callee := strings.Join(strings.Fields(code[s.start+loc[0]:s.start+loc[1]]), "")
		if callee == "func" || callee == "if" || callee == "for" || callee == "switch" || callee == "return" {
			continue
		}
		out = append(out, stmtCall{callee: callee, start: s.start + loc[0], args: span{i + 1, c}})
	}
	return out
}

// splitParams reads a parameter list into names and types. Go groups names
// that share a type (`a, b string`); C# writes one per parameter. typeFirst
// selects the C# order (`Type name`).
func splitParams(code string, params span, typeFirst bool) (names, types []string) {
	items := splitArgs(code, params.start, params.end)
	if typeFirst {
		for _, it := range items {
			t := strings.TrimSpace(code[it.start:it.end])
			if eq := indexTop(t, '='); eq >= 0 {
				t = strings.TrimSpace(t[:eq])
			}
			k := strings.LastIndexAny(t, " \t\n")
			if k < 0 {
				names, types = append(names, ""), append(types, t)
				continue
			}
			names, types = append(names, t[k+1:]), append(types, t[:k])
		}
		return names, types
	}
	names, types = make([]string, len(items)), make([]string, len(items))
	last := ""
	for i := len(items) - 1; i >= 0; i-- {
		t := strings.TrimSpace(code[items[i].start:items[i].end])
		name, typ := t, ""
		if k := strings.IndexAny(t, " \t\n"); k >= 0 {
			name, typ = t[:k], strings.TrimSpace(t[k+1:])
		}
		if typ == "" && isPlainIdent(name) {
			names[i], types[i] = name, last
			continue
		}
		names[i], types[i], last = name, typ, typ
	}
	return names, types
}

// indexTop finds b outside brackets.
func indexTop(s string, b byte) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			depth--
		default:
			if s[i] == b && depth == 0 {
				return i
			}
		}
	}
	return -1
}

// goJoin joins path segments into one rooted path, dropping empty ones.
func goJoin(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p = strings.Trim(p, "/"); p != "" {
			kept = append(kept, p)
		}
	}
	return "/" + strings.Join(kept, "/")
}

func dirOfPath(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

// strictLiteral is stringLiteral for one literal and nothing else: "/"+"x"
// begins and ends with a quote but is a concatenation, which is not read.
func strictLiteral(raw []byte, code string, s span) (string, bool) {
	v, ok := stringLiteral(raw, code, s)
	if !ok || strings.TrimSpace(code[s.start+1:s.end-1]) != "" {
		return "", false
	}
	return v, true
}
