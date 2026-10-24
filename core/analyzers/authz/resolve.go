package authz

import (
	"regexp"
	"sort"
	"strings"
)

// fnRef is a function body located in a file.
type fnRef struct {
	file *jsFile
	s    span
	name string
}

var inlineFnRe = regexp.MustCompile(`^(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]*)?=>|[A-Za-z_$][\w$]*\s*=>)`)

// resolveHandler maps a route's handler argument to the function text that
// handles the request. It follows the shapes Express code actually uses: an
// inline function; a wrapper call around one (`asyncHandler(fn)`,
// `catchAsync(async (req, res) => …)`); a factory call (`retrieveBasket()`)
// whose definition returns the handler; and a named reference resolved through
// the file's own definitions and its imports. Anything else is unresolved,
// and an unresolved handler is never reported on.
func (ix *index) resolveHandler(f *jsFile, s span, depth int) (fnRef, bool) {
	if depth > 4 || s.end <= s.start {
		return fnRef{}, false
	}
	text := f.code[s.start:s.end]
	if inlineFnRe.MatchString(text) {
		return fnRef{file: f, s: s}, true
	}
	if text[len(text)-1] == ')' {
		open := strings.IndexByte(text, '(')
		if open <= 0 || matchClose(f.code, s.start+open) != s.end-1 {
			return fnRef{}, false
		}
		callee := strings.TrimSpace(text[:open])
		args := splitArgs(f.code, s.start+open+1, s.end-1)
		if len(args) == 1 {
			if r, ok := ix.resolveHandler(f, args[0], depth+1); ok {
				return r, true // a wrapper around the handler
			}
		}
		if isChain(callee) {
			return ix.resolveName(f, callee) // a factory returning the handler
		}
		return fnRef{}, false
	}
	if isChain(text) {
		return ix.resolveName(f, text)
	}
	return fnRef{}, false
}

var chainOnlyRe = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$`)

func isChain(s string) bool { return chainOnlyRe.MatchString(s) }

func chainSegments(s string) []string {
	parts := strings.Split(s, ".")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// resolveName finds the definition a (possibly dotted) name refers to.
func (ix *index) resolveName(f *jsFile, chain string) (fnRef, bool) {
	segs := chainSegments(chain)
	name := segs[len(segs)-1]
	if len(segs) == 1 {
		if s, ok := findDefinition(f, name); ok {
			return fnRef{file: f, s: s, name: name}, true
		}
		if n, ok := f.named[name]; ok {
			if g := ix.files[n.file]; g != nil {
				if s, ok := findDefinition(g, n.name); ok {
					return fnRef{file: g, s: s, name: n.name}, true
				}
			}
		}
	} else {
		base := segs[0]
		target := ""
		if t, ok := f.modules[base]; ok {
			target = t
		} else if n, ok := f.named[base]; ok {
			target = n.file
		}
		if g := ix.files[target]; g != nil {
			if s, ok := findDefinition(g, name); ok {
				return fnRef{file: g, s: s, name: name}, true
			}
		}
		if base == "this" {
			if s, ok := findDefinition(f, name); ok {
				return fnRef{file: f, s: s, name: name}, true
			}
		}
	}
	return ix.uniqueDefinition(name)
}

// uniqueDefinition is the last resort: a name defined in exactly one file of
// the repository. Two definitions means the reference is ambiguous, and an
// ambiguous handler is not analysed.
func (ix *index) uniqueDefinition(name string) (fnRef, bool) {
	var found []fnRef
	for _, p := range ix.order {
		g := ix.files[p]
		if _, maybe := g.definitions()[name]; !maybe {
			continue
		}
		if s, ok := findDefinition(g, name); ok {
			found = append(found, fnRef{file: g, s: s, name: name})
			if len(found) > 1 {
				return fnRef{}, false
			}
		}
	}
	if len(found) == 1 {
		return found[0], true
	}
	return fnRef{}, false
}

// findDefinition locates the definition of name in f and returns the span of
// the defining expression or function. Function declarations, variable and
// export bindings, object properties and class/object methods are recognised.
func findDefinition(f *jsFile, name string) (span, bool) {
	for _, c := range f.definitions()[name] {
		if s, ok := definitionSpan(f, c.kind, c.loc); ok {
			return s, true
		}
	}
	return span{}, false
}

const (
	defFunction = iota
	defBinding
	defProperty
	defMethod
)

// defCand is one place a name may be defined: the match locations of the
// pattern of its kind (loc[0]/loc[1] the whole match, loc[2]/loc[3] the name).
type defCand struct {
	kind int
	loc  []int
}

var definitionPatterns = []*regexp.Regexp{
	defFunction: regexp.MustCompile(`\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\(`),
	defBinding:  regexp.MustCompile(`(?:\b(?:const|let|var)\s+|\b(?:exports|module\s*\.\s*exports|this)\s*\.\s*)([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=\s*`),
	defProperty: regexp.MustCompile(`[{,]\s*([A-Za-z_$][\w$]*)\s*:\s*`),
	defMethod:   regexp.MustCompile(`(?m)^[ \t]*(?:(?:public|private|protected|static|async|export|default)\s+)*([A-Za-z_$][\w$]*)\s*\(`),
}

// definitions indexes, once per file, every candidate definition by name, in
// source order.
func (f *jsFile) definitions() map[string][]defCand {
	if f.defs != nil {
		return f.defs
	}
	type located struct {
		at int
		defCand
	}
	byName := map[string][]located{}
	for kind, re := range definitionPatterns {
		for _, loc := range re.FindAllStringSubmatchIndex(f.code, -1) {
			name := f.code[loc[2]:loc[3]]
			byName[name] = append(byName[name], located{loc[0], defCand{kind, loc}})
		}
	}
	f.defs = make(map[string][]defCand, len(byName))
	for name, ls := range byName {
		sort.Slice(ls, func(i, j int) bool {
			if ls[i].at != ls[j].at {
				return ls[i].at < ls[j].at
			}
			return ls[i].kind < ls[j].kind
		})
		cands := make([]defCand, len(ls))
		for i := range ls {
			cands[i] = ls[i].defCand
		}
		f.defs[name] = cands
	}
	return f.defs
}

func definitionSpan(f *jsFile, kind int, loc []int) (span, bool) {
	code := f.code
	switch kind {
	case defFunction, defMethod:
		open := loc[1] - 1
		closeAt := matchClose(code, open)
		if closeAt < 0 {
			return span{}, false
		}
		brace := nextBrace(code, closeAt+1)
		if brace < 0 {
			return span{}, false
		}
		end := matchClose(code, brace)
		if end < 0 {
			return span{}, false
		}
		return span{loc[0], end + 1}, true
	default:
		start := loc[1]
		end := expressionEnd(code, start, kind == defProperty)
		if end <= start {
			return span{}, false
		}
		rhs := strings.TrimSpace(code[start:end])
		if kind == defProperty && !inlineFnRe.MatchString(rhs) {
			return span{}, false
		}
		return span{start, end}, true
	}
}

// nextBrace returns the offset of the `{` that opens a function body after a
// parameter list, skipping a TypeScript return type. A `;` or `=>`-less
// newline before any brace means this was a call, not a definition.
func nextBrace(code string, from int) int {
	for i := from; i < len(code) && i < from+200; i++ {
		switch code[i] {
		case '{':
			return i
		case ';', ')', '}', ',', '=':
			return -1
		case '\n':
			// `foo(x)\n{` is not a JS method; a method body opens on its line.
			if strings.TrimSpace(code[from:i]) == "" {
				continue
			}
			if !strings.Contains(code[from:i], ":") {
				return -1
			}
		}
	}
	return -1
}

// expressionEnd returns the end of the expression starting at from: the first
// `;` at depth zero, a `,` at depth zero when inObject, or a newline at depth
// zero that does not continue the expression.
func expressionEnd(code string, from int, inObject bool) int {
	depth := 0
	for i := from; i < len(code); i++ {
		switch c := code[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		case ';':
			if depth == 0 {
				return i
			}
		case ',':
			if depth == 0 && inObject {
				return i
			}
		case '\n':
			if depth == 0 && !continues(code, from, i) {
				return i
			}
		}
	}
	return len(code)
}

// continues reports whether the line ending at nl carries on into the next:
// it ends with an operator, or the next line starts with one.
func continues(code string, from, nl int) bool {
	prev := strings.TrimRight(code[from:nl], " \t\r")
	if prev == "" {
		return true
	}
	if strings.HasSuffix(prev, "=>") || strings.ContainsAny(prev[len(prev)-1:], "=,(+-*/&|?:.[{") {
		return true
	}
	rest := strings.TrimLeft(code[nl+1:], " \t\r\n")
	return rest != "" && strings.ContainsAny(rest[:1], ".?:+-*/&|)]}")
}
