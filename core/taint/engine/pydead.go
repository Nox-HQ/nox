package engine

import (
	"regexp"
	"strings"
)

// Dead-branch pruning for the Python extractor. See pyconst.go for why, and
// for the evaluator's refuse-rather-than-guess contract.
//
// A branch header is resolved to one of three states:
//
//	branchDead      the body provably never runs: its statements are dropped
//	branchTaken     the body provably runs: its statements are not conditional
//	branchMaybe     anything else: today's behaviour, a conditional body
//
// Only if/elif/else chains and match/case are resolved. Loops, try/except and
// with keep their existing treatment.
type branchState int

const (
	branchMaybe branchState = iota
	branchDead
	branchTaken
)

// pyChain is the state of an if/elif/else chain or a match at one indent.
type pyChain struct {
	kind    byte // 'i' if-chain, 'm' match
	decided bool // an earlier branch was branchTaken: every later one is dead
	unknown bool // an earlier branch was branchMaybe: no later one is taken
	subject pyValue
	subjOK  bool
}

var (
	pyAssignedNameRe = regexp.MustCompile(`(?m)(?:^|[\s,(])([A-Za-z_]\w*)\s*(?:\*\*|//|<<|>>|[-+*/%@&|^:])?=[^=]`)
	pyBindingKwRe    = regexp.MustCompile(`\b(?:for|as|global|nonlocal|del|import)\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)`)
	pyDefParamsRe    = regexp.MustCompile(`\bdef\s+\w+\s*\(([^)]*)\)`)
	pyIdentRe        = regexp.MustCompile(`[A-Za-z_]\w*`)
)

// pySingleAssigned returns the names the file binds exactly once, by a plain
// `name = value`. A name bound twice, by an augmented assignment, a for loop,
// `as`, an import, `global`/`nonlocal`/`del`, or as a parameter is never a
// constant.
func pySingleAssigned(lines []logicalLine) map[string]bool {
	count := map[string]int{}
	never := map[string]bool{}
	for _, ll := range lines {
		code := ll.code
		for _, m := range pyAssignedNameRe.FindAllStringSubmatch(code, -1) {
			count[m[1]]++
		}
		for _, m := range pyAugmentedAnywhere.FindAllStringSubmatch(code, -1) {
			never[m[1]] = true
		}
		for _, m := range pyBindingKwRe.FindAllStringSubmatch(code, -1) {
			for _, n := range pyIdentRe.FindAllString(m[1], -1) {
				never[n] = true
			}
		}
		for _, m := range pyDefParamsRe.FindAllStringSubmatch(code, -1) {
			for _, n := range pyIdentRe.FindAllString(m[1], -1) {
				never[n] = true
			}
		}
		if strings.Contains(code, ":=") {
			for _, m := range pyWalrusRe.FindAllStringSubmatch(code, -1) {
				never[m[1]] = true
			}
		}
	}
	out := map[string]bool{}
	for n, c := range count {
		if c == 1 && !never[n] {
			out[n] = true
		}
	}
	return out
}

var (
	pyAugmentedAnywhere = regexp.MustCompile(`([A-Za-z_]\w*)\s*(?:\*\*|//|<<|>>|[-+*/%@&|^])=`)
	pyWalrusRe          = regexp.MustCompile(`([A-Za-z_]\w*)\s*:=`)
)

// pyEvalText is the raw text of a code span with any trailing comment removed:
// the code view blanks string literals, which the evaluator needs, and the raw
// view keeps comments, which it must not read.
func pyEvalText(ll logicalLine, from, to int) string {
	raw := ll.raw
	if to > len(raw) {
		to = len(raw)
	}
	if from >= to {
		return ""
	}
	out := []byte(raw[from:to])
	code := ll.code
	for i := range out {
		// A '#' that the code view blanked is inside a string; one it kept as
		// a space where raw has '#' starts a comment. Cut at the latter.
		j := from + i
		if out[i] == '#' && j < len(code) && code[j] == ' ' && !insidePyString(raw[:j]) {
			return string(out[:i])
		}
	}
	return string(out)
}

// insidePyString reports whether the end of prefix is inside a quoted string.
func insidePyString(prefix string) bool {
	var q byte
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		switch {
		case q == 0 && (c == '\'' || c == '"'):
			q = c
		case q != 0 && c == '\\':
			i++
		case q != 0 && c == q:
			q = 0
		}
	}
	return q != 0
}

// resolveHeader decides a block header's state, updating the chain at indent.
func resolveHeader(trimmed string, ll logicalLine, indent int, chains map[int]*pyChain, enclosing *pyChain, env pyConstEnv) (branchState, bool) {
	head := strings.TrimSuffix(strings.TrimSpace(trimmed), ":")
	cond := func(kw string) (pyValue, bool) {
		at := strings.Index(ll.code, kw) + len(kw)
		end := strings.LastIndex(ll.code, ":")
		if at < len(kw) || end <= at {
			return pyValue{}, false
		}
		return evalPyConst(pyEvalText(ll, at, end), env)
	}
	decide := func(c *pyChain, v pyValue, ok bool) branchState {
		switch {
		case c.decided:
			return branchDead
		case !ok:
			c.unknown = true
			return branchMaybe
		case !v.truthy():
			return branchDead
		case c.unknown:
			return branchMaybe
		default:
			c.decided = true
			return branchTaken
		}
	}
	switch {
	case strings.HasPrefix(head, "if ") || strings.HasPrefix(head, "if("):
		c := &pyChain{kind: 'i'}
		chains[indent] = c
		v, ok := cond("if")
		return decide(c, v, ok), true
	case strings.HasPrefix(head, "elif ") || strings.HasPrefix(head, "elif("):
		c := chains[indent]
		if c == nil || c.kind != 'i' {
			return branchMaybe, true
		}
		v, ok := cond("elif")
		return decide(c, v, ok), true
	case head == "else":
		c := chains[indent]
		if c == nil || c.kind != 'i' {
			return branchMaybe, false // for/while/try else: not ours
		}
		return decide(c, pyValue{kind: 'b', b: true}, true), true
	case strings.HasPrefix(head, "match "):
		v, ok := cond("match")
		chains[indent] = &pyChain{kind: 'm', subject: v, subjOK: ok}
		return branchTaken, true // the match statement itself always runs
	case strings.HasPrefix(head, "case "):
		if enclosing == nil || enclosing.kind != 'm' {
			return branchMaybe, true
		}
		// The pattern is read from the raw text: the code view blanks the
		// string literals a case pattern is made of.
		at := strings.Index(ll.code, "case") + len("case")
		end := strings.LastIndex(ll.code, ":")
		if end <= at {
			enclosing.unknown = true
			return branchMaybe, true
		}
		return resolveCase(pyEvalText(ll, at, end), enclosing), true
	}
	return branchMaybe, false
}

// resolveCase decides a `case` arm against a constant match subject. Only
// literal patterns joined by `|`, and the wildcard `_`, are understood; a
// capture, a class pattern or a guard makes the arm branchMaybe.
func resolveCase(pattern string, m *pyChain) branchState {
	if m.decided {
		return branchDead
	}
	if !m.subjOK || strings.Contains(pattern, " if ") {
		m.unknown = true
		return branchMaybe
	}
	for _, alt := range strings.Split(pattern, "|") {
		alt = strings.TrimSpace(alt)
		if alt == "_" {
			if m.unknown {
				return branchMaybe
			}
			m.decided = true
			return branchTaken
		}
		v, ok := evalPyConst(alt, nil)
		if !ok {
			m.unknown = true
			return branchMaybe
		}
		if v.equal(m.subject) {
			if m.unknown {
				return branchMaybe
			}
			m.decided = true
			return branchTaken
		}
	}
	return branchDead
}

// rewriteConstTernary turns `x = a if C else b` with a constant C into
// `x = a` or `x = b`, keeping the code and raw views aligned by blanking.
func rewriteConstTernary(ll logicalLine, env pyConstEnv) logicalLine {
	code := ll.code
	ifAt, elseAt := topLevelKeyword(code, " if "), topLevelKeyword(code, " else ")
	eq := strings.Index(code, "=")
	if ifAt < 0 || elseAt < ifAt || eq < 0 || eq > ifAt {
		return ll
	}
	v, ok := evalPyConst(pyEvalText(ll, ifAt+len(" if "), elseAt), env)
	if !ok {
		return ll
	}
	if v.truthy() {
		return logicalLine{line: ll.line, code: blankRange(code, ifAt, len(code)), raw: blankRange(ll.raw, ifAt, min(len(code), len(ll.raw)))}
	}
	return logicalLine{line: ll.line, code: blankRange(code, eq+1, elseAt+len(" else ")), raw: blankRange(ll.raw, eq+1, min(elseAt+len(" else "), len(ll.raw)))}
}

// topLevelKeyword returns the offset of kw in s outside any bracket, or -1.
func topLevelKeyword(s, kw string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		default:
			if depth == 0 && strings.HasPrefix(s[i:], kw) {
				return i
			}
		}
	}
	return -1
}
