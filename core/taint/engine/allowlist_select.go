package engine

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/taint"
)

// An allowlist select is the defence an ORDER BY column needs, since a column
// cannot be bound as a query parameter:
//
//	const ALLOWED = new Set(["title", "status", "createdAt"]);
//	const column = ALLOWED.has(sortField) ? sortField : "createdAt";
//	prisma.$queryRawUnsafe(`… ORDER BY "${column}" …`, filter);
//
// No sanitizer is called, so column read sortField and was tainted, and every
// such query was reported exactly as the unguarded one beside it (the RealVuln
// "safe twins": six of the twelve findings the Prisma/TypeORM/JPA/R2DBC sinks
// added). What makes it a defence is that the assigned value is always one the
// code itself wrote down:
//
//   - a membership select: the checked value when a literal collection holds
//     it, a literal otherwise (`C.has(v) ? v : "x"`, `v if v in C else "x"`,
//     `if (v in C) v else "x"`); or
//   - a lookup: a value of a literal map, with an optional literal default
//     (`M.getOrDefault(k, "x")`, `M.get(k, "x")`, `M[k] ?? "x"`) -- the key
//     selects, it is never what is returned.
//
// The collection must be provably literal: written inline, or bound once in the
// file to literals only and never reassigned or added to except with literals.
// A collection this cannot see into (a parameter, a config value, a set built
// from a query) leaves the finding as it was: unrecognized is not refuted.
//
// It clears every class. The value is one of the code's own literals, so it
// carries nothing the request supplied into any sink.

// litTok matches one string or numeric literal in raw source.
var litTok = regexp.MustCompile(`'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|` + "`[^`$\\\\\\n]*`" + `|\b\d+(?:\.\d+)?\b`)

// collectionOpener is what may follow `NAME =` to start a collection literal or
// a call that builds one from its arguments, up to and including its bracket.
const collectionOpener = `(new\s+(?:Set|Map)\s*(?:<[^>\n]*>)?\s*\(\s*|frozenset\s*\(\s*|set\s*\(\s*|tuple\s*\(\s*|Object\.freeze\s*\(\s*|` +
	`(?:Set|List|Map|EnumSet)\.of\s*|Arrays\.asList\s*|Collections\.unmodifiable\w+\s*\(\s*(?:Set|List|Map)\.of\s*|` +
	`(?:mutable|hash|linkedHash|sorted)?(?:[sS]etOf|[lL]istOf|[mM]apOf)\s*|ImmutableSet\.of\s*|ImmutableList\.of\s*|ImmutableMap\.of\s*)?` +
	`([\[{(])`

// emptyCollection is what may follow `NAME =` to bind an empty map or set: a
// collection that is literal when every store into it is.
const emptyCollection = `(?:new\s+(?:Hash|LinkedHash|Tree|Concurrent|Enum)?(?:Map|Set)\s*(?:<[^>\n]*>)?\s*\(\s*\)|mutableMapOf\s*\(\s*\)|mutableSetOf\s*\(\s*\)|new\s+Map\s*\(\s*\)|new\s+Set\s*\(\s*\)|\{\s*\}|dict\s*\(\s*\)|set\s*\(\s*\))`

// After an occurrence of a collection's name: its binding to a collection
// literal, its binding to an empty collection, any assignment to it, a store
// call into it, and a subscript store. Anchored at the occurrence, so each is
// matched against a few hundred bytes, not the file.
var (
	afterAssign  = `^\s*(?::\s*[^=\n;]+?)?\s*=\s*`
	afterBind    = regexp.MustCompile(afterAssign + collectionOpener)
	afterEmpty   = regexp.MustCompile(afterAssign + emptyCollection)
	afterRebind  = regexp.MustCompile(`^\s*(?::\s*[^=\n;]+?)?\s*=[^=>]`)
	afterStore   = regexp.MustCompile(`^\s*\.\s*(?:put|putIfAbsent|add|addAll|push|unshift|set|append|insert|update|extend|setdefault|computeIfAbsent|merge)\s*\(`)
	afterSubSet  = regexp.MustCompile(`^\s*\[[^\]\n]*\]\s*=[^=]([^\n;]*)`)
	occurrenceIn = 400
)

// occurrences returns the offsets just past each whole-identifier occurrence
// of name that is not a member of something else (`x.name`).
func occurrences(content, name string) []int {
	var out []int
	for from := 0; ; {
		i := strings.Index(content[from:], name)
		if i < 0 {
			return out
		}
		i += from
		end := i + len(name)
		from = end
		if i > 0 && (isIdentByte(content[i-1]) || content[i-1] == '$' || content[i-1] == '.') {
			continue
		}
		if end < len(content) && (isIdentByte(content[end]) || content[end] == '$') {
			continue
		}
		out = append(out, end)
	}
}

// isLiteralCollection reports whether name is bound in content exactly once,
// to a collection of literals only (or an empty one), and never rebound or
// stored into with anything but literals.
func isLiteralCollection(content, name string) bool {
	bindings, assigns := 0, 0
	literal := false
	for _, at := range occurrences(content, name) {
		window := content[at:min(len(content), at+occurrenceIn)]
		switch {
		case afterBind.MatchString(window):
			bindings++
			m := afterBind.FindStringSubmatchIndex(window)
			open := at + m[4]
			end := closeAt(content, open)
			literal = end > 0 && literalBody(content[open+1:end-1])
		case afterEmpty.MatchString(window):
			bindings++
			literal = true
		case afterRebind.MatchString(window):
			assigns++
		case afterStore.MatchString(window):
			m := afterStore.FindStringIndex(window)
			open := at + m[1] - 1
			end := closeAt(content, open)
			if end < 0 || !literalBody(content[open+1:end-1]) {
				return false
			}
		default:
			if m := afterSubSet.FindStringSubmatch(window); len(m) > 1 && !literalBody(m[1]) {
				return false
			}
		}
	}
	return bindings == 1 && assigns == 0 && literal
}

// literalBody reports whether the text between a collection's brackets holds
// literals only: elements, map entries (`"a": "b"`, `"a" to "b"`, `"a", "b"`
// in Map.of, `key: "b"` in a JS object), nested pairs and nothing else.
func literalBody(body string) bool {
	if !litTok.MatchString(body) {
		return false
	}
	rest := litTok.ReplaceAllString(body, " ")
	rest = jsObjectKey.ReplaceAllString(rest, " ")
	rest = kotlinTo.ReplaceAllString(rest, " ")
	rest = asConst.ReplaceAllString(rest, " ")
	rest = lineComment.ReplaceAllString(rest, " ")
	return strings.Trim(rest, " \t\r\n,:()[]{}=>") == "" && !strings.ContainsAny(strings.TrimSpace(rest), "+*/%$`!?&|")
}

var (
	jsObjectKey = regexp.MustCompile(`[A-Za-z_$][\w$]*\s*:`)
	kotlinTo    = regexp.MustCompile(`\bto\b`)
	asConst     = regexp.MustCompile(`\bas\s+const\b`)
	lineComment = regexp.MustCompile(`(?m)(?://|#)[^\n]*$`)
)

// closeAt returns the index just past the bracket matching the one at open,
// skipping string literals, or -1.
func closeAt(s string, open int) int {
	pairs := map[byte]byte{'[': ']', '{': '}', '(': ')'}
	var stack []byte
	for i := open; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'', '"', '`':
			j := i + 1
			for j < len(s) && s[j] != c {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			i = j
		case '[', '{', '(':
			stack = append(stack, pairs[c])
		case ']', '}', ')':
			if len(stack) == 0 || stack[len(stack)-1] != c {
				return -1
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i + 1
			}
		}
	}
	return -1
}

var (
	selVal  = `([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`
	selColl = `([A-Za-z_$][\w$]*|(?:new\s+Set\s*\(\s*)?\[[^\]\n]*\]\s*\)?|(?:Set|List)\.of\s*\([^)\n]*\)|(?:set|list)Of\s*\([^)\n]*\)|[({][^)}\n]*[)}])`
	selLit  = `(` + `'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|` + "`[^`$\\\\\\n]*`" + `|\d+|null|None|undefined|nil)`
	selDecl = `^\s*(?:(?:export\s+)?(?:const|let|var|val|final)\s+|(?:[\w<>\[\],.?]+\s+)?)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]|?. ]+?)?\s*=\s*`
	selEnd  = `\s*;?\s*$`

	// C.has(v) ? v : "x"   and   !C.has(v) ? "x" : v
	selTernary    = regexp.MustCompile(selDecl + selColl + `\s*\.\s*(?:has|includes|contains|containsKey)\s*\(\s*` + selVal + `\s*\)\s*\?\s*` + selVal + `\s*:\s*` + selLit + selEnd)
	selTernaryNeg = regexp.MustCompile(selDecl + `!\s*` + selColl + `\s*\.\s*(?:has|includes|contains|containsKey)\s*\(\s*` + selVal + `\s*\)\s*\?\s*` + selLit + `\s*:\s*` + selVal + selEnd)
	// v if v in C else "x"   and   "x" if v not in C else v
	selPyIn    = regexp.MustCompile(selDecl + selVal + `\s+if\s+` + selVal + `\s+in\s+` + selColl + `\s+else\s+` + selLit + selEnd)
	selPyNotIn = regexp.MustCompile(selDecl + selLit + `\s+if\s+` + selVal + `\s+not\s+in\s+` + selColl + `\s+else\s+` + selVal + selEnd)
	// if (v in C) v else "x"   and   if (C.contains(v)) v else "x"   (Kotlin)
	selKtIn       = regexp.MustCompile(selDecl + `if\s*\(\s*` + selVal + `\s+in\s+` + selColl + `\s*\)\s*` + selVal + `\s+else\s+` + selLit + selEnd)
	selKtContains = regexp.MustCompile(selDecl + `if\s*\(\s*` + selColl + `\s*\.\s*contains\s*\(\s*` + selVal + `\s*\)\s*\)\s*` + selVal + `\s+else\s+` + selLit + selEnd)
	// M.getOrDefault(k, "x"), M.get(k, "x"), M.get(k), M[k], each with an
	// optional `?? "x"`, `|| "x"`, `?: "x"` or `or "x"`.
	selLookup = regexp.MustCompile(selDecl + `([A-Za-z_$][\w$]*)\s*(?:\.\s*(?:getOrDefault|get|getOrElse)\s*\(\s*[^,()\n]+(?:,\s*` + selLit + `)?\s*\)|\[\s*[^\]\n]+\])` +
		`(?:\s*(?:\?\?|\|\||\?:|\bor\b)\s*` + selLit + `)?` + selEnd)
)

// allowlistSelects returns, per 1-based line, the variable an allowlist select
// on that line assigns. It runs on every file, so it does work only where a
// select can be: a line that might hold one (mayHoldSelect), and a collection
// a select actually names.
func allowlistSelects(content []byte) map[int]string {
	text := string(content)
	checked := map[string]bool{}
	known := func(c string) bool {
		c = strings.TrimSpace(c)
		if i := strings.IndexAny(c, "[{("); i >= 0 {
			end := closeAt(c, i)
			return end > 0 && literalBody(c[i+1:end-1])
		}
		ok, seen := checked[c]
		if !seen {
			ok = isLiteralCollection(text, c)
			checked[c] = ok
		}
		return ok
	}
	var out map[int]string
	for i, line := range strings.Split(text, "\n") {
		if !mayHoldSelect(line) {
			continue
		}
		if v, ok := selectOnLine(line, known); ok {
			if out == nil {
				out = map[int]string{}
			}
			out[i+1] = v
		}
	}
	return out
}

// mayHoldSelect is a cheap filter for lines that could match a select shape:
// an assignment with a ternary, a Python or Kotlin conditional expression, a
// map get, or a trailing subscript.
func mayHoldSelect(line string) bool {
	if !strings.Contains(line, "=") {
		return false
	}
	switch {
	case strings.Contains(line, "?") && (strings.Contains(line, ":") || strings.Contains(line, "??")):
		return true
	case strings.Contains(line, " else ") && (strings.Contains(line, " if ") || strings.Contains(line, "if (")):
		return true
	case strings.Contains(line, ".get(") || strings.Contains(line, "getOrDefault(") || strings.Contains(line, "getOrElse("):
		return true
	}
	t := strings.TrimRight(strings.TrimSpace(line), "; ")
	return strings.HasSuffix(t, "]") && !strings.HasSuffix(t, "[]")
}

// selectShape is one select form: the capture holding the collection, and the
// two captures that must name the same value (the one checked and the one
// returned); 0 when the form has no such pair (a lookup returns a map value).
type selectShape struct {
	re                 *regexp.Regexp
	coll, same1, same2 int
}

var selectShapes = []selectShape{
	{selTernary, 2, 3, 4},
	{selTernaryNeg, 2, 3, 5},
	{selPyIn, 4, 2, 3},
	{selPyNotIn, 4, 3, 5},
	{selKtIn, 3, 2, 4},
	{selKtContains, 2, 3, 4},
	{selLookup, 2, 0, 0},
}

func selectOnLine(line string, known func(string) bool) (string, bool) {
	for _, sh := range selectShapes {
		m := sh.re.FindStringSubmatch(line)
		if len(m) <= max(sh.coll, sh.same2) {
			continue
		}
		if sh.same1 > 0 && m[sh.same1] != m[sh.same2] {
			continue
		}
		if known(m[sh.coll]) {
			return m[1], true
		}
	}
	return "", false
}

// attachAllowlistSelects records each select on the unit holding the
// statement that makes that assignment.
func attachAllowlistSelects(units []taint.Unit, selects map[int]string) {
	if len(selects) == 0 {
		return
	}
	for ui := range units {
		for _, st := range units[ui].Stmts {
			if v, ok := selects[st.Line]; ok && v == st.Assigns {
				if units[ui].AllowlistSelects == nil {
					units[ui].AllowlistSelects = map[int]string{}
				}
				units[ui].AllowlistSelects[st.Line] = v
			}
		}
	}
}
