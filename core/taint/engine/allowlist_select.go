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

// collectionHead finds `NAME = <opener>` where opener starts a collection
// literal or a call that builds one from its arguments.
var collectionHead = regexp.MustCompile(`(?m)(?:^|[\s;(,])([A-Za-z_$][\w$]*)\s*(?::\s*[^=\n;]+?)?\s*=\s*` +
	`(new\s+(?:Set|Map)\s*(?:<[^>\n]*>)?\s*\(\s*|frozenset\s*\(\s*|set\s*\(\s*|tuple\s*\(\s*|Object\.freeze\s*\(\s*|` +
	`(?:Set|List|Map|EnumSet)\.of\s*|Arrays\.asList\s*|Collections\.unmodifiable\w+\s*\(\s*(?:Set|List|Map)\.of\s*|` +
	`(?:mutable|hash|linkedHash|sorted)?(?:[sS]etOf|[lL]istOf|[mM]apOf)\s*|ImmutableSet\.of\s*|ImmutableList\.of\s*|ImmutableMap\.of\s*)?` +
	`([\[{(])`)

// emptyMapDecl finds `NAME = new HashMap<>()` and kin: a map that is literal
// when every store into it is.
var emptyMapDecl = regexp.MustCompile(`(?m)(?:^|[\s;(,])([A-Za-z_$][\w$]*)\s*(?::\s*[^=\n;]+?)?\s*=\s*` +
	`(?:new\s+(?:Hash|LinkedHash|Tree|Concurrent|Enum)?(?:Map|Set)\s*(?:<[^>\n]*>)?\s*\(\s*\)|mutableMapOf\s*\(\s*\)|mutableSetOf\s*\(\s*\)|new\s+Map\s*\(\s*\)|new\s+Set\s*\(\s*\)|\{\s*\}|dict\s*\(\s*\)|set\s*\(\s*\))`)

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

// literalCollections returns the names bound in content to a collection of
// literals only, and never rebound or added to with anything but literals.
func literalCollections(content string) map[string]bool {
	bound := map[string]int{}
	ok := map[string]bool{}
	for _, m := range collectionHead.FindAllStringSubmatchIndex(content, -1) {
		name := content[m[2]:m[3]]
		open := m[6]
		end := closeAt(content, open)
		bound[name]++
		ok[name] = end > 0 && literalBody(content[open+1:end-1])
	}
	for _, m := range emptyMapDecl.FindAllStringSubmatch(content, -1) {
		bound[m[1]]++
		ok[m[1]] = true
	}
	out := map[string]bool{}
	for name, good := range ok {
		if !good || bound[name] != 1 || rebound(content, name) || !literalStores(content, name) {
			continue
		}
		out[name] = true
	}
	return out
}

// rebound reports a second assignment to name: `name = …` beyond its binding.
func rebound(content, name string) bool {
	re := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(name) + `\s*=[^=>]`)
	return len(re.FindAllStringIndex(content, -1)) > 1
}

// literalStores reports that every store into name (put/add/push/set/append/
// insert/update/extend, or name[k] = v) stores literals only.
func literalStores(content, name string) bool {
	q := regexp.QuoteMeta(name)
	call := regexp.MustCompile(`(?:^|[^\w$.])` + q + `\s*\.\s*(?:put|putIfAbsent|add|addAll|push|unshift|set|append|insert|update|extend|setdefault|computeIfAbsent|merge)\s*\(`)
	for _, m := range call.FindAllStringIndex(content, -1) {
		open := m[1] - 1
		end := closeAt(content, open)
		if end < 0 || !literalBody(content[open+1:end-1]) {
			return false
		}
	}
	sub := regexp.MustCompile(`(?:^|[^\w$.])` + q + `\s*\[[^\]\n]*\]\s*=[^=]([^\n;]*)`)
	for _, m := range sub.FindAllStringSubmatch(content, -1) {
		if !literalBody(m[1]) {
			return false
		}
	}
	return true
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
// on that line assigns.
func allowlistSelects(content []byte) map[int]string {
	text := string(content)
	colls := literalCollections(text)
	known := func(c string) bool {
		c = strings.TrimSpace(c)
		if colls[c] {
			return true
		}
		if i := strings.IndexAny(c, "[{("); i >= 0 {
			if end := closeAt(c, i); end > 0 {
				return literalBody(c[i+1 : end-1])
			}
		}
		return false
	}
	out := map[int]string{}
	for i, line := range strings.Split(text, "\n") {
		if v, ok := selectOnLine(line, known); ok {
			out[i+1] = v
		}
	}
	return out
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
