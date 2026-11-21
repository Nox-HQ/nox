package engine

import "regexp"

// A query assembled from a function parameter by string formatting is the
// ordinary shape of SQL injection in code where the request is parsed
// somewhere this file does not show: a DAO method `findUser(name)` that
// concatenates name into "SELECT ... WHERE name = '" + name + "'". With no
// source in the file, taint never reaches it. The parameter flow (see
// paramSQLFlows) reports it, and it is held to one premise that keeps it from
// reporting every function that passes a string to something named execute:
// the parameter must be BUILT INTO SQL TEXT, combined with a string literal
// that reads as SQL, on its way to the sink or at it. A pass-through wrapper
// (`delegate.prepareCall(sql)`) and a bare-name JVM sink that is no database
// (`executor.execute(task)`) build no SQL text and are not reported.

// sqlTextRE matches the literal text of a SQL statement or of a fragment of
// one. Statement openers are matched in either case, since SQL is written both
// ways, but only in the combinations a statement has (SELECT ... FROM, INSERT
// INTO, UPDATE ... SET, DELETE FROM): "select a file from the list" is
// English. A lone clause keyword (WHERE, AND x =, ORDER BY, LIMIT) is how a
// query built in pieces reads, and is matched upper-case only, as a word in a
// message ("where", "and", "like") is not SQL.
var sqlTextRE = regexp.MustCompile(
	`(?i:\bselect\b[\s\S]*\bfrom\b|\binsert\s+into\b|\bupdate\s+[\w."` + "`" + `\[\]]+\s+set\b|\bdelete\s+from\b|\border\s+by\b|\bgroup\s+by\b)` +
		`|\bWHERE\b|\bJOIN\b|\bVALUES\s*\(|\bLIMIT\b|\bOFFSET\b|\b(?:AND|OR)\s+[\w.]+\s*(?:=|<|>|!=|\bLIKE\b|\bIN\b|\bIS\b)|\bLIKE\b|\bIN\s*\(`)

// literalText returns the characters of raw that the code view blanked: the
// contents of the string literals (and comments) in the expression. The code
// view and the raw text share offsets, so a byte is literal text exactly when
// the code view replaced it. Every other byte becomes a space, so text on
// either side of an operand never joins into one word.
func literalText(code, raw string) string {
	if len(code) != len(raw) {
		return ""
	}
	b := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		if code[i] != raw[i] {
			b[i] = raw[i]
		} else {
			b[i] = ' '
		}
	}
	return string(b)
}

// identRE finds identifiers in a code view, `$` included for PHP and JS.
var identRE = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

// exprKeywords are words an expression holds that are not variables.
var exprKeywords = map[string]bool{
	"$": true, "new": true, "return": true, "await": true, "typeof": true, "instanceof": true,
	"this": true, "self": true, "null": true, "nil": true, "None": true,
	"true": true, "false": true, "True": true, "False": true, "and": true, "or": true, "not": true,
}

// formatCalls are the calls whose separate arguments ARE combined into one
// string: `String.format("... %s", id)`, `fmt.Sprintf`, `sprintf`.
var formatCalls = map[string]bool{
	"format": true, "Format": true, "sprintf": true, "Sprintf": true,
	"formatted": true, "concat": true, "vsprintf": true,
}

// sqlBuiltVars returns the variables of an expression that are combined with
// SQL literal text in it: concatenated with it, interpolated into it, formatted
// by it. Appearing beside it is not enough. A sibling argument of the call that
// takes the SQL (`new SqlCommand("SELECT ... @id", conn)`), and the receiver of
// that call (`$pdo->prepare("SELECT ...")`), are separate operands: the query
// is a literal and the variable is not in it.
func sqlBuiltVars(code, raw string) []string {
	lit := literalText(code, raw)
	if lit == "" {
		return nil
	}
	tagged := taggedTemplates(raw)
	var sqlAt [][]int
	for _, s := range sqlTextRE.FindAllStringIndex(lit, -1) {
		if !inSpans(tagged, s[0]) {
			sqlAt = append(sqlAt, s)
		}
	}
	if len(sqlAt) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range identRE.FindAllStringIndex(code, -1) {
		name := code[m[0]:m[1]]
		if seen[name] || exprKeywords[name] || isMemberName(code, m[0]) || followedByCallParen(code, m[1]) ||
			inSpans(tagged, m[0]) {
			continue
		}
		for _, s := range sqlAt {
			if combinedWithLiteral(code, m[0], m[1], s[0]) {
				seen[name] = true
				out = append(out, name)
				break
			}
		}
	}
	sortStrings(out)
	return out
}

// isMemberName reports an identifier that is a member access (`.name`,
// `->name`, `::name`), not a variable.
func isMemberName(code string, at int) bool {
	j := at - 1
	for j >= 0 && (code[j] == ' ' || code[j] == '\t') {
		j--
	}
	return j >= 0 && (code[j] == '.' || (code[j] == '>' && j > 0 && code[j-1] == '-') || (code[j] == ':' && j > 0 && code[j-1] == ':'))
}

// followedByCallParen reports a callee: an identifier directly called.
func followedByCallParen(code string, end int) bool {
	for end < len(code) && (code[end] == ' ' || code[end] == '\t') {
		end++
	}
	return end < len(code) && code[end] == '('
}

// combinedWithLiteral reports whether the variable at [vs, ve) and the SQL
// text at sql are one operand: no comma separates them at the level that
// encloses both, unless that level is a format call's argument list, and the
// SQL is not inside the arguments of a call made ON the variable.
func combinedWithLiteral(code string, vs, ve, sql int) bool {
	if sql > ve && receiverOfCallHolding(code, ve, sql) {
		return false
	}
	lo, hi := vs, sql
	if sql < vs {
		lo, hi = sql, vs
	}
	depth, minDepth := 0, 0
	for i := lo; i < hi; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth < minDepth {
				minDepth = depth
			}
		}
	}
	depth = 0
	for i := lo; i < hi; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == minDepth {
				return formatCalls[enclosingCallee(code, lo, minDepth)]
			}
		}
	}
	return true
}

// receiverOfCallHolding reports a variable that a call chain starts from
// (`pdo->prepare(`, `db.query(`) whose argument list holds position sql.
func receiverOfCallHolding(code string, ve, sql int) bool {
	i := ve
	for {
		j := i
		for j < len(code) && (code[j] == ' ' || code[j] == '\t') {
			j++
		}
		switch {
		case j < len(code) && code[j] == '.':
			j++
		case j+1 < len(code) && (code[j:j+2] == "->" || code[j:j+2] == "::"):
			j += 2
		default:
			return false
		}
		k := j
		for k < len(code) && (isIdentPart(code[k]) || code[k] == '$') {
			k++
		}
		if k == j {
			return false
		}
		p := k
		for p < len(code) && (code[p] == ' ' || code[p] == '\t') {
			p++
		}
		if p >= len(code) || code[p] != '(' {
			i = k // a field on the way: `this.db.query(`
			continue
		}
		depth := 0
		for q := p; q < len(code); q++ {
			switch code[q] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					if sql > p && sql < q {
						return true
					}
					i = q + 1
					q = len(code)
				}
			}
		}
		if i <= p {
			return false
		}
	}
}

// enclosingCallee names the call whose bracket opens the level minDepth
// relative to position lo: the identifier before the unmatched '(' found
// walking left from lo.
func enclosingCallee(code string, lo, minDepth int) string {
	need := -minDepth + 1
	depth := 0
	for i := lo - 1; i >= 0; i-- {
		switch code[i] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth > 0 {
				depth--
				continue
			}
			need--
			if need == 0 {
				if code[i] != '(' {
					return ""
				}
				e := i
				for e > 0 && (code[e-1] == ' ' || code[e-1] == '\t') {
					e--
				}
				s := e
				for s > 0 && (isIdentPart(code[s-1]) || code[s-1] == '$') {
					s--
				}
				return code[s:e]
			}
		}
	}
	return ""
}

// taggedTemplates returns the spans of the JavaScript tagged template literals
// in raw: a backtick directly after an identifier, as in sql`... ${id}`. The
// tag receives each ${} value separately -- Drizzle's sql, Prisma's
// $queryRaw, postgres.js and slonik bind them as query parameters -- so a
// value interpolated there is not built into the text. An untagged template,
// `SELECT ... ${id}`, is string building and is not a span.
func taggedTemplates(raw string) [][2]int {
	var spans [][2]int
	for i := 0; i < len(raw); i++ {
		if raw[i] != '`' {
			continue
		}
		end := templateEnd(raw, i)
		if i > 0 && (isIdentPart(raw[i-1]) || raw[i-1] == '$') {
			spans = append(spans, [2]int{i, end})
		}
		i = end
	}
	return spans
}

// templateEnd returns the offset of the backtick closing the template opened
// at open, skipping ${...} substitutions and the templates nested in them;
// len(raw)-1 when it is not closed on this line.
func templateEnd(raw string, open int) int {
	for i := open + 1; i < len(raw); i++ {
		switch {
		case raw[i] == '\\':
			i++
		case raw[i] == '`':
			return i
		case raw[i] == '$' && i+1 < len(raw) && raw[i+1] == '{':
			i = substitutionEnd(raw, i+1)
		}
	}
	return len(raw) - 1
}

// substitutionEnd returns the offset of the brace closing the ${ opened at
// brace, skipping templates nested inside it.
func substitutionEnd(raw string, brace int) int {
	depth := 0
	for j := brace; j < len(raw); j++ {
		switch raw[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return j
			}
		case '`':
			j = templateEnd(raw, j)
		}
	}
	return len(raw) - 1
}

func inSpans(spans [][2]int, at int) bool {
	for _, s := range spans {
		if at >= s[0] && at <= s[1] {
			return true
		}
	}
	return false
}
