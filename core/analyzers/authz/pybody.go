package authz

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
)

// lSQL marks a value that is, or was built into, a SQL statement. A statement
// held in a variable and executed on the next line is still a lookup.
const lSQL label = 1 << 5

// The Python handler analysis mirrors the Express one (body.go): the same
// proposition, the same counterexample classes, the same labels. The
// vocabulary is Python's: variables and statements instead of expressions,
// `abort(403)` and `HTTPException(status_code=403)` instead of `res.status(403)`,
// `current_user` and Depends() parameters instead of `req.user`.

var (
	pyPrincipalRe = regexp.MustCompile(`\bcurrent_user\b|\bcurrent_identity\b|\bg\s*\.\s*[A-Za-z_]\w*|\bget_jwt_identity\s*\(|\bget_jwt\s*\(|\bget_current_\w+\s*\(|\bsession\s*\[|\bsession\s*\.\s*get\s*\(\s*['"]|\brequest\s*\.\s*(?:user|auth|state|principal|jwt|identity|current_user|authorization)\b|\bauth\s*\.\s*current_user\s*\(|\bverify_jwt_in_request\s*\(|\bcurrent_app\s*\.\s*(?:user|principal)\b`)

	pyKeyedRe = `(?:\.\s*get(?:list)?\s*\(\s*['"]([\w-]+)['"]|\[\s*['"]([\w-]+)['"]\s*\])`
	// request.args.get('id'), request.json['id'], request.get_json()['id'].
	pyReqArgsRe = regexp.MustCompile(`\brequest\s*\.\s*(?:args|values|view_args)\s*` + pyKeyedRe)
	pyReqBodyRe = regexp.MustCompile(`\brequest\s*\.\s*(?:form|json|values)\s*` + pyKeyedRe + `|\brequest\s*\.\s*get_json\s*\([^)]*\)\s*` + pyKeyedRe)
	// data = request.get_json(); data.get('order_id') — the container is the source.
	pyContainerRe = regexp.MustCompile(`^([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(?:await\s+)?request\s*\.\s*(get_json\s*\([^)]*\)|json(?:\s*\(\s*\))?|form|args|values)\s*$`)

	pyAssignRe  = regexp.MustCompile(`^([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::[^=\n]+?)?\s*=([^=]|$)`)
	pyForRe     = regexp.MustCompile(`^(?:async\s+)?for\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+in\s`)
	pyCompareRe = regexp.MustCompile(`==|!=|\bnot\s+in\b|\bis\s+not\b`)

	pyForbiddenRe = regexp.MustCompile(`\b403\b|Forbidden|FORBIDDEN|PermissionDenied|PermissionError|HTTP_403`)
	pyAuthzCallRe = regexp.MustCompile(`\b(?:authori[sz]e\w*|can|cannot|ability|accessible_by|check_owner\w*|is_owner\w*|assert_owner\w*|ensure_owner\w*|verify_owner\w*|require_owner\w*|check_access|has_access|can_access|assert_can\w*|enforce|permit|check_perm\w*|has_perm\w*|check_policy|policy|user_can\w*|is_allowed|ensure_\w*access|verify_\w*access|require_\w*perm\w*|has_role|has_roles|roles_required|permission_required)\s*\(|\.\s*can\s*\(`)
	pyUnauthRe    = regexp.MustCompile(`\b401\b|Unauthorized|UNAUTHORIZED|HTTP_401`)
	pyRoleRe      = regexp.MustCompile(`\.\s*(?:role|roles|is_admin|admin|permissions|scopes|scope|is_staff|is_superuser|superuser|groups|access_level|is_manager|has_role)\b`)
	pyNonGating   = setOf("jsonify", "render_template", "make_response", "Response", "JSONResponse", "print", "info", "debug", "warning", "error", "exception", "log", "str", "len", "isinstance", "redirect", "url_for", "flash", "abort", "HTTPException", "dict", "list")
	pyResponseRe  = regexp.MustCompile(`^(?:logger|log|logging|print|app\s*\.\s*logger|current_app\s*\.\s*logger)\b`)

	pyCallModelRe = regexp.MustCompile(`\(\s*([A-Z]\w*)`)
	pyInRe        = regexp.MustCompile(`\bin\b`)

	pyOwnerKeyRe = regexp.MustCompile(`(?i)(?:^|[^\w])["']?(owner\w*|user_?id|user|author\w*|account_?id|tenant_?id|org_?id|organization_?id|created_?by|customer_?id|member_?id)["']?\s*(?::|==|=)`)
	pySQLOwnerRe = regexp.MustCompile(`(?i)\b["\x60]?(?:owner|user|account|tenant|org|organization|customer|author|member)_?id["\x60]?\s*=`)
)

var pyKeywords = setOf("if", "elif", "while", "for", "return", "not", "and", "or", "in", "is", "assert", "with", "lambda", "def", "class",
	"except", "raise", "yield", "await", "async", "del", "global", "from", "import", "as", "else", "try", "print", "super")

// Data-access vocabulary. Keyed methods name a record on their own; generic
// verbs only on a model, session or repository receiver; SQL methods only
// when a statement is in the call.
var (
	pyKeyedMethods = setOf("get_or_404", "first_or_404", "one_or_404", "find_one", "find_one_and_update", "find_one_and_delete",
		"find_one_and_replace", "update_one", "delete_one", "replace_one", "get_by_id", "get_by_pk", "find_by_id", "find_by_pk",
		"filter_by", "filter", "where", "get_object_or_404")
	pyGenericMethods = setOf("get", "delete", "update", "remove", "destroy", "find", "upsert", "count", "exists", "first")
	pySQLMethods     = setOf("execute", "executemany", "query", "raw", "fetch", "fetch_one", "fetch_all", "fetchone", "fetchall", "fetchrow", "fetchval",
		"fetchmany", "exec_driver_sql", "run")
	pyServiceVerbRe = regexp.MustCompile(`^(?:get|find|fetch|load|read|delete|remove|update|destroy|retrieve|select|patch|edit|show)`)
	pyModelRecvRe   = regexp.MustCompile(`(?i)^(?:query|session|db|objects|collection|collections|crud|queries|table)$|(?:dao|repository|repo|service|model|store|manager|crud)$`)
	pyBuiltinCaps   = setOf("Path", "Decimal", "Counter", "OrderedDict", "Response", "JSONResponse", "HTTPException", "UUID", "Query", "Depends",
		"Header", "Cookie", "Form", "File", "Body", "Request", "Enum", "Field", "BaseModel", "Optional", "List", "Dict", "Any", "ObjectId", "Session", "String", "Datetime")
)

type pyBody struct {
	f          *pyFile
	base       int
	text, raw  string
	stmts      []span
	vars       map[string]label
	containers map[string]label
	calls      []callSite
	idKeys     map[string]bool
	accessMemo map[int]bool
	contRes    map[string]*regexp.Regexp
}

// analyzePyBody is the Python counterpart of analyzeBody. idParams are the
// route's identifier-like path parameters; principals are the parameters that
// hold the authenticated caller (a Depends(get_current_user) parameter).
func analyzePyBody(f *pyFile, r *pyRoute, idParams, principals map[string]bool) bodyFacts {
	b := &pyBody{f: f, base: r.fn.bodyStart, text: f.code[r.fn.bodyStart:r.fn.bodyEnd], raw: string(f.raw[r.fn.bodyStart:r.fn.bodyEnd]),
		vars: map[string]label{}, containers: map[string]label{}, idKeys: idParams,
		accessMemo: map[int]bool{}, contRes: map[string]*regexp.Regexp{}}
	b.stmts = pyStatements(b.text)
	for _, p := range r.fn.params {
		switch {
		case principals[p.name]:
			b.vars[p.name] |= lP
		case idParams[p.name]:
			b.vars[p.name] |= lIDPath
		case r.framework == "fastapi" && idishRe.MatchString(p.name) && !strings.Contains(p.def+p.annotation, "Depends") && !strings.Contains(p.annotation, "Request"):
			if strings.Contains(p.def+p.annotation, "Body(") {
				b.vars[p.name] |= lIDBody
			} else {
				b.vars[p.name] |= lIDQuery
			}
		}
	}
	b.collectCalls()
	b.propagate()

	var facts bodyFacts
	for i := range b.calls {
		if h, ok := b.sink(&b.calls[i]); ok {
			facts.sinks = append(facts.sinks, h)
		}
	}
	if len(facts.sinks) == 0 {
		return facts
	}
	facts.inlineAuth = pyUnauthRe.MatchString(b.text) && b.hasPrincipal(b.text) || strings.Contains(b.text, "verify_jwt_in_request")
	facts.refuted = b.refutation(facts.sinks)
	return facts
}

// pyStatements splits masked code into logical statements.
func pyStatements(text string) []span {
	var out []span
	from, depth := 0, 0
	flush := func(end int) {
		s := trimSpan(text, span{from, end})
		if s.end > s.start {
			out = append(out, s)
		}
	}
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '\n':
			if depth <= 0 && (i == 0 || text[i-1] != '\\') {
				flush(i)
				from, depth = i+1, 0
			}
		}
	}
	flush(len(text))
	return out
}

func (b *pyBody) stmtAt(off int) span {
	for _, s := range b.stmts {
		if off >= s.start && off < s.end {
			return s
		}
	}
	return span{off, off}
}

func (b *pyBody) collectCalls() {
	for _, m := range anyCallRe.FindAllStringSubmatchIndex(b.text, -1) {
		name := b.text[m[2]:m[3]]
		if pyKeywords[name] {
			continue
		}
		if before := strings.TrimRight(b.text[:m[2]], " \t"); strings.HasSuffix(before, "def") || strings.HasSuffix(before, "class") {
			continue
		}
		open := m[1] - 1
		closeAt := matchClose(b.text, open)
		if closeAt < 0 {
			continue
		}
		c := callSite{nameStart: m[2], name: name, open: open, closeAt: closeAt, args: splitArgs(b.text, open+1, closeAt)}
		if dot := dotBefore(b.text, m[2]); dot >= 0 {
			c.recvStart = receiverStart(b.text, dot)
			c.recv = strings.TrimSpace(b.text[c.recvStart:dot])
		} else {
			c.recvStart = m[2]
		}
		b.calls = append(b.calls, c)
	}
}

// hasPrincipal reports whether text reads the caller's principal.
func (b *pyBody) hasPrincipal(text string) bool {
	if pyPrincipalRe.MatchString(text) {
		return true
	}
	for v, l := range b.vars {
		if l&lP != 0 && hasWord(text, v) {
			return true
		}
	}
	return false
}

// seedLabels returns the labels b.text[from:to] carries from request input and
// the principal alone.
func (b *pyBody) seedLabels(from, to int) label {
	var l label
	raw := b.raw[from:to]
	code := func(at int) bool { return b.text[from+at] == b.raw[from+at] } // not blanked: real code
	for _, m := range pyReqArgsRe.FindAllStringSubmatchIndex(raw, -1) {
		if code(m[0]) && idishRe.MatchString(keyOf(raw, m)) {
			l |= lIDQuery
		}
	}
	for _, m := range pyReqBodyRe.FindAllStringSubmatchIndex(raw, -1) {
		if code(m[0]) && idishRe.MatchString(keyOf(raw, m)) {
			l |= lIDBody
		}
	}
	for name, src := range b.containers {
		re := b.contRes[name]
		if re == nil {
			re = regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*` + pyKeyedRe)
			b.contRes[name] = re
		}
		for _, m := range re.FindAllStringSubmatchIndex(raw, -1) {
			if code(m[0]) && idishRe.MatchString(keyOf(raw, m)) {
				l |= src
			}
		}
	}
	if b.hasPrincipal(b.text[from:to]) {
		l |= lP
	}
	return l
}

// keyOf returns the first participating key group of a pyKeyedRe match.
func keyOf(s string, m []int) string {
	for i := 2; i+1 < len(m); i += 2 {
		if m[i] >= 0 {
			return s[m[i]:m[i+1]]
		}
	}
	return ""
}

func (b *pyBody) labelsOf(from, to int) label {
	if from < 0 || to > len(b.text) || from >= to {
		return 0
	}
	t := b.text[from:to]
	l := b.seedLabels(from, to)
	for v, vl := range b.vars {
		if l&vl != vl && hasWord(t, v) {
			l |= vl
		}
	}
	if sqlRe.MatchString(b.raw[from:to]) {
		l |= lSQL
	}
	for i := range b.calls {
		c := &b.calls[i]
		if c.nameStart >= from && c.closeAt < to && b.isDataAccess(c) {
			l |= lREC
		}
	}
	return l
}

// propagate computes variable labels from assignments and for-loops.
func (b *pyBody) propagate() {
	type asg struct {
		targets []string
		from    int
		to      int
	}
	var asgs []asg
	for _, s := range b.stmts {
		t := b.text[s.start:s.end]
		if m := pyContainerRe.FindStringSubmatch(t); m != nil {
			src := lIDBody
			if m[2] == "args" || m[2] == "values" {
				src = lIDQuery
			}
			b.containers[m[1]] = src
			continue
		}
		if m := pyAssignRe.FindStringSubmatchIndex(t); m != nil {
			eq := strings.Index(t[m[3]:], "=") + m[3]
			asgs = append(asgs, asg{splitNames(t[m[2]:m[3]]), s.start + eq + 1, s.end})
			continue
		}
		if m := pyForRe.FindStringSubmatchIndex(t); m != nil {
			asgs = append(asgs, asg{splitNames(t[m[2]:m[3]]), s.start + m[1], s.end})
		}
	}
	for pass := 0; pass < 3; pass++ {
		changed := false
		for _, a := range asgs {
			l := b.labelsOf(a.from, a.to)
			for _, name := range a.targets {
				if b.vars[name]|l != b.vars[name] {
					b.vars[name] |= l
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
}

func splitNames(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// recvBase is a receiver without its trailing call groups:
// `db.query(Order)` -> `db.query`.
func recvBase(recv string) string {
	recv = strings.TrimSpace(recv)
	for strings.HasSuffix(recv, ")") || strings.HasSuffix(recv, "]") {
		open := matchOpen(recv, len(recv)-1)
		if open <= 0 {
			break
		}
		recv = strings.TrimSpace(recv[:open])
	}
	return recv
}

func (b *pyBody) isDataAccess(c *callSite) bool {
	if v, ok := b.accessMemo[c.nameStart]; ok {
		return v
	}
	v := b.dataAccess(c)
	b.accessMemo[c.nameStart] = v
	return v
}

func (b *pyBody) dataAccess(c *callSite) bool {
	if c.recv == "" {
		return false
	}
	base := recvBase(c.recv)
	segs := strings.Split(base, ".")
	last := strings.TrimSpace(segs[len(segs)-1])
	switch {
	case pyKeyedMethods[c.name]:
		return true
	case pySQLMethods[c.name] && sqlRe.MatchString(b.raw[c.recvStart:c.closeAt]):
		return true
	case pySQLMethods[c.name] && b.argsCarry(c, lSQL):
		return true
	case pyGenericMethods[c.name]:
		return pyModelReceiver(segs)
	case pyServiceVerbRe.MatchString(c.name):
		return pyModelReceiver(segs) || startsUpper(last) && !pyBuiltinCaps[last]
	}
	return false
}

// pyModelReceiver: a model class, a session, a query or a repository/service
// object. A plain lowercase name (`params`, `data`, `request.args`) is not.
func pyModelReceiver(segs []string) bool {
	for _, s := range segs {
		s = strings.TrimSpace(s)
		if pyModelRecvRe.MatchString(s) || startsUpper(s) && !pyBuiltinCaps[s] {
			return true
		}
	}
	return false
}

func (b *pyBody) argsCarry(c *callSite, want label) bool {
	for _, a := range c.args {
		if b.labelsOfValue(a)&want != 0 {
			return true
		}
	}
	return false
}

// labelsOfValue labels an argument, ignoring a keyword's name.
func (b *pyBody) labelsOfValue(a span) label {
	if _, v, ok := pyKwarg(b.text, a); ok {
		return b.labelsOf(v.start, v.end)
	}
	return b.labelsOf(a.start, a.end)
}

func (b *pyBody) sink(c *callSite) (sinkHit, bool) {
	if !b.isDataAccess(c) {
		return sinkHit{}, false
	}
	var argL label
	for _, a := range c.args {
		argL |= b.labelsOfValue(a)
	}
	if argL&lID == 0 {
		return sinkHit{}, false
	}
	recvL := b.labelsOf(c.recvStart, c.nameStart)
	scoped := (argL|recvL)&lP != 0 || b.ownerScoped(c) || b.scopedLater(c)
	return sinkHit{off: b.base + c.nameStart, method: c.name, idFrom: argL & lID, model: b.modelKey(c), scoped: scoped}, true
}

// ownerScoped: the statement holding the lookup also filters on an owner-like
// field whose value is not caller-controlled (`filter_by(id=i, user_id=uid)`,
// `.filter(Order.owner_id == user.id)`, `{"_id": i, "userId": uid}`), or the
// SQL names an owner column and binds a non-identifier value to it. A query
// built across statements is followed by scopedLater.
func (b *pyBody) ownerScoped(c *callSite) bool {
	stmt := b.stmtAt(c.recvStart)
	if b.ownerKeyIn(c.recvStart, stmt.end) {
		return true
	}
	if !pySQLMethods[c.name] || !pySQLOwnerRe.MatchString(b.raw[c.recvStart:c.closeAt]) {
		return false
	}
	ids, others := 0, 0
	for _, a := range c.args {
		t := b.text[a.start:a.end]
		switch {
		case len(t) >= 2 && strings.ContainsAny(t[:1], "([{") && matchClose(b.text, a.start) == a.end-1:
			for _, e := range splitArgs(b.text, a.start+1, a.end-1) {
				v := e
				if k := strings.Index(b.text[e.start:e.end], ":"); t[0] == '{' && k >= 0 {
					v = trimSpan(b.text, span{e.start + k + 1, e.end})
				}
				if b.labelsOf(v.start, v.end)&lID != 0 {
					ids++
				} else {
					others++
				}
			}
		case sqlRe.MatchString(b.raw[a.start:a.end]) || t == "":
		default:
			if b.labelsOfValue(a)&lID != 0 {
				ids++
			} else {
				others++
			}
		}
	}
	return others > 0 || ids == 0
}

// ownerKeyIn reports an owner-named key in [from,to) whose value is not a
// caller-controlled identifier.
func (b *pyBody) ownerKeyIn(from, to int) bool {
	raw := b.raw[from:to]
	for _, m := range pyOwnerKeyRe.FindAllStringSubmatchIndex(raw, -1) {
		valFrom := from + m[1]
		valTo := expressionEnd(b.text, valFrom, true)
		if valTo > to {
			valTo = to
		}
		if strings.TrimSpace(b.text[valFrom:valTo]) != "" && b.labelsOf(valFrom, valTo)&lID == 0 {
			return true
		}
	}
	return false
}

// scopedLater: the lookup is assigned to a name that a later statement narrows
// by the principal (`stmt = select(Item).where(Item.id == id)` then
// `stmt = stmt.where(Item.owner_id == user.id)`).
func (b *pyBody) scopedLater(c *callSite) bool {
	stmt := b.stmtAt(c.recvStart)
	m := pyAssignRe.FindStringSubmatch(b.text[stmt.start:stmt.end])
	if len(m) < 2 || strings.Contains(m[1], ",") {
		return false
	}
	name := strings.TrimSpace(m[1])
	for _, s := range b.stmts {
		// Only a statement that re-binds the name to something built from
		// it narrows the query; one that merely mentions it beside the
		// principal (a log line, a response) relates nothing.
		t := b.text[s.start:s.end]
		am := pyAssignRe.FindStringSubmatch(t)
		if s.start <= stmt.start || am == nil || !hasWord(t[strings.Index(t, "=")+1:], name) {
			continue
		}
		if !containsString(splitNames(am[1]), name) {
			continue
		}
		if b.labelsOf(s.start, s.end)&lP != 0 || b.ownerKeyIn(s.start, s.end) {
			return true
		}
	}
	return false
}

// modelKey names the collection a lookup targets, as the Express reader does.
func (b *pyBody) modelKey(c *callSite) string {
	if pySQLMethods[c.name] {
		if m := tableRe.FindStringSubmatch(b.raw[c.recvStart:c.closeAt]); m != nil {
			return normalizeModel(m[1])
		}
	}
	recv := recvBase(c.recv)
	segs := strings.Split(recv, ".")
	for i := len(segs) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(segs[i]); startsUpper(s) {
			return normalizeModel(s)
		}
	}
	if len(c.args) > 0 { // session.get(Model, id), db.query(Model)
		first := strings.TrimSpace(b.text[c.args[0].start:c.args[0].end])
		if startsUpper(first) && isChain(first) {
			return normalizeModel(lastSegment(first))
		}
	}
	if m := pyCallModelRe.FindStringSubmatch(c.recv); m != nil {
		return normalizeModel(m[1])
	}
	return normalizeModel(lastSegment(recv))
}

// refutation returns the first observed relation between the record and the
// principal, or "" when the body shows none.
func (b *pyBody) refutation(sinks []sinkHit) string {
	for _, h := range sinks {
		if h.scoped {
			return "the lookup is scoped by the caller's principal (" + h.method + ")"
		}
	}
	if m := pyForbiddenRe.FindString(b.text); m != "" {
		return "the handler can answer 403 (" + strings.TrimSpace(m) + ")"
	}
	if m := pyAuthzCallRe.FindString(b.text); m != "" {
		return "the handler calls an authorization check (" + strings.TrimSpace(m) + ")"
	}
	for _, m := range pyRoleRe.FindAllStringIndex(b.text, -1) {
		start := receiverStart(b.text, m[0])
		if b.labelsOf(start, m[0])&lP != 0 {
			return "the handler reads the caller's role (" + strings.TrimSpace(b.text[start:m[1]]) + ")"
		}
	}
	for _, s := range b.stmts {
		t := b.text[s.start:s.end]
		ops := pyCompareRe.FindAllStringIndex(t, -1)
		if strings.HasPrefix(t, "if ") || strings.HasPrefix(t, "elif ") || strings.HasPrefix(t, "assert ") || strings.HasPrefix(t, "while ") || strings.HasPrefix(t, "return ") {
			ops = append(ops, pyInRe.FindAllStringIndex(t, -1)...)
		}
		for _, m := range ops {
			left := operandBefore(b.text, s.start+m[0])
			right := operandAfter(b.text, s.start+m[1])
			ll, rl := b.labelsOf(left, s.start+m[0]), b.labelsOf(s.start+m[1], right)
			if ll&lP != 0 && rl&(lID|lREC) != 0 || rl&lP != 0 && ll&(lID|lREC) != 0 {
				return "the record is compared with the caller's principal (" + strings.Join(strings.Fields(b.text[left:right]), " ") + ")"
			}
		}
	}
	for i := range b.calls {
		c := &b.calls[i]
		if pyNonGating[c.name] || pyResponseRe.MatchString(c.recv) {
			continue
		}
		l := b.labelsOf(c.recvStart, c.nameStart)
		for _, a := range c.args {
			l |= b.labelsOfValue(a)
		}
		if l&lP != 0 && l&(lID|lREC) != 0 {
			return "the record and the caller's principal meet in a call (" + c.name + ")"
		}
	}
	return ""
}

// ---- access-control classification ----

var (
	pyNotAccessRe = regexp.MustCompile(`(?i)^(?:limit|limiter|rate_?limit\w*|cache|cached|csrf\w*|cors|cross_origin|wraps|route|errorhandler|swag\w*|doc|expect|marshal\w*|validate\w*|deprecated|timer|memoize|compress|etag|response\w*|param\w*|get_db|get_session|get_settings|get_config|get_redis|get_logger|session_?dep|db_?dep)$`)
	pyAuthzNameRe = regexp.MustCompile(`(?i)role|admin|permi|(?:^|_)can_|^can[A-Z_]|abilit|polic|owner|scope|(?:^|_)acl(?:_|$)|rbac|staff|superuser|accounting|deny|(?:^|_)(?:load|fetch)_|tenant|member|belong|restrict|grant|(?:check|has|can|require|verify)_?access|authori[sz]e|authori[sz]ation|_for_(?:user|owner|current)|_or_404$`)
	pyKwAuthzRe   = regexp.MustCompile(`\b(?:roles?|scopes?|permissions?|groups?)\s*=`)
	pyAuthGateRe  = regexp.MustCompile(`is_authenticated|is_anonymous|verify_jwt_in_request|login_required|\b401\b|Unauthorized|HTTP_401`)

	pyAuthnStrong = setOf("jwt", "token", "bearer", "oidc", "keycloak", "firebase", "cognito", "auth0", "clerk", "protect", "passport", "apikey")
	pyAuthnGate   = setOf("require", "requires", "required", "ensure", "verify", "check", "has", "needed", "current")
	pyAuthnSubj   = setOf("login", "signin", "session", "user", "principal", "account", "identity", "member", "logged")
	pyAuthnStop   = setOf("optional", "challenge", "challenges", "parse", "parser", "csrf", "refresh", "cookie", "cookies", "maybe", "try", "soft", "populate",
		"attach", "extract", "decode", "identify", "initialize", "init", "update", "set", "store", "track", "log", "record", "count", "create", "generate",
		"issue", "register", "reset", "forgot", "revoke", "hash")
)

// pyAuthnName reads a decorator or dependency name as words (`login_required`,
// `get_current_active_user`, `verify_jwt_in_request`, `HTTPBearer`) and reports
// whether it authenticates the caller.
func pyAuthnName(name string) bool {
	words := camelRe.FindAllString(strings.ReplaceAll(name, "_", " "), -1)
	strong, gate, subj := false, false, false
	for _, w := range words {
		w = strings.ToLower(w)
		switch {
		case pyAuthnStop[w]:
			return false
		case strings.HasPrefix(w, "auth") && !strings.HasPrefix(w, "authori"), strings.HasPrefix(w, "oauth"), pyAuthnStrong[w]:
			strong = true
		case pyAuthnGate[w]:
			gate = true
		case pyAuthnSubj[w]:
			subj = true
		}
	}
	return strong || gate && subj
}

// classifyPy returns the first authentication and the first authorization
// element on the route's chain.
func classifyPy(deps []pyDep) (authn, authz string) {
	for _, d := range deps {
		if d.inline {
			if authz == "" && (pyForbiddenRe.MatchString(d.text) || pyRoleRe.MatchString(d.text)) {
				authz = d.name
			}
			if authn == "" && pyAuthGateRe.MatchString(d.text) {
				authn = d.name
			}
			continue
		}
		if d.name == "" || pyNotAccessRe.MatchString(d.name) {
			continue
		}
		label := compact(strings.TrimPrefix(strings.TrimSpace(d.raw), "@"))
		if authz == "" && (pyAuthzNameRe.MatchString(d.name) || pyKwAuthzRe.MatchString(d.raw) || pyAuthnName(d.name) && pyStringArg(d.raw)) {
			authz = label
		}
		if authn == "" && pyAuthnName(d.name) && !strings.Contains(d.raw, "optional=True") {
			authn = label
		}
	}
	return authn, authz
}

// pyStringArg: an authentication decorator called with a string literal names
// a permission or role (`@auth.login_required('admin')`).
func pyStringArg(raw string) bool {
	open := strings.IndexByte(raw, '(')
	if open < 0 {
		return false
	}
	rest := strings.TrimSpace(raw[open+1:])
	return strings.HasPrefix(rest, "'") || strings.HasPrefix(rest, `"`)
}

// routeInventory describes every Python route, whether or not it meets
// AUTHZ-001's proposition, with the authentication and authorization elements
// visibly in front of it. It classifies with the same function the lead logic
// uses (classifyPy over inherited router dependencies, the route's decorators
// and its Depends() parameters), so what the inventory records as
// authentication is exactly what the proposition treated as authentication.
//
// A handler that rejects an anonymous caller itself, or takes the caller as a
// parameter, is recorded as authenticated too: "no decorator" is not "no
// authentication", and the inventory, `nox model` and AUTHN-001 must agree.
func (ix *pyIndex) routeInventory() ([]Route, []routeView) {
	out := make([]Route, 0, len(ix.routes))
	views := make([]routeView, 0, len(ix.routes))
	guard := ix.globalGuardUnseen()
	for i := range ix.routes {
		r := &ix.routes[i]
		deps := append(ix.inheritedDeps(r.recv), r.deps...)
		authn, authz := classifyPy(deps)
		handler := ix.handlerText(r)
		if authn == "" && authz == "" && (pyInlineAuthRe.MatchString(handler) || pySecurityParam(r.fn)) {
			authn = inlineAuthLabel
		}
		rt := Route{
			Method:   strings.ToUpper(r.method),
			Path:     joinRoutePath(ix.fullPrefix(r.recv), r.path),
			FilePath: r.file.path,
			Line:     lineAt(r.file.lineStarts, r.offset),
			Authn:    authn,
			Authz:    authz,
		}
		out = append(out, rt)
		var chain strings.Builder
		for _, d := range deps {
			chain.WriteString(d.raw)
			chain.WriteByte(' ')
		}
		views = append(views, routeView{route: rt, handler: handler, known: true, chain: chain.String(), guardUnseen: guard, framework: r.framework})
	}
	return out, views
}

// pySecurityParam: a parameter that carries the caller (a FastAPI Security()
// default, a bearer scheme, a `current_user` or `token` argument).
func pySecurityParam(fn pyFunc) bool {
	for _, p := range fn.params {
		if pySecurityParamRe.MatchString(p.name) || pySecurityParamRe.MatchString(p.annotation) || pySecurityParamRe.MatchString(p.def) {
			return true
		}
	}
	return false
}

// globalGuardUnseen: the repository intercepts every request somewhere this
// reader does not evaluate, or has a before_request hook it could not read as
// authentication. Either way an empty Authn on a route proves nothing.
func (ix *pyIndex) globalGuardUnseen() bool {
	for _, p := range ix.order {
		if pyGlobalGuardRe.MatchString(ix.files[p].code) {
			return true
		}
	}
	for _, deps := range ix.hooks {
		if len(deps) > 0 {
			return true
		}
	}
	return false
}

// handlerText returns the comment-free text of the route's function and of the
// repository functions it calls by name (one level).
func (ix *pyIndex) handlerText(r *pyRoute) string {
	text := r.file.sans[r.fn.defOff:r.fn.bodyEnd]
	if ix.funcText == nil {
		ix.funcText = map[string][]string{}
		for _, p := range ix.order {
			f := ix.files[p]
			for _, m := range pyDefRe.FindAllStringSubmatchIndex(f.code, -1) {
				if fn, ok := parsePyFunc(f, m); ok {
					ix.funcText[fn.name] = append(ix.funcText[fn.name], f.sans[fn.defOff:fn.bodyEnd])
				}
			}
		}
	}
	parts := []string{text}
	seen := map[string]bool{r.fn.name: true}
	for _, m := range pyCallNameRe.FindAllStringSubmatch(r.file.code[r.fn.bodyStart:r.fn.bodyEnd], -1) {
		name := m[1]
		if seen[name] || len(parts) > maxCallees {
			continue
		}
		seen[name] = true
		if defs := ix.funcText[name]; len(defs) == 1 {
			parts = append(parts, defs[0])
		}
	}
	return strings.Join(parts, "\n")
}

var pyCallNameRe = regexp.MustCompile(`(?:^|[^\w.])([A-Za-z_]\w*)\s*\(`)

// ---- the route loop ----

type pyResult struct {
	findings []findings.Finding
	leads    []Lead
	refuted  []pyRefutation
}

type pyRefutation struct {
	path   string
	line   int
	reason string
}

func (ix *pyIndex) findings() pyResult {
	var res pyResult
	reported := map[string]bool{}
	refuted := map[string]pyRefutation{}
	var subjects []string
	for i := range ix.routes {
		r := &ix.routes[i]
		idParams := map[string]bool{}
		for _, p := range r.params {
			if idishRe.MatchString(p) {
				idParams[p] = true
			}
		}
		deps := append(ix.inheritedDeps(r.recv), r.deps...)
		authn, authz := classifyPy(deps)
		principals := map[string]bool{}
		for _, p := range r.fn.params {
			if pa, _ := classifyPy(ix.paramDeps(r.file, p)); pa != "" {
				principals[p.name] = true
			}
		}
		facts := analyzePyBody(r.file, r, idParams, principals)
		if len(facts.sinks) == 0 {
			continue
		}
		if authn == "" && authz == "" && !facts.inlineAuth {
			continue
		}
		sink := facts.sinks[0]
		line := lineAt(r.file.lineStarts, sink.off)
		subject := fmt.Sprintf("%s:%d", r.file.path, line)
		if reported[subject] {
			continue
		}
		if reason := ix.counterexample(facts, authz); reason != "" {
			if _, ok := refuted[subject]; !ok {
				refuted[subject] = pyRefutation{r.file.path, line, reason}
				subjects = append(subjects, subject)
			}
			continue
		}
		if authn == "" {
			authn = "an inline 401 on the caller's principal"
		}
		reported[subject] = true
		full := joinRoutePath(ix.fullPrefix(r.recv), r.path)
		res.findings = append(res.findings, buildFinding(findingData{
			framework: r.framework, method: r.method, path: full, authn: authn, sink: sink,
			routeFile: r.file.path, routeLine: lineAt(r.file.lineStarts, r.offset),
			handlerFile: r.file.path, line: line, function: r.fn.name,
		}))
		res.leads = append(res.leads, Lead{Method: r.method, Path: full, FilePath: r.file.path, Line: line, IDSource: idSources(sink.idFrom)})
	}
	for _, s := range subjects {
		if !reported[s] {
			res.refuted = append(res.refuted, refuted[s])
		}
	}
	return res
}

func (ix *pyIndex) counterexample(facts bodyFacts, authz string) string {
	switch {
	case facts.refuted != "":
		return facts.refuted
	case authz != "":
		return "authorization decorator or dependency on the route (" + authz + ")"
	case ix.rls:
		return "the repository enables Postgres row-level security"
	}
	return ""
}

// refuteTo files a cleared candidate in the reasoning ledger.
func refuteTo(store *reasoning.Store, path string, line int, reason, analysis string) {
	store.RefuteWithin(reasoning.Candidate(RuleID, path, line, 1), evidence.KindStatic, "nox-scan", "authz",
		reason, reasoning.Scope{
			Analysis: analysis,
			Limits:   "middleware and policy recognised by name rather than by behaviour, and a check in a callee the request is not visibly passed to",
		})
}

func sortLeads(leads []Lead) {
	sort.SliceStable(leads, func(i, j int) bool {
		a, b := leads[i], leads[j]
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Method+" "+a.Path < b.Method+" "+b.Path
	})
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
