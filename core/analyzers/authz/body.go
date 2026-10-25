package authz

import (
	"regexp"
	"sort"
	"strings"
)

// label is the dataflow colour a value carries through a handler body.
type label uint8

const (
	// lIDPath, lIDQuery, lIDBody: derived from a caller-controlled identifier
	// in a route parameter, an id-named query parameter, or an id-named body
	// field.
	lIDPath label = 1 << iota
	lIDQuery
	lIDBody
	// lP: derived from the caller's principal or from request context that
	// middleware established (req.user, req.auth, req.accountability,
	// req.tenant, the session, a token, res.locals) or from the bare request
	// object handed to a callee.
	lP
	// lREC: the result of a data-access call — the record itself.
	lREC

	// lID is any caller-controlled identifier.
	lID = lIDPath | lIDQuery | lIDBody
)

// sinkHit is a data-access call whose lookup key carries a caller-controlled
// identifier.
type sinkHit struct {
	off    int // absolute offset of the method name
	method string
	idFrom label // which identifier sources reach the lookup key
	model  string
	scoped bool // the call itself also carries the principal
}

// bodyFacts is what the body analysis observed in one handler.
type bodyFacts struct {
	sinks []sinkHit
	// refuted names the first piece of evidence that relates the record to
	// the principal, or "" when none was seen.
	refuted string
	// inlineAuth: the handler itself rejects an unauthenticated caller
	// (`if (!req.user) return res.status(401)…`).
	inlineAuth bool
}

var (
	reqNameRe = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\??\.\s*(?:params|query)\b`)
	anyCallRe = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\(`)
	declRe    = regexp.MustCompile(`\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=[^=>]`)
	assignRe  = regexp.MustCompile(`(?:^|[;{}\n])[ \t]*([A-Za-z_$][\w$]*)\s*=[^=>]`)
	compareRe = regexp.MustCompile(`===|!==|==|!=`)
	sqlRe     = regexp.MustCompile(`(?i)\b(select\s[\s\S]*\bfrom|update\s+\S+\s+set|delete\s+from)\b`)
	tableRe   = regexp.MustCompile(`(?i)\b(?:from|update|into)\s+["'\x60\[]?([A-Za-z_]\w*)`)
	idishRe   = regexp.MustCompile(`^(?:id|_id|pk|uuid|guid)$|(?:Id|ID|_id|Pk|_pk|Uuid|_uuid|UUID)$`)

	// forbiddenRe: the handler can answer 403 — an authorization decision is
	// being made here, even if this reader cannot see what it tests.
	forbiddenRe = regexp.MustCompile(`\b(?:status|sendStatus|code)\s*\(\s*403\b|\b403\s*\)|Forbidden|FORBIDDEN|HttpStatus\s*\.\s*FORBIDDEN|createError\s*\(\s*403|\bforbidden\s*\(`)
	// authzCallRe: a policy / ability / ownership call (CASL, casbin,
	// accesscontrol, hand-rolled helpers).
	authzCallRe = regexp.MustCompile(`\b(?:authori[sz]e|can|cannot|ability|accessibleBy|checkOwner\w*|isOwner\w*|assertOwner\w*|ensureOwner\w*|verifyOwner\w*|requireOwner\w*|checkAccess|hasAccess|canAccess|assertCan|enforce|permit|checkPermission\w*|hasPermission\w*|checkPolicy|policy|guard)\s*\(|\bsubject\s*\(\s*['"]|\.can\s*\(`)
	// unauthorizedRe: an inline authentication rejection.
	unauthorizedRe = regexp.MustCompile(`\b401\b|Unauthori[sz]ed|UNAUTHORI[SZ]ED`)

	// jwtVerifyRe: `await request.jwtVerify()` (@fastify/jwt) rejects a caller
	// with no valid token: the handler authenticates the caller itself.
	jwtVerifyRe = regexp.MustCompile(`\b(?:req|request)\s*\.\s*jwtVerify\s*\(`)

	responseRecvRe = regexp.MustCompile(`^(?:res|response|reply|ctx\s*\.\s*body|console|logger|log|this\s*\.\s*logger)\b`)
	nonGatingCalls = map[string]bool{"json": true, "send": true, "render": true, "status": true, "log": true, "info": true, "debug": true, "warn": true, "error": true, "trace": true, "end": true, "redirect": true, "sendStatus": true}
)

// Data-access vocabulary. ormMethods name a record by key on their own;
// genericMethods only when the receiver looks like a model or a client;
// sqlMethods only when a SQL statement is in the call; serviceVerbs only on a
// receiver named like a service/repository layer.
var (
	ormMethods = setOf("findById", "findByPk", "findOne", "findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow",
		"findOneBy", "findOneByOrFail", "findOneOrFail", "findByIdAndUpdate", "findByIdAndDelete", "findByIdAndRemove",
		"findOneAndUpdate", "findOneAndDelete", "findOneAndRemove", "findOneAndReplace", "deleteOne", "updateOne",
		"replaceOne", "findAll", "where", "andWhere", "whereIn", "getById", "findByIdOrFail")
	genericMethods = setOf("find", "update", "delete", "remove", "destroy", "upsert", "deleteMany", "updateMany", "count", "findMany")
	sqlMethods     = setOf("query", "execute", "raw", "run", "get", "all", "one", "oneOrNone", "many", "manyOrNone", "any", "none", "result", "exec", "prepare")
	serviceVerbRe  = regexp.MustCompile(`^(?:get|find|fetch|load|read|delete|remove|update|destroy|retrieve|select|patch|edit|show)`)
	serviceRecvRe  = regexp.MustCompile(`(?i)(?:dao|repository|repo|service|model|store|manager|getter|finder|locator|loader|collection|table|db|prisma|knex|orm)$`)
	modelRecvRe    = regexp.MustCompile(`(?i)(?:^|\.)(?:prisma|db|knex|orm|em|manager|entityManager|query|queries|models?|repos?|repositories|daos?|stores?)(?:\.|$)|(?:Model|Repository|Repo|repo|Collection|collection|Table|Dao|DAO|Store)$`)
)

func setOf(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// bodyCtx carries one handler's text and the dataflow state over it.
type bodyCtx struct {
	f         *jsFile
	base      int
	text      string
	raw       string
	req       []string
	idSeed    *regexp.Regexp
	pSeed     *regexp.Regexp
	reqMember *regexp.Regexp
	bareReq   *regexp.Regexp
	authGate  *regexp.Regexp
	vars      map[string]label
	idKeys    map[string]bool // route parameters that are identifiers
	// bodyPrincipal: owner-named body fields carry the principal.
	bodyPrincipal bool
	calls         []callSite
	nonGat        []span // callback bodies whose result cannot affect the response
}

type callSite struct {
	nameStart int // relative offset of the callee name
	name      string
	recv      string // receiver chain text (code), "" for a bare call
	recvStart int
	open      int // relative offset of `(`
	closeAt   int // relative offset of `)`
	args      []span
}

// analyzeBody runs the handler-body analysis. idParams are the route's
// identifier-like parameters; an empty set means the route carries none, in
// which case only id-named query parameters seed lID.
//
// bodyPrincipal is set when middleware on the route writes the principal into
// the request body (`appendUserId()`): an owner-named body field then holds
// the caller's id, not one the caller chose.
func analyzeBody(f *jsFile, s span, idParams map[string]bool, bodyPrincipal bool) bodyFacts {
	b := newBodyCtx(f, s, idParams)
	b.bodyPrincipal = bodyPrincipal
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
	facts.inlineAuth = b.authGate.MatchString(b.text) && unauthorizedRe.MatchString(b.text) || jwtVerifyRe.MatchString(b.text)
	facts.refuted = b.refutation(facts.sinks)
	return facts
}

func newBodyCtx(f *jsFile, s span, idParams map[string]bool) *bodyCtx {
	b := &bodyCtx{f: f, base: s.start, text: maskTSCasts(f.code[s.start:s.end]), raw: string(f.raw[s.start:s.end]), vars: map[string]label{}, idKeys: idParams}
	seen := map[string]bool{"req": true, "request": true, "ctx": true}
	b.req = []string{"req", "request", "ctx"}
	for _, m := range reqNameRe.FindAllStringSubmatch(b.text, -1) {
		if !seen[m[1]] && m[1] != "this" {
			seen[m[1]] = true
			b.req = append(b.req, m[1])
		}
	}
	sort.Strings(b.req)
	alt := strings.Join(b.req, "|")
	b.idSeed = regexp.MustCompile(`\b(?:` + alt + `)\s*\??\.\s*(?:params\s*(?:\??\.\s*([A-Za-z_$][\w$]*)|\[)|query\s*\??\.\s*([A-Za-z_$][\w$]*)|(?:request\s*\.\s*)?body\s*\??\.\s*([A-Za-z_$][\w$]*))`)
	b.reqMember = regexp.MustCompile(`\b(?:` + alt + `)\s*\??\.\s*([A-Za-z_$][\w$]*)(\s*\??\.\s*[A-Za-z_$][\w$]*)?`)
	b.pSeed = regexp.MustCompile(`\bres\s*\.\s*locals\b|\bthis\s*\.\s*(?:user|currentUser)\b|\b(?:currentUser|current_user|getCurrentUser|getSession|getServerSession|authUser|loggedInUser)\b`)
	b.bareReq = regexp.MustCompile(`[(,]\s*(?:` + alt + `)\s*[,)]`)
	// authGate: `if (!req.user …` — the handler rejects a caller with no
	// principal. Only the conventional principal names count here: a custom
	// request flag (`req.isHTML`) next to a 401 for a wrong link password is
	// not authentication.
	b.authGate = regexp.MustCompile(`\bif\s*\(\s*!\s*(?:` + alt + `)\s*\??\.\s*(?:user|auth|session|currentUser|userId|account|principal|identity|claims|isAuthenticated)\b`)
	return b
}

// seedLabels returns the labels b.text[from:to] carries from seeds alone.
func (b *bodyCtx) seedLabels(from, to int) label {
	text := b.text[from:to]
	var l label
	for _, m := range b.idSeed.FindAllStringSubmatchIndex(text, -1) {
		switch {
		case m[2] >= 0:
			if b.idKeys[text[m[2]:m[3]]] {
				l |= lIDPath
			}
		case m[4] >= 0:
			if idishRe.MatchString(text[m[4]:m[5]]) {
				l |= lIDQuery
			}
		case m[6] >= 0:
			key := text[m[6]:m[7]]
			switch {
			case b.bodyPrincipal && ownerFieldRe.MatchString(key):
				l |= lP
			case idishRe.MatchString(key):
				l |= lIDBody
			}
		default: // req.params[…]
			if b.bracketKeyIsID(from + m[1]) {
				l |= lIDPath
			}
		}
	}
	if b.hasPrincipal(text) {
		l |= lP
	}
	return l
}

// bracketKeyIsID reads the key of `params[<key>]` starting at at (just after
// the bracket): a string literal is an identifier only if it names one of the
// route's identifier parameters; a computed key is taken as one.
func (b *bodyCtx) bracketKeyIsID(at int) bool {
	for at < len(b.text) && isSpace(b.text[at]) {
		at++
	}
	if at >= len(b.text) {
		return false
	}
	q := b.text[at]
	if q != '\'' && q != '"' && q != '`' {
		return true
	}
	end := strings.IndexByte(b.text[at+1:], q)
	if end < 0 {
		return false
	}
	return b.idKeys[b.raw[at+1:at+1+end]]
}

// requestInputs are the request members that carry what the CALLER sent, or
// describe the transport. Every other member of the request object was put
// there by middleware (req.user, req.auth, req.accountability, req.tenant,
// req.ability, ctx.state…) and is treated as principal context: a handler
// that hands it to a data call may be scoping that call, and this reader
// cannot tell which custom property is the scope.
var requestInputs = setOf("params", "param", "query", "body", "files", "file", "ip", "ips", "method", "url", "path",
	"originalUrl", "baseUrl", "protocol", "hostname", "host", "get", "header", "headers", "is", "accepts", "acceptsLanguages",
	"acceptsCharsets", "acceptsEncodings", "app", "route", "res", "secure", "xhr", "fresh", "stale", "subdomains",
	"range", "__", "t", "i18n", "flash", "log", "logger", "id", "rawBody", "socket", "connection", "on", "pipe",
	"request", "response", "status", "set", "throw", "redirect", "type", "length", "href", "querystring", "search",
	"origin", "next", "render", "json", "send", "end", "language", "languages", "httpVersion",
	"complete", "aborted", "destroy", "emit", "removeListener", "pause", "resume", "read", "setTimeout", "trailers",
	"rawHeaders", "rawTrailers", "statusCode", "statusMessage", "signedCookies", "cookies", "hash",
	"upload", "uploads", "attachment", "attachments")

// hasPrincipal reports whether text reads the caller's principal or other
// middleware-established request context.
func (b *bodyCtx) hasPrincipal(text string) bool {
	if b.pSeed.MatchString(text) || b.passesRequest(text) {
		return true
	}
	for _, m := range b.reqMember.FindAllStringSubmatch(text, -1) {
		member := m[1]
		switch {
		case member == "headers" || member == "header" || member == "get" || member == "cookies" || member == "signedCookies":
			// The bearer token or session cookie: decoding it is reading the
			// principal. Any other header or cookie is caller input.
			if authCarrierRe.MatchString(m[0] + m[2]) {
				return true
			}
		case member == "request":
			if strings.Contains(m[2], "user") || strings.Contains(m[2], "auth") {
				return true
			}
		case !requestInputs[member]:
			return true
		}
	}
	return false
}

// passesRequest reports whether text hands the bare request object to a
// call (`repoFor(req)`, `authenticatedUsers.from(req)`): the callee can read
// the principal from it. A function's own parameter list (`(req, res) =>`,
// `function (req, res) {`) is not a call.
func (b *bodyCtx) passesRequest(text string) bool {
	for _, m := range b.bareReq.FindAllStringIndex(text, -1) {
		open := m[0]
		if text[open] == ',' {
			open = enclosingOpen(text, m[0]-1) // `f(a, req)`
		}
		if open < 0 || text[open] != '(' {
			continue
		}
		closeAt := matchClose(text, open)
		if closeAt < 0 {
			continue
		}
		after := strings.TrimLeft(text[closeAt+1:], " \t\r\n")
		if strings.HasPrefix(after, "=>") || strings.HasPrefix(after, "{") || strings.HasPrefix(after, ":") {
			continue // a parameter list
		}
		before := strings.TrimRight(text[:open], " \t")
		if strings.HasSuffix(before, "function") || strings.HasSuffix(before, "async") {
			continue
		}
		return true
	}
	return false
}

// enclosingOpen returns the offset of the `(` that encloses off, or -1.
func enclosingOpen(text string, off int) int {
	depth := 0
	for i := off; i >= 0; i-- {
		switch text[i] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

var authCarrierRe = regexp.MustCompile(`(?i)authori[sz]ation|token|jwt|session|auth`)

// labelsOf returns the labels of a span of the body (relative offsets).
func (b *bodyCtx) labelsOf(from, to int) label {
	if from < 0 || to > len(b.text) || from >= to {
		return 0
	}
	t := b.text[from:to]
	l := b.seedLabels(from, to)
	for v, vl := range b.vars {
		if l&vl == vl {
			continue
		}
		if hasWord(t, v) {
			l |= vl
		}
	}
	for i := range b.calls {
		c := &b.calls[i]
		if c.nameStart >= from && c.closeAt < to && b.isDataAccess(c) {
			l |= lREC
		}
	}
	return l
}

// collectCalls records every call in the body with its receiver and args.
func (b *bodyCtx) collectCalls() {
	for _, m := range anyCallRe.FindAllStringSubmatchIndex(b.text, -1) {
		name := b.text[m[2]:m[3]]
		if jsKeywords[name] {
			continue
		}
		open := m[1] - 1
		closeAt := matchClose(b.text, open)
		if closeAt < 0 {
			continue
		}
		c := callSite{nameStart: m[2], name: name, open: open, closeAt: closeAt}
		c.args = splitArgs(b.text, open+1, closeAt)
		if dot := dotBefore(b.text, m[2]); dot >= 0 {
			c.recvStart = receiverStart(b.text, dot)
			c.recv = strings.TrimSpace(b.text[c.recvStart:dot])
		} else {
			c.recvStart = m[2]
		}
		b.calls = append(b.calls, c)
	}
	// Callbacks handed to a call whose result is discarded, and which neither
	// respond nor throw, cannot gate the response: a comparison inside one is
	// instrumentation, not an authorization check.
	for i := range b.calls {
		c := &b.calls[i]
		if !b.isStatement(c.recvStart) {
			continue
		}
		for _, a := range c.args {
			at := b.text[a.start:a.end]
			if !inlineFnRe.MatchString(at) {
				continue
			}
			if strings.Contains(at, "res.") || strings.Contains(at, "response.") || strings.Contains(at, "throw") || strings.Contains(at, "next(") || strings.Contains(at, "ctx.") || strings.Contains(at, "reply.") {
				continue
			}
			b.nonGat = append(b.nonGat, a)
		}
	}
}

var jsKeywords = setOf("if", "for", "while", "switch", "catch", "function", "return", "typeof", "await", "new", "super", "import", "require", "async", "else", "do", "try", "with", "yield", "delete", "void", "in", "of", "instanceof")

// dotBefore returns the offset of the `.` (or `?.`) immediately preceding a
// name, or -1 for a bare call.
func dotBefore(text string, nameStart int) int {
	i := nameStart - 1
	for i >= 0 && isSpace(text[i]) {
		i--
	}
	if i >= 0 && text[i] == '.' {
		if i > 0 && text[i-1] == '?' {
			return i - 1
		}
		return i
	}
	return -1
}

// receiverStart walks back from a member dot over the receiver chain:
// identifiers, dots, optional chaining and balanced call/index groups.
func receiverStart(text string, dot int) int {
	i := dot - 1
	for i >= 0 {
		c := text[i]
		switch {
		case isIdentByte(c) || c == '.' || c == '?':
			i--
		case c == ')' || c == ']':
			j := matchOpen(text, i)
			if j < 0 {
				return i + 1
			}
			i = j - 1
		case isSpace(c):
			// allow whitespace only inside a chain broken across lines (`.x`)
			k := i
			for k >= 0 && isSpace(text[k]) {
				k--
			}
			if k >= 0 && text[k] == '.' || i+1 < len(text) && text[i+1] == '.' {
				i = k
				continue
			}
			return i + 1
		default:
			return i + 1
		}
	}
	return 0
}

func matchOpen(text string, closeAt int) int {
	var stack []byte
	for i := closeAt; i >= 0; i-- {
		switch c := text[i]; c {
		case ')', ']', '}':
			stack = append(stack, c)
		case '(', '[', '{':
			if len(stack) == 0 || opener(stack[len(stack)-1]) != c {
				return -1
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i
			}
		}
	}
	return -1
}

// isStatement reports whether an expression starting at off begins a
// statement (its value is discarded).
func (b *bodyCtx) isStatement(off int) bool {
	i := off - 1
	for i >= 0 && (b.text[i] == ' ' || b.text[i] == '\t') {
		i--
	}
	if i >= 4 && b.text[i-4:i+1] == "await" {
		i -= 5
		for i >= 0 && (b.text[i] == ' ' || b.text[i] == '\t') {
			i--
		}
	}
	return i < 0 || b.text[i] == ';' || b.text[i] == '{' || b.text[i] == '}' || b.text[i] == '\n'
}

func (b *bodyCtx) inNonGating(off int) bool {
	for _, s := range b.nonGat {
		if off >= s.start && off < s.end {
			return true
		}
	}
	return false
}

// propagate computes variable labels from declarations and assignments, to a
// fixpoint over a few passes (assignments are few; three passes cover the
// chains real handlers write).
func (b *bodyCtx) propagate() {
	type asg struct {
		target  string
		rhsFrom int
		rhsTo   int
	}
	var asgs []asg
	for _, m := range declRe.FindAllStringSubmatchIndex(b.text, -1) {
		from := m[1] - 1
		asgs = append(asgs, asg{b.text[m[2]:m[3]], from, expressionEnd(b.text, from, false)})
	}
	for _, m := range assignRe.FindAllStringSubmatchIndex(b.text, -1) {
		from := m[1] - 1
		asgs = append(asgs, asg{b.text[m[2]:m[3]], from, expressionEnd(b.text, from, false)})
	}
	for pass := 0; pass < 3; pass++ {
		changed := false
		for _, a := range asgs {
			rhs := strings.TrimSpace(b.text[a.rhsFrom:a.rhsTo])
			for name, l := range b.targetLabels(a.target, rhs, a.rhsFrom, a.rhsTo) {
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

// targetLabels returns the labels each bound name receives from rhs.
func (b *bodyCtx) targetLabels(target, rhs string, from, to int) map[string]label {
	out := map[string]label{}
	if strings.HasPrefix(target, "{") || strings.HasPrefix(target, "[") {
		src := strings.TrimPrefix(rhs, "await ")
		isParams, isQuery, isBody := false, false, false
		for _, r := range b.req {
			q := `^` + regexp.QuoteMeta(r) + `\s*\??\.\s*`
			isParams = isParams || regexp.MustCompile(q+`params$`).MatchString(src)
			isQuery = isQuery || regexp.MustCompile(q+`query$`).MatchString(src)
			isBody = isBody || regexp.MustCompile(q+`(?:request\s*\.\s*)?body$`).MatchString(src)
		}
		whole := b.labelsOf(from, to)
		for key, local := range patternNames(target[1 : len(target)-1]) {
			switch {
			case isParams:
				if b.idKeys[key] {
					out[local] = lIDPath
				}
			case isQuery:
				if idishRe.MatchString(key) {
					out[local] = lIDQuery
				}
			case isBody:
				if idishRe.MatchString(key) {
					out[local] = lIDBody
				}
			default:
				out[local] = whole
			}
		}
		return out
	}
	if l := b.labelsOf(from, to); l != 0 {
		out[target] = l
	}
	return out
}

// patternNames maps each destructured key to the local name it binds.
func patternNames(inner string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(inner, ",") {
		part = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "..."))
		if part == "" {
			continue
		}
		key, local := part, part
		if i := strings.IndexByte(part, ':'); i >= 0 {
			key, local = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+1:])
		}
		if i := strings.IndexByte(local, '='); i >= 0 {
			local = strings.TrimSpace(local[:i])
		}
		if i := strings.IndexByte(key, '='); i >= 0 {
			key = strings.TrimSpace(key[:i])
		}
		if isPlainIdent(local) {
			out[key] = local
		}
	}
	return out
}

// isDataAccess reports whether a call reads or writes a stored record.
func (b *bodyCtx) isDataAccess(c *callSite) bool {
	if c.recv == "" {
		return false
	}
	switch {
	case ormMethods[c.name]:
		return true
	case genericMethods[c.name]:
		return modelRecvRe.MatchString(c.recv) || startsUpper(lastSegment(c.recv))
	case sqlMethods[c.name]:
		return sqlRe.MatchString(b.raw[c.recvStart:c.closeAt])
	case serviceVerbRe.MatchString(c.name):
		// A repository/service object, or a capitalised model class with a
		// static finder (`Discussion.edit(...)`, `Team.getTeam(...)`).
		last := lastSegment(c.recv)
		return serviceRecvRe.MatchString(last) || startsUpper(last) && !jsBuiltins[last]
	}
	return false
}

// jsBuiltins are capitalised globals whose get*/find* methods touch no store.
var jsBuiltins = setOf("Object", "Array", "Reflect", "Math", "JSON", "Promise", "Number", "String", "Date", "Map", "Set",
	"WeakMap", "Buffer", "URL", "Intl", "Symbol", "Proxy", "Atomics", "BigInt", "Boolean", "Error", "RegExp")

func lastSegment(chain string) string {
	chain = strings.TrimSpace(chain)
	// `ProjectGetter.promises.getProject`: the promise facade of a module is
	// the module.
	chain = strings.TrimSuffix(chain, ".promises")
	if i := strings.LastIndexByte(chain, '.'); i >= 0 {
		return strings.TrimSpace(chain[i+1:])
	}
	return chain
}

func startsUpper(s string) bool { return s != "" && s[0] >= 'A' && s[0] <= 'Z' }

// sink classifies a call as an identifier-keyed data access.
func (b *bodyCtx) sink(c *callSite) (sinkHit, bool) {
	if !b.isDataAccess(c) {
		return sinkHit{}, false
	}
	var argL label
	for _, a := range c.args {
		if inlineFnRe.MatchString(b.text[a.start:a.end]) {
			continue // a callback is not the lookup key
		}
		argL |= b.labelsOf(a.start, a.end)
	}
	if argL&lID == 0 {
		return sinkHit{}, false
	}
	recvL := b.labelsOf(c.recvStart, c.nameStart)
	scoped := (argL|recvL)&lP != 0 || b.recvIsRequestScoped(c.recv) || b.ownerScoped(c)
	return sinkHit{off: b.base + c.nameStart, method: c.name, idFrom: argL & lID, model: b.modelKey(c), scoped: scoped}, true
}

// ownerFieldRe names a field that holds the owning principal's id.
var ownerFieldRe = regexp.MustCompile(`(?i)^(?:user|owner|account|tenant|org|organization|customer|member|author)_?id$`)

var (
	ownerKeyRe   = regexp.MustCompile(`(?i)(?:^|[{,\s])["']?(owner\w*|user_?id|user|author\w*|account_?id|tenant_?id|org_?id|organization_?id|created_?by|customer_?id|member_?id)["']?\s*:`)
	ownerShortRe = regexp.MustCompile(`(?i)[{,]\s*(owner\w*|user_?id|account_?id|tenant_?id|org_?id|organization_?id|customer_?id|member_?id)\s*[,}]`)
	sqlOwnerRe   = regexp.MustCompile(`(?i)\b["\x60]?(?:owner|user|account|tenant|org|organization|customer|author|member)_?id["\x60]?\s*=`)
)

// ownerScoped: the lookup also filters on an owner-like field whose value is
// not the caller-controlled identifier (`{ id, UserId: req.body.UserId }`,
// `WHERE id = $1 AND user_id = $2` with a second, non-identifier bind value).
// Where that value comes from is not traced; an owner filter is taken as the
// developer's ownership check.
func (b *bodyCtx) ownerScoped(c *callSite) bool {
	for _, a := range c.args {
		t := b.text[a.start:a.end]
		if inlineFnRe.MatchString(t) {
			continue
		}
		for _, m := range ownerKeyRe.FindAllStringIndex(t, -1) {
			from := a.start + m[1]
			to := expressionEnd(b.text, from, true)
			if to > a.end {
				to = a.end
			}
			if strings.TrimSpace(b.text[from:to]) != "" && b.labelsOf(from, to)&lID == 0 {
				return true
			}
		}
		for _, m := range ownerShortRe.FindAllStringSubmatch(t, -1) {
			if b.vars[m[1]]&lID == 0 {
				return true
			}
		}
	}
	if !sqlMethods[c.name] || !sqlOwnerRe.MatchString(b.raw[c.recvStart:c.closeAt]) {
		return false
	}
	ids, others := 0, 0
	for _, a := range c.args {
		t := strings.TrimSpace(b.text[a.start:a.end])
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			for _, e := range splitArgs(b.text, a.start+1, a.end-1) {
				if b.labelsOf(e.start, e.end)&lID != 0 {
					ids++
				} else {
					others++
				}
			}
		}
	}
	return others > 0 || ids == 0
}

// recvIsRequestScoped: a data client hung off the request or res.locals is a
// per-request (tenant- or user-scoped) connection.
func (b *bodyCtx) recvIsRequestScoped(recv string) bool {
	if strings.HasPrefix(recv, "res.locals") || strings.HasPrefix(recv, "ctx.state") {
		return true
	}
	for _, r := range b.req {
		if strings.HasPrefix(recv, r+".") {
			return true
		}
	}
	return false
}

// modelKey names the collection a data-access call targets, normalised so
// `Invoice`, `prisma.invoice`, `knex('invoices')` and `FROM invoices` agree.
func (b *bodyCtx) modelKey(c *callSite) string {
	if sqlMethods[c.name] {
		if m := tableRe.FindStringSubmatch(b.raw[c.recvStart:c.closeAt]); m != nil {
			return normalizeModel(m[1])
		}
	}
	recv := strings.TrimSpace(c.recv)
	if strings.HasSuffix(recv, ")") {
		if open := matchOpen(recv, len(recv)-1); open > 0 {
			rawRecv := b.raw[c.recvStart : c.recvStart+len(b.text[c.recvStart:c.nameStart])]
			inner := strings.TrimSpace(rawRecv[open+1 : len(recv)-1])
			inner = strings.Trim(inner, `'"`+"`")
			if i := strings.IndexByte(inner, ','); i >= 0 {
				inner = inner[:i]
			}
			if inner != "" {
				return normalizeModel(inner)
			}
			recv = recv[:open]
		}
	}
	return normalizeModel(lastSegment(recv))
}

var modelSuffixRe = regexp.MustCompile(`(?i)(?:model|dao|repository|repo|service|store|collection|table|manager|schema)$`)

func normalizeModel(s string) string {
	s = strings.TrimSpace(s)
	s = modelSuffixRe.ReplaceAllString(s, "")
	s = strings.Trim(strings.ToLower(s), "_")
	switch {
	case strings.HasSuffix(s, "ies"):
		s = s[:len(s)-3] + "y"
	case strings.HasSuffix(s, "sses"), strings.HasSuffix(s, "xes"), strings.HasSuffix(s, "ches"), strings.HasSuffix(s, "shes"):
		s = s[:len(s)-2]
	case strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss"):
		s = s[:len(s)-1]
	}
	return s
}

// refutation returns the first observed relation between the record and the
// principal, or "" when the body shows none. Each branch is a counterexample
// class from the rule's proposition.
func (b *bodyCtx) refutation(sinks []sinkHit) string {
	for _, h := range sinks {
		if h.scoped {
			return "the lookup is scoped by the caller's principal (" + h.method + ")"
		}
	}
	if m := forbiddenRe.FindString(b.text); m != "" {
		return "the handler can answer 403 (" + strings.TrimSpace(m) + ")"
	}
	if m := authzCallRe.FindString(b.text); m != "" {
		return "the handler calls an authorization check (" + strings.TrimSpace(m) + ")"
	}
	if r := b.roleCheck(); r != "" {
		return r
	}
	for _, m := range compareRe.FindAllStringIndex(b.text, -1) {
		if b.inNonGating(m[0]) {
			continue
		}
		left := operandBefore(b.text, m[0])
		right := operandAfter(b.text, m[1])
		// One side is the principal, the other the record or its id:
		// `doc.owner !== req.user.id`. A side that carries both (`wallet !=
		// null` on a principal-scoped lookup) relates nothing to anything.
		ll, rl := b.labelsOf(left, m[0]), b.labelsOf(m[1], right)
		if ll&lP != 0 && rl&(lID|lREC) != 0 || rl&lP != 0 && ll&(lID|lREC) != 0 {
			return "the record is compared with the caller's principal (" + strings.Join(strings.Fields(b.text[left:right]), " ") + ")"
		}
	}
	for i := range b.calls {
		c := &b.calls[i]
		if b.inNonGating(c.nameStart) || nonGatingCalls[c.name] || responseRecvRe.MatchString(c.recv) {
			continue
		}
		l := b.labelsOf(c.recvStart, c.nameStart)
		for _, a := range c.args {
			if inlineFnRe.MatchString(b.text[a.start:a.end]) {
				continue
			}
			l |= b.labelsOf(a.start, a.end)
		}
		if l&lP != 0 && l&(lID|lREC) != 0 {
			return "the record and the caller's principal meet in a call (" + c.name + ")"
		}
	}
	return ""
}

var roleMemberRe = regexp.MustCompile(`\.\s*(?:role|roles|isAdmin|admin|is_admin|permissions|scopes|scope|isStaff|is_staff|is_superuser|isSuperuser|superuser|groups|accessLevel|access_level)\b`)

// roleCheck: the handler reads the principal's role or permissions, so it is
// role-aware (an admin reading any record is the intended behaviour).
func (b *bodyCtx) roleCheck() string {
	for _, m := range roleMemberRe.FindAllStringIndex(b.text, -1) {
		start := receiverStart(b.text, m[0])
		if b.labelsOf(start, m[0])&lP != 0 {
			return "the handler reads the caller's role (" + strings.TrimSpace(b.text[start:m[1]]) + ")"
		}
	}
	return ""
}

// operandBefore returns the start of the operand ending just before off.
func operandBefore(text string, off int) int {
	i := off - 1
	for i >= 0 && isSpace(text[i]) {
		i--
	}
	if i < 0 {
		return off
	}
	return receiverStart(text, i+1)
}

// operandAfter returns the end of the operand starting just after off.
func operandAfter(text string, off int) int {
	i := off
	for i < len(text) && (isSpace(text[i]) || text[i] == '!') {
		i++
	}
	for i < len(text) {
		c := text[i]
		switch {
		case isIdentByte(c) || c == '.' || c == '?':
			i++
		case c == '(' || c == '[':
			j := matchClose(text, i)
			if j < 0 {
				return i
			}
			i = j + 1
		default:
			return i
		}
	}
	return i
}

var (
	tsParenCastRe = regexp.MustCompile(`\(\s*(\w+\s*\.\s*(?:params|query|body))\s+as\s+(?:any|[A-Za-z_$][\w$.<>\[\]]*|\{[^{}]*\})\s*\)`)
	tsTailCastRe  = regexp.MustCompile(`\w+\s*\.\s*(?:params|query|body)(\s+as\s+(?:any|[A-Za-z_$][\w$.<>\[\]]*|\{[^{}]*\}))`)
)

// maskTSCasts blanks a TypeScript assertion on the request's input so that
// `(request.params as { id: string }).id` and
// `const { id } = request.params as Params` read as `request.params.id` and
// `request.params`. Offsets are unchanged.
func maskTSCasts(text string) string {
	if !strings.Contains(text, " as ") {
		return text
	}
	b := []byte(text)
	blank := func(from, to int) {
		for i := from; i < to; i++ {
			if b[i] != '\n' {
				b[i] = ' '
			}
		}
	}
	for _, m := range tsParenCastRe.FindAllStringSubmatchIndex(text, -1) {
		blank(m[0], m[2])
		blank(m[3], m[1])
	}
	text = string(b)
	for _, m := range tsTailCastRe.FindAllStringSubmatchIndex(text, -1) {
		blank(m[2], m[3])
	}
	return string(b)
}
