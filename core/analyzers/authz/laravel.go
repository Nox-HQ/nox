package authz

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// Laravel routes (routes/*.php) and the controllers they name.
//
// A route is a call on the Route facade (or `$router`): `Route::get('/users/{id}',
// [UserController::class, 'show'])`, `Route::resource`/`apiResource` (expanded
// to their routes, with ->only/->except), `Route::match`, `Route::any`, wrapped
// in `Route::prefix('x')->group(...)`, `Route::middleware('auth')->group(...)`,
// `Route::controller(X::class)->group(...)` and the array form
// `Route::group(['middleware' => ..., 'prefix' => ...], fn)`. A route is judged
// from the middleware in front of it and from the controller it names.
//
// What it states, and no more:
//
//   - a route is authenticated by middleware `auth`, `auth:*` (sanctum, api,
//     web), `auth.basic`, `Authenticate::class`, or a middleware whose own name
//     says it authenticates (jwt.auth, RequireLogin), on the route, on any
//     enclosing group, on a controller constructor (`$this->middleware('auth')`
//     with ->only/->except), in a controller's `middleware()` (HasMiddleware),
//     on a parent controller, or by an inline check on the caller
//     (auth()->user(), Auth::check(), $request->user(), abort(401/403));
//     `can:`, `role:` and `authorizeResource` are access control too.
//     `verified`, `guest`, `throttle`, `signed` and AuthenticateSession are not
//     authentication;
//   - `withoutMiddleware('auth')` removes the middleware it names from the
//     group above it;
//   - routes/web.php and routes/api.php are NOT authenticated by default: the
//     `web` and `api` groups start a session or rate limit, they do not check
//     the caller. routes/api.php is served under /api, as the framework's
//     default RouteServiceProvider and bootstrap/app.php do, unless a provider
//     in the repository maps it elsewhere (its prefix and middleware are then
//     read from the provider);
//   - what this reader cannot see is never called authenticated and never
//     called missing: a middleware list or prefix that is a variable (the
//     routes in it are not read when the path is unknown, and carry no claim
//     when only the middleware is), a global `web`/`api`/global middleware that
//     authenticates in app/Http/Kernel.php or bootstrap/app.php, a route file
//     nothing maps, a controller outside the repository or from a package, a
//     trait whose name says authentication, and a handler it cannot read mark
//     the route `unseen`: in the table, never a lead.
//
// Not read: `Route::view`, `redirect`, `fallback`, `singleton`, route model
// binding, domain routing, `Route::resource(...)->shallow()` (read, never a
// lead), PHP 8 attributes, routes registered by packages and by service
// providers other than the mapping of route files, and middleware aliases
// outside Kernel.php and bootstrap/app.php.

// phpFile is one PHP source file.
type phpFile struct {
	path       string
	code       string // lexctx.MaskNonCode
	sans       string // comments blanked, strings kept
	lineStarts []int
	imports    map[string]string // lower(alias) -> FQN
}

func newPHPFile(path string, raw []byte) *phpFile {
	f := &phpFile{
		path:       path,
		code:       string(lexctx.MaskNonCode(lexctx.LangPHP, raw)),
		sans:       withoutComments(lexctx.LangPHP, raw),
		lineStarts: computeLineStarts(raw),
	}
	f.imports = phpImports(f)
	return f
}

var (
	phpUseRe      = regexp.MustCompile(`(?m)^[ \t]*use\s+([\w\\]+?)(?:\s+as\s+(\w+))?\s*;`)
	phpGroupUseRe = regexp.MustCompile(`(?m)^[ \t]*use\s+([\w\\]+?)\\\{([^}]*)\}\s*;`)
	phpNSRe       = regexp.MustCompile(`(?m)^[ \t]*namespace\s+([\w\\]+)\s*;`)
	phpClassRe    = regexp.MustCompile(`(?m)^[ \t]*(?:(?:abstract|final)\s+)?class\s+(\w+)(?:\s+extends\s+([\w\\]+))?[^{]*\{`)
)

// phpImports reads the file's `use` imports (those before its first class).
func phpImports(f *phpFile) map[string]string {
	head := f.sans
	if loc := phpClassRe.FindStringIndex(f.code); loc != nil {
		head = f.sans[:loc[0]]
	}
	out := map[string]string{}
	for _, m := range phpUseRe.FindAllStringSubmatch(head, -1) {
		name := strings.TrimPrefix(m[1], "\\")
		alias := m[2]
		if alias == "" {
			alias = name[strings.LastIndexByte(name, '\\')+1:]
		}
		out[strings.ToLower(alias)] = name
	}
	for _, m := range phpGroupUseRe.FindAllStringSubmatch(head, -1) {
		for _, part := range strings.Split(m[2], ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, alias, _ := strings.Cut(part, " as ")
			name = strings.TrimSpace(name)
			if alias == "" {
				alias = name[strings.LastIndexByte(name, '\\')+1:]
			}
			out[strings.ToLower(strings.TrimSpace(alias))] = strings.TrimPrefix(m[1], "\\") + "\\" + name
		}
	}
	return out
}

// ---- call chains ----

type phpCall struct {
	name         string
	open, closep int
}

var phpNameRe = regexp.MustCompile(`^[A-Za-z_]\w*`)

// phpChain reads `name(args)->name(args)...` starting at the first name.
func phpChain(code string, nameStart, limit int) (calls []phpCall, end int) {
	i := nameStart
	for i < limit {
		name := phpNameRe.FindString(code[i:limit])
		if name == "" {
			break
		}
		j := skipWS(code, i+len(name), limit)
		if j >= limit || code[j] != '(' {
			break
		}
		c := matchClose(code, j)
		if c < 0 || c >= limit {
			break
		}
		calls = append(calls, phpCall{name, j, c})
		i = c + 1
		k := skipWS(code, i, limit)
		switch {
		case strings.HasPrefix(code[k:limit], "->"):
			i = skipWS(code, k+2, limit)
		case strings.HasPrefix(code[k:limit], "?->"):
			i = skipWS(code, k+3, limit)
		default:
			return calls, c + 1
		}
	}
	if len(calls) == 0 {
		return nil, nameStart
	}
	return calls, calls[len(calls)-1].closep + 1
}

func skipWS(code string, i, end int) int {
	for i < end && isSpace(code[i]) {
		i++
	}
	return i
}

// args splits a call's arguments, trimmed by the comment-free text.
func (f *phpFile) args(c phpCall) []span {
	var out []span
	for _, sp := range rbSplit(f.code, c.open+1, c.closep) {
		for sp.start < sp.end && isSpace(f.sans[sp.start]) {
			sp.start++
		}
		for sp.end > sp.start && isSpace(f.sans[sp.end-1]) {
			sp.end--
		}
		if sp.end > sp.start {
			out = append(out, sp)
		}
	}
	return out
}

func (f *phpFile) text(sp span) string { return f.sans[sp.start:sp.end] }

// str reads a string literal; a double-quoted string with interpolation is not
// a literal.
func (f *phpFile) str(sp span) (string, bool) {
	if sp.end-sp.start < 2 {
		return "", false
	}
	q := f.code[sp.start]
	if (q != '\'' && q != '"') || f.code[sp.end-1] != q {
		return "", false
	}
	v := f.sans[sp.start+1 : sp.end-1]
	if q == '"' && strings.ContainsRune(v, '$') || strings.ContainsRune(v, '\\') && q == '"' {
		return "", false
	}
	return v, true
}

var phpClassRefRe = regexp.MustCompile(`^\\?([A-Za-z_][\w\\]*)::class$`)

// classRef reads `X::class`.
func (f *phpFile) classRef(sp span) (string, bool) {
	m := phpClassRefRe.FindStringSubmatch(strings.TrimSpace(f.text(sp)))
	if m == nil {
		return "", false
	}
	if strings.HasPrefix(strings.TrimSpace(f.text(sp)), "\\") {
		return "\\" + m[1], true
	}
	return m[1], true
}

// list reads an array literal into its element spans.
func (f *phpFile) list(sp span) ([]span, bool) {
	t := f.code[sp.start:sp.end]
	open, last := sp.start, sp.end-1
	switch {
	case strings.HasPrefix(t, "["):
	case strings.HasPrefix(t, "array") && strings.HasSuffix(t, ")"):
		open = sp.start + strings.IndexByte(t, '(')
	default:
		return nil, false
	}
	if matchClose(f.code, open) != last {
		return nil, false
	}
	var out []span
	for _, e := range rbSplit(f.code, open+1, last) {
		for e.start < e.end && isSpace(f.sans[e.start]) {
			e.start++
		}
		for e.end > e.start && isSpace(f.sans[e.end-1]) {
			e.end--
		}
		if e.end > e.start {
			out = append(out, e)
		}
	}
	return out, true
}

// strings reads a string or a list of strings (method names, verbs).
func (f *phpFile) strs(sp span) ([]string, bool) {
	if v, ok := f.str(sp); ok {
		return []string{v}, true
	}
	els, ok := f.list(sp)
	if !ok {
		return nil, false
	}
	var out []string
	for _, e := range els {
		v, ok := f.str(e)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

// pair splits `'key' => value`.
func (f *phpFile) pair(sp span) (key string, val span, ok bool) {
	code := f.code[sp.start:sp.end]
	i := topLevelRocket(code)
	if i < 0 {
		return "", span{}, false
	}
	ks := span{sp.start, sp.start + i}
	for ks.end > ks.start && isSpace(f.sans[ks.end-1]) {
		ks.end--
	}
	key, ok = f.str(ks)
	vs := span{sp.start + i + 2, sp.end}
	for vs.start < vs.end && isSpace(f.sans[vs.start]) {
		vs.start++
	}
	return key, vs, ok
}

// ---- middleware ----

type phpMW struct {
	name  string // as written, for withoutMiddleware and labels
	class string // authn, authz or ""
}

var (
	phpNotAuthnRe = regexp.MustCompile(`(?i)guest|redirectif|authenticatesession|auth\.session|verified|signed|throttle|ratelimit|csrf|cors`)
	phpAuthzWords = setOf("can", "cannot", "role", "roles", "permission", "permissions", "ability", "abilities", "scope", "scopes", "authorize", "authorization", "admin", "isadmin", "policy", "gate")
	phpAuthnNames = setOf("auth", "authenticate", "client", "checkclientcredentials", "authenticatewithbasicauth")
)

// phpClassify says whether a middleware (an alias string or a class name)
// authenticates the caller, or authorizes it.
func phpClassify(item string, aliases map[string]string) string {
	base := item
	if i := strings.IndexByte(base, ':'); i >= 0 {
		base = base[:i]
	}
	base = base[strings.LastIndexByte(base, '\\')+1:]
	if phpNotAuthnRe.MatchString(base) {
		return ""
	}
	if c := phpClassifyName(base); c != "" {
		return c
	}
	if cls, ok := aliases[strings.ToLower(base)]; ok {
		return phpClassify(cls, nil)
	}
	return ""
}

func phpClassifyName(base string) string {
	lower := strings.ToLower(base)
	norm := strings.NewReplacer(".", "_", "-", "_").Replace(base)
	switch {
	case phpAuthnNames[lower] || strings.HasPrefix(lower, "auth.") && lower != "auth.session":
		return "authn"
	case authnName(rbCamelize(norm)) || authnName(norm):
		return "authn"
	}
	for _, w := range camelRe.FindAllString(rbCamelize(norm), -1) {
		if phpAuthzWords[strings.ToLower(w)] {
			return "authz"
		}
	}
	return ""
}

type laravelParser struct {
	files    map[string]*phpFile
	aliases  map[string]map[string]string
	guards   map[string]*phpGuard
	mapping  map[string]phpCtx
	included map[string]bool
	visited  map[string]bool
	routes   []phpRoute
	provider bool
}

type phpGuard struct {
	all    bool
	groups map[string]bool
}

// mwItems reads a middleware argument: a string, a class, or a list of them.
func (p *laravelParser) mwItems(f *phpFile, root string, sp span) ([]phpMW, bool) {
	els, isList := f.list(sp)
	if !isList {
		els = []span{sp}
	}
	var out []phpMW
	for _, e := range els {
		name := ""
		if v, ok := f.str(e); ok {
			name = v
		} else if v, ok := f.classRef(e); ok {
			name = v
		} else {
			return out, false
		}
		out = append(out, phpMW{name: name, class: phpClassify(name, p.aliases[root])})
	}
	return out, true
}

// ---- contexts and routes ----

type phpCtx struct {
	prefix     string
	mw         []phpMW
	without    map[string]bool
	controller string // Route::controller(X::class)
	namespace  string
	unseen     bool
	badPath    bool // a prefix this reader cannot read
	groups     []string
}

func (c phpCtx) withMW(items ...phpMW) phpCtx {
	c.mw = append(append([]phpMW(nil), c.mw...), items...)
	return c
}

func (c phpCtx) withoutMW(names ...string) phpCtx {
	m := map[string]bool{}
	for k := range c.without {
		m[k] = true
	}
	for _, n := range names {
		m[strings.ToLower(n)] = true
	}
	c.without = m
	return c
}

type phpRoute struct {
	file         *phpFile
	line         int
	method, path string
	cls          string // class as written
	action       string
	inline       string // a closure handler's text
	handlerKnown bool
	mw           []phpMW
	without      map[string]bool
	unseen       bool
	groups       []string
	root         string
	ns           string // Route::namespace('Admin')
}

var phpRouteStartRe = regexp.MustCompile(`\bRoute\s*::\s*(\w+)\s*\(|\$router\s*->\s*(\w+)\s*\(`)

var phpVerbs = map[string]string{"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "options": "OPTIONS", "any": "ALL"}

var phpDefining = setOf("get", "post", "put", "patch", "delete", "options", "any", "match", "resource", "apiResource", "resources", "apiResources", "group", "view", "redirect", "permanentRedirect", "fallback", "singleton", "apiSingleton")

func phpRootOf(path, marker string) string {
	p := "/" + path
	i := strings.LastIndex(p, "/"+marker)
	if i < 0 {
		return ""
	}
	return strings.TrimPrefix(p[:i+1], "/")
}

func phpRoutesRoot(path string) string { return phpRootOf(path, "routes/") }

// region reads the route calls in [from, to) of f.
func (p *laravelParser) region(f *phpFile, from, to int, ctx phpCtx, root string, depth int) {
	pos := from
	for pos < to {
		m := phpRouteStartRe.FindStringSubmatchIndex(f.code[pos:to])
		if m == nil {
			return
		}
		at := pos + m[0]
		ns := m[2]
		if ns < 0 {
			ns = m[4]
		}
		calls, end := phpChain(f.code, pos+ns, to)
		if len(calls) == 0 {
			pos = at + 1
			continue
		}
		p.chain(f, at, calls, ctx, root, depth)
		pos = end
	}
}

func (p *laravelParser) chain(f *phpFile, at int, calls []phpCall, ctx phpCtx, root string, depth int) {
	d := -1
	for i, c := range calls {
		if phpDefining[c.name] {
			d = i
			break
		}
	}
	if d < 0 {
		return
	}
	for _, c := range calls[:d] {
		ctx = p.modifier(f, c, ctx, root)
	}
	def := calls[d]
	if def.name == "group" {
		p.group(f, def, ctx, root, depth)
		return
	}
	var routeMW []phpMW
	without := map[string]bool{}
	only, except := map[string]bool(nil), map[string]bool{}
	unseen := ctx.unseen
	for _, c := range calls[d+1:] {
		switch c.name {
		case "middleware":
			for _, a := range f.args(c) {
				items, ok := p.mwItems(f, root, a)
				routeMW = append(routeMW, items...)
				unseen = unseen || !ok
			}
		case "withoutMiddleware":
			for _, a := range f.args(c) {
				if names, ok := f.strs(a); ok {
					for _, n := range names {
						without[strings.ToLower(n)] = true
					}
				}
			}
		case "can":
			routeMW = append(routeMW, phpMW{name: "can", class: "authz"})
		case "only", "except":
			set, ok := map[string]bool{}, true
			for _, a := range f.args(c) {
				names, k := f.strs(a)
				ok = ok && k
				for _, n := range names {
					set[n] = true
				}
			}
			unseen = unseen || !ok
			if c.name == "only" {
				only = set
			} else {
				except = set
			}
		case "shallow":
			unseen = true
		}
	}
	line := lineAt(f.lineStarts, at)
	base := phpRoute{file: f, line: line, mw: append(append([]phpMW(nil), ctx.mw...), routeMW...), unseen: unseen, groups: ctx.groups, root: root, ns: ctx.namespace}
	base.without = map[string]bool{}
	for k := range ctx.without {
		base.without[k] = true
	}
	for k := range without {
		base.without[k] = true
	}
	p.define(f, def, ctx, base, only, except)
}

// modifier applies a group-level call (prefix, middleware, ...) to ctx.
func (p *laravelParser) modifier(f *phpFile, c phpCall, ctx phpCtx, root string) phpCtx {
	args := f.args(c)
	switch c.name {
	case "prefix":
		if len(args) == 1 {
			if v, ok := f.str(args[0]); ok {
				ctx.prefix = rbJoin(ctx.prefix, v)
				return ctx
			}
		}
		ctx.badPath = true
	case "middleware":
		for _, a := range args {
			items, ok := p.mwItems(f, root, a)
			ctx = ctx.withMW(items...)
			ctx.unseen = ctx.unseen || !ok
			ctx.groups = append(append([]string(nil), ctx.groups...), mwGroups(items)...)
		}
	case "withoutMiddleware":
		for _, a := range args {
			if names, ok := f.strs(a); ok {
				ctx = ctx.withoutMW(names...)
			}
		}
	case "controller":
		if len(args) == 1 {
			if v, ok := f.classRef(args[0]); ok {
				ctx.controller = v
				return ctx
			}
		}
		ctx.unseen = true
	case "namespace":
		if len(args) == 1 {
			if v, ok := f.str(args[0]); ok {
				ctx.namespace = strings.Trim(ctx.namespace+"\\"+v, "\\")
			}
		}
	}
	return ctx
}

func mwGroups(items []phpMW) []string {
	var out []string
	for _, it := range items {
		if it.name == "web" || it.name == "api" {
			out = append(out, it.name)
		}
	}
	return out
}

// group reads Route::group / ->group: a closure, a routes file, or an array
// of attributes and a closure.
func (p *laravelParser) group(f *phpFile, c phpCall, ctx phpCtx, root string, depth int) {
	args := f.args(c)
	if len(args) == 0 {
		return
	}
	last := args[len(args)-1]
	if len(args) == 2 {
		ctx = p.attributes(f, args[0], ctx, root)
	}
	if name, ok := phpRoutesFileArg(f.text(last)); ok {
		p.groupFile(f, root, name, ctx, depth)
		return
	}
	if from, to, ok := phpClosureBody(f, last); ok {
		p.region(f, from, to, ctx, root, depth+1)
	}
}

var (
	phpRoutesFileRe = regexp.MustCompile(`routes[/\\]+([\w\-./]+?)\.php`)
	phpFnRe         = regexp.MustCompile(`^(?:static\s+)?function\s*&?\s*\(`)
	phpArrowRe      = regexp.MustCompile(`^(?:static\s+)?fn\s*&?\s*\(`)
)

func phpRoutesFileArg(text string) (string, bool) {
	m := phpRoutesFileRe.FindStringSubmatch(text)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// phpClosureBody returns the body range of a closure argument.
func phpClosureBody(f *phpFile, sp span) (from, to int, ok bool) {
	t := f.code[sp.start:sp.end]
	switch {
	case phpFnRe.MatchString(t):
		open := strings.IndexByte(t, '{')
		if open < 0 {
			return 0, 0, false
		}
		c := matchClose(f.code, sp.start+open)
		if c < 0 {
			return 0, 0, false
		}
		return sp.start + open + 1, c, true
	case phpArrowRe.MatchString(t):
		if i := strings.Index(t, "=>"); i >= 0 {
			return sp.start + i + 2, sp.end, true
		}
	}
	return 0, 0, false
}

// attributes reads the array form's keys.
func (p *laravelParser) attributes(f *phpFile, sp span, ctx phpCtx, root string) phpCtx {
	els, ok := f.list(sp)
	if !ok {
		ctx.unseen = true
		return ctx
	}
	for _, e := range els {
		key, val, ok := f.pair(e)
		if !ok {
			continue
		}
		switch key {
		case "prefix":
			if v, ok := f.str(val); ok {
				ctx.prefix = rbJoin(ctx.prefix, v)
			} else {
				ctx.badPath = true
			}
		case "middleware":
			items, ok := p.mwItems(f, root, val)
			ctx = ctx.withMW(items...)
			ctx.unseen = ctx.unseen || !ok
			ctx.groups = append(append([]string(nil), ctx.groups...), mwGroups(items)...)
		case "namespace":
			if v, ok := f.str(val); ok {
				ctx.namespace = strings.Trim(ctx.namespace+"\\"+v, "\\")
			}
		case "controller":
			if v, ok := f.classRef(val); ok {
				ctx.controller = v
			}
		}
	}
	return ctx
}

// groupFile reads `->group(base_path('routes/admin.php'))`. In a provider that
// is the mapping of a route file; in a routes file it includes one.
func (p *laravelParser) groupFile(f *phpFile, root, name string, ctx phpCtx, depth int) {
	target := root + "routes/" + name + ".php"
	if p.provider {
		p.mapping[target] = ctx
		return
	}
	if g := p.files[target]; g != nil && depth < 6 && !p.visited[target+"|"+ctx.prefix] {
		p.visited[target+"|"+ctx.prefix] = true
		p.region(g, 0, len(g.code), ctx, root, depth+1)
	}
}

func (p *laravelParser) define(f *phpFile, def phpCall, ctx phpCtx, base phpRoute, only, except map[string]bool) {
	if ctx.badPath {
		return
	}
	args := f.args(def)
	switch def.name {
	case "get", "post", "put", "patch", "delete", "options", "any":
		if len(args) >= 1 {
			p.verb(f, []string{phpVerbs[def.name]}, args[0], args[1:], ctx, base)
		}
	case "match":
		if len(args) >= 2 {
			if vs, ok := f.strs(args[0]); ok {
				var ms []string
				for _, v := range vs {
					ms = append(ms, strings.ToUpper(v))
				}
				p.verb(f, ms, args[1], args[2:], ctx, base)
			}
		}
	case "resource", "apiResource":
		if len(args) >= 2 {
			p.resource(f, def.name == "apiResource", args[0], args[1], ctx, base, only, except)
		}
	case "resources", "apiResources":
		if len(args) >= 1 {
			if els, ok := f.list(args[0]); ok {
				for _, e := range els {
					if key, val, ok := f.pair(e); ok {
						p.resource(f, def.name == "apiResources", span{e.start, e.start}, val, ctx, base, only, except, key)
					}
				}
			}
		}
	}
}

// verb emits one route per method.
func (p *laravelParser) verb(f *phpFile, methods []string, pathArg span, rest []span, ctx phpCtx, base phpRoute) {
	path, ok := f.str(pathArg)
	if !ok {
		return // a path built at run time is not guessed
	}
	r := base
	if len(rest) == 0 {
		return
	}
	cls, action, inline, known := p.handler(f, rest[0], ctx)
	if !known {
		return // view, redirect, fallback... have no handler to read
	}
	r.cls, r.action, r.inline = cls, action, inline
	r.handlerKnown = cls != "" || inline != ""
	for _, m := range methods {
		rr := r
		rr.method, rr.path = m, rbJoin(ctx.prefix, path)
		p.routes = append(p.routes, rr)
	}
}

// handler reads the second argument of a route call.
func (p *laravelParser) handler(f *phpFile, sp span, ctx phpCtx) (cls, action, inline string, ok bool) {
	t := strings.TrimSpace(f.text(sp))
	if _, _, isClosure := phpClosureBody(f, sp); isClosure {
		return "", "", t, true
	}
	if els, isList := f.list(sp); isList && len(els) == 2 {
		c, ok1 := f.classRef(els[0])
		if !ok1 {
			c, ok1 = f.str(els[0])
		}
		m, ok2 := f.str(els[1])
		if ok1 && ok2 {
			return c, m, "", true
		}
		return "", "", "", true // an unreadable handler: still a route, unseen
	}
	if c, isRef := f.classRef(sp); isRef {
		return c, "__invoke", "", true
	}
	if v, isStr := f.str(sp); isStr {
		if c, m, found := strings.Cut(v, "@"); found {
			return c, m, "", true
		}
		if ctx.controller != "" {
			return ctx.controller, v, "", true
		}
		if v != "" && v[0] >= 'A' && v[0] <= 'Z' {
			return v, "__invoke", "", true // a legacy invokable controller: 'FileUploader'
		}
		return "", "", "", false // a view name or something this reader does not know
	}
	return "", "", "", true
}

var phpRestful = []struct {
	action, method, suffix string
	api                    bool
}{
	{"index", "GET", "", true},
	{"create", "GET", "/create", false},
	{"store", "POST", "", true},
	{"show", "GET", "/{p}", true},
	{"edit", "GET", "/{p}/edit", false},
	{"update", "PUT", "/{p}", true},
	{"update", "PATCH", "/{p}", true},
	{"destroy", "DELETE", "/{p}", true},
}

func phpSingular(s string) string {
	return strings.ReplaceAll(rbSingular(s), "-", "_")
}

func (p *laravelParser) resource(f *phpFile, api bool, nameArg, ctrlArg span, ctx phpCtx, base phpRoute, only, except map[string]bool, nameOverride ...string) {
	name := ""
	if len(nameOverride) > 0 {
		name = nameOverride[0]
	} else if v, ok := f.str(nameArg); ok {
		name = v
	} else {
		return
	}
	cls, ok := f.classRef(ctrlArg)
	if !ok {
		cls, ok = f.str(ctrlArg)
	}
	if !ok {
		base.unseen = true
	}
	path := ""
	segs := strings.Split(strings.Trim(name, "/"), ".")
	for i, s := range segs {
		path += "/" + s
		if i < len(segs)-1 {
			path += "/{" + phpSingular(s[strings.LastIndexByte(s, '/')+1:]) + "}"
		}
	}
	param := phpSingular(segs[len(segs)-1][strings.LastIndexByte(segs[len(segs)-1], '/')+1:])
	for _, r := range phpRestful {
		if api && !r.api || (only != nil && !only[r.action]) || except[r.action] {
			continue
		}
		rr := base
		rr.cls, rr.action, rr.handlerKnown = cls, r.action, true
		rr.method = r.method
		rr.path = rbJoin(ctx.prefix, path+strings.ReplaceAll(r.suffix, "{p}", "{"+param+"}"))
		p.routes = append(p.routes, rr)
	}
}

// ---- controllers ----

type phpOp struct {
	class, label string
	only, except map[string]bool
	uncertain    bool
}

type phpClass struct {
	file    *phpFile
	fqn     string
	super   string // resolved, as written when unresolved
	ops     []phpOp
	actions map[string]string
	traits  []string
	opaque  bool
}

type phpIndex struct {
	byFQN   map[string][]*phpClass
	byShort map[string][]*phpClass
}

var (
	phpFunctionRe  = regexp.MustCompile(`\bfunction\s+&?\s*(\w+)\s*\(`)
	phpThisMWRe    = regexp.MustCompile(`\$this\s*->\s*(middleware|authorizeResource)\s*\(`)
	phpNewMWRe     = regexp.MustCompile(`\bnew\s+\\?(?:[\w\\]*\\)?Middleware\s*\(`)
	phpNamedArgRe  = regexp.MustCompile(`^(\w+)\s*:\s*`)
	phpInlineAuth  = regexp.MustCompile(`\bauth\s*\(|\bAuth\s*::\s*(?:user|id|check|guard|guest|once|attempt|viaRemember)\b|\$request\s*->\s*(?:user|bearerToken)\s*\(|\brequest\s*\(\s*\)\s*->\s*user\b|\$this\s*->\s*authorize\s*\(|\bGate\s*::\s*(?:authorize|allows|denies|check|inspect|forUser)\b|\babort(?:_if|_unless)?\s*\([^;]*\b40[13]\b|->tokenCan\s*\(|->currentAccessToken\s*\(|\bJWTAuth\s*::|->authorizeForUser\s*\(`)
	phpResourceOps = []string{"index", "create", "store", "show", "edit", "update", "destroy"}
)

func (ix *phpIndex) addFile(p *laravelParser, f *phpFile, root string) {
	ns := ""
	if m := phpNSRe.FindStringSubmatch(f.sans); m != nil {
		ns = m[1]
	}
	for _, loc := range phpClassRe.FindAllStringSubmatchIndex(f.code, -1) {
		name := f.sans[loc[2]:loc[3]]
		c := &phpClass{file: f, fqn: strings.Trim(ns+"\\"+name, "\\"), actions: map[string]string{}}
		if loc[4] >= 0 {
			c.super = phpResolve(f.sans[loc[4]:loc[5]], f.imports, ns)
		}
		open := loc[1] - 1
		end := matchClose(f.code, open)
		if end < 0 {
			continue
		}
		ix.members(p, c, f, open+1, end, root)
		ix.byFQN[strings.ToLower(c.fqn)] = append(ix.byFQN[strings.ToLower(c.fqn)], c)
		ix.byShort[strings.ToLower(name)] = append(ix.byShort[strings.ToLower(name)], c)
	}
}

// phpResolve resolves a class name as written in a file.
func phpResolve(name string, imports map[string]string, ns string) string {
	if strings.HasPrefix(name, "\\") {
		return name[1:]
	}
	first, rest, _ := strings.Cut(name, "\\")
	if full, ok := imports[strings.ToLower(first)]; ok {
		if rest != "" {
			return full + "\\" + rest
		}
		return full
	}
	return strings.Trim(ns+"\\"+name, "\\")
}

// members walks the class body's top-level members.
func (ix *phpIndex) members(p *laravelParser, c *phpClass, f *phpFile, from, to int, root string) {
	pos := from
	for pos < to {
		i := pos
		for i < to && f.code[i] != ';' && f.code[i] != '{' {
			if f.code[i] == '(' || f.code[i] == '[' {
				if m := matchClose(f.code, i); m > 0 {
					i = m
				}
			}
			i++
		}
		if i >= to {
			return
		}
		header := f.code[pos:i]
		end := i
		if f.code[i] == '{' {
			if m := matchClose(f.code, i); m > 0 {
				end = m
			}
		}
		ix.member(p, c, f, header, pos, i, end, root)
		pos = end + 1
	}
}

func (ix *phpIndex) member(p *laravelParser, c *phpClass, f *phpFile, header string, hs, bodyOpen, end int, root string) {
	trimmed := strings.TrimSpace(header)
	if strings.HasPrefix(trimmed, "use ") || trimmed == "use" {
		for _, t := range strings.Split(strings.TrimSpace(f.sans[hs:bodyOpen])[3:], ",") {
			if t = strings.TrimSpace(t); t != "" {
				c.traits = append(c.traits, t)
			}
		}
		return
	}
	m := phpFunctionRe.FindStringSubmatch(header)
	if m == nil || f.code[bodyOpen] != '{' {
		return
	}
	body := span{bodyOpen + 1, end}
	c.actions[m[1]] = f.sans[bodyOpen:end]
	switch {
	case m[1] == "__construct":
		p.constructorOps(c, f, body, root)
	case m[1] == "middleware" && strings.Contains(header, "static"):
		p.hasMiddlewareOps(c, f, body, root)
	}
}

// onlyExcept reads a method-name list.
func (p *laravelParser) names(f *phpFile, sp span) (map[string]bool, bool) {
	vs, ok := f.strs(sp)
	if !ok {
		return nil, false
	}
	set := map[string]bool{}
	for _, v := range vs {
		set[v] = true
	}
	return set, true
}

func (p *laravelParser) constructorOps(c *phpClass, f *phpFile, body span, root string) {
	pos := body.start
	for pos < body.end {
		m := phpThisMWRe.FindStringSubmatchIndex(f.code[pos:body.end])
		if m == nil {
			return
		}
		calls, end := phpChain(f.code, pos+m[2], body.end)
		if len(calls) == 0 {
			pos += m[1]
			continue
		}
		pos = end
		if calls[0].name == "authorizeResource" {
			set := map[string]bool{}
			for _, a := range phpResourceOps {
				set[a] = true
			}
			c.ops = append(c.ops, phpOp{class: "authz", label: "authorizeResource", only: set})
			continue
		}
		p.middlewareOp(c, f, calls, root)
	}
}

// middlewareOp reads `$this->middleware(...)->only(...)->except(...)`.
func (p *laravelParser) middlewareOp(c *phpClass, f *phpFile, calls []phpCall, root string) {
	args := f.args(calls[0])
	if len(args) == 0 {
		return
	}
	op := phpOp{except: map[string]bool{}}
	if _, _, isClosure := phpClosureBody(f, args[0]); isClosure {
		if phpInlineAuth.MatchString(f.text(args[0])) {
			op.class, op.label = "authn", inlineAuthLabel
		}
		c.ops = append(c.ops, p.restrict(f, op, calls[1:], args[1:]))
		return
	}
	items, ok := p.mwItems(f, root, args[0])
	if !ok {
		op.uncertain = true
	}
	op = p.restrict(f, op, calls[1:], args[1:])
	for _, it := range items {
		o := op
		o.class, o.label = it.class, "middleware '"+it.name+"'"
		if o.class != "" || o.uncertain {
			c.ops = append(c.ops, o)
		}
	}
}

// restrict applies ->only/->except and the array-options argument.
func (p *laravelParser) restrict(f *phpFile, op phpOp, calls []phpCall, extra []span) phpOp {
	apply := func(kind string, sp span) {
		set, ok := p.names(f, sp)
		if !ok {
			op.uncertain = true
			return
		}
		if kind == "only" {
			op.only = set
		} else {
			op.except = set
		}
	}
	for _, e := range extra {
		if els, ok := f.list(e); ok {
			for _, el := range els {
				if k, v, isPair := f.pair(el); isPair && (k == "only" || k == "except") {
					apply(k, v)
				}
			}
		}
	}
	for _, c := range calls {
		if c.name != "only" && c.name != "except" {
			continue
		}
		args := f.args(c)
		if len(args) != 1 {
			op.uncertain = true
			continue
		}
		apply(c.name, args[0])
	}
	return op
}

// hasMiddlewareOps reads `public static function middleware(): array`.
func (p *laravelParser) hasMiddlewareOps(c *phpClass, f *phpFile, body span, root string) {
	t := f.code[body.start:body.end]
	i := strings.Index(t, "return")
	if i < 0 {
		c.opaque = true
		return
	}
	j := body.start + i + len("return")
	j = skipWS(f.code, j, body.end)
	if j >= body.end || f.code[j] != '[' {
		c.opaque = true
		return
	}
	end := matchClose(f.code, j)
	if end < 0 {
		c.opaque = true
		return
	}
	els, _ := f.list(span{j, end + 1})
	for _, e := range els {
		if loc := phpNewMWRe.FindStringIndex(f.code[e.start:e.end]); len(loc) == 2 && loc[0] == 0 {
			open := e.start + loc[1] - 1
			cl := matchClose(f.code, open)
			if cl < 0 {
				c.opaque = true
				continue
			}
			call := phpCall{name: "Middleware", open: open, closep: cl}
			a := f.args(call)
			if len(a) == 0 {
				continue
			}
			op := phpOp{except: map[string]bool{}}
			items, ok := p.mwItems(f, root, a[0])
			op.uncertain = !ok
			for _, x := range a[1:] {
				text := f.code[x.start:x.end]
				if m := phpNamedArgRe.FindStringSubmatch(text); len(m) > 1 && (m[1] == "only" || m[1] == "except") {
					set, k := p.names(f, span{x.start + len(m[0]), x.end})
					op.uncertain = op.uncertain || !k
					if m[1] == "only" {
						op.only = set
					} else {
						op.except = set
					}
				}
			}
			for _, it := range items {
				o := op
				o.class, o.label = it.class, "middleware '"+it.name+"'"
				if o.class != "" || o.uncertain {
					c.ops = append(c.ops, o)
				}
			}
			continue
		}
		items, ok := p.mwItems(f, root, e)
		for _, it := range items {
			if it.class != "" {
				c.ops = append(c.ops, phpOp{class: it.class, label: "middleware '" + it.name + "'", except: map[string]bool{}})
			}
		}
		if !ok {
			c.ops = append(c.ops, phpOp{uncertain: true, except: map[string]bool{}})
		}
	}
}

func (ix *phpIndex) lookup(fqn string) (*phpClass, bool) {
	cs := ix.byFQN[strings.ToLower(fqn)]
	if len(cs) == 1 {
		return cs[0], true
	}
	return nil, false
}

var phpFrameworkTraits = map[string]bool{"authorizesrequests": true, "validatesrequests": true, "dispatchesjobs": true}

var phpNeutralSuper = map[string]bool{"illuminate\\routing\\controller": true}

// phpEvidence is what a controller shows about one action.
type phpEvidence struct {
	authn, authz string
	unseen       bool
	body         string
	// defined: a class in the chain defines the action; complete: every class
	// and trait in the chain was read, so "not defined" means not defined.
	defined, complete bool
}

func (ix *phpIndex) evidence(c *phpClass, action string) phpEvidence {
	var chain []*phpClass
	ev := phpEvidence{}
	seen := map[*phpClass]bool{}
	for cur := c; cur != nil; {
		if seen[cur] {
			ev.unseen = true
			break
		}
		seen[cur] = true
		chain = append([]*phpClass{cur}, chain...)
		if cur.super == "" {
			break
		}
		next, ok := ix.lookup(cur.super)
		if !ok {
			if !phpNeutralSuper[strings.ToLower(cur.super)] {
				ev.unseen = true
			}
			break
		}
		cur = next
	}
	ev.complete = !ev.unseen
	for _, cls := range chain {
		if cls.opaque {
			ev.unseen = true
		}
		if _, has := cls.actions[action]; has {
			ev.defined = true
		}
		if _, has := cls.actions["__call"]; has {
			ev.complete = false
		}
		for _, t := range cls.traits {
			base := t[strings.LastIndexByte(t, '\\')+1:]
			if authnName(base) && !strings.EqualFold(base, "AuthorizesRequests") {
				ev.unseen = true
			}
			if !phpFrameworkTraits[strings.ToLower(base)] {
				ev.complete = false
			}
		}
		for _, op := range cls.ops {
			if op.only != nil && !op.only[action] || op.except[action] {
				continue
			}
			if op.uncertain {
				ev.unseen = true
			}
			if op.class == "authn" && ev.authn == "" {
				ev.authn = op.label
			}
			if op.class == "authz" && ev.authz == "" {
				ev.authz = op.label
			}
		}
	}
	for i := len(chain) - 1; i >= 0 && ev.body == ""; i-- {
		ev.body = chain[i].actions[action]
	}
	if ev.authn == "" && ev.authz == "" && phpInlineAuth.MatchString(ev.body) {
		ev.authn = inlineAuthLabel
	}
	return ev
}

// resolveClass finds the controller a route names.
func (ix *phpIndex) resolveClass(r phpRoute, ctxNS string) (*phpClass, bool) {
	name := r.cls
	if name == "" {
		return nil, false
	}
	name = strings.ReplaceAll(name, "/", "\\")
	if strings.HasPrefix(name, "\\") {
		return ix.lookup(name[1:])
	}
	first, rest, _ := strings.Cut(name, "\\")
	if full, ok := r.file.imports[strings.ToLower(first)]; ok {
		if rest != "" {
			full += "\\" + rest
		}
		return ix.lookup(full)
	}
	for _, cand := range []string{"App\\Http\\Controllers\\" + name, name} {
		if ctxNS != "" {
			if c, ok := ix.lookup("App\\Http\\Controllers\\" + ctxNS + "\\" + name); ok {
				return c, true
			}
		}
		if c, ok := ix.lookup(cand); ok {
			return c, true
		}
	}
	short := strings.ToLower(name[strings.LastIndexByte(name, '\\')+1:])
	if cs := ix.byShort[short]; len(cs) == 1 {
		return cs[0], true
	}
	return nil, false
}

// ---- global guards and aliases ----

var (
	phpAliasPairRe = regexp.MustCompile(`['"]([\w.\-:]+)['"]\s*=>\s*\\?([\w\\]+)::class`)
	phpQuotedRe    = regexp.MustCompile(`([\w\\]+)::class|'([^']+)'|"([^"]+)"`)
	phpBootCallRe  = regexp.MustCompile(`\$\w+\s*->\s*(web|api|append|prepend|use|appendToGroup|prependToGroup|group)\s*\(`)
)

func (p *laravelParser) readKernel(f *phpFile, root string) {
	if p.aliases[root] == nil {
		p.aliases[root] = map[string]string{}
	}
	for _, m := range phpAliasPairRe.FindAllStringSubmatch(f.sans, -1) {
		p.aliases[root][strings.ToLower(m[1])] = m[2]
	}
	g := p.guards[root]
	if g == nil {
		g = &phpGuard{groups: map[string]bool{}}
		p.guards[root] = g
	}
	if filepath.Base(f.path) == "Kernel.php" {
		p.kernelGuards(f, root, g)
		return
	}
	for _, loc := range phpBootCallRe.FindAllStringSubmatchIndex(f.code, -1) {
		open := loc[1] - 1
		c := matchClose(f.code, open)
		if c < 0 {
			continue
		}
		method := f.sans[loc[2]:loc[3]]
		args := f.sans[open+1 : c]
		first := ""
		if method == "appendToGroup" || method == "prependToGroup" || method == "group" {
			if m := phpQuotedRe.FindStringSubmatch(args); m != nil {
				first = m[2] + m[3]
			}
			args = args[strings.IndexByte(args+",", ',')+1:]
		}
		if !p.hasAuthn(args, root) {
			continue
		}
		switch method {
		case "web", "api":
			g.groups[method] = true
		case "appendToGroup", "prependToGroup", "group":
			g.groups[first] = true
		default:
			g.all = true
		}
	}
}

func (p *laravelParser) hasAuthn(text, root string) bool {
	for _, m := range phpQuotedRe.FindAllStringSubmatch(text, -1) {
		name := m[1] + m[2] + m[3]
		if phpClassify(name, p.aliases[root]) == "authn" {
			return true
		}
	}
	return false
}

func (p *laravelParser) kernelGuards(f *phpFile, root string, g *phpGuard) {
	if i := regexpIndex(`\$middleware\s*=\s*\[`, f.code); i[0] >= 0 {
		if c := matchClose(f.code, i[1]-1); c > 0 && p.hasAuthn(f.sans[i[1]:c], root) {
			g.all = true
		}
	}
	if i := regexpIndex(`\$middlewareGroups\s*=\s*\[`, f.code); i[0] >= 0 {
		end := matchClose(f.code, i[1]-1)
		if end < 0 {
			return
		}
		for _, loc := range regexp.MustCompile(`['"](\w+)['"]\s*=>\s*\[`).FindAllStringSubmatchIndex(f.sans[i[1]:end], -1) {
			open := i[1] + loc[1] - 1
			if c := matchClose(f.code, open); c > 0 && p.hasAuthn(f.sans[open+1:c], root) {
				g.groups[f.sans[i[1]+loc[2]:i[1]+loc[3]]] = true
			}
		}
	}
}

func regexpIndex(pat, s string) [2]int {
	loc := regexp.MustCompile(pat).FindStringIndex(s)
	if loc == nil {
		return [2]int{-1, -1}
	}
	return [2]int{loc[0], loc[1]}
}

// ---- assembling ----

var (
	phpControllerFileRe = regexp.MustCompile(`(?i)(?:^|/)controllers?/.+\.php$`)
	phpRoutesFileNameRe = regexp.MustCompile(`(?:^|/)routes/([\w\-./]+?)\.php$`)
	phpProviderFileRe   = regexp.MustCompile(`(?:^|/)app/Providers/\w+\.php$|(?:^|/)bootstrap/app\.php$`)
	phpKernelFileRe     = regexp.MustCompile(`(?:^|/)(?:app/Http/Kernel|bootstrap/app)\.php$`)
)

func (p *laravelParser) defaultCtx(name string) phpCtx {
	switch name {
	case "web":
		return phpCtx{groups: []string{"web"}}
	case "api":
		return phpCtx{prefix: "/api", groups: []string{"api"}}
	}
	return phpCtx{unseen: true}
}

func (p *laravelParser) guarded(r phpRoute) bool {
	g := p.guards[r.root]
	if g == nil {
		return false
	}
	if g.all {
		return true
	}
	for _, name := range r.groups {
		if g.groups[name] {
			return true
		}
	}
	return false
}

// readLaravel reads every Laravel route file and joins routes to controllers.
func readLaravel(files map[string]*phpFile, order []string) ([]Route, []routeView) {
	p := &laravelParser{files: files, aliases: map[string]map[string]string{}, guards: map[string]*phpGuard{}, mapping: map[string]phpCtx{}, included: map[string]bool{}, visited: map[string]bool{}}
	for _, path := range order {
		if phpKernelFileRe.MatchString(path) {
			root := phpRootOf(path, "app/Http/")
			if strings.HasSuffix(path, "bootstrap/app.php") {
				root = phpRootOf(path, "bootstrap/")
			}
			p.readKernel(files[path], root)
		}
	}
	for _, path := range order {
		if !phpProviderFileRe.MatchString(path) {
			continue
		}
		root := phpRootOf(path, "app/Providers/")
		if strings.HasSuffix(path, "bootstrap/app.php") {
			root = phpRootOf(path, "bootstrap/")
		}
		p.provider = true
		p.region(files[path], 0, len(files[path].code), phpCtx{}, root, 0)
		p.provider = false
	}
	routesFiles := map[string]string{}
	for _, path := range order {
		if m := phpRoutesFileNameRe.FindStringSubmatch(path); len(m) > 1 && m[1] != "console" && m[1] != "channels" {
			routesFiles[path] = m[1]
			for _, ref := range phpRoutesFileRe.FindAllStringSubmatch(files[path].sans, -1) {
				p.included[phpRoutesRoot(path)+"routes/"+ref[1]+".php"] = true
			}
		}
	}
	for _, path := range order {
		name, ok := routesFiles[path]
		if !ok || (p.included[path] && !p.mappedExplicit(path)) {
			continue
		}
		ctx := p.defaultCtx(name)
		if m, ok := p.mapping[path]; ok {
			ctx = m
			if len(ctx.groups) == 0 {
				ctx.groups = p.defaultCtx(name).groups
			}
		}
		root := phpRoutesRoot(path)
		p.visited[path+"|"+ctx.prefix] = true
		p.region(files[path], 0, len(files[path].code), ctx, root, 0)
	}
	return p.finish(files, order)
}

func (p *laravelParser) mappedExplicit(path string) bool {
	_, ok := p.mapping[path]
	return ok
}

func (p *laravelParser) finish(files map[string]*phpFile, order []string) ([]Route, []routeView) {
	ix := &phpIndex{byFQN: map[string][]*phpClass{}, byShort: map[string][]*phpClass{}}
	for _, path := range order {
		if phpControllerFileRe.MatchString(path) {
			ix.addFile(p, files[path], "")
		}
	}
	var routes []Route
	var views []routeView
	for _, r := range p.routes {
		rt := Route{Method: r.method, Path: r.path, FilePath: r.file.path, Line: r.line, Reader: ReaderLaravel}
		v := routeView{framework: "laravel", guardUnseen: r.unseen || p.guarded(r)}
		for _, mw := range r.mw {
			if r.without[strings.ToLower(mw.name)] || r.without[strings.ToLower(strings.SplitN(mw.name, ":", 2)[0])] {
				continue
			}
			switch {
			case mw.class == "authn" && rt.Authn == "":
				rt.Authn = "middleware '" + mw.name + "'"
			case mw.class == "authz" && rt.Authz == "":
				rt.Authz = "middleware '" + mw.name + "'"
			}
		}
		switch {
		case r.inline != "":
			v.handler = r.inline
			if rt.Authn == "" && rt.Authz == "" && phpInlineAuth.MatchString(r.inline) {
				rt.Authn = inlineAuthLabel
			}
		case r.cls == "" || r.action == "":
			v.guardUnseen = true
		default:
			cls, ok := ix.resolveClass(r, r.ns)
			if !ok {
				v.guardUnseen = true
				break
			}
			ev := ix.evidence(cls, r.action)
			if rt.Authn == "" {
				rt.Authn = ev.authn
			}
			if rt.Authz == "" {
				rt.Authz = ev.authz
			}
			v.handler = ev.body
			v.guardUnseen = v.guardUnseen || ev.unseen
			if ev.complete && !ev.defined && r.method != "GET" && r.method != "ALL" {
				v.guardUnseen = true // a method nothing defines is a 500, not the data
			}
		}
		v.route = rt
		routes, views = append(routes, rt), append(views, v)
	}
	return routes, views
}
