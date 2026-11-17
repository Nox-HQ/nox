package authz

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// actix-web routes (Rust).
//
// A route is one of two things. An attribute macro on a handler, `#[get
// ("/users/{id}")]` (or `#[route("/x", method = "GET", method = "POST")]`),
// states the path and verb, and a registration, `.service(handler)`, mounts
// it. A builder states both at once: `web::resource("/orders").route(web::
// post().to(h))`, or `.route("/stats", web::get().to(h))` on an App or scope.
// The reader follows the builder chain that starts at `App::new()`, the way
// the Go reader follows a router: a `web::scope("/api")` gives every service
// inside it the prefix, `.configure(f)` runs the function f against the
// builder it is called on, and a handler or resource it meets is resolved
// within the scanned tree.
//
// What it states, and no more:
//
//   - a handler carrying an attribute is a route only when something
//     registers it (a `.service(name)` that resolves to it): an unregistered
//     function answers nothing;
//   - Authn is `.wrap(mw)` on the App, an enclosing scope or the resource
//     (whatever its order in the chain: actix builds the wrapped service when
//     the App is finished), a `wrap = "Name"` argument of the attribute, an
//     extractor of the handler that only exists for an authenticated caller
//     (BearerAuth, AuthenticatedUser, Identity not inside an Option), or an
//     answer of 401/403 in the handler's body. Middleware is judged by its
//     name, as the Go reader does, so Logger and Compress are not
//     authentication;
//   - a builder the reader could not trace to an App (a configure function
//     nothing calls, a scope held in a variable) is opaque: its routes are
//     listed with the prefix this reader could see, never claimed to be
//     unauthenticated, never a lead.
//
// The reader looks only at files that name actix_web, so Rocket's and Axum's
// attribute macros and `.route` calls are not mistaken for routes.
//
// Not read: routes whose path or verb is a constant, `web::method(...)`,
// guards (a `guard::Post()` narrows the resource but is not read), apps built
// in several statements, `wrap_fn`, and a handler registered by a macro.

const ReaderActix = "actix-web"

var (
	rsFnRe       = regexp.MustCompile(`\bfn\s+([A-Za-z_]\w*)\s*(?:<[^>{}()]*>)?\s*\(`)
	rsAttrRe     = regexp.MustCompile(`#\[\s*(?:actix_web\s*::\s*)?(get|post|put|delete|patch|head|options|trace|connect|route)\s*\(`)
	rsAfterAttr  = regexp.MustCompile(`^\s*\](?:\s*#\[[^\]]*\])*\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(fn)\s+[A-Za-z_]\w*`)
	rsAppRe      = regexp.MustCompile(`\bApp\s*::\s*new\s*\(`)
	rsBuilderRe  = regexp.MustCompile(`\bweb\s*::\s*(?:scope|resource)\s*\(`)
	rsCfgParamRe = regexp.MustCompile(`([A-Za-z_]\w*)\s*:\s*&\s*mut\s+(?:\w+\s*::\s*)*ServiceConfig\b`)
	rsKeyValRe   = regexp.MustCompile(`^\s*(\w+)\s*=\s*"([^"]*)"\s*$`)
	rsOptionRe   = regexp.MustCompile(`Option\s*<[^<>]*>`)
	rsAuthTypeRe = regexp.MustCompile(`\b(?:BearerAuth|BasicAuth|AuthenticatedUser|AuthUser|CurrentUser|LoggedUser|Identity|Claims|JwtClaims|Authenticated)\b`)
	rsInlineRe   = regexp.MustCompile(`HttpResponse\s*::\s*(?:Unauthorized|Forbidden)\b|\bError(?:Unauthorized|Forbidden)\b|StatusCode\s*::\s*(?:UNAUTHORIZED|FORBIDDEN)\b|\bAUTHORIZATION\b|"[Aa]uthorization"`)
	rsVerbs      = setOf("get", "post", "put", "delete", "patch", "head", "options", "trace", "connect")
)

type rsFile struct {
	path       string
	raw        []byte
	code, sans string
	lineStarts []int
}

// rsFn is a function of an actix file; a route attribute attaches to it.
type rsFn struct {
	file         *rsFile
	name         string
	fnAt         int
	params, body span
	routes       []rsAttrRoute
	cfg          string // the name of its ServiceConfig parameter
}

type rsAttrRoute struct {
	method, path string
	wrap         string
	line         int
	ok           bool
}

func newRSFile(p string, raw []byte) *rsFile {
	return &rsFile{path: p, raw: raw, code: string(lexctx.MaskNonCode(lexctx.LangRust, raw)), sans: withoutComments(lexctx.LangRust, raw), lineStarts: computeLineStarts(raw)}
}

type rsCtx struct {
	prefix       string
	authn, authz string
	opaque       bool
}

type rsRec struct {
	method, path string
	file         *rsFile
	line         int
	authn, authz string
	opaque       bool
}

type rsIndex struct {
	files    []*rsFile
	fns      map[string][]*rsFn
	byFnAt   map[string]*rsFn
	consumed map[string]bool
	recs     []rsRec
	seen     map[string]bool
	ran      map[*rsFn]bool
}

func newRSIndex(files []*rsFile) *rsIndex {
	ix := &rsIndex{files: files, fns: map[string][]*rsFn{}, byFnAt: map[string]*rsFn{}, consumed: map[string]bool{}, seen: map[string]bool{}, ran: map[*rsFn]bool{}}
	for _, f := range files {
		ix.indexFns(f)
	}
	return ix
}

func rsKey(f *rsFile, at int) string { return f.path + ":" + strconv.Itoa(at) }

func (ix *rsIndex) indexFns(f *rsFile) {
	for _, m := range rsFnRe.FindAllStringSubmatchIndex(f.code, -1) {
		open := m[1] - 1
		end := matchClose(f.code, open)
		if end < 0 {
			continue
		}
		fn := &rsFn{file: f, name: f.code[m[2]:m[3]], fnAt: m[0], params: span{open + 1, end}}
		for i := end + 1; i < len(f.code); i++ {
			if f.code[i] == ';' {
				break
			}
			if f.code[i] == '{' {
				if c := matchClose(f.code, i); c > 0 {
					fn.body = span{i + 1, c}
				}
				break
			}
		}
		if cm := rsCfgParamRe.FindStringSubmatch(f.code[fn.params.start:fn.params.end]); cm != nil {
			fn.cfg = cm[1]
		}
		ix.fns[fn.name] = append(ix.fns[fn.name], fn)
		ix.byFnAt[rsKey(f, m[0])] = fn
	}
	for _, m := range rsAttrRe.FindAllStringSubmatchIndex(f.code, -1) {
		open := m[1] - 1
		end := matchClose(f.code, open)
		if end < 0 {
			continue
		}
		loc := rsAfterAttr.FindStringSubmatchIndex(f.code[end+1:])
		if loc == nil {
			continue
		}
		fn := ix.byFnAt[rsKey(f, end+1+loc[2])]
		if fn == nil {
			continue
		}
		fn.routes = append(fn.routes, ix.attrRoutes(f, f.code[m[2]:m[3]], span{open + 1, end}, lineAt(f.lineStarts, m[0]))...)
	}
}

// attrRoutes reads one route attribute into the routes it declares.
func (ix *rsIndex) attrRoutes(f *rsFile, kind string, args span, line int) []rsAttrRoute {
	items := splitArgs(f.code, args.start, args.end)
	if len(items) == 0 {
		return nil
	}
	path, ok := strictLiteral(f.raw, f.code, items[0])
	var methods []string
	if kind != "route" {
		methods = []string{strings.ToUpper(kind)}
	}
	wrap := ""
	for _, it := range items[1:] {
		kv := rsKeyValRe.FindStringSubmatch(string(f.raw[it.start:it.end]))
		if kv == nil {
			continue
		}
		switch kv[1] {
		case "method":
			if _, verb := goVerbs[strings.ToUpper(kv[2])]; verb {
				methods = append(methods, strings.ToUpper(kv[2]))
			}
		case "wrap":
			wrap = kv[2]
		}
	}
	var out []rsAttrRoute
	for _, m := range methods {
		out = append(out, rsAttrRoute{method: m, path: path, wrap: wrap, line: line, ok: ok})
	}
	return out
}

// resolve finds the function a (possibly module-qualified) name denotes.
func (ix *rsIndex) resolve(name string, from *rsFile) *rsFn {
	name = strings.Join(strings.Fields(name), "")
	segs := strings.Split(name, "::")
	last := segs[len(segs)-1]
	cands := ix.fns[last]
	if len(segs) > 1 {
		mod := segs[len(segs)-2]
		var kept []*rsFn
		for _, c := range cands {
			p := strings.TrimSuffix(c.file.path, ".rs")
			if strings.HasSuffix(p, "/"+mod) || p == mod || strings.HasSuffix(p, "/"+mod+"/mod") || strings.Contains(p, "/"+mod+"/") {
				kept = append(kept, c)
			}
		}
		cands = kept
	}
	if len(cands) > 1 {
		var same []*rsFn
		for _, c := range cands {
			if c.file == from {
				same = append(same, c)
			}
		}
		cands = same
	}
	if len(cands) != 1 {
		return nil
	}
	return cands[0]
}

// ---- chains ----

type rsSeg struct {
	name  string
	args  span
	call  bool
	start int
}

type rsChain struct {
	head     string
	headArgs span
	headCall bool
	headAt   int
	segs     []rsSeg
}

func rsIdentEnd(code string, i int) int {
	for i < len(code) && (isIdentByte(code[i]) || code[i] == ':' && i+1 < len(code) && code[i+1] == ':' || code[i] == ':' && i > 0 && code[i-1] == ':') {
		i++
	}
	return i
}

func rsSkipSpace(code string, i int) int {
	for i < len(code) && isSpace(code[i]) {
		i++
	}
	return i
}

// readChain reads `head::path(args).a(b).c(d)` from pos.
func rsReadChain(code string, pos int) (rsChain, bool) {
	c := rsChain{headAt: pos}
	i := rsIdentEnd(code, pos)
	if i == pos {
		return c, false
	}
	c.head = strings.Join(strings.Fields(code[pos:i]), "")
	j := rsSkipSpace(code, i)
	if j < len(code) && code[j] == '(' {
		end := matchClose(code, j)
		if end < 0 {
			return c, false
		}
		c.headArgs, c.headCall, i = span{j + 1, end}, true, end+1
	}
	for {
		j := rsSkipSpace(code, i)
		if j >= len(code) || code[j] != '.' {
			return c, true
		}
		j = rsSkipSpace(code, j+1)
		k := j
		for k < len(code) && isIdentByte(code[k]) {
			k++
		}
		if k == j {
			return c, true
		}
		sg := rsSeg{name: code[j:k], start: j}
		i = k
		if strings.HasPrefix(code[i:], "::<") { // turbofish
			depth := 0
			for ; i < len(code); i++ {
				if code[i] == '<' {
					depth++
				} else if code[i] == '>' {
					if depth--; depth == 0 {
						i++
						break
					}
				}
			}
		}
		if m := rsSkipSpace(code, i); m < len(code) && code[m] == '(' {
			end := matchClose(code, m)
			if end < 0 {
				return c, true
			}
			sg.args, sg.call, i = span{m + 1, end}, true, end+1
		}
		c.segs = append(c.segs, sg)
	}
}

// ---- interpretation ----

func (ix *rsIndex) run() {
	for _, f := range ix.files {
		for _, m := range rsAppRe.FindAllStringIndex(f.code, -1) {
			if ix.consumed[rsKey(f, m[0])] {
				continue
			}
			if ch, ok := rsReadChain(f.code, m[0]); ok {
				ix.build(f, ch, rsCtx{}, 0)
			}
		}
	}
	// A configure function no App reached: its routes are listed, never claimed.
	for _, name := range sortedFnNames(ix.fns) {
		for _, fn := range ix.fns[name] {
			if fn.cfg != "" && !ix.ran[fn] {
				ix.runConfig(fn, rsCtx{opaque: true}, 0)
			}
		}
	}
	for _, f := range ix.files {
		for _, m := range rsBuilderRe.FindAllStringIndex(f.code, -1) {
			if ix.consumed[rsKey(f, m[0])] {
				continue
			}
			if ch, ok := rsReadChain(f.code, m[0]); ok {
				ix.build(f, ch, rsCtx{opaque: true}, 0)
			}
		}
	}
}

func sortedFnNames(m map[string][]*rsFn) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (ix *rsIndex) runConfig(fn *rsFn, ctx rsCtx, depth int) {
	ix.ran[fn] = true
	if depth > 8 || fn.body.end <= fn.body.start {
		return
	}
	f := fn.file
	re := regexp.MustCompile(`(?:^|[;{}\s])(` + regexp.QuoteMeta(fn.cfg) + `)\s*\.`)
	for _, m := range re.FindAllStringSubmatchIndex(f.code[fn.body.start:fn.body.end], -1) {
		at := fn.body.start + m[2]
		if ix.consumed[rsKey(f, at)] {
			continue
		}
		if ch, ok := rsReadChain(f.code, at); ok {
			ix.build(f, ch, ctx, depth+1)
		}
	}
}

// build interprets one builder chain under the context its parent gives it.
func (ix *rsIndex) build(f *rsFile, ch rsChain, parent rsCtx, depth int) {
	ix.consumed[rsKey(f, ch.headAt)] = true
	if depth > 8 {
		return
	}
	ctx := parent
	resourcePath, resource := "", false
	switch ch.head {
	case "web::scope", "web::resource":
		args := splitArgs(f.code, ch.headArgs.start, ch.headArgs.end)
		p, ok := "", false
		if len(args) > 0 {
			p, ok = strictLiteral(f.raw, f.code, args[0])
		}
		if ch.head == "web::scope" {
			ctx.prefix = goJoin(parent.prefix, p)
			ctx.opaque = parent.opaque || !ok
		} else {
			resource, resourcePath = true, p
			ctx.opaque = parent.opaque || !ok
		}
	}
	for _, sg := range ch.segs {
		if sg.call && sg.name == "wrap" {
			args := splitArgs(f.code, sg.args.start, sg.args.end)
			if len(args) > 0 {
				n, z := rsMiddleware(f.sans[args[0].start:args[0].end])
				ctx.authn, ctx.authz = firstNonEmpty(ctx.authn, n), firstNonEmpty(ctx.authz, z)
			}
		}
	}
	for _, sg := range ch.segs {
		if !sg.call {
			continue
		}
		args := splitArgs(f.code, sg.args.start, sg.args.end)
		switch sg.name {
		case "service":
			if len(args) == 1 {
				ix.service(f, args[0], ctx, depth)
			}
		case "route":
			switch {
			case resource && len(args) == 1:
				ix.route(f, ctx, resourcePath, true, args[0], lineAt(f.lineStarts, sg.start))
			case !resource && len(args) == 2:
				if p, ok := strictLiteral(f.raw, f.code, args[0]); ok {
					ix.route(f, ctx, p, true, args[1], lineAt(f.lineStarts, sg.start))
				}
			}
		case "to":
			if resource && len(args) == 1 {
				ix.record(f, ctx, "ALL", resourcePath, lineAt(f.lineStarts, sg.start), ix.handlerEvidence(f, args[0]))
			}
		case "configure":
			if len(args) == 1 {
				if fn := ix.resolve(f.sans[args[0].start:args[0].end], f); fn != nil && fn.cfg != "" {
					ix.runConfig(fn, ctx, depth+1)
				}
			}
		}
	}
}

// service reads the argument of `.service(...)`: a handler, a tuple of them, or a nested builder.
func (ix *rsIndex) service(f *rsFile, arg span, ctx rsCtx, depth int) {
	arg = trimSpan(f.code, arg)
	text := f.code[arg.start:arg.end]
	switch {
	case strings.HasPrefix(text, "("):
		if end := matchClose(f.code, arg.start); end == arg.end-1 {
			for _, a := range splitArgs(f.code, arg.start+1, end) {
				ix.service(f, a, ctx, depth)
			}
		}
	case rsBuilderRe.MatchString(text) && rsBuilderRe.FindStringIndex(text)[0] == 0:
		if ch, ok := rsReadChain(f.code, arg.start); ok {
			ix.build(f, ch, ctx, depth+1)
		}
	case regexp.MustCompile(`^[A-Za-z_][\w:\s]*$`).MatchString(text):
		fn := ix.resolve(f.sans[arg.start:arg.end], f)
		if fn == nil {
			return
		}
		ev := ix.fnEvidence(fn)
		for _, r := range fn.routes {
			if !r.ok {
				continue
			}
			rctx := ctx
			if r.wrap != "" {
				n, z := rsMiddleware(r.wrap)
				rctx.authn, rctx.authz = firstNonEmpty(rctx.authn, n), firstNonEmpty(rctx.authz, z)
			}
			ix.record(fn.file, rctx, r.method, r.path, r.line, ev)
		}
	}
}

// route reads `web::get().to(handler)`.
func (ix *rsIndex) route(f *rsFile, ctx rsCtx, path string, _ bool, expr span, line int) {
	ch, ok := rsReadChain(f.code, trimSpan(f.code, expr).start)
	if !ok || !strings.HasPrefix(ch.head, "web::") {
		return
	}
	method := strings.ToLower(strings.TrimPrefix(ch.head, "web::"))
	switch {
	case rsVerbs[method]:
		method = strings.ToUpper(method)
	case method == "route":
		method = "ALL"
	default:
		return
	}
	for _, sg := range ch.segs {
		if sg.call && sg.name == "to" {
			if args := splitArgs(f.code, sg.args.start, sg.args.end); len(args) == 1 {
				ix.record(f, ctx, method, path, line, ix.handlerEvidence(f, args[0]))
				return
			}
		}
	}
}

type rsEvidence struct{ authn string }

func (ix *rsIndex) fnEvidence(fn *rsFn) rsEvidence {
	params := rsOptionRe.ReplaceAllString(fn.file.sans[fn.params.start:fn.params.end], "")
	if rsAuthTypeRe.MatchString(params) || (fn.body.end > fn.body.start && rsInlineRe.MatchString(fn.file.sans[fn.body.start:fn.body.end])) {
		return rsEvidence{authn: inlineAuthLabel}
	}
	return rsEvidence{}
}

// handlerEvidence reads the handler argument of `.to(...)`: a function of the tree or a closure.
func (ix *rsIndex) handlerEvidence(f *rsFile, arg span) rsEvidence {
	arg = trimSpan(f.code, arg)
	text := f.sans[arg.start:arg.end]
	if strings.HasPrefix(text, "|") || strings.HasPrefix(text, "move") || strings.HasPrefix(text, "async") {
		if rsInlineRe.MatchString(text) || rsAuthTypeRe.MatchString(rsOptionRe.ReplaceAllString(text, "")) {
			return rsEvidence{authn: inlineAuthLabel}
		}
		return rsEvidence{}
	}
	if fn := ix.resolve(text, f); fn != nil {
		return ix.fnEvidence(fn)
	}
	return rsEvidence{}
}

func (ix *rsIndex) record(f *rsFile, ctx rsCtx, method, rel string, line int, ev rsEvidence) {
	p := goJoin(ctx.prefix, rel)
	key := f.path + ":" + strconv.Itoa(line) + " " + method + " " + p
	if ix.seen[key] {
		return
	}
	ix.seen[key] = true
	ix.recs = append(ix.recs, rsRec{method: method, path: p, file: f, line: line, authn: firstNonEmpty(ctx.authn, ev.authn), authz: ctx.authz, opaque: ctx.opaque})
}

// rsMiddleware judges a wrap argument by its name: `HttpAuthentication::bearer(v)`.
func rsMiddleware(text string) (authn, authz string) {
	text = strings.TrimSpace(strings.Trim(strings.TrimSpace(text), `"`))
	name := text
	if i := strings.IndexByte(name, '('); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(strings.ReplaceAll(name, "::", " "))
	var n, z bool
	for _, w := range strings.Fields(name) {
		wn, wz := goMiddlewareClass(w)
		n, z = n || wn, z || wz
	}
	if n2, _ := goMiddlewareClass(strings.ReplaceAll(name, " ", "")); n2 {
		n = true
	}
	if n {
		authn = compact(text)
	}
	if z {
		authz = compact(text)
	}
	return authn, authz
}

func (ix *rsIndex) routes() ([]Route, []routeView) {
	var routes []Route
	var views []routeView
	for _, r := range ix.recs {
		rt := Route{Method: r.method, Path: r.path, FilePath: r.file.path, Line: r.line, Authn: r.authn, Authz: r.authz, Reader: ReaderActix}
		routes = append(routes, rt)
		views = append(views, routeView{route: rt, guardUnseen: r.opaque, framework: "actix"})
	}
	return routes, views
}
