package authz

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// Go routes: net/http ServeMux (including Go 1.22 "METHOD /path/{id}"
// patterns), Gin, Echo and Chi.
//
// There is no declaration to read, so the reader runs the registration code:
// each statement of a function is interpreted in order against a table of the
// routers in scope. `r := gin.Default()` creates one; `v1 := r.Group("/v1")`
// derives one with a prefix and the middleware its parent has at that moment;
// `r.Use(authMiddleware)` adds middleware to the router it is called on;
// `r.GET("/x", h)` registers a route that carries the middleware the router
// has right now. A function that receives a router (`func Register(rg
// *gin.RouterGroup)`) is run once per call site with the caller's router bound
// to the parameter, in the same package or in another package of the scanned
// tree that an import path resolves to.
//
// What it states, and no more:
//
//   - a route's Authn is middleware on the route (Gin/Echo arguments, a
//     wrapping call such as mux.Handle("/x", requireAuth(h))), on its group or
//     router at the point of registration, on a Chi router reached through
//     With or Route, or an inline check in the handler, judged by name with
//     authnName. Order matters in Gin, Chi and Echo groups, so a Use written
//     after a route does not cover it. Echo applies Echo-level Use at request
//     time, so there it covers every route.
//   - a router whose handler the program wraps (http.ListenAndServe(addr,
//     auth(mux)), Handler: auth(mux)) is authenticated as a whole;
//   - a router the reader could not trace to its construction (a parameter
//     never bound, a struct field whose middleware is added in another
//     function) is opaque: its routes are listed, never claimed to be
//     unauthenticated, and never a lead.
//
// What it does not do: gorilla/mux and other routers, routes registered
// through a path held in a constant or a concatenation, Chi Mount of a handler
// that is not a router built in the scanned tree, routers returned through
// interfaces or stored in maps, and middleware judged by anything but its name
// and the handler's own text.

var (
	goFuncRe     = regexp.MustCompile(`(?m)^func\s*(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\(`)
	goVersionRe  = regexp.MustCompile(`^v\d+$`)
	goAssignRe   = regexp.MustCompile(`^(?:var\s+)?([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*(:=|=)([^=]|$)`)
	goStructRe   = regexp.MustCompile(`(?m)^type\s+\w+\s+struct\s*\{`)
	goFieldRe    = regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s+\*?([A-Za-z_]\w*\.[A-Za-z_]\w*)\s*(?://.*)?$`)
	goNotCallRe  = regexp.MustCompile(`^(?:if|else|for|switch|select|defer|go|return|case)\b\s*`)
	goHandlerCtx = regexp.MustCompile(`\bListenAndServe(?:TLS)?\b|\bServe\s*\(|\bHandler\b`)

	// goInlineAuthRe: the handler or middleware itself checks the caller.
	goInlineAuthRe = regexp.MustCompile(`(?i)\bStatusUnauthorized\b|\bStatusForbidden\b|\bUnauthorized\s*\(|\bForbidden\s*\(` +
		`|(?:Header\s*\.\s*Get|GetHeader|Get)\s*\(\s*"Authorization"|\bBasicAuth\s*\(\s*\)|\bParseWithClaims\b|\bjwt\s*\.\s*Parse` +
		`|\b(?:WriteHeader|AbortWithStatus|Error|Status)\s*\([^)]*\b40[13]\b|\bUserFromContext\b|\bFromContext\s*\(\s*\w*\s*\)\s*;?\s*(?:user|claims|principal)\b` +
		`|\bcurrentUser\b|\bgetSession\b|\bGetUserFromContext\b|\bsessions?\s*\.\s*(?:Get|Values|Default)\b`)

	goRouterTypes = map[goKind]map[string]bool{
		goGin:  {"Engine": true, "RouterGroup": true, "IRouter": true, "IRoutes": true},
		goEcho: {"Echo": true, "Group": true},
		goChi:  {"Router": true, "Mux": true},
		goStd:  {"ServeMux": true},
	}
	goVerbs = map[string]string{"GET": "GET", "POST": "POST", "PUT": "PUT", "DELETE": "DELETE", "PATCH": "PATCH", "HEAD": "HEAD", "OPTIONS": "OPTIONS", "CONNECT": "CONNECT", "TRACE": "TRACE"}
)

type goKind int

const (
	goStd goKind = iota + 1
	goGin
	goEcho
	goChi
)

// goRoot is the application a tree of routers belongs to.
type goRoot struct {
	// wrap: the handler the program serves wraps this router in authentication.
	wrap string
	// late: Echo-level Use, which Echo applies when a request arrives.
	late string
}

// goRouter is one router, group or sub-router.
type goRouter struct {
	kind   goKind
	root   *goRoot
	parent *goRouter
	prefix string
	authn  string
	authz  string
	opaque bool
	// inherited: what a parent contributed when this router was mounted late.
	inherited string
	engine    bool
}

func (r *goRouter) fullPrefix() string {
	var parts []string
	for c := r; c != nil; c = c.parent {
		parts = append([]string{c.prefix}, parts...)
	}
	return goJoin(parts...)
}

func (r *goRouter) covered() (authn string, opaque bool) {
	for c := r; c != nil; c = c.parent {
		opaque = opaque || c.opaque
		for _, s := range []string{c.root.wrap, c.root.late, c.inherited} {
			if authn == "" {
				authn = s
			}
		}
	}
	return authn, opaque
}

type goFile struct {
	path, dir  string
	raw        []byte
	code, sans string
	lineStarts []int
	imports    map[string]string
}

type goFunc struct {
	file       *goFile
	name       string
	params     []string
	types      []string
	body       span
	builder    bool // has a router parameter or returns a router
	ambiguous  bool
	paramKinds []goKind
}

type goPkg struct {
	dir     string
	files   []*goFile
	funcs   map[string]*goFunc
	fields  map[string]goKind
	cached  map[string]*goRouter
	useOn   map[string]bool
	defMux  *goRouter
	memo    map[string]*goRouter
	handled map[*goFunc]bool
	all     []*goFunc
}

type goRec struct {
	rt                   *goRouter
	method, rel          string
	file                 *goFile
	line                 int
	authn, authz         string // on the route itself
	snapAuthn, snapAuthz string // on its router when it was registered
}

type goIndex struct {
	pkgs map[string]*goPkg
	dirs []string
	recs []goRec
}

func newGoFile(p string, raw []byte) *goFile {
	f := &goFile{path: p, dir: dirOfPath(p), raw: raw, code: string(lexctx.MaskNonCode(lexctx.LangGo, raw)), sans: withoutComments(lexctx.LangGo, raw), lineStarts: computeLineStarts(raw), imports: map[string]string{}}
	f.readImports()
	return f
}

var goImportLineRe = regexp.MustCompile(`^\s*(?:([A-Za-z_.]\w*)\s+)?"([^"]+)"`)

func (f *goFile) readImports() {
	add := func(line string) {
		if m := goImportLineRe.FindStringSubmatch(line); m != nil {
			alias := m[1]
			if alias == "" {
				alias = goImportName(m[2])
			}
			if alias != "_" && alias != "." {
				f.imports[alias] = m[2]
			}
		}
	}
	for _, loc := range regexp.MustCompile(`(?m)^import\s*(\()?`).FindAllStringSubmatchIndex(f.code, -1) {
		if loc[2] >= 0 {
			end := matchClose(f.code, loc[2])
			if end < 0 {
				continue
			}
			for _, l := range strings.Split(f.sans[loc[2]+1:end], "\n") {
				add(l)
			}
			continue
		}
		eol := strings.IndexByte(f.sans[loc[1]:], '\n')
		if eol < 0 {
			eol = len(f.sans) - loc[1]
		}
		add(f.sans[loc[1] : loc[1]+eol])
	}
}

func goImportName(p string) string {
	segs := strings.Split(p, "/")
	n := segs[len(segs)-1]
	if goVersionRe.MatchString(n) && len(segs) > 1 {
		n = segs[len(segs)-2]
	}
	return n
}

func goKindOfImport(p string) goKind {
	trim := func(base string) bool {
		if p == base {
			return true
		}
		rest, ok := strings.CutPrefix(p, base+"/")
		return ok && goVersionRe.MatchString(rest)
	}
	switch {
	case p == "net/http":
		return goStd
	case trim("github.com/gin-gonic/gin"):
		return goGin
	case trim("github.com/labstack/echo"):
		return goEcho
	case trim("github.com/go-chi/chi"):
		return goChi
	}
	return 0
}

// typeKind resolves a type such as `*gin.RouterGroup` to a router kind.
func (f *goFile) typeKind(t string) goKind {
	t = strings.TrimLeft(strings.TrimSpace(t), "*")
	pkg, name, ok := strings.Cut(t, ".")
	if !ok {
		return 0
	}
	k := goKindOfImport(f.imports[pkg])
	if k != 0 && goRouterTypes[k][name] {
		return k
	}
	return 0
}

func newGoIndex(files []*goFile) *goIndex {
	ix := &goIndex{pkgs: map[string]*goPkg{}}
	for _, f := range files {
		p := ix.pkgs[f.dir]
		if p == nil {
			p = &goPkg{dir: f.dir, funcs: map[string]*goFunc{}, fields: map[string]goKind{}, cached: map[string]*goRouter{}, useOn: map[string]bool{}, memo: map[string]*goRouter{}, handled: map[*goFunc]bool{}}
			ix.pkgs[f.dir] = p
			ix.dirs = append(ix.dirs, f.dir)
		}
		p.files = append(p.files, f)
	}
	sort.Strings(ix.dirs)
	for _, d := range ix.dirs {
		ix.pkgs[d].index()
	}
	return ix
}

func (p *goPkg) index() {
	for _, f := range p.files {
		for _, loc := range goStructRe.FindAllStringIndex(f.code, -1) {
			end := matchClose(f.code, loc[1]-1)
			if end < 0 {
				continue
			}
			for _, m := range goFieldRe.FindAllStringSubmatch(f.sans[loc[1]:end], -1) {
				if k := f.typeKind(m[2]); k != 0 {
					p.fields[m[1]] = k
				}
			}
		}
		for _, m := range regexp.MustCompile(`\.\s*([A-Za-z_]\w*)\s*\.\s*Use\s*\(`).FindAllStringSubmatch(f.code, -1) {
			p.useOn[m[1]] = true
		}
		for _, loc := range goFuncRe.FindAllStringSubmatchIndex(f.code, -1) {
			if fn := p.readFunc(f, loc); fn != nil {
				p.all = append(p.all, fn)
				if _, dup := p.funcs[fn.name]; dup {
					p.funcs[fn.name].ambiguous = true
					continue
				}
				p.funcs[fn.name] = fn
			}
		}
	}
}

func (p *goPkg) readFunc(f *goFile, loc []int) *goFunc {
	open := loc[1] - 1
	end := matchClose(f.code, open)
	if end < 0 {
		return nil
	}
	i, ok := bodyStart(f.code, end)
	if !ok {
		return nil
	}
	bodyEnd := matchClose(f.code, i)
	if bodyEnd < 0 {
		return nil
	}
	fn := &goFunc{file: f, name: f.code[loc[4]:loc[5]], body: span{i + 1, bodyEnd}}
	fn.params, fn.types = splitParams(f.code, span{open + 1, end}, false)
	for _, t := range fn.types {
		k := f.typeKind(t)
		fn.paramKinds = append(fn.paramKinds, k)
		fn.builder = fn.builder || k != 0
	}
	for _, t := range strings.FieldsFunc(f.code[end+1:i], func(r rune) bool { return r == ',' || r == ' ' || r == '(' || r == ')' || r == '\n' || r == '\t' }) {
		fn.builder = fn.builder || f.typeKind(t) != 0
	}
	return fn
}

// resolve finds the function a call names: a bare name in this package, a
// package-qualified name through an import, or a method by name when it is
// unique in the package.
func (ix *goIndex) resolve(p *goPkg, f *goFile, callee string) (*goFunc, *goPkg) {
	parts := strings.Split(callee, ".")
	switch len(parts) {
	case 1:
		if fn := p.funcs[callee]; fn != nil && !fn.ambiguous {
			return fn, p
		}
	case 2:
		if imp, ok := f.imports[parts[0]]; ok {
			if q := ix.pkgForImport(imp); q != nil {
				if fn := q.funcs[parts[1]]; fn != nil && !fn.ambiguous {
					return fn, q
				}
			}
			return nil, nil
		}
		fallthrough
	default:
		if fn := p.funcs[parts[len(parts)-1]]; fn != nil && !fn.ambiguous {
			return fn, p
		}
	}
	return nil, nil
}

// pkgForImport finds the one scanned directory an import path ends in.
func (ix *goIndex) pkgForImport(imp string) *goPkg {
	segs := strings.Split(imp, "/")
	for k := len(segs); k >= 1; k-- {
		tail := strings.Join(segs[len(segs)-k:], "/")
		var hit *goPkg
		n := 0
		for _, d := range ix.dirs {
			if d == tail || strings.HasSuffix(d, "/"+tail) {
				hit, n = ix.pkgs[d], n+1
			}
		}
		if n == 1 {
			return hit
		}
		if n > 1 {
			return nil
		}
	}
	return nil
}

// goExec interprets one function body.
// goWrap is a variable holding authn(router).
type goWrap struct {
	router *goRouter
	label  string
}

type goExec struct {
	ix       *goIndex
	pkg      *goPkg
	file     *goFile
	vars     map[string]*goRouter
	wrapVars map[string]goWrap
	ret      *goRouter
	opaque   bool
	depth    int
}

func (ix *goIndex) run() {
	for _, d := range ix.dirs {
		p := ix.pkgs[d]
		for _, fn := range p.all {
			if !fn.builder {
				ix.runFunc(p, fn, nil, false, 0)
			}
		}
	}
	for _, d := range ix.dirs {
		p := ix.pkgs[d]
		for _, fn := range p.all {
			if !p.handled[fn] {
				ix.runFunc(p, fn, nil, true, 0)
			}
		}
	}
}

func (ix *goIndex) runFunc(p *goPkg, fn *goFunc, args []*goRouter, opaque bool, depth int) *goRouter {
	key := fn.file.path + ":" + strconv.Itoa(fn.body.start)
	for _, a := range args {
		key += "|" + ptrKey(a)
	}
	if r, done := p.memo[key]; done {
		return r
	}
	p.memo[key] = nil
	p.handled[fn] = true
	if depth > 8 {
		return nil
	}
	e := &goExec{ix: ix, pkg: p, file: fn.file, vars: map[string]*goRouter{}, wrapVars: map[string]goWrap{}, opaque: opaque, depth: depth}
	for i, name := range fn.params {
		k := fn.paramKinds[i]
		if k == 0 || name == "" {
			continue
		}
		if i < len(args) && args[i] != nil {
			e.vars[name] = args[i]
		} else {
			e.vars[name] = &goRouter{kind: k, root: &goRoot{}, opaque: true}
		}
	}
	e.region(fn.body.start, fn.body.end)
	p.memo[key] = e.ret
	return e.ret
}

func ptrKey(r *goRouter) string { return fmt.Sprintf("%p", r) }

func (e *goExec) region(from, to int) {
	for _, s := range splitStatements(e.file.code, from, to, true) {
		e.statement(s)
	}
}

func (e *goExec) statement(s span) {
	code := e.file.code
	for {
		loc := goNotCallRe.FindStringIndex(code[s.start:s.end])
		if loc == nil || strings.HasPrefix(code[s.start:s.end], "return") {
			break
		}
		s.start += loc[1]
	}
	if s.end <= s.start {
		return
	}
	if rest, ok := strings.CutPrefix(code[s.start:s.end], "return"); ok && (rest == "" || !isIdentByte(rest[0])) {
		if args := splitArgs(code, s.start+len("return"), s.end); len(args) > 0 {
			if r := e.eval(args[0]); r != nil && e.ret == nil {
				e.ret = r
			}
		}
		return
	}
	text := code[s.start:s.end]
	if m := goAssignRe.FindStringSubmatchIndex(text); m != nil {
		name := strings.Join(strings.Fields(text[m[2]:m[3]]), "")
		e.assign(name, trimSpan(code, span{s.start + m[5], s.end}))
		return
	}
	if segs, ok := parseChain(code, s); ok && segs[len(segs)-1].call {
		if e.chainStatement(segs, s) {
			return
		}
	}
	e.scanCalls(s, false)
}

func (e *goExec) assign(name string, rhs span) {
	if r := e.eval(rhs); r != nil {
		e.vars[name] = r
		return
	}
	delete(e.vars, name)
	delete(e.wrapVars, name)
	_, label, r := e.wrapOf(rhs)
	switch {
	case r == nil:
	case strings.HasSuffix(name, ".Handler"):
		e.serve(r, label)
	default:
		e.wrapVars[name] = goWrap{r, label}
	}
	e.scanCalls(rhs, strings.HasSuffix(name, ".Handler"))
}

// wrapOf recognises an authentication-named call whose argument is a router.
func (e *goExec) wrapOf(s span) (callee, label string, r *goRouter) {
	segs, ok := parseChain(e.file.code, s)
	if !ok || !segs[len(segs)-1].call {
		return "", "", nil
	}
	last := segs[len(segs)-1]
	var names []string
	for _, sg := range segs {
		names = append(names, sg.name)
	}
	callee = strings.Join(names, ".")
	if fn, _ := e.ix.resolve(e.pkg, e.file, callee); fn != nil && fn.builder {
		return "", "", nil
	}
	authn, _ := goMiddlewareClass(callee)
	if !authn {
		return "", "", nil
	}
	for _, a := range splitArgs(e.file.code, last.args.start, last.args.end) {
		if rt := e.eval(a); rt != nil {
			return callee, compact(e.file.sans[s.start:s.end]), rt
		}
	}
	return "", "", nil
}

// eval resolves an expression to the router it denotes.
func (e *goExec) eval(s span) *goRouter {
	s = trimSpan(e.file.code, s)
	for s.end > s.start && (e.file.code[s.start] == '&' || e.file.code[s.start] == '*') {
		s.start++
	}
	segs, ok := parseChain(e.file.code, s)
	if !ok {
		return nil
	}
	return e.evalSegs(segs)
}

func (e *goExec) lookup(name string) *goRouter {
	if r := e.vars[name]; r != nil {
		return r
	}
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return nil
	}
	field := name[i+1:]
	k, ok := e.pkg.fields[field]
	if !ok {
		return nil
	}
	if r := e.pkg.cached[field]; r != nil {
		return r
	}
	r := &goRouter{kind: k, root: &goRoot{}, engine: true, opaque: e.pkg.useOn[field]}
	e.pkg.cached[field] = r
	return r
}

func (e *goExec) evalSegs(segs []seg) *goRouter {
	n := 0
	for n < len(segs) && !segs[n].call {
		n++
	}
	var cur *goRouter
	idx := n
	names := make([]string, 0, n)
	for _, sg := range segs[:n] {
		names = append(names, sg.name)
	}
	base := strings.Join(names, ".")
	switch {
	case n == 0:
		cur = e.callFunc(segs[0].name, segs[0])
		idx = 1
	case n == len(segs) && n == 2 && goKindOfImport(e.file.imports[names[0]]) == goStd && names[1] == "DefaultServeMux":
		return e.defaultMux()
	case e.file.imports[names[0]] != "" && n == 1 && idx < len(segs):
		cur = e.qualified(names[0], segs[idx])
		idx++
	default:
		cur = e.lookup(base)
	}
	for ; cur != nil && idx < len(segs); idx++ {
		cur = e.derive(cur, segs[idx])
	}
	return cur
}

func (e *goExec) defaultMux() *goRouter {
	if e.pkg.defMux == nil {
		e.pkg.defMux = &goRouter{kind: goStd, root: &goRoot{}, engine: true}
	}
	return e.pkg.defMux
}

func (e *goExec) newRoot(k goKind) *goRouter {
	return &goRouter{kind: k, root: &goRoot{}, engine: true, opaque: e.opaque}
}

// qualified evaluates pkg.Func(...): a router constructor, or a function of a scanned package.
func (e *goExec) qualified(alias string, sg seg) *goRouter {
	switch k, name := goKindOfImport(e.file.imports[alias]), sg.name; {
	case k == goGin && (name == "Default" || name == "New"), k == goEcho && name == "New",
		k == goChi && (name == "NewRouter" || name == "NewMux"), k == goStd && name == "NewServeMux":
		return e.newRoot(k)
	}
	return e.callFunc(alias+"."+sg.name, sg)
}

// callFunc runs a scanned function that builds or receives routers, and returns the router it returns.
func (e *goExec) callFunc(callee string, sg seg) *goRouter {
	fn, p := e.ix.resolve(e.pkg, e.file, callee)
	if fn == nil || !fn.builder || e.depth >= 8 {
		return nil
	}
	return e.ix.runFunc(p, fn, e.argRouters(fn, sg.args), e.opaque, e.depth+1)
}

func (e *goExec) argRouters(fn *goFunc, args span) []*goRouter {
	var out []*goRouter
	for i, a := range splitArgs(e.file.code, args.start, args.end) {
		var r *goRouter
		if i < len(fn.paramKinds) && fn.paramKinds[i] != 0 {
			r = e.eval(a)
		}
		out = append(out, r)
	}
	return out
}

// derive applies a call that yields a router: Group, With and the Use that returns its receiver.
func (e *goExec) derive(r *goRouter, sg seg) *goRouter {
	if !sg.call {
		return nil
	}
	args := splitArgs(e.file.code, sg.args.start, sg.args.end)
	switch sg.name {
	case "Group":
		return e.group(r, args)
	case "With":
		c := *r
		c.engine = false
		e.applyMiddleware(&c, args)
		return &c
	case "Use":
		e.use(r, args)
		return r
	}
	return nil
}

func (e *goExec) group(r *goRouter, args []span) *goRouter {
	c := &goRouter{kind: r.kind, root: r.root, parent: r, authn: r.authn, authz: r.authz, opaque: r.opaque}
	switch r.kind {
	case goGin, goEcho:
		if len(args) == 0 {
			return nil
		}
		p, ok := e.literal(args[0])
		if !ok {
			c.opaque = true
		}
		c.prefix = p
		e.applyMiddleware(c, args[1:])
	case goChi:
		if len(args) > 0 {
			return nil
		}
	default:
		return nil
	}
	return c
}

func (e *goExec) literal(s span) (string, bool) {
	return strictLiteral(e.file.raw, e.file.code, trimSpan(e.file.code, s))
}

func (e *goExec) use(r *goRouter, args []span) {
	if r.kind == goEcho && r.engine {
		for _, a := range args {
			if authn, _ := e.mwEvidence(a); authn != "" && r.root.late == "" {
				r.root.late = authn
			}
		}
		return
	}
	e.applyMiddleware(r, args)
}

func (e *goExec) applyMiddleware(r *goRouter, args []span) {
	for _, a := range args {
		authn, authz := e.mwEvidence(a)
		if r.authn == "" {
			r.authn = authn
		}
		if r.authz == "" {
			r.authz = authz
		}
	}
}

// goOptionalCallRe: a middleware called with the single literal false. Such a
// constructor takes a switch (`AuthMiddleware(auto401 bool)`), and false is
// the value that lets an unauthenticated request through, so it is no evidence.
var goOptionalCallRe = regexp.MustCompile(`^[\w.]+\s*\(\s*false\s*\)$`)

// enforcingImport: the middleware comes from a package whose every middleware
// rejects an unauthenticated request (echo-jwt). Packages that only decode a
// token (chi's jwtauth.Verifier) are judged by the name alone.
func (e *goExec) enforcingImport(callee string) bool {
	pkg, _, ok := strings.Cut(callee, ".")
	return ok && strings.HasPrefix(e.file.imports[pkg], "github.com/labstack/echo-jwt")
}

// goMiddlewareClass judges a middleware by its name.
func goMiddlewareClass(name string) (authn, authz bool) {
	if notAccessControlRe.MatchString(name) {
		return false, false
	}
	if loggedRe.MatchString(name) && !loggedInRe.MatchString(name) {
		name = loggedRe.ReplaceAllString(name, "Log") // "Logged" logs; only "LoggedIn" authenticates
	}
	return authnName(acronymBoundary.ReplaceAllString(name, "$1 $2")), authzMWRe.MatchString(name)
}

// acronymBoundary splits "JWTAuth" into "JWT Auth", which authnName reads as two words.
var (
	loggedRe   = regexp.MustCompile(`(?i)logged`)
	loggedInRe = regexp.MustCompile(`(?i)logged[_ -]?in`)
)

var acronymBoundary = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)

// mwEvidence reads one middleware expression: a name, a call, or a function literal.
func (e *goExec) mwEvidence(a span) (authn, authz string) {
	a = trimSpan(e.file.code, a)
	text := e.file.sans[a.start:a.end]
	if strings.HasPrefix(text, "func") {
		if goInlineAuthRe.MatchString(text) {
			return inlineAuthLabel, ""
		}
		return "", ""
	}
	name := text
	if i := strings.IndexByte(name, '('); i >= 0 {
		name = name[:i]
	}
	if goOptionalCallRe.MatchString(text) {
		return "", "" // AuthMiddleware(false): the flag that makes it let anonymous callers through
	}
	n, z := goMiddlewareClass(strings.TrimSpace(name))
	if !n && e.enforcingImport(strings.TrimSpace(name)) {
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

// handlerEvidence reads a handler argument: a wrapping call such as
// requireAuth(h) is middleware; a function literal or a function of the
// scanned tree is judged by what it does with the caller.
func (e *goExec) handlerEvidence(a span) (authn, authz, body string) {
	a = trimSpan(e.file.code, a)
	for depth := 0; depth < 4; depth++ {
		text := e.file.sans[a.start:a.end]
		if strings.HasPrefix(text, "func") {
			if goInlineAuthRe.MatchString(text) {
				authn = firstNonEmpty(authn, inlineAuthLabel)
			}
			return authn, authz, text
		}
		segs, ok := parseChain(e.file.code, a)
		if !ok {
			return authn, authz, ""
		}
		last := segs[len(segs)-1]
		var names []string
		for _, sg := range segs {
			names = append(names, sg.name)
		}
		callee := strings.Join(names, ".")
		if !last.call {
			if fn, _ := e.ix.resolve(e.pkg, e.file, callee); fn != nil {
				body = fn.file.sans[fn.body.start:fn.body.end]
				if goInlineAuthRe.MatchString(body) {
					authn = firstNonEmpty(authn, inlineAuthLabel)
				}
			}
			return authn, authz, body
		}
		n, z := goMiddlewareClass(callee)
		if n {
			authn = firstNonEmpty(authn, compact(e.file.sans[a.start:a.end]))
		}
		if z {
			authz = firstNonEmpty(authz, compact(e.file.sans[a.start:a.end]))
		}
		inner := splitArgs(e.file.code, last.args.start, last.args.end)
		if len(inner) == 0 {
			return authn, authz, ""
		}
		a = inner[0]
	}
	return authn, authz, ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// chainStatement handles `receiver.Action(args)`; false when the receiver is no router.
func (e *goExec) chainStatement(segs []seg, s span) bool {
	last := segs[len(segs)-1]
	var rt *goRouter
	if len(segs) == 2 && !segs[0].call && goKindOfImport(e.file.imports[segs[0].name]) == goStd && (last.name == "Handle" || last.name == "HandleFunc") {
		rt = e.defaultMux()
	} else if len(segs) > 1 {
		rt = e.evalSegs(segs[:len(segs)-1])
	}
	if rt == nil {
		return false
	}
	e.action(rt, last)
	return true
}

func (e *goExec) action(rt *goRouter, sg seg) {
	args := splitArgs(e.file.code, sg.args.start, sg.args.end)
	switch name := sg.name; {
	case name == "Use":
		e.use(rt, args)
	case name == "Group" && rt.kind == goChi && len(args) == 1:
		e.closure(rt, args[0], nil)
	case name == "Route" && rt.kind == goChi && len(args) == 2:
		e.closure(rt, args[1], &args[0])
	case name == "Mount" && rt.kind == goChi && len(args) == 2:
		e.mount(rt, args)
	default:
		e.register(rt, sg, args)
	}
}

// closure runs `func(r chi.Router) { ... }` against a router derived from rt.
func (e *goExec) closure(rt *goRouter, lit span, prefix *span) {
	code := e.file.code
	lit = trimSpan(code, lit)
	if !strings.HasPrefix(code[lit.start:lit.end], "func") {
		return
	}
	open := strings.IndexByte(code[lit.start:lit.end], '(')
	if open < 0 {
		return
	}
	pend := matchClose(code, lit.start+open)
	if pend < 0 {
		return
	}
	body := strings.IndexByte(code[pend:lit.end], '{')
	if body < 0 {
		return
	}
	bend := matchClose(code, pend+body)
	if bend < 0 {
		return
	}
	child := &goRouter{kind: rt.kind, root: rt.root, parent: rt, authn: rt.authn, authz: rt.authz, opaque: rt.opaque}
	if prefix != nil {
		p, ok := e.literal(*prefix)
		child.prefix, child.opaque = p, child.opaque || !ok
	}
	names, _ := splitParams(code, span{lit.start + open + 1, pend}, false)
	sub := &goExec{ix: e.ix, pkg: e.pkg, file: e.file, vars: map[string]*goRouter{}, wrapVars: e.wrapVars, opaque: e.opaque, depth: e.depth}
	for k, v := range e.vars {
		sub.vars[k] = v
	}
	if len(names) > 0 && names[0] != "" {
		sub.vars[names[0]] = child
	}
	sub.region(pend+body+1, bend)
}

func (e *goExec) mount(rt *goRouter, args []span) {
	p, ok := e.literal(args[0])
	if !ok {
		return
	}
	sub := e.eval(args[1])
	if sub == nil || sub.parent != nil || sub == rt {
		return
	}
	sub.parent, sub.prefix, sub.inherited = rt, p, rt.authn
}

// register records a route registration call.
func (e *goExec) register(rt *goRouter, sg seg, args []span) {
	method, pathArg, handlers, ok := e.registration(rt, sg.name, args)
	if !ok {
		return
	}
	pat, lit := e.literal(pathArg)
	if !lit {
		return
	}
	if rt.kind == goStd {
		method, pat, ok = goStdPattern(pat)
		if !ok {
			return
		}
	}
	rec := goRec{rt: rt, method: method, rel: pat, file: e.file, line: lineAt(e.file.lineStarts, sg.start), snapAuthn: rt.authn, snapAuthz: rt.authz}
	for _, h := range handlers.mw {
		n, z := e.mwEvidence(h)
		rec.authn, rec.authz = firstNonEmpty(rec.authn, n), firstNonEmpty(rec.authz, z)
	}
	for _, h := range handlers.handler {
		n, z, _ := e.handlerEvidence(h)
		rec.authn, rec.authz = firstNonEmpty(rec.authn, n), firstNonEmpty(rec.authz, z)
	}
	e.ix.recs = append(e.ix.recs, rec)
}

type goHandlers struct{ mw, handler []span }

// registration maps a call on a router to (verb, path argument, handler arguments).
func (e *goExec) registration(rt *goRouter, name string, args []span) (method string, path span, h goHandlers, ok bool) {
	pick := func(m string, i int) (string, span, goHandlers, bool) {
		if len(args) <= i {
			return "", span{}, goHandlers{}, false
		}
		return m, args[i], e.split(rt.kind, args[i+1:]), true
	}
	switch rt.kind {
	case goGin, goEcho:
		if v, isVerb := goVerbs[name]; isVerb {
			return pick(v, 0)
		}
		switch name {
		case "Any":
			return pick("ALL", 0)
		case "Handle", "Add":
			if len(args) < 3 {
				return "", span{}, goHandlers{}, false
			}
			m, lit := e.literal(args[0])
			if !lit {
				return "", span{}, goHandlers{}, false
			}
			return pick(strings.ToUpper(m), 1)
		}
	case goChi:
		if v, isVerb := goVerbs[strings.ToUpper(name)]; isVerb && name == strings.ToUpper(name[:1])+strings.ToLower(name[1:]) {
			return pick(v, 0)
		}
		switch name {
		case "Handle", "HandleFunc":
			return pick("ALL", 0)
		case "Method", "MethodFunc":
			if len(args) < 3 {
				return "", span{}, goHandlers{}, false
			}
			m, lit := e.literal(args[0])
			if !lit {
				return "", span{}, goHandlers{}, false
			}
			return pick(strings.ToUpper(m), 1)
		}
	case goStd:
		if name == "Handle" || name == "HandleFunc" {
			return pick("ALL", 0)
		}
	}
	return "", span{}, goHandlers{}, false
}

// split separates a registration's trailing arguments into middleware and handler.
func (e *goExec) split(k goKind, rest []span) goHandlers {
	switch {
	case len(rest) == 0:
		return goHandlers{}
	case k == goEcho:
		return goHandlers{handler: rest[:1], mw: rest[1:]}
	case k == goGin:
		return goHandlers{mw: rest[:len(rest)-1], handler: rest[len(rest)-1:]}
	}
	return goHandlers{handler: rest[:1]}
}

// goStdPattern reads a ServeMux pattern: "[METHOD ][HOST]/path".
func goStdPattern(p string) (method, pat string, ok bool) {
	method = "ALL"
	p = strings.TrimSpace(p)
	if m, rest, found := strings.Cut(p, " "); found {
		if _, verb := goVerbs[m]; !verb {
			return "", "", false
		}
		method, p = m, strings.TrimSpace(rest)
	}
	if !strings.HasPrefix(p, "/") {
		return "", "", false // a host-qualified pattern
	}
	return method, p, true
}

// scanCalls looks for calls that pass a router to a scanned function, and for
// authentication that wraps a router before it is served.
func (e *goExec) scanCalls(s span, served bool) {
	code := e.file.code
	served = served || goHandlerCtx.MatchString(code[s.start:s.end])
	for _, c := range findCalls(code, s) {
		if i := strings.LastIndexByte(c.callee, '.'); i > 0 && e.lookup(c.callee[:i]) != nil {
			continue
		}
		if fn, p := e.ix.resolve(e.pkg, e.file, c.callee); fn != nil && fn.builder && e.depth < 8 {
			e.ix.runFunc(p, fn, e.argRouters(fn, c.args), e.opaque, e.depth+1)
			continue
		}
		if served {
			if _, label, r := e.wrapOf(span{c.start, c.args.end + 1}); r != nil {
				e.serve(r, label)
			}
		}
	}
	if served {
		for name, w := range e.wrapVars {
			if hasWord(code[s.start:s.end], name) {
				e.serve(w.router, w.label)
			}
		}
	}
}

// serve records that a router is only reachable through authentication.
func (e *goExec) serve(r *goRouter, label string) {
	if r.root.wrap == "" {
		r.root.wrap = label
	}
}

// routes turns the recorded registrations into the route table.
func (ix *goIndex) routes() ([]Route, []routeView) {
	var routes []Route
	var views []routeView
	seen := map[string]bool{}
	for _, rec := range ix.recs {
		cov, opaque := rec.rt.covered()
		authn := firstNonEmpty(firstNonEmpty(rec.authn, rec.snapAuthn), cov)
		authz := firstNonEmpty(rec.authz, rec.snapAuthz)
		p := goJoin(rec.rt.fullPrefix(), rec.rel)
		if strings.HasSuffix(rec.rel, "/") && p != "/" {
			p += "/"
		}
		key := rec.file.path + ":" + strconv.Itoa(rec.line) + " " + rec.method + " " + p
		if seen[key] {
			continue
		}
		seen[key] = true
		rt := Route{Method: rec.method, Path: p, FilePath: rec.file.path, Line: rec.line, Authn: authn, Authz: authz, Reader: ReaderGo}
		routes = append(routes, rt)
		views = append(views, routeView{route: rt, guardUnseen: opaque, framework: "go"})
	}
	return routes, views
}

// bodyStart finds the `{` of a function's body after its parameter list, which
// ends at paramsEnd. Result types may hold braces (`struct{}`, `interface{}`),
// and a declaration without a body ends at its line.
func bodyStart(code string, paramsEnd int) (int, bool) {
	depth := 0
	for i := paramsEnd + 1; i < len(code); i++ {
		switch c := code[i]; {
		case c == '(' || c == '[':
			depth++
		case c == ')' || c == ']':
			depth--
		case c == '\n' && depth == 0 && strings.TrimSpace(code[paramsEnd+1:i]) == "":
			return 0, false
		case c == '{' && depth == 0:
			w := strings.TrimSpace(code[paramsEnd+1 : i])
			if !strings.HasSuffix(w, "interface") && !strings.HasSuffix(w, "struct") {
				return i, true
			}
			c2 := matchClose(code, i)
			if c2 < 0 {
				return 0, false
			}
			i = c2
		}
	}
	return 0, false
}
