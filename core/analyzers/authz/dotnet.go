package authz

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// ASP.NET Core: attribute-routed controllers and minimal APIs.
//
// A controller route is an attribute pair: `[Route("api/[controller]")]` on a
// class and `[HttpGet("{id}")]` on a method. A minimal API route is a call on
// an endpoint route builder: `app.MapGet("/x", handler)`, optionally inside
// `app.MapGroup("/api")`. The reader interprets the registration code the way
// the Go reader does: variables hold route builders, a group derives a builder
// with a prefix, and an extension method that receives a builder (`app.MapGroup
// ("api/catalog").MapCatalogApi()`) is run with the caller's builder bound to
// its `this` parameter.
//
// What it states, and no more:
//
//   - a route's Authn is [Authorize] (or an attribute named like an
//     authenticator) on its method or class or a base class in the project,
//     `.RequireAuthorization()` on its endpoint or on any group it is in (a
//     group convention applies to every endpoint of the group, whatever the
//     order), an [Authorize] on a minimal API handler, or a handler that reads
//     the caller (a ClaimsPrincipal parameter, User.Identity);
//   - [AllowAnonymous] and .AllowAnonymous() mean public on purpose, at any
//     level: ASP.NET lets the request through whatever else is written, so a
//     route marked so is never a lead;
//   - UseAuthentication() and UseAuthorization() alone authenticate nothing:
//     they only apply policies endpoints ask for, so they are not evidence;
//   - a project-wide requirement (an AuthorizeFilter added to MVC, a
//     FallbackPolicy, MapControllers().RequireAuthorization(), a middleware
//     named for authentication) decides authentication somewhere this reader
//     does not evaluate: a route with no evidence of its own is unseen, never
//     a lead. A project is the nearest directory holding a .csproj.
//
// What it does not do: conventional routing (MapControllerRoute), Razor
// Pages, Web API 2 (System.Web.Http), path templates built from constants or
// interpolation (the route is skipped, not guessed), routes declared on an
// interface, and anything a base class outside the scanned tree declares
// (such a controller is unseen).

var (
	csTypeRe       = regexp.MustCompile(`\b(class|struct|interface|record|enum|namespace)\s+([A-Za-z_][\w.]*)`)
	csAssignRe     = regexp.MustCompile(`^(?:[A-Za-z_][\w<>\[\]?.,]*\s+)?([A-Za-z_]\w*)\s*=([^=>]|$)`)
	csGlobalAuthRe = regexp.MustCompile(`\bFallbackPolicy\s*=\s*\S|\.\s*SetFallbackPolicy\s*\(|\bnew\s+AuthorizeFilter\b|\bAdd\s*<\s*AuthorizeFilter\b`)
	// csNegatedRe: [NoPermissionRequired] and the like say the opposite of what authzMWRe hears in them.
	csNegatedRe      = regexp.MustCompile(`^(?:No|Skip|Bypass|Ignore|Disable)(?:Auth|Permission|Role|Policy|Security)`)
	csNullFallbackRe = regexp.MustCompile(`\bFallbackPolicy\s*=\s*null\b`)
	csUseMiddleware  = regexp.MustCompile(`\.\s*(Use\w*)\s*(?:<\s*(\w+)[^>]*>)?\s*\(`)
	csInlineAuthRe   = regexp.MustCompile(`\bClaimsPrincipal\b|\bUser\s*\.\s*(?:Identity|Claims|FindFirst|IsInRole)\b|\bHttpContext\s*\.\s*User\b|\bUnauthorized\s*\(|\bResults\s*\.\s*(?:Unauthorized|Forbid)\b|\bTypedResults\s*\.\s*(?:Unauthorized|Forbid)\b|\bForbid\s*\(|\bStatusCodes\s*\.\s*Status40[13]|\bGetUserId\s*\(|\bGetCurrentUser\w*\s*\(`)
	csHandlerAttrRe  = regexp.MustCompile(`\[\s*(?:Microsoft\.AspNetCore\.Authorization\.)?(Authorize|AllowAnonymous)\w*`)
	csRouterType     = regexp.MustCompile(`\b(?:IEndpointRouteBuilder|RouteGroupBuilder|WebApplication)\b`)
	csMapVerbs       = map[string]string{"MapGet": "GET", "MapPost": "POST", "MapPut": "PUT", "MapDelete": "DELETE", "MapPatch": "PATCH", "MapMethods": "ALL"}
	csNonRouting     = setOf("ApiController", "Route", "Area", "Produces", "Consumes", "ProducesResponseType", "ProducesDefaultResponse", "ApiExplorerSettings", "NonAction", "NonController", "ApiVersion", "MapToApiVersion", "SwaggerOperation", "SwaggerResponse", "FromBody", "FromQuery", "FromRoute", "FromServices", "FromForm", "FromHeader", "ValidateAntiForgeryToken", "IgnoreAntiforgeryToken", "ResponseCache", "EnableCors", "DisableCors", "EnableRateLimiting", "DisableRateLimiting", "Obsolete", "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "HttpHead", "HttpOptions", "AcceptVerbs")
)

type csAttr struct {
	name    string
	args    span
	hasArgs bool
	start   int
}

type csMember struct {
	attrs              []csAttr
	declStart, declEnd int
	bodyStart, bodyEnd int // bodyStart is -1 without a block
	end                int
	declStartWithAttrs int
}

func (m csMember) decl(code string) string { return code[m.declStart:m.declEnd] }

// csScan walks the members of the region [from, to) at depth 0.
func csScan(code string, from, to int) []csMember {
	var out []csMember
	pos := from
	for pos < to {
		for pos < to && (isSpace(code[pos]) || code[pos] == ';') {
			pos++
		}
		if pos >= to {
			break
		}
		if code[pos] == '#' {
			for pos < to && code[pos] != '\n' {
				pos++
			}
			continue
		}
		m := csMember{bodyStart: -1, declStartWithAttrs: pos}
		for pos < to && code[pos] == '[' {
			c := matchClose(code, pos)
			if c < 0 || c >= to {
				return out
			}
			m.attrs = append(m.attrs, csAttrs(code, pos+1, c)...)
			pos = c + 1
			for pos < to && isSpace(code[pos]) {
				pos++
			}
		}
		m.declStart = pos
		depth := 0
		for i := pos; i < to; i++ {
			switch code[i] {
			case '(', '[':
				depth++
			case ')', ']':
				depth--
			case ';':
				if depth <= 0 {
					m.declEnd, m.end, pos = i, i+1, i+1
					out = append(out, m)
					goto next
				}
			case '{':
				if depth <= 0 {
					c := matchClose(code, i)
					if c < 0 || c >= to {
						return out
					}
					m.declEnd, m.bodyStart, m.bodyEnd, m.end, pos = i, i, c, c+1, c+1
					out = append(out, m)
					goto next
				}
			}
			if i == to-1 {
				return out
			}
		}
		return out
	next:
	}
	return out
}

// csAttrs reads the attributes of one list, `[A, B(x)]`, skipping targeted ones.
func csAttrs(code string, from, to int) []csAttr {
	var out []csAttr
	for _, a := range splitArgs(code, from, to) {
		text := code[a.start:a.end]
		j := 0
		for j < len(text) && (isIdentByte(text[j]) || text[j] == '.') {
			j++
		}
		if j == 0 {
			continue
		}
		rest := strings.TrimLeft(text[j:], " \t\n\r")
		if strings.HasPrefix(rest, ":") {
			continue // [return: ...], [assembly: ...]
		}
		name := text[:j]
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		name = strings.TrimSuffix(name, "Attribute")
		at := csAttr{name: name, start: a.start}
		if strings.HasPrefix(rest, "(") {
			open := a.start + j + (len(text[j:]) - len(rest))
			if c := matchClose(code, open); c > 0 && c < a.end+1 {
				at.args, at.hasArgs = span{open + 1, c}, true
			}
		}
		out = append(out, at)
	}
	return out
}

type csFile struct {
	path       string
	project    string
	raw        []byte
	code, sans string
	lineStarts []int
	aspnet     bool
	// authAttrs: attributes of the project that derive from [Authorize]; filled once the project is indexed.
	authAttrs map[string]bool
}

type csEvidence struct {
	authn, authz string
	public       bool
}

func (e csEvidence) any() bool { return e.authn != "" || e.authz != "" || e.public }

func (e *csEvidence) merge(o csEvidence) {
	e.authn, e.authz = firstNonEmpty(e.authn, o.authn), firstNonEmpty(e.authz, o.authz)
	e.public = e.public || o.public
}

type csClass struct {
	file     *csFile
	name     string
	base     string
	member   csMember
	body     span
	routes   []string
	routesOK bool
	hasRoute bool
	area     string
	apiCtl   bool
	attrs    []csAttr
}

type csRouter struct {
	parent *csRouter
	prefix string
	ev     csEvidence
	opaque bool
}

func (r *csRouter) fullPrefix() string {
	var parts []string
	for c := r; c != nil; c = c.parent {
		parts = append([]string{c.prefix}, parts...)
	}
	return goJoin(parts...)
}

func (r *csRouter) inherited() (ev csEvidence, opaque bool) {
	for c := r; c != nil; c = c.parent {
		ev.merge(c.ev)
		opaque = opaque || c.opaque
	}
	return ev, opaque
}

type csFunc struct {
	file    *csFile
	name    string
	params  []string
	types   []string
	member  csMember
	builder bool
	dup     bool
}

type csProject struct {
	dir      string
	files    []*csFile
	classes  map[string][]*csClass
	funcs    map[string]*csFunc
	all      []*csFunc
	guarded  bool // something project-wide decides authentication
	ctlGuard bool // MapControllers().RequireAuthorization()
	handled  map[*csFunc]bool
	memo     map[string]*csRouter
}

type csRec struct {
	rt          *csRouter
	method, rel string
	file        *csFile
	project     *csProject
	line        int
	ev          csEvidence
}

type csIndex struct {
	projects map[string]*csProject
	order    []string
	recs     []csRec
	out      []Route
	views    []routeView
}

func newCSFile(p, project string, raw []byte) *csFile {
	f := &csFile{path: p, project: project, raw: raw, code: string(lexctx.MaskNonCode(lexctx.LangCSharp, raw)), sans: withoutComments(lexctx.LangCSharp, raw), lineStarts: computeLineStarts(raw)}
	f.aspnet = strings.Contains(f.sans, "Microsoft.AspNetCore") || strings.Contains(f.code, "WebApplication") || strings.Contains(f.code, "[ApiController") || strings.Contains(f.code, "IEndpointRouteBuilder")
	return f
}

// csProjectDir is the nearest directory at or above file that holds a .csproj.
func csProjectDir(root, rel string, cache map[string]string) string {
	dir := dirOfPath(filepath.ToSlash(rel))
	var walked []string
	for {
		if v, ok := cache[dir]; ok {
			for _, w := range walked {
				cache[w] = v
			}
			return v
		}
		walked = append(walked, dir)
		if m, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(dir), "*.csproj")); len(m) > 0 {
			break
		}
		if dir == "" {
			break
		}
		dir = dirOfPath(dir)
	}
	for _, w := range walked {
		cache[w] = dir
	}
	return dir
}

func newCSIndex(files []*csFile) *csIndex {
	ix := &csIndex{projects: map[string]*csProject{}}
	for _, f := range files {
		p := ix.projects[f.project]
		if p == nil {
			p = &csProject{dir: f.project, classes: map[string][]*csClass{}, funcs: map[string]*csFunc{}, handled: map[*csFunc]bool{}, memo: map[string]*csRouter{}}
			ix.projects[f.project] = p
			ix.order = append(ix.order, f.project)
		}
		p.files = append(p.files, f)
	}
	sort.Strings(ix.order)
	for _, d := range ix.order {
		ix.projects[d].index()
	}
	return ix
}

// index reads the classes and methods of a project, and what it declares globally.
func (p *csProject) index() {
	for _, f := range p.files {
		if csGlobalAuthRe.MatchString(f.code) && !csNullFallbackRe.MatchString(f.code) {
			p.guarded = true
		}
		for _, m := range csUseMiddleware.FindAllStringSubmatch(f.code, -1) {
			name := m[1]
			if m[2] != "" && name == "UseMiddleware" {
				name = m[2]
			}
			if name != "UseAuthentication" && name != "UseAuthorization" && name != "UseMiddleware" && authnName(name) {
				p.guarded = true
			}
		}
		p.scanTypes(f, 0, len(f.code))
	}
	p.deriveAuthAttrs()
}

// deriveAuthAttrs finds the project's own attributes that extend [Authorize],
// directly or through another of them: [HasPermission] is an [Authorize].
func (p *csProject) deriveAuthAttrs() {
	known := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for name, cs := range p.classes {
			short := strings.TrimSuffix(name, "Attribute")
			base := strings.TrimSuffix(cs[0].base, "Attribute")
			if !known[short] && (base == "Authorize" || known[base]) {
				known[short], changed = true, true
			}
		}
	}
	for _, f := range p.files {
		f.authAttrs = known
	}
}

func (p *csProject) scanTypes(f *csFile, from, to int) {
	for _, m := range csScan(f.code, from, to) {
		decl := m.decl(f.code)
		tm := csTypeRe.FindStringSubmatchIndex(decl)
		if tm == nil {
			continue
		}
		kind, name := decl[tm[2]:tm[3]], decl[tm[4]:tm[5]]
		if kind == "namespace" {
			if m.bodyStart >= 0 {
				p.scanTypes(f, m.bodyStart+1, m.bodyEnd)
			}
			continue
		}
		if m.bodyStart < 0 || kind == "enum" || kind == "interface" {
			continue
		}
		c := p.readClass(f, m, name, decl[tm[1]:])
		p.classes[name] = append(p.classes[name], c)
		for _, mm := range csScan(f.code, m.bodyStart+1, m.bodyEnd) {
			if fn := p.readFunc(f, mm); fn != nil {
				p.all = append(p.all, fn)
				if _, dup := p.funcs[fn.name]; dup {
					p.funcs[fn.name].dup = true
					continue
				}
				p.funcs[fn.name] = fn
			}
		}
	}
}

func (p *csProject) readClass(f *csFile, m csMember, name, afterName string) *csClass {
	c := &csClass{file: f, name: name, member: m, body: span{m.bodyStart + 1, m.bodyEnd}, routesOK: true}
	if i := indexTop(afterName, ':'); i >= 0 {
		base := strings.TrimSpace(afterName[i+1:])
		if j := strings.Index(base, " where "); j >= 0 {
			base = base[:j]
		}
		first, _, _ := strings.Cut(base, ",")
		first = strings.TrimSpace(first)
		if j := strings.IndexByte(first, '<'); j >= 0 {
			first = first[:j]
		}
		if j := strings.LastIndexByte(first, '.'); j >= 0 {
			first = first[j+1:]
		}
		c.base = first
	}
	c.attrs = m.attrs
	for _, a := range m.attrs {
		switch a.name {
		case "ApiController":
			c.apiCtl = true
		case "Route":
			c.hasRoute = true
			if v, ok := csTemplate(f, a); ok {
				c.routes = append(c.routes, v)
			} else {
				c.routesOK = false
			}
		case "Area":
			if v, ok := csTemplate(f, a); ok {
				c.area = v
			}
		}
	}
	return c
}

func (p *csProject) readFunc(f *csFile, m csMember) *csFunc {
	decl := m.decl(f.code)
	if csTypeRe.MatchString(decl) || m.bodyStart < 0 && !strings.Contains(decl, "=>") {
		return nil
	}
	open := strings.IndexByte(decl, '(')
	if open <= 0 {
		return nil
	}
	nm := regexp.MustCompile(`([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*$`).FindStringSubmatch(decl[:open])
	if nm == nil {
		return nil
	}
	pend := matchClose(f.code, m.declStart+open)
	if pend < 0 {
		return nil
	}
	fn := &csFunc{file: f, name: nm[1], member: m}
	fn.params, fn.types = splitParams(f.code, span{m.declStart + open + 1, pend}, true)
	for _, t := range fn.types {
		fn.builder = fn.builder || csRouterType.MatchString(t)
	}
	fn.builder = fn.builder || csRouterType.MatchString(decl[:open])
	return fn
}

// csTemplate reads the template of a Route or Http* attribute: its first positional string.
func csTemplate(f *csFile, a csAttr) (string, bool) {
	if !a.hasArgs {
		return "", true
	}
	args := splitArgs(f.code, a.args.start, a.args.end)
	if len(args) == 0 {
		return "", true
	}
	first := f.code[args[0].start:args[0].end]
	if regexp.MustCompile(`^[A-Za-z_]\w*\s*=[^=]`).MatchString(first) {
		for _, x := range args {
			t := f.code[x.start:x.end]
			if strings.HasPrefix(t, "Template") {
				return strictLiteral(f.raw, f.code, trimSpan(f.code, span{x.start + strings.IndexByte(t, '=') + 1, x.end}))
			}
		}
		return "", true
	}
	return strictLiteral(f.raw, f.code, args[0])
}

// csAttrEvidence judges one attribute: [Authorize] and its lookalikes
// authenticate, [AllowAnonymous] makes the route public.
func csAttrEvidence(f *csFile, a csAttr) csEvidence {
	if f.authAttrs[a.name] {
		return csEvidence{authn: compact("[" + strings.TrimSpace(f.sans[a.start:attrEnd(f, a)]) + "]")}
	}
	var ev csEvidence
	text := compact("[" + strings.TrimSpace(f.sans[a.start:attrEnd(f, a)]) + "]")
	switch {
	case a.name == "AllowAnonymous" || nestPublicRe.MatchString(a.name):
		ev.public = true
	case csNonRouting[a.name] || csNegatedRe.MatchString(a.name):
	case a.name == "ServiceFilter" || a.name == "TypeFilter":
		if a.hasArgs {
			n, z := goMiddlewareClass(f.sans[a.args.start:a.args.end])
			if n {
				ev.authn = text
			}
			if z {
				ev.authz = text
			}
		}
	default:
		n, z := goMiddlewareClass(a.name)
		if n {
			ev.authn = text
		} else if z {
			ev.authz = text
		}
	}
	return ev
}

func attrEnd(f *csFile, a csAttr) int {
	if a.hasArgs {
		return a.args.end + 1
	}
	return a.start + len(a.name)
}

// ---- controllers ----

func (ix *csIndex) controllerRoutes() {
	for _, d := range ix.order {
		p := ix.projects[d]
		for _, name := range sortedClassNames(p) {
			for _, c := range p.classes[name] {
				ix.controller(p, c)
			}
		}
	}
}

func sortedClassNames(p *csProject) []string {
	names := make([]string, 0, len(p.classes))
	for n := range p.classes {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// csEffective is what a controller class declares once its base classes in
// the project are folded in.
type csEffective struct {
	ev       csEvidence
	routes   []string
	routesOK bool
	hasRoute bool
	apiCtl   bool
	external bool // a base class outside the scanned tree: its attributes are unseen
	area     string
}

// effective folds a class's attributes with its base classes' in the project.
func (p *csProject) effective(c *csClass, seen map[*csClass]bool) csEffective {
	e := csEffective{routes: c.routes, routesOK: c.routesOK, hasRoute: c.hasRoute, apiCtl: c.apiCtl, area: c.area}
	for _, a := range c.attrs {
		e.ev.merge(csAttrEvidence(c.file, a))
	}
	seen[c] = true
	switch bases := p.classes[c.base]; {
	case c.base == "" || c.base == "Controller" || c.base == "ControllerBase":
	case len(bases) != 1 || seen[bases[0]]:
		e.external = true
	default:
		b := p.effective(bases[0], seen)
		e.ev.merge(b.ev)
		if !e.hasRoute {
			e.routes, e.routesOK, e.hasRoute = b.routes, b.routesOK, b.hasRoute
		}
		e.apiCtl, e.external = e.apiCtl || b.apiCtl, b.external
		e.area = firstNonEmpty(e.area, b.area)
	}
	return e
}

func (ix *csIndex) controller(p *csProject, c *csClass) {
	if !c.file.aspnet {
		return
	}
	e := p.effective(c, map[*csClass]bool{})
	if !e.routesOK || (!e.apiCtl && c.base != "Controller" && c.base != "ControllerBase" && !strings.HasSuffix(c.name, "Controller")) {
		return
	}
	routes := e.routes
	if !e.hasRoute {
		routes = []string{""}
	}
	ctlName := strings.TrimSuffix(c.name, "Controller")
	for _, m := range csScan(c.file.code, c.body.start, c.body.end) {
		ix.action(p, c, m, e.ev, e.external, routes, ctlName, e.area)
	}
}

func (ix *csIndex) action(p *csProject, c *csClass, m csMember, class csEvidence, external bool, routes []string, ctl, area string) {
	f := c.file
	fn := p.readFunc(f, m)
	if fn == nil {
		return
	}
	var verbs []string
	var tmpl []string
	var hasOwn bool
	var ev csEvidence
	for _, a := range m.attrs {
		switch a.name {
		case "NonAction":
			return
		case "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "HttpHead", "HttpOptions":
			v, ok := csTemplate(f, a)
			if !ok {
				return
			}
			verbs = append(verbs, strings.ToUpper(strings.TrimPrefix(a.name, "Http")))
			tmpl = append(tmpl, v)
		case "Route":
			v, ok := csTemplate(f, a)
			if !ok {
				return
			}
			hasOwn = true
			tmpl = append(tmpl, v)
		}
		ev.merge(csAttrEvidence(f, a))
	}
	if len(verbs) == 0 && !hasOwn {
		return
	}
	if len(verbs) == 0 {
		verbs = []string{"ALL"}
	}
	if !ev.any() {
		ev = class
	} else {
		ev.merge(class)
	}
	body := f.sans[m.declStart:m.end]
	if ev.authn == "" && !ev.public && csInlineAuthRe.MatchString(body) {
		ev.authn = inlineAuthLabel
	}
	opaque := external && ev.authn == "" && ev.authz == "" && !ev.public
	guarded := (p.guarded || p.ctlGuard || opaque) && !ev.public
	line := lineAt(f.lineStarts, m.declStart)
	if len(m.attrs) > 0 {
		line = lineAt(f.lineStarts, m.attrs[0].start)
	}
	for i, verb := range verbs {
		t := tmpl[min(i, len(tmpl)-1)]
		var paths []string
		if strings.HasPrefix(t, "/") || strings.HasPrefix(t, "~/") {
			paths = []string{goJoin(strings.TrimPrefix(t, "~"))}
		} else {
			for _, r := range routes {
				paths = append(paths, goJoin(csTokens(r, ctl, fn.name, area), csTokens(t, ctl, fn.name, area)))
			}
		}
		for _, pth := range paths {
			if pth == "/" && len(routes) == 1 && routes[0] == "" && t == "" {
				continue // no route template at all
			}
			rt := Route{Method: verb, Path: pth, FilePath: f.path, Line: line, Authn: ev.authn, Authz: ev.authz, Reader: ReaderASPNET}
			ix.out = append(ix.out, rt)
			ix.views = append(ix.views, routeView{route: rt, guardUnseen: guarded, declaredPublic: ev.public, framework: "aspnet"})
		}
	}
}

var csTokenRe = regexp.MustCompile(`\[(controller|action|area)\]`)

func csTokens(t, ctl, action, area string) string {
	return csTokenRe.ReplaceAllStringFunc(t, func(s string) string {
		switch s {
		case "[controller]":
			return ctl
		case "[action]":
			return action
		}
		return area
	})
}
