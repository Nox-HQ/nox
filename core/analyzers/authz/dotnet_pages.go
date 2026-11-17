package authz

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ASP.NET Core Razor Pages and conventional MVC routing, read beside the
// attribute-routed controllers and minimal APIs of dotnet.go.
//
// RAZOR PAGES. A page is a `.cshtml` file under a `Pages` directory whose first
// directive is `@page`. Its route is the file's path under Pages (`Pages/Admin/
// Users.cshtml` is /Admin/Users; an `Index` is its directory; an `Areas/X/
// Pages` page is under /X), a rooted `@page "/admin/users/{id?}"` replaces that
// path and a relative template is appended to it. Its handlers are the public
// methods of its PageModel (`@model`, found in the project) named `OnGet`,
// `OnPost`, `OnPut`, `OnDelete`, `OnPatch`, with an optional named handler and
// `Async` (`OnPostDeleteAsync`); a page answers GET with no `OnGet` too.
//
// A page is authenticated by [Authorize] on its model, a base model of the
// project or the handler, by `@attribute [Authorize]` in the page, or by an
// Authorize convention registered for the project (`options.Conventions.
// AuthorizeFolder("/Admin")`, `AuthorizePage`, `AuthorizeAreaFolder`,
// `AuthorizeAreaPage`); [AllowAnonymous] and AllowAnonymousTo* conventions
// make it public on purpose. A folder convention covers the folder and what is
// under it, never a folder that merely shares a prefix. A project-wide
// requirement (a fallback policy, `MapRazorPages().RequireAuthorization()`),
// a base model outside the scanned tree and a model the project does not
// declare are unseen, as in the controllers.
//
// Not read: pages outside a `Pages` root, handlers written in an `@functions`
// or `@code` block, Blazor components (`.razor`), conventions registered
// through a variable, and the ordering of `PageRouteModelConvention`s.
//
// CONVENTIONAL MVC. `MapControllerRoute(name:, pattern: "{controller=Home}/
// {action=Index}/{id?}")`, `MapDefaultControllerRoute()`, `MapAreaControllerRoute`
// and the older `UseMvc(r => r.MapRoute(name, template))` give every public
// action of a controller that has no attribute route a path: the pattern with
// {controller} and {action} replaced (an area pattern only for controllers with
// that [Area]). An action is attribute-routed, so not conventional, when its
// controller has [Route], it has [Route], or an Http* attribute carries a
// template; a bare [HttpPost] only narrows the verb. [NonAction], static,
// non-public and overriding methods, ApiControllers and classes that are not
// public are not actions. The path keeps the action name (`/Users/Index/{id?}`)
// even where the pattern would let it default away.

const (
	ReaderRazorPages = "ASP.NET Razor Pages"
	ReaderAspNetMVC  = "ASP.NET Core MVC"
)

type razorPage struct {
	path, project string
	text          string // the page without Razor comments
}

var (
	razorCommentRe = regexp.MustCompile(`(?s)@\*.*?\*@`)
	razorPageRe    = regexp.MustCompile(`(?m)^[ \t]*@page\b[ \t]*(?:"([^"\n]*)")?`)
	razorModelRe   = regexp.MustCompile(`(?m)^[ \t]*@model[ \t]+([\w.]+)`)
	razorAttrRe    = regexp.MustCompile(`(?m)^[ \t]*@attribute[ \t]+\[(.*)\][ \t]*$`)
	razorHandlerRe = regexp.MustCompile(`^On(Get|Post|Put|Delete|Patch|Head|Options)([A-Z][A-Za-z0-9_]*?)?(Async)?$`)
	razorConvRe    = regexp.MustCompile(`\.\s*(AuthorizeFolder|AuthorizePage|AuthorizeAreaFolder|AuthorizeAreaPage|AllowAnonymousToFolder|AllowAnonymousToPage|AllowAnonymousToAreaFolder|AllowAnonymousToAreaPage)\s*\(\s*"([^"]*)"(?:\s*,\s*"([^"]*)")?`)
	razorRequireRe = regexp.MustCompile(`\bMapRazorPages\s*\(\s*\)\s*\.\s*RequireAuthorization\b`)
	mvcMapRe       = regexp.MustCompile(`\b(MapControllerRoute|MapAreaControllerRoute|MapRoute|MapAreaRoute)\s*\(`)
	mvcDefaultRe   = regexp.MustCompile(`\b(?:MapDefaultControllerRoute|UseMvcWithDefaultRoute)\s*\(\s*\)`)
	mvcNamedArgRe  = regexp.MustCompile(`^([A-Za-z_]\w*)\s*:\s*`)
	mvcTokenRe     = regexp.MustCompile(`\{(controller|action|area)(?:[=:?][^}]*)?\}`)
)

const mvcDefaultPattern = "{controller=Home}/{action=Index}/{id?}"

// razorConv is one Authorize or AllowAnonymous convention of a project.
type razorConv struct {
	anon, folder bool
	area, path   string
	text         string
}

// mvcPattern is one conventional route of a project.
type mvcPattern struct {
	pattern string
	area    string // set by MapAreaControllerRoute: only controllers of that area
}

func newRazorPage(p, project string, raw []byte) *razorPage {
	text := razorCommentRe.ReplaceAllStringFunc(string(raw), func(s string) string {
		return strings.Map(func(r rune) rune {
			if r == '\n' {
				return r
			}
			return ' '
		}, s)
	})
	if !razorPageRe.MatchString(text) {
		return nil
	}
	return &razorPage{path: p, project: project, text: text}
}

// scanPagesAndConventions reads what a file declares for Razor Pages and MVC.
func (p *csProject) scanPagesAndConventions(f *csFile) {
	if razorRequireRe.MatchString(f.code) {
		p.ctlGuard = true
	}
	for _, m := range razorConvRe.FindAllStringSubmatch(f.sans, -1) {
		c := razorConv{text: compact(m[0][1:]), anon: strings.HasPrefix(m[1], "AllowAnonymous"), folder: strings.HasSuffix(m[1], "Folder")}
		if strings.Contains(m[1], "Area") {
			c.area, c.path = m[2], m[3]
		} else {
			c.path = m[2]
		}
		p.convs = append(p.convs, c)
	}
	if mvcDefaultRe.MatchString(f.code) {
		p.patterns = append(p.patterns, mvcPattern{pattern: mvcDefaultPattern})
	}
	for _, loc := range mvcMapRe.FindAllStringSubmatchIndex(f.code, -1) {
		open := loc[1] - 1
		end := matchClose(f.code, open)
		if end < 0 {
			continue
		}
		args := splitArgs(f.code, open+1, end)
		var pat mvcPattern
		var ok bool
		switch f.code[loc[2]:loc[3]] {
		case "MapControllerRoute":
			pat.pattern, ok = mvcArg(f, args, "pattern", 1)
		case "MapRoute":
			pat.pattern, ok = mvcArg(f, args, "template", 1)
		case "MapAreaControllerRoute":
			var a string
			if a, ok = mvcArg(f, args, "areaName", 1); ok {
				pat.area = a
				pat.pattern, ok = mvcArg(f, args, "pattern", 2)
			}
		case "MapAreaRoute":
			var a string
			if a, ok = mvcArg(f, args, "area", 1); ok {
				pat.area = a
				pat.pattern, ok = mvcArg(f, args, "template", 2)
			}
		}
		if ok && pat.pattern != "" {
			p.patterns = append(p.patterns, pat)
		}
	}
}

// mvcArg reads a string-literal argument by name, or by position when no argument is named for it.
func mvcArg(f *csFile, args []span, name string, pos int) (string, bool) {
	for _, a := range args {
		text := f.code[a.start:a.end]
		if m := mvcNamedArgRe.FindStringSubmatch(text); m != nil && m[1] == name {
			return strictLiteral(f.raw, f.code, trimSpan(f.code, span{a.start + len(m[0]), a.end}))
		}
	}
	if pos < len(args) && mvcNamedArgRe.FindString(f.code[args[pos].start:args[pos].end]) == "" {
		return strictLiteral(f.raw, f.code, args[pos])
	}
	return "", false
}

// ---- Razor Pages ----

func (ix *csIndex) razorRoutes() {
	for _, pg := range ix.pages {
		ix.razorPage(pg)
	}
}

// razorLocation reads where a page is served from: its path under the Pages
// root, the same path relative to its area, and the area.
func razorLocation(p string) (view, area string, ok bool) {
	segs := strings.Split(strings.TrimSuffix(filepath.ToSlash(p), ".cshtml"), "/")
	for i, s := range segs {
		if !strings.EqualFold(s, "Pages") {
			continue
		}
		if i >= 2 && strings.EqualFold(segs[i-2], "Areas") {
			area = segs[i-1]
		}
		return "/" + strings.Join(segs[i+1:], "/"), area, i+1 < len(segs)
	}
	return "", "", false
}

func (ix *csIndex) razorPage(pg *razorPage) {
	view, area, ok := razorLocation(pg.path)
	if !ok {
		return
	}
	p := ix.projects[pg.project]
	if p == nil {
		p = &csProject{dir: pg.project, classes: map[string][]*csClass{}}
	}
	base := strings.TrimSuffix(strings.TrimSuffix(view, "Index"), "/")
	if area != "" {
		base = goJoin(area, base)
	}
	loc := razorPageRe.FindStringSubmatchIndex(pg.text)
	route := base
	if loc[2] >= 0 {
		if tmpl := pg.text[loc[2]:loc[3]]; strings.HasPrefix(tmpl, "/") {
			route = tmpl
		} else {
			route = goJoin(base, tmpl)
		}
	}
	route = goJoin(route)
	line := 1 + strings.Count(pg.text[:loc[0]], "\n")

	var page csEvidence
	external, opaque := false, false
	var cls *csClass
	if m := razorModelRe.FindStringSubmatch(pg.text); m != nil {
		name := m[1][strings.LastIndexByte(m[1], '.')+1:]
		if cs := p.classes[name]; len(cs) == 1 {
			cls = cs[0]
		} else {
			opaque = true
		}
	}
	for _, m := range razorAttrRe.FindAllStringSubmatch(pg.text, -1) {
		tmp := newCSFile(pg.path, pg.project, []byte("["+m[1]+"]"))
		if len(p.files) > 0 {
			tmp.authAttrs = p.files[0].authAttrs
		}
		for _, a := range csAttrs(tmp.code, 1, len(tmp.code)-1) {
			page.merge(csAttrEvidence(tmp, a))
		}
	}
	page.merge(p.razorConventions(view, area))
	if cls != nil {
		e := p.effective(cls, map[*csClass]bool{})
		page.merge(e.ev)
		external = e.external
	}
	guardedFor := func(ev csEvidence) bool {
		return (p.guarded || p.ctlGuard || opaque || external) && !ev.public
	}
	emit := func(file string, line int, verb string, ev csEvidence) {
		rt := Route{Method: verb, Path: route, FilePath: file, Line: line, Authn: ev.authn, Authz: ev.authz, Reader: ReaderRazorPages}
		ix.addExtra(rt, routeView{route: rt, guardUnseen: guardedFor(ev) && ev.authn == "" && ev.authz == "", declaredPublic: ev.public, framework: "aspnet"})
	}
	haveGet := false
	if cls != nil {
		f := cls.file
		for _, mm := range csScan(f.code, cls.body.start, cls.body.end) {
			fn := p.readFunc(f, mm)
			if fn == nil || !csPublicInstance(mm.decl(f.code)) {
				continue
			}
			hm := razorHandlerRe.FindStringSubmatch(fn.name)
			if hm == nil || csHasAttr(mm, "NonHandler") {
				continue
			}
			ev := csEvidence{}
			for _, a := range mm.attrs {
				ev.merge(csAttrEvidence(f, a))
			}
			ev.merge(page)
			if ev.authn == "" && !ev.public && csInlineAuthRe.MatchString(f.sans[mm.declStart:mm.end]) {
				ev.authn = inlineAuthLabel
			}
			verb := strings.ToUpper(hm[1])
			haveGet = haveGet || verb == "GET"
			ln := lineAt(f.lineStarts, mm.declStart)
			if len(mm.attrs) > 0 {
				ln = lineAt(f.lineStarts, mm.attrs[0].start)
			}
			emit(f.path, ln, verb, ev)
		}
	}
	if !haveGet {
		emit(pg.path, line, "GET", page)
	}
}

// razorConventions folds the project's conventions that cover a page.
func (p *csProject) razorConventions(view, area string) csEvidence {
	var ev csEvidence
	for _, c := range p.convs {
		if c.area != area {
			continue
		}
		covers := strings.EqualFold(c.path, view) || strings.EqualFold(c.path, strings.TrimSuffix(view, "/Index"))
		if c.folder {
			f := strings.TrimSuffix(c.path, "/")
			covers = f == "" || strings.EqualFold(view, f) || len(view) > len(f) && strings.EqualFold(view[:len(f)], f) && view[len(f)] == '/'
		}
		switch {
		case !covers:
		case c.anon:
			ev.public = true
		default:
			ev.authn = firstNonEmpty(ev.authn, c.text)
		}
	}
	return ev
}

func csHasAttr(m csMember, name string) bool {
	for _, a := range m.attrs {
		if a.name == name {
			return true
		}
	}
	return false
}

// csPublicInstance reports whether a member declaration is public, not static and not an override.
func csPublicInstance(decl string) bool {
	if i := strings.IndexByte(decl, '('); i >= 0 {
		decl = decl[:i]
	}
	public := false
	for _, w := range strings.Fields(decl) {
		switch w {
		case "public":
			public = true
		case "static", "override", "abstract":
			return false
		}
	}
	return public
}

// addExtra files a route the Razor Pages and MVC readers produced.
func (ix *csIndex) addExtra(rt Route, v routeView) {
	key := rt.FilePath + ":" + strconv.Itoa(rt.Line) + " " + rt.Method + " " + rt.Path
	if ix.extraSeen[key] {
		return
	}
	if ix.extraSeen == nil {
		ix.extraSeen = map[string]bool{}
	}
	ix.extraSeen[key] = true
	ix.out = append(ix.out, rt)
	ix.views = append(ix.views, v)
}

// ---- conventional MVC ----

// conventional gives the actions of a controller without attribute routes the
// paths the project's conventional routes assign.
func (ix *csIndex) conventional(p *csProject, c *csClass, e csEffective) {
	f := c.file
	decl := c.member.decl(f.code)
	if len(p.patterns) == 0 || e.hasRoute || e.apiCtl || !e.routesOK || !f.aspnet ||
		!strings.Contains(" "+decl, " public ") || strings.Contains(" "+decl, " abstract ") {
		return
	}
	ctl := strings.TrimSuffix(c.name, "Controller")
	for _, m := range csScan(f.code, c.body.start, c.body.end) {
		fn := p.readFunc(f, m)
		if fn == nil || fn.name == c.name || fn.name == "Dispose" || !csPublicInstance(m.decl(f.code)) {
			continue
		}
		verbs, action, ok := conventionalAction(f, m, fn.name)
		if !ok {
			continue
		}
		ev := csEvidence{}
		for _, a := range m.attrs {
			ev.merge(csAttrEvidence(f, a))
		}
		if !ev.any() {
			ev = e.ev
		} else {
			ev.merge(e.ev)
		}
		if ev.authn == "" && !ev.public && csInlineAuthRe.MatchString(f.sans[m.declStart:m.end]) {
			ev.authn = inlineAuthLabel
		}
		opaque := e.external && ev.authn == "" && ev.authz == "" && !ev.public
		guarded := (p.guarded || p.ctlGuard || opaque) && !ev.public
		line := lineAt(f.lineStarts, m.declStart)
		if len(m.attrs) > 0 {
			line = lineAt(f.lineStarts, m.attrs[0].start)
		}
		for _, pat := range p.patterns {
			path, ok := mvcExpand(pat, ctl, action, e.area)
			if !ok {
				continue
			}
			for _, verb := range verbs {
				rt := Route{Method: verb, Path: path, FilePath: f.path, Line: line, Authn: ev.authn, Authz: ev.authz, Reader: ReaderAspNetMVC}
				ix.addExtra(rt, routeView{route: rt, guardUnseen: guarded, declaredPublic: ev.public, framework: "aspnet"})
			}
		}
	}
}

// conventionalAction reads an action's attributes: the verbs it is narrowed to
// and its name. ok is false for an action that is not conventionally routed.
func conventionalAction(f *csFile, m csMember, name string) (verbs []string, action string, ok bool) {
	action = name
	for _, a := range m.attrs {
		switch a.name {
		case "NonAction", "Route":
			return nil, "", false
		case "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "HttpHead", "HttpOptions":
			if a.hasArgs && len(splitArgs(f.code, a.args.start, a.args.end)) > 0 {
				return nil, "", false // a template makes it attribute-routed
			}
			verbs = append(verbs, strings.ToUpper(strings.TrimPrefix(a.name, "Http")))
		case "AcceptVerbs":
			for _, x := range splitArgs(f.code, a.args.start, a.args.end) {
				if v, lit := stringLiteral(f.raw, f.code, x); lit {
					verbs = append(verbs, strings.ToUpper(v))
				}
			}
		case "ActionName":
			if v, lit := csTemplate(f, a); lit && v != "" {
				action = v
			}
		}
	}
	if len(verbs) == 0 {
		verbs = []string{"ALL"}
	}
	return verbs, action, true
}

// mvcExpand applies a conventional pattern to a controller and action.
func mvcExpand(pat mvcPattern, ctl, action, area string) (string, bool) {
	hasArea := strings.Contains(pat.pattern, "{area")
	switch {
	case pat.area != "" && pat.area != area:
		return "", false
	case pat.area == "" && hasArea != (area != ""):
		return "", false
	}
	out := mvcTokenRe.ReplaceAllStringFunc(pat.pattern, func(tok string) string {
		switch {
		case strings.HasPrefix(tok, "{controller"):
			return ctl
		case strings.HasPrefix(tok, "{action"):
			return action
		}
		return area
	})
	return goJoin(out), true
}
