package authz

import (
	"regexp"
	"sort"
	"strings"
)

// Django (urls.py + views, with Django REST framework).
//
// A Django route is a `path()` / `re_path()` entry in a urls.py, `include()`d
// under a prefix by its parent urls.py, pointing at a function view or a
// class's `as_view()`, or a DRF router registration of a viewset. This reader
// resolves that structure (which urls file is mounted under what prefix, which
// view a pattern names, what the view and its base classes declare) and turns
// it into the same Route and routeView the other frameworks produce.
//
// Access control it reads, by name and by declaration:
//
//   - function views: @login_required, @permission_required, @user_passes_test,
//     @staff_member_required, DRF's @permission_classes([...]); @login_not_required
//     and @permission_classes([AllowAny]) declare a view public;
//   - class views: LoginRequiredMixin, PermissionRequiredMixin,
//     UserPassesTestMixin and their kin, in the class or a base class defined in
//     the repository; `permission_classes = [...]`; @method_decorator(login_required,
//     name='dispatch');
//   - DRF @action methods are routes of their own (see django_action.go);
//   - project-wide: REST_FRAMEWORK DEFAULT_PERMISSION_CLASSES (any class but
//     AllowAny), Django 5.1's LoginRequiredMiddleware, and an inline read of the
//     caller (request.user.is_authenticated, a 401/403) in the handler.
//
// A custom authentication middleware this reader cannot evaluate makes every
// Django route's empty Authn proof of nothing (guardUnseen), and a view it
// cannot find in the repository is unread (known=false) and never a lead.
//
// Not read: viewsets whose methods are mapped by a dict in
// as_view({...}) beyond the mapping keys, django-rest-framework-simplejwt or
// guardian object permissions beyond the names above, URLconfs built in a loop,
// and AUTHZ-001's body analysis over these handlers.

var (
	djPathCallRe  = regexp.MustCompile(`(?:^|[^\w.])(path|re_path|url)\s*\(`)
	djRegisterRe  = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*\.\s*register\s*\(`)
	djClassRe     = regexp.MustCompile(`(?m)^class[ \t]+([A-Za-z_]\w*)[ \t]*(?:\(([^)]*)\))?[ \t]*:`)
	djConverterRe = regexp.MustCompile(`<(?:[A-Za-z_]\w*:)?([A-Za-z_]\w*)>`)
	djNamedGroup  = regexp.MustCompile(`\(\?P<([A-Za-z_]\w*)>[^)]*\)`)

	djAuthDecoRe  = regexp.MustCompile(`(?i)\b(login_required|staff_member_required|superuser_required|jwt_required|token_required|authentication_required|user_is_authenticated)\b`)
	djAuthzDecoRe = regexp.MustCompile(`(?i)\b(permission_required|user_passes_test|staff_member_required|superuser_required|group_required|role_required)\b`)
	djPublicDeco  = regexp.MustCompile(`\blogin_not_required\b`)
	djMixinRe     = regexp.MustCompile(`\b(?:LoginRequired|PermissionRequired|UserPassesTest|Access|Staffuser?Required|StaffRequired|SuperuserRequired|GroupRequired|[A-Za-z]*Auth(?:enticated|entication|orized)?(?:Required)?)Mixin\b`)
	djAuthzMixin  = regexp.MustCompile(`Permission|UserPassesTest|Staff|Superuser|Group`)

	djPermClassesRe = regexp.MustCompile(`\bpermission_classes\s*=\s*[\[(]([^\])]*)[\])]`)
	djPermDecoRe    = regexp.MustCompile(`@permission_classes\s*\(\s*[\[(]([^\])]*)[\])]`)
	djAuthClsEmpty  = regexp.MustCompile(`\bauthentication_classes\s*=\s*[\[(]\s*[\])]|@authentication_classes\s*\(\s*[\[(]\s*[\])]\s*\)`)
	djAPIViewRe     = regexp.MustCompile(`@api_view\s*\(\s*[\[(]([^\])]*)[\])]`)
	djRequireRe     = regexp.MustCompile(`@require_(POST|GET|safe)\b|@require_http_methods\s*\(\s*[\[(]([^\])]*)[\])]`)
	djMethodDefRe   = regexp.MustCompile(`(?m)^[ \t]+(?:async[ \t]+)?def[ \t]+(get|post|put|patch|delete)[ \t]*\(`)
	djReqMethodRe   = regexp.MustCompile(`request\s*\.\s*method\s*(?:==|in)\s*[\[(]?\s*['"](GET|POST|PUT|PATCH|DELETE)['"]`)
	djAsViewMapRe   = regexp.MustCompile(`as_view\s*\(\s*\{([^}]*)\}`)
	djDefaultPermRe = regexp.MustCompile(`DEFAULT_PERMISSION_CLASSES['"]\s*:\s*[\[(]([^\])]*)[\])]`)
	djMiddlewareRe  = regexp.MustCompile(`(?s)\bMIDDLEWARE\s*=\s*[\[(](.*?)[\])]`)
	djGuardMWRe     = regexp.MustCompile(`(?i)auth|login|jwt|token|sso|oidc|keycloak|saml|firebase|cognito`)
	djQuoted        = regexp.MustCompile(`['"]([^'"]+)['"]`)
	djDecoNameRe    = regexp.MustCompile(`(?m)^\s*@\s*([A-Za-z_][\w.]*)`)
	// djNotAccessRe: decorators that are not access control, whatever their name
	// suggests (a CORS or caching decorator mentioning a token header).
	djNotAccessRe = regexp.MustCompile(`(?i)csrf|cors|require_|cache|vary_on|api_view|permission_classes|authentication_classes|renderer|parser|throttle|ratelimit|rate_limit|action|schema|swagger|method_decorator|never_|gzip|condition|xframe|sensitive|transaction|wraps|login_not_required`)
)

// djGenericMethods are the HTTP methods Django's and DRF's generic views
// serve, by base class name.
var djGenericMethods = map[string][]string{
	"TemplateView": {"GET"}, "RedirectView": {"GET"}, "ListView": {"GET"}, "DetailView": {"GET"},
	"CreateView": {"GET", "POST"}, "UpdateView": {"GET", "POST"}, "FormView": {"GET", "POST"}, "DeleteView": {"GET", "POST", "DELETE"},
	"ListAPIView": {"GET"}, "RetrieveAPIView": {"GET"}, "CreateAPIView": {"POST"}, "UpdateAPIView": {"PUT", "PATCH"}, "DestroyAPIView": {"DELETE"},
	"ListCreateAPIView": {"GET", "POST"}, "RetrieveUpdateAPIView": {"GET", "PUT", "PATCH"}, "RetrieveDestroyAPIView": {"GET", "DELETE"},
	"RetrieveUpdateDestroyAPIView": {"GET", "PUT", "PATCH", "DELETE"},
}

// djView is one resolved view: a function or a class.
type djView struct {
	file      *pyFile
	name      string
	class     bool
	off       int
	bodyStart int
	bodyEnd   int
	bases     string
	decos     string
}

// text is the view's source, comment-free, with the arguments of its @action
// decorators blanked: `@action(..., permission_classes=[AllowAny])` is that
// one action's setting, and read as the class's own it would declare the whole
// viewset public (or, with IsAuthenticated, covered).
func (v djView) text() string { return blankActionArgs(v.file.sans[v.off:v.bodyEnd]) }

// djEntry is one urlpatterns entry or router registration.
type djEntry struct {
	file    *pyFile
	off     int
	route   string
	view    string // the view expression, "" for an include
	include string // resolved urls file for include('x.urls')
	router  string // router variable for include(router.urls)
	// viewset and prefix are set for a router registration.
	viewset string
}

type djIndex struct {
	ix       *pyIndex
	entries  map[string][]djEntry // by urls file
	routers  map[string][]djEntry // by file + "|" + router var
	classes  map[string][]djView  // by name, repository-wide
	funcs    map[string][]djView
	drfAuth  string // label of DEFAULT_PERMISSION_CLASSES that requires something
	mwAuth   bool   // Django LoginRequiredMiddleware
	guard    bool   // a custom auth middleware this reader cannot evaluate
	urlFiles []string
}

// djangoRoutes reads every Django urls.py among the Python files.
func (ix *pyIndex) djangoRoutes() ([]Route, []routeView) {
	d := &djIndex{ix: ix, entries: map[string][]djEntry{}, routers: map[string][]djEntry{},
		classes: map[string][]djView{}, funcs: map[string][]djView{}}
	included := map[string]bool{}
	for _, p := range ix.order {
		f := ix.files[p]
		if strings.Contains(f.code, "urlpatterns") && (strings.Contains(f.code, "path") || strings.Contains(f.code, "url")) {
			d.parseURLs(f)
		}
		d.indexDefs(f)
		d.readSettings(f)
	}
	if len(d.urlFiles) == 0 {
		return nil, nil
	}
	for _, p := range d.urlFiles {
		for _, e := range d.entries[p] {
			if e.include != "" {
				included[e.include] = true
			}
		}
	}
	var out []Route
	var views []routeView
	seen := map[string]bool{}
	for _, p := range d.urlFiles {
		if included[p] {
			continue
		}
		d.walk(p, "", map[string]bool{}, seen, &out, &views)
	}
	// A urls file that is only reachable through a cycle or an include this
	// reader could not resolve still describes routes; read it at its own root.
	for _, p := range d.urlFiles {
		if included[p] && !d.reached(p, seen) {
			d.walk(p, "", map[string]bool{}, seen, &out, &views)
		}
	}
	sortRoutes(out)
	return out, views
}

func (d *djIndex) reached(file string, seen map[string]bool) bool {
	for k := range seen {
		if strings.HasPrefix(k, file+"|") {
			return true
		}
	}
	return false
}

// ---- parsing ----

func (d *djIndex) parseURLs(f *pyFile) {
	d.urlFiles = append(d.urlFiles, f.path)
	for _, m := range djPathCallRe.FindAllStringSubmatchIndex(f.code, -1) {
		open := m[1] - 1
		closeAt := matchClose(f.code, open)
		if closeAt < 0 {
			continue
		}
		kind := f.code[m[2]:m[3]]
		args := splitArgs(f.code, open+1, closeAt)
		if len(args) < 2 {
			continue
		}
		route, ok := pyStringLit(f, args[0])
		if !ok {
			continue
		}
		e := djEntry{file: f, off: m[2], route: djRoute(kind, route)}
		view := strings.TrimSpace(f.code[args[1].start:args[1].end])
		if strings.HasPrefix(view, "include") {
			if iOpen := strings.IndexByte(view, '('); iOpen >= 0 {
				inner := view[iOpen+1:]
				inner = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(inner), ")"))
				innerRaw := strings.TrimSpace(string(f.raw[args[1].start+iOpen+1 : args[1].end]))
				innerRaw = strings.TrimSpace(strings.TrimSuffix(innerRaw, ")"))
				switch {
				case strings.HasSuffix(inner, ".urls") && !strings.ContainsAny(inner, "\"' ,"):
					e.router = strings.TrimSuffix(inner, ".urls")
				default:
					if mod, ok := firstStringLit(innerRaw); ok {
						e.include = d.ix.resolveModule(f.path, 0, mod)
					}
				}
			}
			if e.include == "" && e.router == "" {
				continue
			}
		} else {
			e.view = view
		}
		d.entries[f.path] = append(d.entries[f.path], e)
	}
	for _, m := range djRegisterRe.FindAllStringSubmatchIndex(f.code, -1) {
		open := m[1] - 1
		closeAt := matchClose(f.code, open)
		if closeAt < 0 {
			continue
		}
		args := splitArgs(f.code, open+1, closeAt)
		if len(args) < 2 {
			continue
		}
		prefix, ok := pyStringLit(f, args[0])
		if !ok {
			continue
		}
		router := f.code[m[2]:m[3]]
		e := djEntry{file: f, off: m[2], route: strings.Trim(prefix, "^$/"), viewset: strings.TrimSpace(f.code[args[1].start:args[1].end])}
		d.routers[f.path+"|"+router] = append(d.routers[f.path+"|"+router], e)
	}
}

func firstStringLit(raw string) (string, bool) {
	m := djQuoted.FindStringSubmatch(raw)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// djRoute turns a Django route string into the path style the table uses.
func djRoute(kind, route string) string {
	if kind == "path" {
		return djConverterRe.ReplaceAllString(route, ":$1")
	}
	route = strings.TrimPrefix(route, "^")
	route = strings.TrimSuffix(route, "$")
	route = djNamedGroup.ReplaceAllString(route, ":$1")
	route = strings.NewReplacer(`\.`, ".", `\/`, "/", "?", "").Replace(route)
	return route
}

func (d *djIndex) indexDefs(f *pyFile) {
	if strings.Contains(f.code, "urlpatterns") && !strings.Contains(f.code, "def ") && !strings.Contains(f.code, "class ") {
		return
	}
	for _, m := range pyDefRe.FindAllStringSubmatchIndex(f.code, -1) {
		if m[3]-m[2] != 0 {
			continue // methods and nested functions are not views
		}
		fn, ok := parsePyFunc(f, m)
		if !ok {
			continue
		}
		d.funcs[fn.name] = append(d.funcs[fn.name], djView{file: f, name: fn.name, off: fn.defOff, bodyStart: fn.bodyStart, bodyEnd: fn.bodyEnd, decos: decoratorsAbove(f, fn.defOff)})
	}
	for _, m := range djClassRe.FindAllStringSubmatchIndex(f.code, -1) {
		name := f.code[m[2]:m[3]]
		bases := ""
		if m[4] >= 0 {
			bases = f.code[m[4]:m[5]]
		}
		colon := m[1] - 1
		d.classes[name] = append(d.classes[name], djView{file: f, name: name, class: true, off: m[0], bodyStart: m[1], bodyEnd: bodyEnd(f.code, colon, 0), bases: bases, decos: decoratorsAbove(f, m[0])})
	}
}

// decoratorsAbove returns the comment-free text of the decorators directly
// above the definition at off, found the way parseFunctions finds a route's:
// each decorator is a logical line, and the chain is those that touch the
// definition with only whitespace between.
func decoratorsAbove(f *pyFile, off int) string {
	type deco struct{ start, end int }
	var decos []deco
	for _, m := range pyDecoRe.FindAllStringIndex(f.code, -1) {
		if m[0] >= off {
			break
		}
		decos = append(decos, deco{m[0], logicalEnd(f.code, m[1])})
	}
	var parts []string
	cursor := off
	for {
		found := false
		for _, dc := range decos {
			if dc.end <= cursor && strings.TrimSpace(f.code[dc.end:cursor]) == "" {
				parts = append(parts, f.sans[dc.start:dc.end])
				cursor = dc.start
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return strings.Join(parts, "\n")
}

func (d *djIndex) readSettings(f *pyFile) {
	raw := f.sans
	if strings.Contains(raw, "DEFAULT_PERMISSION_CLASSES") {
		if m := djDefaultPermRe.FindStringSubmatch(raw); m != nil {
			names := quotedNames(m[1])
			for _, n := range names {
				if lastDotted(n) != "AllowAny" {
					d.drfAuth = "REST_FRAMEWORK DEFAULT_PERMISSION_CLASSES " + lastDotted(n)
					break
				}
			}
		}
	}
	if strings.Contains(raw, "LoginRequiredMiddleware") {
		d.mwAuth = true
	}
	if m := djMiddlewareRe.FindStringSubmatch(raw); m != nil {
		for _, name := range quotedNames(m[1]) {
			last := lastDotted(name)
			if last == "AuthenticationMiddleware" || last == "LoginRequiredMiddleware" || !djGuardMWRe.MatchString(last) {
				continue
			}
			d.guard = true
		}
	}
}

func quotedNames(s string) []string {
	var out []string
	for _, m := range djQuoted.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// ---- walking ----

// djJoin joins a mount prefix and a route and writes the result the way the
// other readers do: a leading slash, no trailing one (Django's trailing slash
// is the framework's convention, not a different route).
func djJoin(prefix, route string) string {
	p := joinRoutePath(prefix, route)
	p = "/" + strings.Trim(p, "/")
	return p
}

func (d *djIndex) walk(file, prefix string, onPath, seen map[string]bool, out *[]Route, views *[]routeView) {
	key := file + "|" + prefix
	if onPath[key] || seen[key] {
		return
	}
	onPath[key], seen[key] = true, true
	defer delete(onPath, key)
	for _, e := range d.entries[file] {
		full := djJoin(prefix, e.route)
		switch {
		case e.include != "":
			d.walk(e.include, full, onPath, seen, out, views)
		case e.router != "":
			for _, reg := range d.routers[file+"|"+e.router] {
				d.emitViewset(reg, full, e, out, views)
			}
		default:
			d.emitView(e, full, out, views)
		}
	}
}

// lookup resolves a view expression written in file f to a view.
func (d *djIndex) lookup(f *pyFile, expr string) (djView, bool) {
	expr = strings.TrimSpace(expr)
	if i := strings.Index(expr, ".as_view"); i >= 0 {
		expr = expr[:i]
	}
	if i := strings.IndexByte(expr, '('); i >= 0 {
		expr = expr[:i]
	}
	recv, name := "", expr
	if i := strings.LastIndexByte(expr, '.'); i >= 0 {
		recv, name = expr[:i], expr[i+1:]
	}
	var target string
	switch {
	case recv != "":
		target = f.modules[strings.SplitN(recv, ".", 2)[0]]
	default:
		if n, ok := f.named[name]; ok {
			target, name = n.file, n.name
		} else {
			target = f.path
		}
	}
	pick := func(vs []djView) (djView, bool) {
		var inFile []djView
		for _, v := range vs {
			if v.file.path == target {
				inFile = append(inFile, v)
			}
		}
		if len(inFile) == 1 {
			return inFile[0], true
		}
		if len(vs) == 1 && len(inFile) == 0 {
			return vs[0], true // re-exported through a package __init__
		}
		return djView{}, false
	}
	if v, ok := pick(d.classes[name]); ok {
		return v, true
	}
	return pick(d.funcs[name])
}

func (d *djIndex) emitView(e djEntry, full string, out *[]Route, views *[]routeView) {
	line := lineAt(e.file.lineStarts, e.off)
	if strings.Contains(e.view, "admin.site.urls") {
		return
	}
	v, ok := d.lookup(e.file, e.view)
	if !ok {
		// A view this reader cannot find is not a view it can call unguarded.
		rt := Route{Method: "ALL", Path: full, FilePath: e.file.path, Line: line, Reader: ReaderDjango}
		*out = append(*out, rt)
		*views = append(*views, routeView{route: rt, framework: "django", guardUnseen: true})
		return
	}
	methods := d.methodsOf(v, e)
	for _, m := range methods {
		authn, authz, public := d.access(v, m)
		rt := Route{Method: m, Path: full, FilePath: e.file.path, Line: line, Authn: authn, Authz: authz, Reader: ReaderDjango}
		*out = append(*out, rt)
		*views = append(*views, routeView{route: rt, handler: d.handlerText(v), known: true, chain: v.decos + " " + v.bases,
			guardUnseen: d.guard, declaredPublic: public, framework: "django"})
	}
}

func (d *djIndex) emitViewset(reg djEntry, full string, inc djEntry, out *[]Route, views *[]routeView) {
	v, ok := d.lookup(reg.file, reg.viewset)
	list := djJoin(full, reg.route)
	detail := djJoin(list, ":pk")
	line := lineAt(reg.file.lineStarts, reg.off)
	if !ok {
		rt := Route{Method: "ALL", Path: list, FilePath: reg.file.path, Line: line, Reader: ReaderDjango}
		*out = append(*out, rt)
		*views = append(*views, routeView{route: rt, framework: "django", guardUnseen: true})
		return
	}
	for _, m := range d.viewsetRoutes(v) {
		p := list
		if m.detail {
			p = detail
		}
		authn, authz, public := d.access(v, m.method)
		rt := Route{Method: m.method, Path: p, FilePath: reg.file.path, Line: line, Authn: authn, Authz: authz, Reader: ReaderDjango}
		*out = append(*out, rt)
		*views = append(*views, routeView{route: rt, handler: d.handlerText(v), known: true, chain: v.decos + " " + v.bases,
			guardUnseen: d.guard, declaredPublic: public, framework: "django"})
	}
	d.emitActions(v, list, detail, out, views)
}

type viewsetRoute struct {
	method string
	detail bool
}

// viewsetRoutes are the routes a DRF router builds for a viewset, from the
// base classes and mixins it names (searching base classes in the repository).
func (d *djIndex) viewsetRoutes(v djView) []viewsetRoute {
	bases := d.baseNames(v, 3)
	has := func(n string) bool { return bases[n] }
	var rs []viewsetRoute
	add := func(m string, detail bool) { rs = append(rs, viewsetRoute{m, detail}) }
	switch {
	case has("ModelViewSet"):
		add("GET", false)
		add("POST", false)
		add("GET", true)
		add("PUT", true)
		add("PATCH", true)
		add("DELETE", true)
	case has("ReadOnlyModelViewSet"):
		add("GET", false)
		add("GET", true)
	default:
		if has("ListModelMixin") {
			add("GET", false)
		}
		if has("CreateModelMixin") {
			add("POST", false)
		}
		if has("RetrieveModelMixin") {
			add("GET", true)
		}
		if has("UpdateModelMixin") {
			add("PUT", true)
			add("PATCH", true)
		}
		if has("DestroyModelMixin") {
			add("DELETE", true)
		}
		if len(rs) == 0 {
			// A plain ViewSet: the methods it defines (list, create, ...) map to
			// routes; this reader cannot tell which, so it records one ALL.
			add("ALL", false)
		}
	}
	return rs
}

// baseNames returns the names of the classes v derives from, following bases
// defined in the repository up to depth levels.
func (d *djIndex) baseNames(v djView, depth int) map[string]bool {
	out := map[string]bool{}
	var visit func(v djView, depth int)
	visit = func(v djView, depth int) {
		for _, b := range strings.Split(v.bases, ",") {
			b = strings.TrimSpace(b)
			if i := strings.LastIndexByte(b, '.'); i >= 0 {
				b = b[i+1:]
			}
			if b == "" || strings.Contains(b, "=") {
				continue
			}
			out[b] = true
			if depth > 0 {
				if cs := d.classes[b]; len(cs) == 1 {
					visit(cs[0], depth-1)
				}
			}
		}
	}
	visit(v, depth)
	return out
}

// classChain is v followed by the repository classes it derives from, nearest
// first.
func (d *djIndex) classChain(v djView) []djView {
	chain := []djView{v}
	cur := v
	for i := 0; i < 3; i++ {
		var next *djView
		for _, b := range strings.Split(cur.bases, ",") {
			b = strings.TrimSpace(b)
			if j := strings.LastIndexByte(b, '.'); j >= 0 {
				b = b[j+1:]
			}
			if cs := d.classes[b]; len(cs) == 1 && cs[0].name != cur.name {
				c := cs[0]
				chain = append(chain, c)
				if next == nil {
					next = &c
				}
			}
		}
		if next == nil {
			break
		}
		cur = *next
	}
	return chain
}

func (d *djIndex) handlerText(v djView) string {
	t := v.text()
	if !v.class {
		for _, c := range d.calleeViews(v) {
			t += "\n" + c.text()
		}
		return t
	}
	for _, c := range d.classChain(v)[1:] {
		t += "\n" + c.text()
	}
	return t
}

// methodsOf says which HTTP methods a view serves.
func (d *djIndex) methodsOf(v djView, e djEntry) []string {
	set := map[string]bool{}
	if !v.class {
		if m := djAPIViewRe.FindStringSubmatch(v.decos); m != nil {
			for _, q := range djQuoted.FindAllStringSubmatch(m[1], -1) {
				set[strings.ToUpper(q[1])] = true
			}
		} else if m := djRequireRe.FindStringSubmatch(v.decos); m != nil {
			switch {
			case m[1] == "POST":
				set["POST"] = true
			case m[1] != "":
				set["GET"] = true
			default:
				for _, q := range djQuoted.FindAllStringSubmatch(m[2], -1) {
					set[strings.ToUpper(q[1])] = true
				}
			}
		} else {
			for _, m := range djReqMethodRe.FindAllStringSubmatch(v.text(), -1) {
				set[m[1]] = true
			}
		}
	} else {
		viewText := d.handlerText(v)
		for _, m := range djMethodDefRe.FindAllStringSubmatch(viewText, -1) {
			set[strings.ToUpper(m[1])] = true
		}
		if mm := djAsViewMapRe.FindStringSubmatch(string(e.file.raw[e.off:min(len(e.file.raw), e.off+400)])); mm != nil {
			for _, q := range djQuoted.FindAllStringSubmatch(mm[1], -1) {
				if _, isVerb := map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true}[q[1]]; isVerb {
					set[strings.ToUpper(q[1])] = true
				}
			}
		}
		for b := range d.baseNames(v, 3) {
			for _, m := range djGenericMethods[b] {
				set[m] = true
			}
		}
	}
	if len(set) == 0 {
		return []string{"ALL"}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// access reads what stands in front of a view for one method: the access
// control it declares or inherits, and whether it declares itself public.
func (d *djIndex) access(v djView, method string) (authn, authz string, public bool) {
	text := d.handlerText(v)
	label := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	if djPublicDeco.MatchString(v.decos) {
		return "", "", true
	}
	if djAuthClsEmpty.MatchString(v.decos) || djAuthClsEmpty.MatchString(text) {
		return "", "", true
	}
	// Decorators on a function or on the class (@method_decorator(login_required...)).
	authn, authz = decoAccess(v.decos)
	for _, c := range d.calleeViews(v) {
		ca, cz := decoAccess(c.decos)
		authn, authz = firstOf(authn, ca), firstOf(authz, cz)
	}
	if m := djPermDecoRe.FindStringSubmatch(v.decos); m != nil {
		a, z, pub := classifyPermClasses(m[1], method)
		if pub {
			return "", "", true
		}
		authn, authz = firstOf(authn, a), firstOf(authz, z)
	}
	if v.class {
		for _, c := range d.classChain(v) {
			for _, b := range strings.Split(c.bases, ",") {
				b = strings.TrimSpace(b)
				if djMixinRe.MatchString(b) {
					if djAuthzMixin.MatchString(b) {
						authz = firstOf(authz, label(b))
					} else {
						authn = firstOf(authn, label(b))
					}
				}
			}
			if m := djAuthzDecoRe.FindStringSubmatch(c.decos); m != nil {
				authz = firstOf(authz, m[1])
			}
			if m := djAuthDecoRe.FindStringSubmatch(c.decos); m != nil {
				authn = firstOf(authn, m[1])
			}
		}
		for _, c := range d.classChain(v) {
			if m := djPermClassesRe.FindStringSubmatch(c.text()); m != nil {
				a, z, pub := classifyPermClasses(m[1], method)
				if pub {
					return "", "", true
				}
				authn, authz = firstOf(authn, a), firstOf(authz, z)
				break // the nearest class that sets permission_classes decides
			}
		}
	}
	drf := djAPIViewRe.MatchString(v.decos) || d.isDRFClass(v)
	if authn == "" && authz == "" {
		switch {
		case drf && d.drfAuth != "":
			authn = d.drfAuth
		case !drf && d.mwAuth:
			authn = "LoginRequiredMiddleware"
		case pyInlineAuthRe.MatchString(text):
			authn = inlineAuthLabel
		}
	}
	return authn, authz, false
}

func (d *djIndex) isDRFClass(v djView) bool {
	for b := range d.baseNames(v, 3) {
		if strings.HasSuffix(b, "APIView") || strings.HasSuffix(b, "ViewSet") || b == "APIView" || strings.HasPrefix(b, "Generic") && strings.HasSuffix(b, "View") {
			return true
		}
	}
	return false
}

// decoAccess reads access control from decorator names: the Django and DRF
// ones by name, then any other decorator whose name says it authenticates or
// authorizes the caller (a project's own @authorize, @api_key_required).
func decoAccess(decos string) (authn, authz string) {
	if m := djAuthzDecoRe.FindStringSubmatch(decos); m != nil {
		authz = m[1]
	}
	if m := djAuthDecoRe.FindStringSubmatch(decos); m != nil {
		authn = m[1]
	}
	for _, m := range djDecoNameRe.FindAllStringSubmatch(decos, -1) {
		name := lastDotted(m[1])
		if djNotAccessRe.MatchString(name) || notAccessControlRe.MatchString(name) {
			continue
		}
		switch {
		case authnName(name):
			authn = firstOf(authn, name)
		case authzMWRe.MatchString(name):
			authz = firstOf(authz, name)
		}
	}
	return authn, authz
}

// calleeViews are the repository functions a function view calls by name, one
// level deep: a dispatcher view that hands each method to an @authorize'd
// function is authenticated by what it calls.
func (d *djIndex) calleeViews(v djView) []djView {
	if v.class {
		return nil
	}
	var out []djView
	seen := map[string]bool{v.name: true}
	for _, m := range pyCallNameRe.FindAllStringSubmatch(v.file.code[v.bodyStart:v.bodyEnd], -1) {
		name := m[1]
		if seen[name] || len(out) >= maxCallees {
			continue
		}
		seen[name] = true
		if fs := d.funcs[name]; len(fs) == 1 {
			out = append(out, fs[0])
		}
	}
	return out
}

func firstOf(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// classifyPermClasses reads a permission_classes list. AllowAny alone declares
// the view public; any other class is access control (an authorization class
// when its name says role, owner, admin or permission); IsAuthenticatedOrReadOnly
// authenticates only the unsafe methods.
func classifyPermClasses(list, method string) (authn, authz string, public bool) {
	var names []string
	for _, n := range strings.Split(list, ",") {
		n = strings.TrimSpace(n)
		if i := strings.LastIndexByte(n, '.'); i >= 0 {
			n = n[i+1:]
		}
		n = strings.TrimSuffix(strings.TrimSpace(n), "()")
		if n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "", "", true // permission_classes = [] removes the default guard
	}
	allowAny, readOnly := 0, 0
	for _, n := range names {
		switch {
		case n == "AllowAny":
			allowAny++
		case n == "IsAuthenticatedOrReadOnly":
			readOnly++
			if !safeMethods[method] && method != "ALL" {
				authn = firstOf(authn, n)
			}
		case authzMWRe.MatchString(n) || strings.Contains(n, "Admin") || strings.Contains(n, "Permission"):
			authz = firstOf(authz, n)
		default:
			authn = firstOf(authn, n)
		}
	}
	if allowAny == len(names) || allowAny+readOnly == len(names) && safeMethods[method] {
		// AllowAny declares the view public; IsAuthenticatedOrReadOnly declares
		// its reads public.
		return "", "", true
	}
	return authn, authz, false
}
