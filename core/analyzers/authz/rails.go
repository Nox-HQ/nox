package authz

import (
	"regexp"
	"strings"
)

// Rails routes (config/routes.rb and the files it draws) and the controllers
// they name.
//
// A route is a statement of the routing DSL: `get 'users/:id', to:
// 'users#show'`, `resources :users, only: [...]` (expanded to its RESTful
// routes), `resource :profile`, with `namespace`, `scope`, `controller`,
// `member`/`collection` and nested `resources` blocks carrying their path and
// controller module. Each route is joined to its action in
// app/controllers/**/*_controller.rb and judged from what that controller
// shows, never from the routing file alone.
//
// What it states, and no more:
//
//   - a route is authenticated by a before_action (or prepend_/append_,
//     before_filter) whose name says it authenticates the caller
//     (authenticate_user!, require_login, authenticate_admin!), by
//     http_basic_authenticate_with, by an authorizing macro
//     (load_and_authorize_resource) or admin gate, by a Rails 8
//     `include Authentication` concern that is in the repository and declares
//     a before_action, by an `authenticate :user do` / `authenticated :user do`
//     block in routes.rb, or by a check on the caller inside the action
//     (current_user, authenticate_user!, head :unauthorized);
//   - the callbacks of the superclass chain apply (class UsersController <
//     Admin::BaseController < ApplicationController), outermost first, and
//     `only:`/`except:` and `skip_before_action` are honoured per action. A
//     skip leaves the action without that callback: it is not authenticated by
//     it, and not declared public either, so a state-changing action that skips
//     authentication is still a lead;
//   - what this reader cannot see is never called authenticated and never
//     called missing: a callback with `if:`/`unless:`, a condition it cannot
//     read, a superclass or module from a gem or outside the repository, a
//     controller it cannot find, a constraint that is a lambda or a class, an
//     engine's routes (their mount path is elsewhere), and an unresolved
//     `include` whose name says authentication mark the route `unseen`: in the
//     table, never a lead;
//   - csrf (`verify_authenticity_token`) is not authentication.
//
// Not read: routes added by gems (devise_for), `mount`, `concerns`, Rack-app
// and redirect routes, `shallow` nesting (read, but never a lead),
// `resources ... param:`, lambdas as callbacks, authentication done in a
// Rack middleware, and a callback registered by metaprogramming.

// The framework readers this file and laravel.go add.
const (
	ReaderRails   = "Rails"
	ReaderLaravel = "Laravel"
)

var (
	rbRoutesFileRe = regexp.MustCompile(`(?:^|/)config/routes\.rb$`)
	rbDrawnFileRe  = regexp.MustCompile(`(?:^|/)config/routes/(.+)\.rb$`)
	rbEngineRe     = regexp.MustCompile(`Engine\s*\.\s*routes\s*\.\s*(?:draw|append)\b`)
	rbRoutesDrawRe = regexp.MustCompile(`\.routes\s*\.\s*draw\b`)
)

// rbResource is a `resources`/`resource` declaration in scope.
type rbResource struct {
	collection string // /users
	member     string // /users/:id
	nested     string // /users/:user_id
	ctrl       string // controller path, module included
	singular   bool
}

// rbCtx is what the enclosing blocks contribute to a statement.
type rbCtx struct {
	path       string
	module     string
	controller string // `controller :x do`
	authn      string
	unseen     bool
	skip       bool // inside a concern: not routes
	res        *rbResource
}

// rbRoute is a route before its controller is looked at.
type rbRoute struct {
	file         *rbFile
	line         int
	method, path string
	ctrl, action string
	authn        string
	unseen       bool
}

type rbRoutesParser struct {
	files   map[string]*rbFile
	routes  []rbRoute
	drawn   map[string]bool
	visited map[string]bool
}

func rbJoin(parts ...string) string {
	var kept []string
	for _, p := range parts {
		for {
			q := rbOptionalGroup.ReplaceAllString(p, "")
			if q == p {
				break
			}
			p = q
		}
		if p = strings.Trim(p, "/"); p != "" {
			kept = append(kept, p)
		}
	}
	return "/" + strings.Join(kept, "/")
}

var rbOptionalGroup = regexp.MustCompile(`\([^()]*\)`)

func rbSingular(s string) string {
	switch {
	case strings.HasSuffix(s, "ies") && len(s) > 3:
		return s[:len(s)-3] + "y"
	case strings.HasSuffix(s, "sses"), strings.HasSuffix(s, "xes"), strings.HasSuffix(s, "ches"), strings.HasSuffix(s, "shes"):
		return s[:len(s)-2]
	case strings.HasSuffix(s, "ss"):
		return s
	case strings.HasSuffix(s, "s") && len(s) > 1:
		return s[:len(s)-1]
	}
	return s
}

func rbPlural(s string) string {
	switch {
	case strings.HasSuffix(s, "s"), strings.HasSuffix(s, "x"), strings.HasSuffix(s, "ch"), strings.HasSuffix(s, "sh"):
		return s + "es"
	case strings.HasSuffix(s, "y") && len(s) > 1 && !strings.ContainsRune("aeiou", rune(s[len(s)-2])):
		return s[:len(s)-1] + "ies"
	}
	return s + "s"
}

// parseFile reads one routes file under ctx. nested says a draw site gave it
// its context; a file nothing draws is not read.
func (p *rbRoutesParser) parseFile(f *rbFile, ctx rbCtx, depth int) {
	if depth > 6 || p.visited[f.path+"|"+ctx.path+"|"+ctx.module] {
		return
	}
	p.visited[f.path+"|"+ctx.path+"|"+ctx.module] = true
	if rbEngineRe.MatchString(f.code) {
		ctx.unseen = true
	}
	stack := []rbCtx{ctx}
	for _, st := range rbStatements(f) {
		cur := stack[len(stack)-1]
		if st.ends > st.opens {
			for n := st.ends - st.opens; n > 0 && len(stack) > 1; n-- {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		child := p.statement(f, st, cur, depth)
		for n := st.opens - st.ends; n > 0; n-- {
			stack = append(stack, child)
		}
	}
}

func (p *rbRoutesParser) statement(f *rbFile, st rbStmt, ctx rbCtx, depth int) rbCtx {
	head, he := rbHead(f, st)
	if rbRoutesDrawRe.MatchString(st.text(f)) {
		return ctx
	}
	if ctx.skip {
		return ctx
	}
	args := rbCallArgs(f, st, skipSpaces(f.code, he, st.end))
	line := lineAt(f.lineStarts, st.start)
	switch head {
	case "get", "post", "put", "patch", "delete", "match", "root":
		p.verb(f, line, ctx, head, args)
		return ctx
	case "resources", "resource":
		return p.resources(f, line, ctx, head == "resource", args)
	case "namespace":
		return rbNamespace(ctx, args)
	case "scope":
		return rbScope(ctx, args)
	case "controller":
		if len(args.pos) > 0 {
			if c, ok := rbStr(args.pos[0]); ok {
				ctx.controller = c
			}
		}
	case "member", "collection":
		if ctx.res != nil {
			ctx.path = ctx.res.collection
			if head == "member" {
				ctx.path = ctx.res.member
			}
		}
	case "new", "concern":
		ctx.skip = true
	case "authenticate", "authenticated":
		if ctx.authn == "" {
			ctx.authn = head
			if len(args.pos) > 0 {
				ctx.authn += " " + args.pos[0]
			}
		}
	case "constraints":
		if !rbHashConstraint(args) {
			ctx.unseen = true
		}
	case "shallow":
		ctx.unseen = true
	case "draw":
		p.draw(f, args, ctx, depth)
	}
	return ctx
}

func skipSpaces(code string, i, end int) int {
	for i < end && (code[i] == ' ' || code[i] == '\t') {
		i++
	}
	return i
}

// rbHashConstraint: constraints given as a hash (subdomain, format, id regexp)
// do not decide who the caller is; a lambda or a class might.
func rbHashConstraint(a rbArgs) bool {
	if len(a.pos) == 0 {
		return len(a.kw) > 0
	}
	return false
}

func rbNamespace(ctx rbCtx, a rbArgs) rbCtx {
	name := ""
	if len(a.pos) > 0 {
		name, _ = rbStr(a.pos[0])
	}
	path, mod := name, name
	if v, ok := rbStr(a.kw["path"]); ok {
		path = v
	}
	if v, ok := rbStr(a.kw["module"]); ok {
		mod = v
	}
	ctx.path = rbJoin(ctx.path, path)
	ctx.module = rbJoinModule(ctx.module, mod)
	ctx.res = nil
	return rbScopeOptions(ctx, a)
}

func rbScope(ctx rbCtx, a rbArgs) rbCtx {
	if len(a.pos) > 0 {
		if v, ok := rbStr(a.pos[0]); ok {
			ctx.path = rbJoin(ctx.path, v)
		}
	}
	if v, ok := rbStr(a.kw["path"]); ok {
		ctx.path = rbJoin(ctx.path, v)
	}
	if v, ok := rbStr(a.kw["module"]); ok {
		ctx.module = rbJoinModule(ctx.module, v)
	}
	if v, ok := rbStr(a.kw["controller"]); ok {
		ctx.controller = v
	}
	return rbScopeOptions(ctx, a)
}

// rbScopeOptions applies what a scope-like call says beyond a path: a
// constraint object or a shallow nesting hides routes' guards from this reader.
func rbScopeOptions(ctx rbCtx, a rbArgs) rbCtx {
	if c, ok := a.kw["constraints"]; ok && !strings.HasPrefix(c, "{") {
		ctx.unseen = true
	}
	if s, ok := a.kw["shallow"]; ok && s != "false" {
		ctx.unseen = true
	}
	return ctx
}

func rbJoinModule(a, b string) string {
	return strings.Trim(strings.Trim(a, "/")+"/"+strings.Trim(b, "/"), "/")
}

// controllerOf resolves a route's controller path and action.
func (p *rbRoutesParser) controllerOf(ctx rbCtx, a rbArgs, path string) (ctrl, action string, ok bool) {
	to := a.kw["to"]
	if len(a.pairs) > 0 {
		to = a.pairs[0][1]
	}
	if to != "" {
		v, isStr := rbStr(to)
		if !isStr || !strings.Contains(v, "#") {
			return "", "", false // a Rack app, a redirect or a lambda
		}
		c, act, _ := strings.Cut(v, "#")
		if c == "" {
			c = ctx.controller
		}
		return rbJoinModule(ctx.module, c), act, true
	}
	ctrl, action = ctx.controller, ""
	if v, ok := rbStr(a.kw["controller"]); ok {
		ctrl = v
	}
	if v, ok := rbStr(a.kw["action"]); ok {
		action = v
	}
	if ctrl == "" && ctx.res != nil {
		ctrl = ctx.res.ctrl
		return ctrl, action, true
	}
	if ctrl == "" {
		return "", action, true // resolved from the path by the caller
	}
	return rbJoinModule(ctx.module, ctrl), action, true
}

func (p *rbRoutesParser) verb(f *rbFile, line int, ctx rbCtx, head string, a rbArgs) {
	methods := rbVerbMethods(head, a)
	if len(methods) == 0 {
		return
	}
	ctrl, action, ok := p.controllerOf(ctx, a, "")
	if !ok {
		return
	}
	var paths []string
	for _, v := range a.pos {
		if s, isStr := rbStr(v); isStr {
			paths = append(paths, s)
		}
	}
	for _, pr := range a.pairs {
		if s, isStr := rbStr(pr[0]); isStr {
			paths = append(paths, s)
		}
	}
	if head == "root" {
		paths = []string{""}
		if len(a.pos) > 0 {
			if v, isStr := rbStr(a.pos[0]); isStr && ctrl == "" {
				c, act, _ := strings.Cut(v, "#")
				ctrl, action = rbJoinModule(ctx.module, c), act
			}
		}
	}
	if len(paths) == 0 {
		return
	}
	base := ctx.path
	if on, _ := rbStr(a.kw["on"]); ctx.res != nil && (on == "member" || on == "collection") {
		base = ctx.res.collection
		if on == "member" {
			base = ctx.res.member
		}
	}
	unseen := ctx.unseen
	if c, has := a.kw["constraints"]; has && !strings.HasPrefix(c, "{") {
		unseen = true
	}
	for _, pth := range paths {
		c, act := ctrl, action
		if c == "" || act == "" {
			c, act = rbFromPath(ctx, pth, c, act)
		}
		for _, m := range methods {
			p.routes = append(p.routes, rbRoute{file: f, line: line, method: m, path: rbJoin(base, pth), ctrl: c, action: act, authn: ctx.authn, unseen: unseen || c == "" || act == ""})
		}
	}
}

// rbFromPath derives what Rails derives when a route names no controller or
// action: `get 'photos/show'` is photos#show, and inside a controller or
// resource block `get :search` is that controller's search.
func rbFromPath(ctx rbCtx, path, ctrl, action string) (ctrlOut, actionOut string) {
	path = strings.Trim(path, "/")
	if strings.ContainsAny(path, ":*()") {
		return ctrl, action
	}
	if ctrl == "" {
		i := strings.LastIndexByte(path, '/')
		if i < 0 {
			return "", action
		}
		ctrl = rbJoinModule(ctx.module, path[:i])
		if action == "" {
			action = path[i+1:]
		}
		return ctrl, action
	}
	if action == "" && !strings.Contains(path, "/") {
		action = path
	}
	return ctrl, action
}

func rbVerbMethods(head string, a rbArgs) []string {
	switch head {
	case "get", "post", "put", "patch", "delete":
		return []string{strings.ToUpper(head)}
	case "root":
		return []string{"GET"}
	}
	via, ok := a.kw["via"]
	if !ok {
		return nil
	}
	if strings.TrimSpace(via) == ":all" {
		return []string{"ALL"}
	}
	list, ok := rbList(via)
	if !ok {
		return nil
	}
	var out []string
	for _, v := range list {
		out = append(out, strings.ToUpper(v))
	}
	return out
}

var rbRestful = []struct {
	action, method, plural, singular string
}{
	{"index", "GET", "", "-"},
	{"create", "POST", "", ""},
	{"new", "GET", "/new", "/new"},
	{"edit", "GET", "/:id/edit", "/edit"},
	{"show", "GET", "/:id", ""},
	{"update", "PATCH", "/:id", ""},
	{"update", "PUT", "/:id", ""},
	{"destroy", "DELETE", "/:id", ""},
}

func (p *rbRoutesParser) resources(f *rbFile, line int, ctx rbCtx, singular bool, a rbArgs) rbCtx {
	var names []string
	for _, v := range a.pos {
		if n, ok := rbStr(v); ok {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return ctx
	}
	only, onlyOK := rbActionSet(a.kw["only"])
	except, exceptOK := rbActionSet(a.kw["except"])
	unseen := ctx.unseen || !onlyOK || !exceptOK
	if c, has := a.kw["constraints"]; has && !strings.HasPrefix(c, "{") {
		unseen = true
	}
	if s, has := a.kw["shallow"]; has && s != "false" {
		unseen = true
	}
	var last rbCtx
	for _, name := range names {
		seg := name
		if v, ok := rbStr(a.kw["path"]); ok {
			seg = v
		}
		ctrl := rbPlural(name)
		if !singular {
			ctrl = name
		}
		if v, ok := rbStr(a.kw["controller"]); ok {
			ctrl = v
		}
		mod := ctx.module
		if v, ok := rbStr(a.kw["module"]); ok {
			mod = rbJoinModule(mod, v)
		}
		res := &rbResource{ctrl: rbJoinModule(mod, ctrl), singular: singular}
		res.collection = rbJoin(ctx.path, seg)
		param := "id"
		if v, ok := rbStr(a.kw["param"]); ok {
			param = v
		}
		switch {
		case singular:
			res.member, res.nested = res.collection, res.collection
		default:
			res.member = rbJoin(res.collection, ":"+param)
			res.nested = rbJoin(res.collection, ":"+rbSingular(name)+"_"+param)
		}
		for _, r := range rbRestful {
			if (only != nil && !only[r.action]) || except[r.action] {
				continue
			}
			suffix := r.plural
			if singular {
				suffix = r.singular
				if suffix == "-" {
					continue // a singular resource has no index
				}
			}
			p.routes = append(p.routes, rbRoute{file: f, line: line, method: r.method, path: rbJoin(res.collection, strings.ReplaceAll(suffix, ":id", ":"+param)), ctrl: res.ctrl, action: r.action, authn: ctx.authn, unseen: unseen})
		}
		child := ctx
		child.res, child.path, child.unseen = res, res.nested, unseen
		last = child
	}
	return last
}

// rbActionSet reads only:/except: into a set; nil means the option is absent.
// ok is false when the option is present but not a literal list.
func rbActionSet(v string) (map[string]bool, bool) {
	if strings.TrimSpace(v) == "" {
		return nil, true
	}
	list, ok := rbList(v)
	if !ok {
		return nil, false
	}
	set := map[string]bool{}
	for _, a := range list {
		set[a] = true
	}
	return set, true
}

// draw reads `draw :admin`: config/routes/admin.rb, in the context of the site.
func (p *rbRoutesParser) draw(f *rbFile, a rbArgs, ctx rbCtx, depth int) {
	if len(a.pos) == 0 {
		return
	}
	name, ok := rbStr(a.pos[0])
	if !ok {
		return
	}
	root := f.path[:strings.LastIndex(f.path, "config/routes")]
	if g := p.files[root+"config/routes/"+name+".rb"]; g != nil {
		p.drawn[g.path] = true
		p.parseFile(g, ctx, depth+1)
	}
}

// ---- controllers ----

// rbCallback is one entry of a controller's callback chain.
type rbOp struct {
	kind        string // add, skip, include
	name        string
	class       string // authn, authz or "" (not access control)
	only        map[string]bool
	except      map[string]bool
	conditional bool
	label       string
}

type rbClass struct {
	file     *rbFile
	fqn      string
	isModule bool
	super    string
	lex      []string // enclosing scopes, outermost first
	ops      []rbOp
	actions  map[string]string
	opaque   bool
	dynamic  bool // defines actions at run time: "not defined" proves nothing
}

type rbIndex struct {
	classes map[string][]*rbClass
}

func (ix *rbIndex) lookup(name string, lex []string) (*rbClass, bool) {
	name = strings.TrimPrefix(name, "::")
	var cands []string
	for i := len(lex) - 1; i >= 0; i-- {
		cands = append(cands, lex[i]+"::"+name)
	}
	cands = append(cands, name)
	for _, c := range cands {
		if cs := ix.classes[rbKey(c)]; len(cs) == 1 {
			return cs[0], true
		} else if len(cs) > 1 {
			return nil, false
		}
	}
	return nil, false
}

var (
	rbClassRe    = regexp.MustCompile(`^class\s+((?:::)?[A-Z]\w*(?:::[A-Z]\w*)*)\s*(?:<\s*((?:::)?[A-Z]\w*(?:::[A-Z]\w*)*))?`)
	rbModuleRe   = regexp.MustCompile(`^module\s+((?:::)?[A-Z]\w*(?:::[A-Z]\w*)*)`)
	rbDefRe      = regexp.MustCompile(`^def\s+([a-z_]\w*[?!]?)(?:[\s(;=]|$)`)
	rbCondOpenRe = regexp.MustCompile(`^(?:if|unless|case)\b`)

	rbBeforeRe = regexp.MustCompile(`^(?:prepend_|append_)?before_(?:action|filter)$`)
	rbSkipRe   = regexp.MustCompile(`^skip_(?:before_(?:action|filter)|filter|action_callback)$`)

	rbDynamicRe = regexp.MustCompile(`\b(?:define_method|method_missing|alias_method|class_eval|instance_eval|public_send|delegate)\b`)
	rbOpaqueRe  = regexp.MustCompile(`\bbase\s*\.\s*(?:before_action|skip_before_action|before_filter|class_eval)\b|\bdef\s+self\.included\b|\bsend\s*\(\s*:(?:before|skip)_`)

	// rbInlineAuthRe: the action looks at who the caller is. A bare
	// `authenticate_user!` rejects; `User.authenticate(email, password)` is the
	// login itself and is not a check on the caller. Writes are filtered by
	// rbHasInlineAuth.
	rbInlineAuthRe = regexp.MustCompile(`(?:^|[^.\w])authenticate\w*!|(?:^|[^.\w])authenticate_or_request_with_http_\w+|\bcurrent_(?:user|account|member|admin)\b|\buser_signed_in\?|\bsigned_in\?|\blogged_in\?|\brequire_login\b|\bwarden\s*\.\s*authenticate|\bdoorkeeper_token\b|\bhead\s*\(?\s*:(?:unauthorized|forbidden)|status:\s*(?::unauthorized|:forbidden|401|403)|session\s*\[\s*:(?:user|account|member)_?id\s*\]|\brequest\s*\.\s*headers\s*\[\s*['"]Authorization['"]`)

	rbAuthzCallbackRe = regexp.MustCompile(`^(?:(?:require|ensure|check|verify|authorize|restrict_to)_(?:admin|staff|superuser|moderator|role|permission)\w*|(?:admin|staff|moderator)_(?:required|only|user|check)|correct_user)[!?]?$`)
	rbAuthnExtraRe    = regexp.MustCompile(`^(?:require|ensure|validate|restrict|verify|check)_(?:api_?key|access_?token|access)[!?]?$|^restrict_access[!?]?$`)
)

// rbHasInlineAuth reports whether body reads who the caller is. An assignment
// (`session[:user_id] = user.id`, `@current_user ||= ...`) is the login or the
// memoisation, not a check.
func rbHasInlineAuth(body string) bool {
	for _, loc := range rbInlineAuthRe.FindAllStringIndex(body, -1) {
		rest := strings.TrimLeft(body[loc[1]:], " \t")
		write := strings.HasPrefix(rest, "||=") || strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") && !strings.HasPrefix(rest, "=~")
		if !write {
			return true
		}
	}
	return false
}

// rbCallbackClass says whether a callback name is access control.
func rbCallbackClass(name string) string {
	n := strings.TrimRight(name, "!?")
	switch {
	case strings.Contains(n, "authenticity") || strings.Contains(n, "forgery"):
		return ""
	case rbAuthzCallbackRe.MatchString(name):
		return "authz"
	case strings.Contains(n, "authoriz"):
		return "authz"
	case authnName(rbCamelize(n)) || rbAuthnExtraRe.MatchString(name):
		return "authn"
	}
	return ""
}

// rbCamelize turns snake_case into the CamelCase authnName reads as words.
func rbCamelize(s string) string {
	parts := strings.Split(s, "_")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}

type rbFrame struct {
	kind   string // class, module, def, if, included, cb, other
	fqn    string
	cls    *rbClass
	start  int
	action string
	op     int // index into cls.ops for a block callback
}

func (ix *rbIndex) addFile(f *rbFile) {
	var stack []rbFrame
	lexOf := func() []string {
		var lex []string
		for _, fr := range stack {
			if fr.kind == "class" || fr.kind == "module" {
				lex = append(lex, fr.fqn)
			}
		}
		return lex
	}
	target := func() (*rbClass, bool, bool) { // class, in scope, conditional
		cond := false
		for i := len(stack) - 1; i >= 0; i-- {
			switch stack[i].kind {
			case "if":
				cond = true
			case "class", "included", "module":
				return stack[i].cls, true, cond
			default:
				return nil, false, false
			}
		}
		return nil, false, false
	}
	for _, st := range rbStatements(f) {
		text := strings.TrimSpace(st.text(f))
		text = rbModifierPrefixRe.ReplaceAllString(text, "")
		if st.ends > st.opens {
			for n := st.ends - st.opens; n > 0 && len(stack) > 0; n-- {
				stack = ix.pop(f, stack, st)
			}
			continue
		}
		var fr rbFrame
		fr.start = st.start
		fr.kind = "other"
		switch {
		case rbClassRe.MatchString(text) && !strings.HasPrefix(text, "class <<"):
			m := rbClassRe.FindStringSubmatch(text)
			fr = ix.declare(f, m[1], m[2], false, lexOf(), st)
		case rbModuleRe.MatchString(text):
			fr = ix.declare(f, rbModuleRe.FindStringSubmatch(text)[1], "", true, lexOf(), st)
		case strings.HasPrefix(text, "def "):
			fr = rbFrame{kind: "def", start: st.start}
			if c, ok, cond := target(); ok && !cond {
				if m := rbDefRe.FindStringSubmatch(text); m != nil {
					fr.cls, fr.action = c, m[1]
					if st.opens == st.ends {
						c.actions[m[1]] = st.sans(f)
					}
				}
			}
		case rbCondOpenRe.MatchString(text):
			fr.kind = "if"
		default:
			if c, ok, cond := target(); ok {
				fr = ix.classStatement(f, st, c, cond, len(stack) > 0 && stack[len(stack)-1].kind != "module", fr)
			}
		}
		for n := st.opens - st.ends; n > 0; n-- {
			stack = append(stack, fr)
			fr = rbFrame{kind: "other", start: st.start}
		}
	}
}

func (ix *rbIndex) declare(f *rbFile, name, super string, module bool, lex []string, st rbStmt) rbFrame {
	fqn := strings.TrimPrefix(name, "::")
	if !strings.HasPrefix(name, "::") && len(lex) > 0 {
		fqn = lex[len(lex)-1] + "::" + name
	}
	c := &rbClass{file: f, fqn: fqn, isModule: module, super: strings.TrimPrefix(super, "::"), lex: lex, actions: map[string]string{}, dynamic: rbDynamicRe.MatchString(f.code)}
	ix.classes[rbKey(fqn)] = append(ix.classes[rbKey(fqn)], c)
	kind := "class"
	if module {
		kind = "module"
	}
	return rbFrame{kind: kind, fqn: fqn, cls: c, start: st.start}
}

// classStatement reads a statement directly in a class body.
func (ix *rbIndex) classStatement(f *rbFile, st rbStmt, c *rbClass, cond, inIncluded bool, fr rbFrame) rbFrame {
	head, he := rbHead(f, st)
	text := st.text(f)
	if c.isModule && !inIncluded {
		if head == "included" && st.opens > st.ends {
			fr.kind, fr.cls = "included", c
		}
		if rbOpaqueRe.MatchString(text) {
			c.opaque = true
		}
		return fr
	}
	args := rbCallArgs(f, st, skipSpaces(f.code, he, st.end))
	switch {
	case rbBeforeRe.MatchString(head):
		ix.addCallbacks(c, f, st, "add", args, cond, &fr)
	case rbSkipRe.MatchString(head):
		ix.addCallbacks(c, f, st, "skip", args, cond, &fr)
	case head == "allow_unauthenticated_access":
		c.ops = append(c.ops, rbOp{kind: "skip", name: "require_authentication", only: rbSet(args.kw["only"]), except: rbSet(args.kw["except"]), conditional: cond || rbUncertain(args)})
	case head == "http_basic_authenticate_with", head == "acts_as_token_authentication_handler_for":
		c.ops = append(c.ops, rbOp{kind: "add", name: head, class: "authn", only: rbSet(args.kw["only"]), except: rbSet(args.kw["except"]), conditional: cond || rbUncertain(args), label: head})
	case head == "load_and_authorize_resource", head == "authorize_resource":
		c.ops = append(c.ops, rbOp{kind: "add", name: head, class: "authz", only: rbSet(args.kw["only"]), except: rbSet(args.kw["except"]), conditional: cond || rbUncertain(args), label: head})
	case head == "skip_authorize_resource", head == "skip_load_and_authorize_resource":
		c.ops = append(c.ops, rbOp{kind: "skip", name: strings.TrimPrefix(head, "skip_"), only: rbSet(args.kw["only"]), except: rbSet(args.kw["except"]), conditional: cond || rbUncertain(args)})
	case head == "include":
		for _, v := range args.pos {
			c.ops = append(c.ops, rbOp{kind: "include", name: strings.TrimSpace(v)})
		}
	}
	return fr
}

func rbSet(v string) map[string]bool {
	set, _ := rbActionSet(v)
	return set
}

// rbUncertain: only:/except:/if:/unless: present in a form this reader cannot read.
func rbUncertain(a rbArgs) bool {
	for _, k := range []string{"only", "except"} {
		if _, ok := rbActionSet(a.kw[k]); !ok {
			return true
		}
	}
	_, hasIf := a.kw["if"]
	_, hasUnless := a.kw["unless"]
	return hasIf || hasUnless
}

func (ix *rbIndex) addCallbacks(c *rbClass, f *rbFile, st rbStmt, kind string, a rbArgs, cond bool, fr *rbFrame) {
	op := rbOp{kind: kind, only: rbSet(a.kw["only"]), except: rbSet(a.kw["except"]), conditional: cond || rbUncertain(a)}
	var names []string
	for _, v := range a.pos {
		if n, ok := rbStr(v); ok {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		if kind == "add" {
			// a block or a lambda: judged by what it does, when its body is read
			op.name, op.label = "(block)", "an inline check on the caller's identity"
			if rbHasInlineAuth(st.sans(f)) {
				op.class = "authn"
			}
			c.ops = append(c.ops, op)
			if st.opens > st.ends {
				fr.kind, fr.cls, fr.op = "cb", c, len(c.ops)-1
			}
		}
		return
	}
	for _, n := range names {
		o := op
		o.name = n
		if kind == "add" {
			o.class = rbCallbackClass(n)
			o.label = "before_action :" + n
		}
		c.ops = append(c.ops, o)
	}
}

func (ix *rbIndex) pop(f *rbFile, stack []rbFrame, st rbStmt) []rbFrame {
	fr := stack[len(stack)-1]
	switch fr.kind {
	case "def":
		if fr.cls != nil && fr.action != "" {
			fr.cls.actions[fr.action] = f.sans[fr.start:st.end]
		}
	case "cb":
		if rbHasInlineAuth(f.sans[fr.start:st.end]) {
			fr.cls.ops[fr.op].class = "authn"
		}
	}
	return stack[:len(stack)-1]
}

// rbEvidence is what a controller shows about one action.
type rbEvidence struct {
	authn, authz string
	unseen       bool
	body         string
	// defined: some class in the chain, or a module it includes, defines the
	// action. complete: every class and module in the chain was read, so that
	// "not defined" means not defined.
	defined, complete bool
}

type rbState struct {
	mods       []*rbClass
	order      []string
	active     map[string]rbOp
	unseen     bool
	defined    bool
	incomplete bool
}

func (s *rbState) apply(op rbOp, action string) {
	if (op.only != nil && !op.only[action]) || op.except[action] {
		return
	}
	switch op.kind {
	case "add":
		if op.conditional && op.class != "" {
			s.unseen = true
			return
		}
		if _, ok := s.active[op.name]; !ok {
			s.order = append(s.order, op.name)
		}
		s.active[op.name] = op
	case "skip":
		if _, ok := s.active[op.name]; ok {
			delete(s.active, op.name)
			if op.conditional {
				s.unseen = true
			}
		}
	}
}

// ancestry lists c and its superclasses, outermost first. unseen is set when
// a superclass cannot be read here.
func (ix *rbIndex) ancestry(c *rbClass) (chain []*rbClass, unseen bool) {
	seen := map[*rbClass]bool{}
	for cur := c; cur != nil; {
		if seen[cur] {
			return chain, true
		}
		seen[cur] = true
		chain = append([]*rbClass{cur}, chain...)
		if cur.super == "" {
			break
		}
		next, ok := ix.lookup(cur.super, cur.lex)
		if !ok {
			if !rbNeutralSuper[cur.super] {
				unseen = true
			}
			break
		}
		cur = next
	}
	return chain, unseen
}

var rbNeutralSuper = map[string]bool{"ActionController::Base": true, "ActionController::API": true, "ActionController::Metal": true, "ActionController::Live": true}

func (ix *rbIndex) expand(c *rbClass, st *rbState, action string, depth int) {
	for _, op := range c.ops {
		if op.kind != "include" {
			st.apply(op, action)
			continue
		}
		m, ok := ix.lookup(op.name, c.lex)
		if !ok || !m.isModule || depth >= 6 {
			st.incomplete = true
		}
		switch {
		case ok && m.isModule && depth < 6:
			if m.opaque {
				st.unseen = true
			}
			st.mods = append(st.mods, m)
			if _, has := m.actions[action]; has {
				st.defined = true
			}
			ix.expand(m, st, action, depth+1)
		case !ok && authnName(rbCamelize(lastColon(op.name))):
			st.unseen = true
		}
	}
}

func lastColon(s string) string {
	if i := strings.LastIndex(s, "::"); i >= 0 {
		return s[i+2:]
	}
	return s
}

func (ix *rbIndex) evidence(c *rbClass, action string) rbEvidence {
	chain, unseen := ix.ancestry(c)
	st := &rbState{active: map[string]rbOp{}, unseen: unseen, incomplete: unseen}
	for _, cls := range chain {
		if _, has := cls.actions[action]; has {
			st.defined = true
		}
		if cls.dynamic {
			st.incomplete = true
		}
		ix.expand(cls, st, action, 0)
	}
	ev := rbEvidence{unseen: st.unseen, defined: st.defined, complete: !st.incomplete}
	defs := rbDefs(chain, st.mods)
	for _, n := range st.order {
		op, ok := st.active[n]
		if !ok || ix.optionalPair(chain, n) {
			continue
		}
		class := op.class
		switch {
		case class == "":
			class = rbRejectionClass(defs[n]) // a callback not named for it that answers 401 is the gate
		case !rbEnforcing(defs, n, op.name):
			class = ""
		}
		if class != "" && op.conditional {
			ev.unseen = true // a gate that applies only sometimes
			continue
		}
		if class == "authn" && ev.authn == "" {
			ev.authn = op.label
		}
		if class == "authz" && ev.authz == "" {
			ev.authz = op.label
		}
	}
	for i := len(chain) - 1; i >= 0 && ev.body == ""; i-- {
		ev.body = chain[i].actions[action]
	}
	if ev.authn == "" && ev.authz == "" && rbHasInlineAuth(ev.body) {
		ev.authn = inlineAuthLabel
	}
	return ev
}

// rbDefs collects the methods the chain and its modules define; the leaf wins.
func rbDefs(chain, mods []*rbClass) map[string]string {
	defs := map[string]string{}
	for _, m := range mods {
		for k, v := range m.actions {
			defs[k] = v
		}
	}
	for _, c := range chain {
		for k, v := range c.actions {
			defs[k] = v
		}
	}
	return defs
}

var (
	rbRejectRe = regexp.MustCompile(`\b(?:head|render|redirect_to|redirect_back|redirect_back_or_to|raise|throw|halt|respond_with|request_http_basic_authentication|deny_access|access_denied|not_authorized|unauthorized|forbidden|authorize!?)\b|authenticate_\w+!|authenticate_or_request_with_http_\w+|\bwarden\s*\.\s*authenticate!|\bdoorkeeper_authorize!`)
	rbIdentRe  = regexp.MustCompile(`[a-z_]\w*[?!]?`)
)

var (
	rbUnauthRe    = regexp.MustCompile(`:unauthorized\b|\bstatus:\s*401\b|\bhead\s*\(?\s*401\b|\brender_unauthorized\b|\bunauthorized!|\brequest_http_basic_authentication\b|\bauthenticate_or_request_with_http_\w+`)
	rbForbiddenRe = regexp.MustCompile(`:forbidden\b|\bstatus:\s*403\b|\bhead\s*\(?\s*403\b|\brender_forbidden\b|\bforbidden!|\baccess_denied\b|\bnot_authorized\b`)
)

// rbRejectionClass reads a callback's own body for the response that makes it
// access control: 401 means it authenticates, 403 that it authorizes.
func rbRejectionClass(body string) string {
	switch {
	case rbUnauthRe.MatchString(body):
		return "authn"
	case rbForbiddenRe.MatchString(body):
		return "authz"
	}
	return ""
}

// rbEnforcing reports whether the callback named name can stop a request. A
// callback the repository defines is read: one that only looks for a session
// and returns (Lobsters' `authenticate_user`, which always returns true) does
// not authenticate anything, whatever its name says. One it does not define is
// a gem's helper (Devise's `authenticate_user!`) and is taken at its name.
func rbEnforcing(defs map[string]string, name, _ string) bool {
	if _, defined := defs[name]; !defined {
		return true
	}
	return rbRejects(defs, name, 3, map[string]bool{})
}

func rbRejects(defs map[string]string, name string, depth int, seen map[string]bool) bool {
	body, ok := defs[name]
	if !ok || seen[name] {
		return false
	}
	seen[name] = true
	if rbRejectRe.MatchString(body) {
		return true
	}
	if depth == 0 {
		return false
	}
	for _, tok := range rbIdentRe.FindAllString(body, -1) {
		if tok != name && rbRejects(defs, tok, depth-1, seen) {
			return true
		}
	}
	return false
}

// optionalPair: a chain that defines both `authenticate_user` and
// `authenticate_user!` is the Devise-style split between reading the caller
// when there is one and requiring one; the bare name is the optional half.
func (ix *rbIndex) optionalPair(chain []*rbClass, name string) bool {
	if strings.HasSuffix(name, "!") || strings.HasSuffix(name, "?") {
		return false
	}
	var bare, bang bool
	for _, c := range chain {
		_, a := c.actions[name]
		_, b := c.actions[name+"!"]
		bare, bang = bare || a, bang || b
	}
	return bare && bang
}

// ---- assembling ----

// readRails reads every Rails routes file in files and joins its routes to
// their controllers.
func readRails(files map[string]*rbFile, order []string) ([]Route, []routeView) {
	ix := &rbIndex{classes: map[string][]*rbClass{}}
	for _, p := range order {
		if rbControllerFileRe.MatchString(p) {
			ix.addFile(files[p])
		}
	}
	parser := &rbRoutesParser{files: files, drawn: map[string]bool{}, visited: map[string]bool{}}
	for _, p := range order {
		if rbRoutesFileRe.MatchString(p) {
			parser.parseFile(files[p], rbCtx{}, 0)
		}
	}
	var routes []Route
	var views []routeView
	for _, r := range parser.routes {
		rt, v := ix.finish(r)
		routes, views = append(routes, rt), append(views, v)
	}
	return routes, views
}

var rbControllerFileRe = regexp.MustCompile(`(?:^|/)(?:controllers|concerns)/.+\.rb$`)

func (ix *rbIndex) finish(r rbRoute) (Route, routeView) {
	rt := Route{Method: r.method, Path: r.path, FilePath: r.file.path, Line: r.line, Authn: r.authn, Reader: ReaderRails}
	v := routeView{route: rt, framework: "rails", guardUnseen: r.unseen}
	if r.ctrl == "" || r.action == "" {
		v.guardUnseen = true
		return rt, v
	}
	cls, ok := ix.lookup(strings.ReplaceAll(r.ctrl, "/", "::")+"_controller", nil)
	if !ok {
		v.guardUnseen = true
		return rt, v
	}
	ev := ix.evidence(cls, r.action)
	if rt.Authn == "" {
		rt.Authn = ev.authn
	}
	rt.Authz = ev.authz
	v.route = rt
	v.handler = ev.body
	v.guardUnseen = v.guardUnseen || ev.unseen
	if ev.complete && !ev.defined && r.method != "GET" && r.method != "ALL" {
		v.guardUnseen = true // a route to an action nothing defines answers 404, not the data
	}
	return rt, v
}
