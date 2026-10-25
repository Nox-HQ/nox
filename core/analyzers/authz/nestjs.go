package authz

import (
	"regexp"
	"strings"
)

// NestJS controllers.
//
// A Nest route is a decorator pair: `@Controller('users')` on a class and
// `@Get(':id')` on a method. This reader walks each file's classes and their
// decorators over the masked text and produces the same Route and routeView the
// Express, Flask and Next.js readers do, so AUTHN-001, WEBHOOK-001 and
// `nox model` cover Nest.
//
// What it states, and no more:
//
//   - a route's Authn is set by a guard named like an authenticator in
//     `@UseGuards(...)` on its class or method, or by an authenticating guard
//     registered application-wide (`app.useGlobalGuards(...)`, a provider
//     `{ provide: APP_GUARD, useClass: ... }`);
//   - a guard named like a role or permission check sets Authz, not Authn;
//   - `@Public()` and its lookalikes mark the route public on purpose, which is
//     intent and never a missing-authentication lead;
//   - a guard this reader cannot name as access control (not a rate limiter, not
//     recognisably authenticating), application middleware, and Fastify hooks
//     make an empty Authn prove nothing (guardUnseen), as in the other readers.
//
// Only a file that imports from `@nestjs/` is read: `@Controller` and `@Get`
// are also routing-controllers, tsoa and Inversify decorators, whose guards
// are not Nest's.
//
// What it does not do: a path built from a constant (`@Controller(ROUTES.X)`)
// is not resolved, so that route is skipped, not guessed; RouterModule prefixes
// and inherited controller routes are not followed; GraphQL resolvers, gateways
// and microservice patterns are not HTTP routes here; and AUTHZ-001's body
// analysis does not run over these handlers.

var (
	nestImportRe  = regexp.MustCompile(`from\s+['"]@nestjs/|require\(\s*['"]@nestjs/`)
	nestClassRe   = regexp.MustCompile(`^(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)`)
	nestMethodRe  = regexp.MustCompile(`^(?:(?:public|private|protected|static|async|override|readonly)\s+)*\*?\s*([A-Za-z_$][\w$]*)\s*[<(]`)
	nestCtorRe    = regexp.MustCompile(`constructor\s*\(`)
	nestParamRe   = regexp.MustCompile(`(?:private|protected|public|readonly)\s+(?:readonly\s+)?([A-Za-z_$][\w$]*)\s*\??\s*:\s*([A-Za-z_$][\w$]*)`)
	nestThisCall  = regexp.MustCompile(`this\s*\.\s*([A-Za-z_$][\w$]*)\s*\.\s*[A-Za-z_$][\w$]*\s*\(`)
	nestPublicRe  = regexp.MustCompile(`^(?:Public|IsPublic|PublicRoute|SkipAuth|SkipJwtAuth|SkipAuthGuard|NoAuth|NoAuthRequired|AllowAnonymous|AllowUnauthenticated|AllowAny|Anonymous|OptionalAuth|Unprotected|SkipGuard)$`)
	nestGlobalGrd = regexp.MustCompile(`provide\s*:\s*APP_GUARD\s*,\s*use(?:Class|Existing|Value)\s*:\s*(?:new\s+)?([A-Za-z_$][\w$.]*)|use(?:Class|Existing|Value)\s*:\s*(?:new\s+)?([A-Za-z_$][\w$.]*)\s*,\s*provide\s*:\s*APP_GUARD`)
	nestUseGlobal = regexp.MustCompile(`\.\s*useGlobalGuards\s*\(`)
	nestPrefixRe  = regexp.MustCompile(`\.\s*setGlobalPrefix\s*\(`)
	nestVersionRe = regexp.MustCompile(`\.\s*enableVersioning\s*\(`)
	// Request interception this reader does not evaluate: Fastify hooks,
	// middleware applied through a module's configure(), and app.use(...).
	nestHookRe    = regexp.MustCompile(`\.\s*addHook\s*\(\s*['"](?:onRequest|preHandler|preValidation|preParsing)['"]`)
	nestMWApplyRe = regexp.MustCompile(`\.\s*apply\s*\(\s*([A-Za-z_$][\w$.]*)[^)]*\)\s*\.\s*(?:exclude\s*\([^)]*\)\s*\.\s*)?forRoutes\s*\(`)
	nestAppUseRe  = regexp.MustCompile(`\bapp\s*\.\s*use\s*\(\s*([A-Za-z_$][\w$.]*)`)
	nestBenignMW  = regexp.MustCompile(`(?i)log|cors|helmet|morgan|requestid|correlation|trace|compress|body|cookieparser|i18n|locale|timing|metric|csrf|json|urlencoded|static`)
	// nestUserParamRe: a parameter decorator that reads the authenticated caller.
	nestUserParamRe = regexp.MustCompile(`@(?:CurrentUser|GetUser|AuthUser|ReqUser|ActiveUser|AuthenticatedUser|LoggedUser|Principal|Session|Jwt|JwtPayload|UserId|CurrentUserId)\s*\(`)

	nestVerbs = map[string]string{"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "Options": "OPTIONS", "Head": "HEAD", "All": "ALL", "Sse": "GET"}
	// nestNotAccess: guards that match "guard" without controlling who the caller is.
	nestNotAccess = regexp.MustCompile(`(?i)throttl|ratelimit|limiter|cache|csrf|cors|validation|logging|timeout`)
)

type nestDecorator struct {
	name       string
	args       span // between the parentheses; empty span when none
	hasArgs    bool
	start, end int
}

// nestMember is a class member with the decorators written before it.
type nestMember struct {
	decos      []nestDecorator
	start, end int // of the signature and body, decorators excluded
	body       int // offset of the body's `{`, or -1
}

// nestScan walks the members of the brace-delimited region [from, to) at depth
// 0: a run of decorators, then a signature that ends at its body or a `;`.
func nestScan(code string, from, to int) []nestMember {
	var out []nestMember
	pos := from
	for pos < to {
		for pos < to && (isSpace(code[pos]) || code[pos] == ';') {
			pos++
		}
		if pos >= to {
			break
		}
		var decos []nestDecorator
		for pos < to && code[pos] == '@' {
			d, next, ok := nestDecoratorAt(code, pos, to)
			if !ok {
				break
			}
			decos = append(decos, d)
			pos = next
			for pos < to && isSpace(code[pos]) {
				pos++
			}
		}
		start := pos
		body := -1
		depth := 0
	run:
		for pos < to {
			switch c := code[pos]; c {
			case '(', '[':
				depth++
			case ')', ']':
				depth--
			case '{':
				if depth <= 0 {
					body = pos
					if end := matchClose(code, pos); end >= 0 {
						pos = end
					} else {
						pos = to
					}
					pos++
					break run
				}
				depth++
			case '}':
				depth--
			case ';':
				if depth <= 0 {
					pos++
					break run
				}
			case '@':
				// A decorator at the start of a line, outside any bracket,
				// begins the next member of a class written without semicolons.
				if depth <= 0 && pos > start && lineStartsAt(code, pos) {
					break run
				}
			}
			pos++
		}
		end := pos
		if end > to {
			end = to
		}
		if len(decos) > 0 || end > start {
			out = append(out, nestMember{decos: decos, start: start, end: end, body: body})
		}
	}
	return out
}

func lineStartsAt(code string, pos int) bool {
	for i := pos - 1; i >= 0; i-- {
		switch code[i] {
		case '\n':
			return true
		case ' ', '\t', '\r':
		default:
			return false
		}
	}
	return true
}

func nestDecoratorAt(code string, pos, to int) (nestDecorator, int, bool) {
	i := pos + 1
	for i < to && (isIdentByte(code[i]) || code[i] == '.') {
		i++
	}
	if i == pos+1 {
		return nestDecorator{}, pos, false
	}
	d := nestDecorator{name: code[pos+1 : i], start: pos}
	j := i
	for j < to && isSpace(code[j]) {
		j++
	}
	if j < to && code[j] == '(' {
		end := matchClose(code, j)
		if end < 0 || end >= to {
			return nestDecorator{}, pos, false
		}
		d.args, d.hasArgs = span{j + 1, end}, true
		i = end + 1
	}
	d.end = i
	return d, i, true
}

// nestPaths reads the path argument of a route or controller decorator: none
// (""), one literal, an array of literals, or an object's `path` property.
// ok is false when the path is not a literal this reader can read.
func nestPaths(f *jsFile, d nestDecorator, objectKey bool) (paths []string, version string, ok bool) {
	if !d.hasArgs {
		return []string{""}, "", true
	}
	args := trimSpan(f.code, d.args)
	if args.end <= args.start {
		return []string{""}, "", true
	}
	first := splitArgs(f.code, d.args.start, d.args.end)
	if len(first) == 0 {
		return []string{""}, "", true
	}
	a := first[0]
	if v, isLit := stringLiteral(f.raw, f.code, a); isLit {
		return []string{v}, "", true
	}
	switch f.code[a.start] {
	case '[':
		end := matchClose(f.code, a.start)
		if end < 0 {
			return nil, "", false
		}
		for _, e := range splitArgs(f.code, a.start+1, end) {
			v, isLit := stringLiteral(f.raw, f.code, e)
			if !isLit {
				return nil, "", false
			}
			paths = append(paths, v)
		}
		if len(paths) == 0 {
			return []string{""}, "", true
		}
		return paths, "", true
	case '{':
		if !objectKey {
			return nil, "", false
		}
		end := matchClose(f.code, a.start)
		if end < 0 {
			return nil, "", false
		}
		paths = []string{""}
		for _, prop := range splitArgs(f.code, a.start+1, end) {
			colon := strings.IndexByte(f.code[prop.start:prop.end], ':')
			if colon < 0 {
				continue
			}
			key := strings.TrimSpace(f.code[prop.start : prop.start+colon])
			val := trimSpan(f.code, span{prop.start + colon + 1, prop.end})
			switch key {
			case "path":
				v, isLit := stringLiteral(f.raw, f.code, val)
				if !isLit {
					return nil, "", false
				}
				paths = []string{v}
			case "version":
				if v, isLit := stringLiteral(f.raw, f.code, val); isLit {
					version = v
				}
			}
		}
		return paths, version, true
	}
	return nil, "", false
}

// nestGuardNames splits a decorator's arguments into the guard names they
// reference: `AuthGuard('jwt')` -> AuthGuard, `new RolesGuard(r)` -> RolesGuard.
func nestGuardNames(f *jsFile, d nestDecorator) []string {
	if !d.hasArgs {
		return nil
	}
	var out []string
	for _, a := range splitArgs(f.code, d.args.start, d.args.end) {
		t := strings.TrimSpace(f.sans[a.start:a.end])
		t = strings.TrimPrefix(t, "new ")
		t = strings.TrimSpace(t)
		end := 0
		for end < len(t) && (isIdentByte(t[end]) || t[end] == '.') {
			end++
		}
		if end > 0 {
			out = append(out, t[:end])
		}
	}
	return out
}

type nestGuardClass int

const (
	nestGuardOther nestGuardClass = iota // present, cannot be named as access control
	nestGuardAuthn
	nestGuardAuthz
	nestGuardIgnored // a rate limiter and the like: not access control
)

func classifyNestGuard(name string) nestGuardClass {
	base := name
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		base = base[i+1:]
	}
	switch {
	case nestNotAccess.MatchString(base) || notAccessControlRe.MatchString(base):
		return nestGuardIgnored
	case authzMWRe.MatchString(base):
		return nestGuardAuthz
	case authnName(base):
		return nestGuardAuthn
	}
	return nestGuardOther
}

// nestScope is what one Nest application declares for itself: its global
// guards, global prefix and URI versioning. A repository can hold many
// applications (a monorepo, the framework's own integration apps), and a
// guard registered in one says nothing about a controller in another, so each
// declaration applies only under the directory of the application that makes it.
type nestScope struct {
	root         string
	authn, authz string
	prefix       string
	versioned    bool
}

// nestGlobals is the repository-wide picture.
type nestGlobals struct {
	scopes []*nestScope
	// unseen: something that may guard routes and that this reader does not
	// evaluate (application middleware, Fastify hooks, a guard it cannot name)
	// exists. It is repository-wide on purpose: silence is the safe direction.
	unseen bool
}

// nestAppRoot is the directory an application's declarations govern: the
// parent of its src directory, or the file's own directory when it has none.
func nestAppRoot(file string) string {
	segs := strings.Split(file, "/")
	for i := len(segs) - 2; i >= 0; i-- {
		if segs[i] == "src" {
			return strings.Join(segs[:i], "/")
		}
	}
	return strings.Join(segs[:len(segs)-1], "/")
}

func nestUnder(root, file string) bool {
	return root == "" || strings.HasPrefix(file, root+"/")
}

func (g *nestGlobals) scopeFor(root string) *nestScope {
	for _, s := range g.scopes {
		if s.root == root {
			return s
		}
	}
	s := &nestScope{root: root}
	g.scopes = append(g.scopes, s)
	return s
}

// of returns the most specific scope that governs file, or nil.
func (g *nestGlobals) of(file string) *nestScope {
	var best *nestScope
	for _, s := range g.scopes {
		if nestUnder(s.root, file) && (best == nil || len(s.root) > len(best.root)) {
			best = s
		}
	}
	return best
}

func (ix *index) nestGlobals(nestFiles []*jsFile) nestGlobals {
	var g nestGlobals
	for _, f := range nestFiles {
		sc := &nestScope{}
		classify := func(label, name string) {
			switch classifyNestGuard(name) {
			case nestGuardAuthn:
				if sc.authn == "" {
					sc.authn = label
				}
			case nestGuardAuthz:
				if sc.authz == "" {
					sc.authz = label
				}
			case nestGuardOther:
				g.unseen = true
			}
		}
		for _, m := range nestGlobalGrd.FindAllStringSubmatch(f.sans, -1) {
			name := m[1] + m[2]
			classify("global guard "+name, name)
		}
		for _, m := range nestUseGlobal.FindAllStringIndex(f.code, -1) {
			end := matchClose(f.code, m[1]-1)
			if end < 0 {
				g.unseen = true
				continue
			}
			d := nestDecorator{hasArgs: true, args: span{m[1], end}}
			for _, name := range nestGuardNames(f, d) {
				classify("global guard "+name, name)
			}
		}
		if nestHookRe.MatchString(f.sans) {
			g.unseen = true
		}
		for _, m := range nestMWApplyRe.FindAllStringSubmatch(f.sans, -1) {
			if !nestBenignMW.MatchString(m[1]) {
				g.unseen = true
			}
		}
		for _, m := range nestAppUseRe.FindAllStringSubmatch(f.sans, -1) {
			if !nestBenignMW.MatchString(m[1]) && authnName(m[1]) {
				g.unseen = true
			}
		}
		for _, m := range nestPrefixRe.FindAllStringIndex(f.code, -1) {
			end := matchClose(f.code, m[1]-1)
			if end < 0 {
				continue
			}
			args := splitArgs(f.code, m[1], end)
			if len(args) > 0 {
				if v, ok := stringLiteral(f.raw, f.code, args[0]); ok {
					sc.prefix = v
				}
			}
		}
		for _, m := range nestVersionRe.FindAllStringIndex(f.code, -1) {
			end := matchClose(f.code, m[1]-1)
			if end > 0 && strings.Contains(f.sans[m[1]:end], "VersioningType.URI") {
				sc.versioned = true
			}
		}
		if sc.authn == "" && sc.authz == "" && sc.prefix == "" && !sc.versioned {
			continue
		}
		dst := g.scopeFor(nestAppRoot(f.path))
		if dst.authn == "" {
			dst.authn = sc.authn
		}
		if dst.authz == "" {
			dst.authz = sc.authz
		}
		if dst.prefix == "" {
			dst.prefix = sc.prefix
		}
		dst.versioned = dst.versioned || sc.versioned
	}
	return g
}

// nestRoutes reads every Nest controller among the JavaScript/TypeScript files.
func (ix *index) nestRoutes() ([]Route, []routeView) {
	var nestFiles []*jsFile
	for _, p := range ix.order {
		if f := ix.files[p]; nestImportRe.MatchString(f.sans) {
			nestFiles = append(nestFiles, f)
		}
	}
	if len(nestFiles) == 0 {
		return nil, nil
	}
	g := ix.nestGlobals(nestFiles)
	classes := ix.nestClassBodies(nestFiles)
	var routes []Route
	var views []routeView
	for _, f := range nestFiles {
		for _, c := range nestScan(f.code, 0, len(f.code)) {
			rs, vs := nestController(f, c, g, classes)
			routes, views = append(routes, rs...), append(views, vs...)
		}
	}
	return routes, views
}

// nestClassBodies maps a class name to the comment-free text of its body, over
// every Nest file, so a controller's injected service can be read one level.
func (ix *index) nestClassBodies(files []*jsFile) map[string][]string {
	out := map[string][]string{}
	for _, f := range files {
		for _, m := range nestScan(f.code, 0, len(f.code)) {
			if m.body < 0 {
				continue
			}
			cm := nestClassRe.FindStringSubmatch(f.code[m.start:m.body])
			if cm == nil {
				continue
			}
			if end := matchClose(f.code, m.body); end > 0 {
				out[cm[1]] = append(out[cm[1]], f.sans[m.body:end+1])
			}
		}
	}
	return out
}

func nestController(f *jsFile, c nestMember, g nestGlobals, classes map[string][]string) ([]Route, []routeView) {
	sc := g.of(f.path)
	if c.body < 0 {
		return nil, nil
	}
	var ctl *nestDecorator
	for i := range c.decos {
		if c.decos[i].name == "Controller" {
			ctl = &c.decos[i]
		}
	}
	if ctl == nil || !nestClassRe.MatchString(f.code[c.start:c.body]) {
		return nil, nil
	}
	prefixes, ctlVersion, ok := nestPaths(f, *ctl, true)
	if !ok {
		return nil, nil // @Controller(ROUTES.USERS): not resolved, not guessed
	}
	end := matchClose(f.code, c.body)
	if end < 0 {
		return nil, nil
	}
	services := nestInjected(f, c.body, end)

	var classAuthn, classAuthz string
	classUnseen, classPublic := false, false
	classChain := ""
	for _, d := range c.decos {
		nestApplyDecorator(f, d, &classAuthn, &classAuthz, &classUnseen, &classPublic)
		classChain += " " + f.sans[d.start:d.end]
	}

	var routes []Route
	var views []routeView
	for _, m := range nestScan(f.code, c.body+1, end) {
		if m.body < 0 {
			continue
		}
		var verbs []nestDecorator
		chain := classChain
		authn, authz := classAuthn, classAuthz
		unseen, public := classUnseen, classPublic
		version := ctlVersion
		for _, d := range m.decos {
			if _, isVerb := nestVerbs[d.name]; isVerb {
				verbs = append(verbs, d)
				continue
			}
			if d.name == "Version" && d.hasArgs {
				if v, isLit := stringLiteral(f.raw, f.code, trimSpan(f.code, d.args)); isLit {
					version = v
				}
			}
			nestApplyDecorator(f, d, &authn, &authz, &unseen, &public)
			chain += " " + f.sans[d.start:d.end]
		}
		if len(verbs) == 0 || nestMethodRe.FindStringSubmatch(f.code[m.start:m.end]) == nil {
			continue
		}
		handler := f.sans[m.start:m.end]
		known := true
		for _, tc := range nestThisCall.FindAllStringSubmatch(f.sans[m.start:m.end], -1) {
			if class, resolved := services[tc[1]]; resolved {
				for _, b := range classes[class] {
					handler += "\n" + b
				}
				if len(classes[class]) == 0 {
					known = false
				}
			} else if !nestHarmlessField(tc[1]) {
				known = false
			}
		}
		unseenHere := unseen || g.unseen
		if sc != nil && authn == "" && authz == "" && !public {
			if sc.authn != "" {
				authn = sc.authn
			} else if sc.authz != "" {
				authz = sc.authz
			}
		}
		if sc == nil && g.anyGuard() && !public {
			// Another application in this repository registers a guard. It is
			// not this controller's, but this reader cannot tell the
			// applications apart with certainty: say nothing rather than guess.
			unseenHere = true
		}
		if authn == "" && authz == "" && (jsInlineAuthRe.MatchString(handler) || nextAuthRe.MatchString(handler) || nestUserParamRe.MatchString(handler)) {
			authn = inlineAuthLabel
		}
		for _, vd := range verbs {
			paths, ok := nestRoutePaths(f, vd, prefixes)
			if !ok {
				continue
			}
			method := nestVerbs[vd.name]
			for _, p := range paths {
				full := nestJoin(sc, version, p)
				rt := Route{Method: method, Path: full, FilePath: f.path, Line: lineAt(f.lineStarts, vd.start), Authn: authn, Authz: authz}
				routes = append(routes, rt)
				views = append(views, routeView{route: rt, handler: handler, known: known, chain: chain,
					guardUnseen: unseenHere, declaredPublic: public, framework: "nestjs"})
			}
		}
	}
	return routes, views
}

// nestRoutePaths joins each controller prefix with the method's own path.
func nestRoutePaths(f *jsFile, verb nestDecorator, prefixes []string) ([]string, bool) {
	own, _, ok := nestPaths(f, verb, false)
	if !ok {
		return nil, false
	}
	var out []string
	for _, p := range prefixes {
		for _, o := range own {
			out = append(out, strings.TrimRight(p, "/")+"/"+strings.TrimLeft(o, "/"))
		}
	}
	return out, true
}

func nestJoin(sc *nestScope, version, p string) string {
	var parts []string
	if sc != nil {
		parts = append(parts, strings.Trim(sc.prefix, "/"))
	}
	if sc != nil && sc.versioned && version != "" {
		parts = append(parts, "v"+version)
	}
	parts = append(parts, strings.Trim(p, "/"))
	var kept []string
	for _, s := range parts {
		if s != "" {
			kept = append(kept, s)
		}
	}
	return "/" + strings.Join(kept, "/")
}

// nestApplyDecorator folds one non-route decorator into what protects a route.
func nestApplyDecorator(f *jsFile, d nestDecorator, authn, authz *string, unseen, public *bool) {
	switch {
	case nestPublicRe.MatchString(d.name):
		*public = true
	case d.name == "UseGuards":
		for _, name := range nestGuardNames(f, d) {
			label := "@UseGuards(" + name + ")"
			switch classifyNestGuard(name) {
			case nestGuardAuthn:
				if *authn == "" {
					*authn = label
				}
			case nestGuardAuthz:
				if *authz == "" {
					*authz = label
				}
			case nestGuardOther:
				*unseen = true
			}
		}
	}
}

// nestInjected maps constructor-injected field names to their class names.
func nestInjected(f *jsFile, bodyStart, bodyEnd int) map[string]string {
	out := map[string]string{}
	text := f.sans[bodyStart:bodyEnd]
	loc := nestCtorRe.FindStringIndex(text)
	if loc == nil {
		return out
	}
	open := bodyStart + loc[1] - 1
	end := matchClose(f.code, open)
	if end < 0 {
		return out
	}
	for _, m := range nestParamRe.FindAllStringSubmatch(f.sans[open:end], -1) {
		out[m[1]] = m[2]
	}
	return out
}

// nestHarmlessField: a field whose methods cannot be what verifies a request.
func nestHarmlessField(name string) bool {
	switch strings.ToLower(name) {
	case "logger", "log", "config", "configservice", "reflector", "i18n", "metrics":
		return true
	}
	return false
}

// anyGuard: some application in the repository registers an authenticating or
// authorizing guard.
func (g nestGlobals) anyGuard() bool {
	for _, s := range g.scopes {
		if s.authn != "" || s.authz != "" {
			return true
		}
	}
	return false
}
