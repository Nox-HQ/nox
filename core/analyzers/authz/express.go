package authz

import (
	"bytes"
	"path"
	"regexp"
	"strings"
)

// jsFile is one JavaScript/TypeScript file as the Express reader sees it.
type jsFile struct {
	path       string // repo-relative, forward slashes
	raw        []byte
	code       string // lexctx.MaskNonCode(raw)
	sans       string // raw with comments blanked, strings kept
	lineStarts []int
	// modules maps a local binding to the repo-relative file it names: a
	// `require('./x')`, an `import * as x` / default import, or an instance
	// `new X(...)` of such a binding.
	modules map[string]string
	// named maps a local binding to (file, exported name) for a destructured
	// require or a named import.
	named map[string]namedImport
	// defs indexes candidate definitions by name (see definitions).
	defs map[string][]defCand
}

type namedImport struct{ file, name string }

// route is one Express route registration.
type route struct {
	file     *jsFile
	offset   int // of the registration
	receiver string
	method   string
	path     string
	params   []string
	// args are the arguments after the path: middleware and the handler.
	// Which one handles the request is decided by the body analysis, not by
	// position: `.get(auth, handler, guard.check([...]))` is real code.
	args []span
}

// use is one `X.use(...)` call: an optional path prefix, middleware, and any
// arguments that resolve to a router file (a mount).
type use struct {
	file     *jsFile
	offset   int
	receiver string
	prefix   string
	mw       []span
	mounts   []string // repo-relative files mounted by this call
}

var (
	// An optional TypeScript type argument sits between the method and the call
	// (`fastify.get<{ Params: { id: string } }>('/x/:id', ...)`).
	routeMethodRe = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|del|all)\s*(?:<[^()]*>)?\s*\(`)
	routeChainRe  = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(`)
	chainMethodRe = regexp.MustCompile(`^\s*\.\s*(get|post|put|patch|delete|del|all)\s*\(`)
	useRe         = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(`)
	paramRe       = regexp.MustCompile(`\.\s*param\s*\(\s*(['"])`)
	routerDeclRe  = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?(?:express\s*\(|express\s*\.\s*Router\s*\(|Router\s*\()`)
	pathParamRe   = regexp.MustCompile(`:([A-Za-z_$][\w$]*)`)

	// fastifyDeclRe: `const app = Fastify(...)` / `fastify()` / `require('fastify')()`.
	fastifyDeclRe = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:[Ff]astify\s*\(|(require\s*\(\s*['"][^'"]*['"]\s*\)\s*\())`)
	// A Fastify plugin is `function (instance, opts[, done])`.
	fastifyPluginFnRe    = regexp.MustCompile(`\bfunction\s*\*?\s*[A-Za-z_$]*\s*\(\s*([A-Za-z_$][\w$]*)\s*(?::[^,)]+)?,\s*_?(?:opts|options|done|next)\b`)
	fastifyPluginArrowRe = regexp.MustCompile(`\(\s*([A-Za-z_$][\w$]*)\s*(?::[^,)]+)?,\s*_?(?:opts|options|done)\b[^)]*\)\s*(?::[^=]+)?=>`)
	fastifyRouteCallRe   = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*route\s*(?:<[^()]*>)?\s*\(\s*\{`)
	fastifyHookCallRe    = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*addHook\s*\(`)
	fastifyRegisterRe    = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*register\s*\(`)

	requireRe       = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*(['"])`)
	requireDestRe   = regexp.MustCompile(`\b(?:const|let|var)\s+\{([^}]*)\}\s*=\s*require\s*\(\s*(['"])`)
	importDefaultRe = regexp.MustCompile(`\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{([^}]*)\})?\s*from\s*(['"])`)
	importNamedRe   = regexp.MustCompile(`\bimport\s*\{([^}]*)\}\s*from\s*(['"])`)
	newInstanceRe   = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*=\s*new\s+([A-Za-z_$][\w$]*)\s*\(`)
	inlineRequireRe = regexp.MustCompile(`^require\s*\(\s*(['"])`)
)

// conventionalRouterNames are receivers an Express app or router is commonly
// bound to. A receiver outside this set counts only when the file declares it
// from express()/Router(): `cache.get('/a/:b', fn)` is not a route.
var conventionalRouterNames = map[string]bool{
	"app": true, "router": true, "api": true, "routes": true, "route": true,
	"server": true, "r": true, "apiRouter": true, "userRouter": true,
	// Fastify's instance is conventionally `fastify`, and a plugin receives
	// the encapsulated instance as its first parameter.
	"fastify": true, "instance": true,
}

func routerReceiver(recv string, declared map[string]bool) bool {
	if conventionalRouterNames[recv] || declared[recv] {
		return true
	}
	lower := strings.ToLower(recv)
	return strings.HasSuffix(lower, "router") || strings.HasSuffix(lower, "routes")
}

func declaredRouters(f *jsFile) map[string]bool {
	out := map[string]bool{}
	for _, m := range routerDeclRe.FindAllStringSubmatch(f.code, -1) {
		out[m[1]] = true
	}
	for _, m := range fastifyDeclRe.FindAllStringSubmatchIndex(f.code, -1) {
		// require('fastify')() has its module name in a string: read it raw.
		if m[4] < 0 || bytes.Contains(f.raw[m[0]:m[1]], []byte("fastify")) {
			out[f.code[m[2]:m[3]]] = true
		}
	}
	if bytes.Contains(f.raw, []byte("fastify")) {
		for _, re := range []*regexp.Regexp{fastifyPluginFnRe, fastifyPluginArrowRe} {
			for _, m := range re.FindAllStringSubmatch(f.code, -1) {
				out[m[1]] = true
			}
		}
	}
	return out
}

// parseRoutes finds `R.method('/path', ...mw, handler)` and
// `R.route('/path').method(...mw, handler)` registrations.
func parseRoutes(f *jsFile) []route {
	declared := declaredRouters(f)
	var out []route
	for _, m := range routeMethodRe.FindAllStringSubmatchIndex(f.code, -1) {
		recv := f.code[m[2]:m[3]]
		if !routerReceiver(recv, declared) {
			continue
		}
		open := m[1] - 1
		closeAt := matchClose(f.code, open)
		if closeAt < 0 {
			continue
		}
		args := splitArgs(f.code, open+1, closeAt)
		if len(args) < 2 {
			continue // app.get('setting') reads a setting; a route needs a handler
		}
		p, ok := stringLiteral(f.raw, f.code, args[0])
		if !ok || !strings.HasPrefix(p, "/") {
			continue
		}
		out = append(out, newRoute(f, m[0], recv, f.code[m[4]:m[5]], p, args[1:]))
	}
	out = append(out, parseFastifyRoutes(f)...)
	for _, m := range routeChainRe.FindAllStringSubmatchIndex(f.code, -1) {
		recv := f.code[m[2]:m[3]]
		if !routerReceiver(recv, declared) {
			continue
		}
		open := m[1] - 1
		closeAt := matchClose(f.code, open)
		if closeAt < 0 {
			continue
		}
		args := splitArgs(f.code, open+1, closeAt)
		if len(args) != 1 {
			continue
		}
		p, ok := stringLiteral(f.raw, f.code, args[0])
		if !ok || !strings.HasPrefix(p, "/") {
			continue
		}
		at := closeAt + 1
		for {
			cm := chainMethodRe.FindStringSubmatchIndex(f.code[at:])
			if cm == nil {
				break
			}
			copen := at + cm[1] - 1
			cclose := matchClose(f.code, copen)
			if cclose < 0 {
				break
			}
			cargs := splitArgs(f.code, copen+1, cclose)
			if len(cargs) >= 1 {
				out = append(out, newRoute(f, at+cm[2], recv, f.code[at+cm[2]:at+cm[3]], p, cargs))
			}
			at = cclose + 1
		}
	}
	return out
}

func newRoute(f *jsFile, off int, recv, method, p string, rest []span) route {
	r := route{file: f, offset: off, receiver: recv, method: method, path: p}
	for _, pm := range pathParamRe.FindAllStringSubmatch(p, -1) {
		r.params = append(r.params, pm[1])
	}
	r.args = fastifyRouteArgs(f, rest)
	return r
}

// fastifyHooks are the lifecycle hooks that run before a Fastify handler,
// where authentication and authorization live.
var fastifyHooks = setOf("onRequest", "preParsing", "preValidation", "preHandler", "beforeHandler")

// fastifyRouteArgs flattens a route's options object. Fastify takes
// `fastify.get(path, { preHandler: [auth] }, handler)` and
// `fastify.route({ method, url, preHandler, handler })`: the hook values are
// the route's middleware and the `handler` value is its handler. Express routes
// never pass an object literal, so for them this is the identity.
func fastifyRouteArgs(f *jsFile, rest []span) []span {
	out := make([]span, 0, len(rest))
	for _, a := range rest {
		if a.end-a.start < 2 || f.code[a.start] != '{' || matchClose(f.code, a.start) != a.end-1 {
			out = append(out, a)
			continue
		}
		for _, prop := range splitArgs(f.code, a.start+1, a.end-1) {
			key, val, ok := splitProp(f.code, prop)
			switch {
			case !ok:
			case key == "handler":
				out = append(out, val)
			case fastifyHooks[key]:
				out = append(out, hookValues(f, val)...)
			}
		}
	}
	return out
}

// splitProp splits `key: value` (or the shorthand `key`) at the first
// top-level colon.
func splitProp(code string, prop span) (key string, val span, ok bool) {
	text := code[prop.start:prop.end]
	depth := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ':':
			if depth == 0 {
				k := strings.Trim(strings.TrimSpace(text[:i]), `'"`+"`")
				v := trimSpan(code, span{prop.start + i + 1, prop.end})
				return k, v, k != "" && v.end > v.start
			}
		}
	}
	if isPlainIdent(strings.TrimSpace(text)) {
		return strings.TrimSpace(text), prop, true
	}
	return "", span{}, false
}

// hookValues returns the functions a hook option names: one, or each element
// of an array.
func hookValues(f *jsFile, val span) []span {
	if val.end-val.start >= 2 && f.code[val.start] == '[' && matchClose(f.code, val.start) == val.end-1 {
		return splitArgs(f.code, val.start+1, val.end-1)
	}
	return []span{val}
}

var quotedRe = regexp.MustCompile(`['"]([A-Za-z]+)['"]`)

// parseFastifyRoutes finds `fastify.route({ method, url, preHandler, handler })`.
func parseFastifyRoutes(f *jsFile) []route {
	declared := declaredRouters(f)
	var out []route
	for _, m := range fastifyRouteCallRe.FindAllStringSubmatchIndex(f.code, -1) {
		recv := f.code[m[2]:m[3]]
		if !routerReceiver(recv, declared) {
			continue
		}
		open := m[1] - 1 // the `{`
		closeAt := matchClose(f.code, open)
		if closeAt < 0 {
			continue
		}
		var method, url string
		hasHandler := false
		for _, prop := range splitArgs(f.code, open+1, closeAt) {
			key, val, ok := splitProp(f.code, prop)
			if !ok {
				continue
			}
			switch key {
			case "method":
				if q := quotedRe.FindSubmatch(f.raw[val.start:val.end]); q != nil {
					method = string(q[1])
				}
			case "url", "path":
				if p, ok := stringLiteral(f.raw, f.code, val); ok {
					url = p
				}
			case "handler":
				hasHandler = true
			}
		}
		if method == "" || !strings.HasPrefix(url, "/") || !hasHandler {
			continue
		}
		// The whole options object is the route's argument: newRoute flattens
		// it the same way as a get() options argument.
		out = append(out, newRoute(f, m[0], recv, strings.ToLower(method), url, []span{{open, closeAt + 1}}))
	}
	return out
}

// parseFastifyUses finds `fastify.addHook('onRequest', auth)` (middleware for
// every later route on the instance) and `fastify.register(plugin, { prefix })`
// (a mount, like Express's `app.use('/x', router)`).
func parseFastifyUses(f *jsFile, resolve func(f *jsFile, s span) string) []use {
	declared := declaredRouters(f)
	var out []use
	for _, m := range fastifyHookCallRe.FindAllStringSubmatchIndex(f.code, -1) {
		recv := f.code[m[2]:m[3]]
		if !routerReceiver(recv, declared) {
			continue
		}
		closeAt := matchClose(f.code, m[1]-1)
		if closeAt < 0 {
			continue
		}
		args := splitArgs(f.code, m[1], closeAt)
		if len(args) < 2 {
			continue
		}
		if name, ok := stringLiteral(f.raw, f.code, args[0]); ok && fastifyHooks[name] {
			out = append(out, use{file: f, offset: m[0], receiver: recv, mw: args[1:]})
		}
	}
	for _, m := range fastifyRegisterRe.FindAllStringSubmatchIndex(f.code, -1) {
		recv := f.code[m[2]:m[3]]
		if !routerReceiver(recv, declared) {
			continue
		}
		closeAt := matchClose(f.code, m[1]-1)
		if closeAt < 0 {
			continue
		}
		args := splitArgs(f.code, m[1], closeAt)
		if len(args) == 0 {
			continue
		}
		target := resolve(f, args[0])
		if target == "" || target == f.path {
			continue
		}
		u := use{file: f, offset: m[0], receiver: recv, mounts: []string{target}}
		if len(args) > 1 && args[1].end-args[1].start >= 2 && f.code[args[1].start] == '{' {
			for _, prop := range splitArgs(f.code, args[1].start+1, args[1].end-1) {
				if key, val, ok := splitProp(f.code, prop); ok && key == "prefix" {
					u.prefix, _ = stringLiteral(f.raw, f.code, val)
				}
			}
		}
		out = append(out, u)
	}
	return out
}

// parseUses finds every `R.use(...)` call on a router receiver.
func parseUses(f *jsFile, resolve func(f *jsFile, s span) string) []use {
	declared := declaredRouters(f)
	var out []use
	for _, m := range useRe.FindAllStringSubmatchIndex(f.code, -1) {
		recv := f.code[m[2]:m[3]]
		if !routerReceiver(recv, declared) {
			continue
		}
		open := m[1] - 1
		closeAt := matchClose(f.code, open)
		if closeAt < 0 {
			continue
		}
		args := splitArgs(f.code, open+1, closeAt)
		u := use{file: f, offset: m[0], receiver: recv}
		for i, a := range args {
			if i == 0 {
				if p, ok := stringLiteral(f.raw, f.code, a); ok {
					u.prefix = p
					continue
				}
			}
			if target := resolve(f, a); target != "" && target != f.path {
				u.mounts = append(u.mounts, target)
				continue
			}
			u.mw = append(u.mw, a)
		}
		out = append(out, u)
	}
	return out
}

// parseParamLoaders returns the route parameters a `router.param('id', fn)`
// call loads: Express runs fn for every route on that parameter, which is
// where an ownership check commonly lives.
func parseParamLoaders(f *jsFile) map[string]bool {
	out := map[string]bool{}
	for _, m := range paramRe.FindAllStringSubmatchIndex(f.code, -1) {
		q := m[2]
		end := strings.IndexByte(f.code[q+1:], f.code[q])
		if end > 0 {
			out[string(f.raw[q+1:q+1+end])] = true
		}
	}
	return out
}

// parseImports fills f.modules and f.named from require/import statements.
// specifier resolves a module specifier relative to f to a repo file, or "".
func parseImports(f *jsFile, specifier func(from, spec string) string) {
	f.modules = map[string]string{}
	f.named = map[string]namedImport{}
	quoted := func(quoteAt int) string {
		q := f.code[quoteAt]
		end := strings.IndexByte(f.code[quoteAt+1:], q)
		if end < 0 {
			return ""
		}
		return string(f.raw[quoteAt+1 : quoteAt+1+end])
	}
	for _, m := range requireRe.FindAllStringSubmatchIndex(f.code, -1) {
		if t := specifier(f.path, quoted(m[4])); t != "" {
			f.modules[f.code[m[2]:m[3]]] = t
		}
	}
	for _, m := range requireDestRe.FindAllStringSubmatchIndex(f.code, -1) {
		if t := specifier(f.path, quoted(m[4])); t != "" {
			addNamed(f, f.code[m[2]:m[3]], t, ":")
		}
	}
	for _, m := range importDefaultRe.FindAllStringSubmatchIndex(f.code, -1) {
		t := specifier(f.path, quoted(m[6]))
		if t == "" {
			continue
		}
		f.modules[f.code[m[2]:m[3]]] = t
		if m[4] >= 0 {
			addNamed(f, f.code[m[4]:m[5]], t, " as ")
		}
	}
	for _, m := range importNamedRe.FindAllStringSubmatchIndex(f.code, -1) {
		if t := specifier(f.path, quoted(m[4])); t != "" {
			addNamed(f, f.code[m[2]:m[3]], t, " as ")
		}
	}
	for _, m := range newInstanceRe.FindAllStringSubmatch(f.code, -1) {
		if t, ok := f.modules[m[2]]; ok {
			f.modules[m[1]] = t
		} else if n, ok := f.named[m[2]]; ok {
			f.modules[m[1]] = n.file
		}
	}
}

// addNamed records `a, b: c` (require destructuring) or `a, b as c` (import).
func addNamed(f *jsFile, list, file, renameSep string) {
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "type ")
		if part == "" {
			continue
		}
		exported, local := part, part
		if i := strings.Index(part, renameSep); i >= 0 {
			exported = strings.TrimSpace(part[:i])
			local = strings.TrimSpace(part[i+len(renameSep):])
		}
		if j := strings.IndexByte(local, '='); j >= 0 {
			local = strings.TrimSpace(local[:j])
		}
		if local != "" && exported != "" {
			f.named[local] = namedImport{file: file, name: exported}
		}
	}
}

// jsExtensions are tried, in order, when a module specifier has none.
var jsExtensions = []string{".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", "/index.js", "/index.ts"}

// resolveSpecifier maps a relative module specifier to a known repo file.
func resolveSpecifier(files map[string]*jsFile) func(from, spec string) string {
	return func(from, spec string) string {
		if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") {
			return ""
		}
		base := path.Clean(path.Join(path.Dir(from), spec))
		if _, ok := files[base]; ok {
			return base
		}
		for _, ext := range jsExtensions {
			if _, ok := files[base+ext]; ok {
				return base + ext
			}
		}
		return ""
	}
}

// mountTarget resolves a `use` argument to the router file it mounts: an
// inline `require('./routes/x')`, or a binding imported from a file.
func mountTarget(spec func(from, spec string) string) func(f *jsFile, s span) string {
	return func(f *jsFile, s span) string {
		text := f.code[s.start:s.end]
		if m := inlineRequireRe.FindStringSubmatchIndex(text); m != nil {
			q := s.start + m[2]
			end := strings.IndexByte(f.code[q+1:], f.code[q])
			if end < 0 {
				return ""
			}
			return spec(f.path, string(f.raw[q+1:q+1+end]))
		}
		if !isPlainIdent(text) {
			return ""
		}
		if t, ok := f.modules[text]; ok {
			return t
		}
		if n, ok := f.named[text]; ok {
			return n.file
		}
		return ""
	}
}

func isPlainIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return s[0] < '0' || s[0] > '9'
}
