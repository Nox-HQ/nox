package authz

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// This file is the Python half of the route reader: Flask (Blueprints with
// url_prefix, `<int:id>` converters), FastAPI (APIRouter prefixes,
// include_router, path parameters as function arguments, Depends) and the
// registration shapes they share. Like the JavaScript reader it works on text
// masked by core/lexctx, so a route-looking string or comment is never code,
// and it resolves the app's structure (which router is mounted where, under
// what prefix, behind what dependency) before it judges a handler.

// pyFile is one Python file.
type pyFile struct {
	path       string
	raw        []byte
	code       string // lexctx.MaskNonCode(raw): same length, same offsets
	lineStarts []int
	// modules maps a local binding to the repo file it names (`import a.b as
	// c`, `from . import users`); named maps a local binding to (file, name)
	// for `from x import y as z`.
	modules map[string]string
	named   map[string]namedImport
}

type pyKey struct{ file, name string }

// pyDep is one access-control element in front of a handler: a decorator, a
// Depends()/Security() dependency, a router-level dependency or a
// before_request hook. inline marks a hook whose body is the text.
type pyDep struct {
	name   string // callable name, last dotted segment
	text   string // the whole expression (masked), for argument checks
	raw    string
	inline bool
}

// pyDecl is a Flask/FastAPI/Blueprint/APIRouter instance.
type pyDecl struct {
	prefix    string
	deps      []pyDep
	framework string // flask | fastapi
}

// pyInclude is one mount: parent.register_blueprint(child, url_prefix=…) or
// parent.include_router(child, prefix=…).
type pyInclude struct {
	parent pyKey
	prefix string
	deps   []pyDep
}

type pyParam struct{ name, annotation, def string }

// pyFunc is a handler: its parameters and body.
type pyFunc struct {
	name               string
	defOff             int
	params             []pyParam
	bodyStart, bodyEnd int
}

type pyRoute struct {
	file      *pyFile
	offset    int
	recv      pyKey
	framework string
	method    string
	path      string
	params    []string // path parameters
	deps      []pyDep  // decorators, dependencies=[…], Depends() parameters
	fn        pyFunc
}

type pyIndex struct {
	files    map[string]*pyFile
	order    []string
	decls    map[pyKey]*pyDecl
	includes map[pyKey]pyInclude
	hooks    map[pyKey][]pyDep
	aliases  map[string]pyDep // Annotated[User, Depends(get_current_user)] aliases
	consts   map[string][]string
	rls      bool
	routes   []pyRoute
}

var (
	pyDeclRe       = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*(?:[A-Za-z_][\w.]*\.)?(Flask|FastAPI|Blueprint|APIRouter|Quart)\s*\(`)
	pyMountRe      = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*\.\s*(register_blueprint|include_router)\s*\(`)
	pyAliasRe      = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_]\w*)\s*(?::\s*[\w.]+)?\s*=\s*Annotated\s*\[`)
	pyConstRe      = regexp.MustCompile(`(?m)^[ \t]*([A-Z][A-Z0-9_]*)\s*(?::\s*[\w\[\], .]+)?=\s*['"](/[^'"\n]*)['"]`)
	pyDefRe        = regexp.MustCompile(`(?m)^([ \t]*)(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w*)[ \t]*\(`)
	pyDecoRe       = regexp.MustCompile(`(?m)^[ \t]*@`)
	pyFromImportRe = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+(\([^)]*\)|[^\n]+)`)
	pyImportRe     = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([\w.]+)(?:[ \t]+as[ \t]+(\w+))?`)
	pyDependsRe    = regexp.MustCompile(`\b(?:Depends|Security)\s*\(\s*([A-Za-z_][\w.]*)?`)
	pyFlaskPathRe  = regexp.MustCompile(`<(?:[^<>:]+(?:\([^)]*\))?:)?([A-Za-z_]\w*)>`)
	pyFastPathRe   = regexp.MustCompile(`\{([A-Za-z_]\w*)(?::[^}]*)?\}`)
	pyKwargRe      = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=[^=]`)
	pyMethodStrRe  = regexp.MustCompile(`['"]([A-Za-z]+)['"]`)
)

// pyRouteVerbs are the decorator methods that register a route.
var pyRouteVerbs = setOf("route", "get", "post", "put", "patch", "delete", "api_route")

var pyConventionalRouters = setOf("app", "bp", "blueprint", "router", "api", "api_router", "routes", "main", "web")

// loadPy builds the index from the Python files.
func newPyIndex(files map[string]*pyFile, order []string, rls bool) *pyIndex {
	ix := &pyIndex{files: files, order: order, rls: rls,
		decls: map[pyKey]*pyDecl{}, includes: map[pyKey]pyInclude{}, hooks: map[pyKey][]pyDep{},
		aliases: map[string]pyDep{}, consts: map[string][]string{}}
	for _, p := range order {
		parsePyImports(ix, ix.files[p])
	}
	for _, p := range order {
		ix.parseDecls(ix.files[p])
		ix.parseAliasesAndConsts(ix.files[p])
	}
	for _, p := range order {
		ix.parseMounts(ix.files[p])
	}
	for _, p := range order {
		ix.parseFunctions(ix.files[p])
	}
	return ix
}

// ---- imports ----

func parsePyImports(ix *pyIndex, f *pyFile) {
	f.modules = map[string]string{}
	f.named = map[string]namedImport{}
	for _, m := range pyFromImportRe.FindAllStringSubmatch(f.code, -1) {
		dots, mod, names := len(m[1]), m[2], strings.Trim(m[3], "() \t")
		modFile := ix.resolveModule(f.path, dots, mod)
		for _, part := range strings.Split(strings.ReplaceAll(names, "\n", " "), ",") {
			part = strings.TrimSpace(part)
			if part == "" || part == "*" {
				continue
			}
			name, local := part, part
			if i := strings.Index(part, " as "); i >= 0 {
				name, local = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+4:])
			}
			joined := strings.Trim(mod+"."+name, ".")
			if sub := ix.resolveModule(f.path, dots, joined); sub != "" && sub != modFile {
				f.modules[local] = sub // `from . import users`: a submodule
			} else if modFile != "" {
				f.named[local] = namedImport{file: modFile, name: name}
			}
		}
	}
	for _, m := range pyImportRe.FindAllStringSubmatch(f.code, -1) {
		target := ix.resolveModule(f.path, 0, m[1])
		if target == "" {
			continue
		}
		local := m[2]
		if local == "" {
			local = strings.SplitN(m[1], ".", 2)[0]
			if strings.Contains(m[1], ".") {
				continue // `import a.b` binds `a`, which is a package, not b
			}
		}
		f.modules[local] = target
	}
}

// resolveModule maps a (possibly relative) dotted module to a repo file, or "".
func (ix *pyIndex) resolveModule(from string, dots int, mod string) string {
	rel := strings.ReplaceAll(mod, ".", "/")
	if dots > 0 {
		base := path.Dir(from)
		for i := 1; i < dots; i++ {
			base = path.Dir(base)
		}
		return ix.moduleAt(path.Join(base, rel))
	}
	if rel == "" {
		return ""
	}
	var cands []string
	for _, p := range ix.order {
		stem := strings.TrimSuffix(p, ".py")
		stem = strings.TrimSuffix(stem, "/__init__")
		if stem == rel || strings.HasSuffix(stem, "/"+rel) {
			cands = append(cands, p)
		}
	}
	if len(cands) == 0 {
		return ""
	}
	// Prefer the candidate nearest the importing file, then the shortest path.
	sort.SliceStable(cands, func(i, j int) bool {
		ci, cj := commonDirPrefix(cands[i], from), commonDirPrefix(cands[j], from)
		if ci != cj {
			return ci > cj
		}
		return len(cands[i]) < len(cands[j])
	})
	return cands[0]
}

func commonDirPrefix(a, b string) int {
	as, bs := strings.Split(path.Dir(a), "/"), strings.Split(path.Dir(b), "/")
	n := 0
	for n < len(as) && n < len(bs) && as[n] == bs[n] {
		n++
	}
	return n
}

func (ix *pyIndex) moduleAt(base string) string {
	base = path.Clean(base)
	for _, c := range []string{base + ".py", base + "/__init__.py"} {
		if _, ok := ix.files[c]; ok {
			return c
		}
	}
	return ""
}

// ---- declarations, mounts, aliases ----

func (ix *pyIndex) parseDecls(f *pyFile) {
	for _, m := range pyDeclRe.FindAllStringSubmatchIndex(f.code, -1) {
		open := m[1] - 1
		closeAt := matchClose(f.code, open)
		if closeAt < 0 {
			continue
		}
		d := &pyDecl{framework: "flask"}
		if k := f.code[m[4]:m[5]]; k == "FastAPI" || k == "APIRouter" {
			d.framework = "fastapi"
		}
		args := splitArgs(f.code, open+1, closeAt)
		d.prefix = ix.prefixKwarg(f, args, "url_prefix", "prefix")
		d.deps = pyDepsKwarg(f, args)
		ix.decls[pyKey{f.path, f.code[m[2]:m[3]]}] = d
	}
}

func (ix *pyIndex) parseAliasesAndConsts(f *pyFile) {
	for _, m := range pyAliasRe.FindAllStringSubmatchIndex(f.code, -1) {
		open := m[1] - 1
		closeAt := matchClose(f.code, open)
		if closeAt < 0 {
			continue
		}
		if d := pyDependsRe.FindStringSubmatch(f.code[open:closeAt]); d != nil {
			ix.aliases[f.code[m[2]:m[3]]] = pyDep{name: lastDotted(d[1]), text: f.code[open:closeAt], raw: string(f.raw[open:closeAt])}
		}
	}
	for _, m := range pyConstRe.FindAllSubmatch(f.raw, -1) {
		ix.consts[string(m[1])] = append(ix.consts[string(m[1])], string(m[2]))
	}
}

func (ix *pyIndex) parseMounts(f *pyFile) {
	for _, m := range pyMountRe.FindAllStringSubmatchIndex(f.code, -1) {
		open := m[1] - 1
		closeAt := matchClose(f.code, open)
		if closeAt < 0 {
			continue
		}
		args := splitArgs(f.code, open+1, closeAt)
		if len(args) == 0 {
			continue
		}
		parent, ok := ix.resolveRouter(f, f.code[m[2]:m[3]])
		child, ok2 := ix.resolveRouter(f, strings.TrimSpace(f.code[args[0].start:args[0].end]))
		if !ok || !ok2 || parent == child {
			continue
		}
		if _, dup := ix.includes[child]; dup {
			continue // the first mount (files are read in path order) names the route
		}
		ix.includes[child] = pyInclude{parent: parent, prefix: ix.prefixKwarg(f, args[1:], "url_prefix", "prefix"), deps: pyDepsKwarg(f, args[1:])}
	}
}

// resolveRouter maps an expression (`bp`, `users.router`, an imported name) to
// the instance it names.
func (ix *pyIndex) resolveRouter(f *pyFile, expr string) (pyKey, bool) {
	segs := strings.Split(strings.ReplaceAll(expr, " ", ""), ".")
	for _, s := range segs {
		if !isPlainIdent(s) {
			return pyKey{}, false
		}
	}
	cur, name := f, segs[0]
	if len(segs) == 2 {
		target, ok := f.modules[segs[0]]
		if !ok {
			return pyKey{}, false
		}
		cur, name = ix.files[target], segs[1]
	} else if len(segs) != 1 {
		return pyKey{}, false
	}
	for hop := 0; hop < 4 && cur != nil; hop++ {
		if _, ok := ix.decls[pyKey{cur.path, name}]; ok {
			return pyKey{cur.path, name}, true
		}
		n, ok := cur.named[name]
		if !ok {
			break
		}
		cur, name = ix.files[n.file], n.name
	}
	return pyKey{}, false
}

// prefixKwarg reads a string-valued keyword argument. A value that is not a
// literal is resolved through a unique module-level string constant
// (`prefix=settings.API_V1_STR`), and otherwise kept as written in braces so a
// lead never shows a prefix it did not read.
func (ix *pyIndex) prefixKwarg(f *pyFile, args []span, keys ...string) string {
	for _, a := range args {
		k, v, ok := pyKwarg(f.code, a)
		if !ok {
			continue
		}
		for _, want := range keys {
			if k != want {
				continue
			}
			if s, ok := pyStringLit(f, v); ok {
				return s
			}
			expr := strings.TrimSpace(f.code[v.start:v.end])
			if vals := ix.consts[lastDotted(expr)]; len(vals) == 1 {
				return vals[0]
			}
			return "{" + compact(expr) + "}"
		}
	}
	return ""
}

func pyDepsKwarg(f *pyFile, args []span) []pyDep {
	var out []pyDep
	for _, a := range args {
		if k, v, ok := pyKwarg(f.code, a); ok && k == "dependencies" {
			out = append(out, pyDepsIn(f, v)...)
		}
	}
	return out
}

// pyDepsIn lists the Depends()/Security() calls in a span.
func pyDepsIn(f *pyFile, s span) []pyDep {
	var out []pyDep
	text := f.code[s.start:s.end]
	for _, m := range pyDependsRe.FindAllStringSubmatchIndex(text, -1) {
		end := s.start + m[1]
		if closeAt := matchClose(f.code, s.start+strings.IndexByte(text[m[0]:], '(')+m[0]); closeAt > 0 {
			end = closeAt + 1
		}
		name := ""
		if m[2] >= 0 {
			name = lastDotted(text[m[2]:m[3]])
		}
		out = append(out, pyDep{name: name, text: f.code[s.start+m[0] : end], raw: string(f.raw[s.start+m[0] : end])})
	}
	return out
}

func pyKwarg(code string, a span) (key string, val span, ok bool) {
	t := code[a.start:a.end]
	m := pyKwargRe.FindStringSubmatchIndex(t)
	if m == nil {
		return "", span{}, false
	}
	eq := strings.IndexByte(t, '=')
	return t[m[2]:m[3]], trimSpan(code, span{a.start + eq + 1, a.end}), true
}

// pyStringLit returns the value of the string literal s is exactly, with its
// prefix (r, b, u, f) and quotes removed. An f-string with a replacement field
// is not a literal.
func pyStringLit(f *pyFile, s span) (string, bool) {
	t := strings.TrimSpace(string(f.raw[s.start:s.end]))
	i := 0
	for i < len(t) && i < 2 && strings.ContainsRune("rRbBuUfF", rune(t[i])) {
		i++
	}
	prefix := strings.ToLower(t[:i])
	t = t[i:]
	for _, q := range []string{`"""`, `'''`, `"`, `'`} {
		if strings.HasPrefix(t, q) && strings.HasSuffix(t, q) && len(t) >= 2*len(q) {
			val := t[len(q) : len(t)-len(q)]
			if strings.Contains(prefix, "f") && strings.ContainsAny(val, "{}") {
				return "", false
			}
			return val, true
		}
	}
	return "", false
}

func lastDotted(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

// fullPrefix is the path a router is served under: its own prefix, the prefix
// of the include that mounts it, and the prefixes above that.
func (ix *pyIndex) fullPrefix(k pyKey) string {
	prefix, cur, seen := "", k, map[pyKey]bool{}
	for depth := 0; depth < 8 && !seen[cur]; depth++ {
		seen[cur] = true
		d := ix.decls[cur]
		if d != nil {
			prefix = joinRoutePath(d.prefix, prefix)
		}
		inc, ok := ix.includes[cur]
		if !ok {
			break
		}
		prefix = joinRoutePath(inc.prefix, prefix)
		cur = inc.parent
	}
	return prefix
}

// inheritedDeps are the router-level dependencies and before_request hooks on
// k and every router above it.
func (ix *pyIndex) inheritedDeps(k pyKey) []pyDep {
	var out []pyDep
	cur, seen := k, map[pyKey]bool{}
	for depth := 0; depth < 8 && !seen[cur]; depth++ {
		seen[cur] = true
		if d := ix.decls[cur]; d != nil {
			out = append(out, d.deps...)
		}
		out = append(out, ix.hooks[cur]...)
		inc, ok := ix.includes[cur]
		if !ok {
			break
		}
		out = append(out, inc.deps...)
		cur = inc.parent
	}
	return out
}

// ---- functions and routes ----

type pyDeco struct {
	start, end int
	callee     string
	args       []span
	hasCall    bool
}

func (ix *pyIndex) parseFunctions(f *pyFile) {
	var decos []pyDeco
	for _, m := range pyDecoRe.FindAllStringIndex(f.code, -1) {
		at := m[1]
		end := logicalEnd(f.code, at)
		d := pyDeco{start: m[0], end: end}
		text := f.code[at:end]
		if open := strings.IndexByte(text, '('); open >= 0 {
			if closeAt := matchClose(f.code, at+open); closeAt >= 0 {
				d.callee = strings.ReplaceAll(strings.TrimSpace(text[:open]), " ", "")
				d.args = splitArgs(f.code, at+open+1, closeAt)
				d.hasCall = true
			}
		} else {
			d.callee = strings.ReplaceAll(strings.TrimSpace(text), " ", "")
		}
		decos = append(decos, d)
	}
	for _, m := range pyDefRe.FindAllStringSubmatchIndex(f.code, -1) {
		fn, ok := parsePyFunc(f, m)
		if !ok {
			continue
		}
		// The decorators directly above the def, nearest first.
		var mine []pyDeco
		cursor := m[0]
		for {
			found := false
			for _, d := range decos {
				if d.end <= cursor && strings.TrimSpace(f.code[d.end:cursor]) == "" {
					mine = append(mine, d)
					cursor = d.start
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
		ix.registerFunction(f, fn, mine)
	}
}

func parsePyFunc(f *pyFile, m []int) (pyFunc, bool) {
	open := m[1] - 1
	closeAt := matchClose(f.code, open)
	if closeAt < 0 {
		return pyFunc{}, false
	}
	fn := pyFunc{name: f.code[m[4]:m[5]], defOff: m[0]}
	for _, a := range splitArgs(f.code, open+1, closeAt) {
		fn.params = append(fn.params, parsePyParam(f, a))
	}
	// The header ends at the first colon at depth zero after the parameters
	// (a return annotation may contain brackets).
	depth, colon := 0, -1
	for i := closeAt + 1; i < len(f.code); i++ {
		c := f.code[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ':':
			if depth == 0 {
				colon = i
			}
		case '\n':
			if depth == 0 && colon < 0 {
				return pyFunc{}, false
			}
		}
		if colon >= 0 {
			break
		}
	}
	if colon < 0 {
		return pyFunc{}, false
	}
	indent := m[3] - m[2]
	fn.bodyStart = colon + 1
	fn.bodyEnd = bodyEnd(f.code, colon, indent)
	return fn, true
}

// bodyEnd is the offset where the block that opened at colon ends: the start
// of the first later line, indented no deeper than the def, that has code.
func bodyEnd(code string, colon, indent int) int {
	i := strings.IndexByte(code[colon:], '\n')
	if i < 0 {
		return len(code)
	}
	for pos := colon + i + 1; pos < len(code); {
		eol := strings.IndexByte(code[pos:], '\n')
		line := code[pos:]
		next := len(code)
		if eol >= 0 {
			line, next = code[pos:pos+eol], pos+eol+1
		}
		if strings.TrimSpace(line) != "" && leadingSpace(line) <= indent {
			return pos
		}
		pos = next
	}
	return len(code)
}

func leadingSpace(line string) int {
	n := 0
	for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
		n++
	}
	return n
}

// logicalEnd returns the end of the logical line starting at from: the first
// newline at bracket depth zero not preceded by a backslash.
func logicalEnd(code string, from int) int {
	depth := 0
	for i := from; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '\n':
			if depth <= 0 && (i == 0 || code[i-1] != '\\') {
				return i
			}
		}
	}
	return len(code)
}

func parsePyParam(f *pyFile, a span) pyParam {
	t := f.code[a.start:a.end]
	p := pyParam{}
	depth, eq, colon := 0, -1, -1
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ':':
			if depth == 0 && colon < 0 && eq < 0 {
				colon = i
			}
		case '=':
			if depth == 0 && eq < 0 {
				eq = i
			}
		}
	}
	nameEnd := len(t)
	if colon >= 0 {
		nameEnd = colon
	} else if eq >= 0 {
		nameEnd = eq
	}
	p.name = strings.TrimLeft(strings.TrimSpace(t[:nameEnd]), "*")
	if colon >= 0 {
		end := len(t)
		if eq >= 0 {
			end = eq
		}
		p.annotation = strings.TrimSpace(t[colon+1 : end])
	}
	if eq >= 0 {
		p.def = strings.TrimSpace(t[eq+1:])
	}
	return p
}

// registerFunction turns a decorated def into a route, a before_request hook,
// or nothing.
func (ix *pyIndex) registerFunction(f *pyFile, fn pyFunc, decos []pyDeco) {
	var routeDeco *pyDeco
	var others []pyDep
	var recv pyKey
	known := false
	for i := range decos {
		d := &decos[i]
		recvExpr, verb := splitCallee(d.callee)
		if recvExpr != "" && pyRouteVerbs[verb] && d.hasCall && routeDeco == nil {
			if k, ok := ix.resolveRouter(f, recvExpr); ok {
				routeDeco, recv, known = d, k, true
				continue
			}
			if pyConventionalRouters[lastDotted(recvExpr)] && pyFrameworkFile(f) {
				routeDeco, recv = d, pyKey{f.path, lastDotted(recvExpr)}
				continue
			}
		}
		if recvExpr != "" && (verb == "before_request" || verb == "before_app_request") {
			if k, ok := ix.resolveRouter(f, recvExpr); ok {
				ix.hooks[k] = append(ix.hooks[k], pyDep{name: fn.name + " (before_request)", text: f.code[fn.bodyStart:fn.bodyEnd], raw: string(f.raw[fn.bodyStart:fn.bodyEnd]), inline: true})
			}
			continue
		}
		others = append(others, pyDep{name: lastDotted(d.callee), text: f.code[d.start:d.end], raw: string(f.raw[d.start:d.end])})
	}
	if routeDeco == nil {
		return
	}
	fw := "flask"
	if known {
		fw = ix.decls[recv].framework
	} else if strings.Contains(strings.ToLower(string(f.raw)), "fastapi") {
		fw = "fastapi"
	}
	_, verb := splitCallee(routeDeco.callee)
	if len(routeDeco.args) == 0 {
		return
	}
	var routePath string
	var kw []span
	for i, a := range routeDeco.args {
		if _, _, isKw := pyKwarg(f.code, a); isKw {
			kw = append(kw, a)
			continue
		}
		if i == 0 {
			routePath, _ = pyStringLit(f, a)
		}
	}
	for _, a := range kw {
		if k, v, _ := pyKwarg(f.code, a); (k == "rule" || k == "path") && routePath == "" {
			routePath, _ = pyStringLit(f, v)
		}
	}
	if !strings.HasPrefix(routePath, "/") {
		return
	}
	method := strings.ToUpper(verb)
	if verb == "route" || verb == "api_route" {
		method = "GET"
		for _, a := range kw {
			if k, v, _ := pyKwarg(f.code, a); k == "methods" {
				if ms := pyMethodStrRe.FindStringSubmatch(string(f.raw[v.start:v.end])); ms != nil {
					method = strings.ToUpper(ms[1])
				}
			}
		}
	}
	r := pyRoute{file: f, offset: routeDeco.start, recv: recv, framework: fw, method: method, path: routePath, fn: fn}
	re := pyFlaskPathRe
	if fw == "fastapi" {
		re = pyFastPathRe
	}
	for _, m := range re.FindAllStringSubmatch(routePath, -1) {
		r.params = append(r.params, m[1])
	}
	r.deps = append(r.deps, pyDepsKwarg(f, kw)...)
	r.deps = append(r.deps, others...)
	for _, p := range fn.params {
		r.deps = append(r.deps, ix.paramDeps(f, p)...)
	}
	ix.routes = append(ix.routes, r)
}

// paramDeps returns the dependencies a parameter declares: a Depends() default
// or annotation, or an Annotated alias.
func (ix *pyIndex) paramDeps(f *pyFile, p pyParam) []pyDep {
	var out []pyDep
	for _, t := range []string{p.def, p.annotation} {
		for _, m := range pyDependsRe.FindAllStringSubmatch(t, -1) {
			out = append(out, pyDep{name: lastDotted(m[1]), text: t, raw: t})
		}
	}
	if len(out) == 0 {
		for alias, d := range ix.aliases {
			if hasWord(p.annotation, alias) {
				out = append(out, d)
			}
		}
	}
	return out
}

func pyFrameworkFile(f *pyFile) bool {
	l := strings.ToLower(string(f.raw))
	return strings.Contains(l, "flask") || strings.Contains(l, "fastapi") || strings.Contains(l, "quart")
}

// splitCallee splits `bp.route` into ("bp", "route"); a bare name has no
// receiver.
func splitCallee(callee string) (recv, verb string) {
	if i := strings.LastIndexByte(callee, '.'); i >= 0 {
		return callee[:i], callee[i+1:]
	}
	return "", callee
}
