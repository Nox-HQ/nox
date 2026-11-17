package callgraph

import (
	"path"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/depimports"
	"github.com/nox-hq/nox/core/reach"
	"github.com/nox-hq/nox/core/taint"
)

// A call graph for every language the taint extractor reads.
//
// BuildGo parses Go with go/ast. Everything else is read through the units the
// taint engine already extracts (core/taint/engine): one unit per function,
// method or callback, each with the calls its statements make, and with calls
// through an imported name already expanded to the module they name
// (`rq.get` is also `requests.get`). The scan extracts those units once for
// taint analysis; this graph is built from the same walk and parses nothing
// again.
//
// Resolution is deliberately narrow, because every edge it adds is a step in
// a witness a reader is asked to believe:
//
//   - a bare call binds to the one function of that name in the same file, or
//     failing that to the one function of that name among the project's files
//     of the same language. Two candidates bind to neither;
//   - a call on self/this/cls binds within the file;
//   - a call qualified by a module binds to the function of that name in the
//     file the module names (a relative JavaScript import, a dotted Python
//     module, or a file whose stem is the qualifier, as a Java class is);
//   - a call whose module is a dependency the FILE imports is a call into that
//     dependency, recorded against it and never bound to a project function.
//
// Anything else — a method on a value of unknown type, a function value, a
// callback registered with a framework — is a call this graph cannot name the
// far end of. It is counted, and like the Go graph this one never refutes.
type SourceBuilder struct {
	files []sourceFile
	// loaded are dependencies every file of an ecosystem has loaded without
	// importing them itself (see AddLoaded).
	loaded map[string][]string
}

type sourceFile struct {
	path    string
	lang    string
	eco     string
	imports []string
	units   []taint.Unit
	test    bool
}

// NewSourceBuilder returns an empty builder.
func NewSourceBuilder() *SourceBuilder { return &SourceBuilder{} }

// Add records one file's units. path is the file's path in the scanned tree,
// which is the path findings carry. Go files are ignored: BuildGo reads them
// with a real parser.
func (b *SourceBuilder) Add(filePath string, content []byte, units []taint.Unit) {
	if b == nil || strings.HasSuffix(filePath, ".go") || len(units) == 0 {
		return
	}
	eco, imports := depimports.FileImports(filePath, content)
	b.files = append(b.files, sourceFile{
		path:    filePath,
		lang:    units[0].Language,
		eco:     eco,
		imports: imports,
		units:   units,
		test:    isTestPath(filePath),
	})
}

// AddLoaded records dependencies the runtime loads for every file of an
// ecosystem, so a file calls into them without importing them: a Rails
// application's gems, which `Bundler.require` loads at boot. names are as a
// lockfile names them.
func (b *SourceBuilder) AddLoaded(ecosystem string, names []string) {
	if b == nil || len(names) == 0 {
		return
	}
	eco, _ := depimports.FileImports("x"+ecosystemExt(ecosystem), nil)
	if eco == "" {
		return
	}
	if b.loaded == nil {
		b.loaded = map[string][]string{}
	}
	for _, n := range names {
		b.loaded[eco] = append(b.loaded[eco], depimports.NormalizeName(ecosystem, n))
	}
}

// Len returns the number of files added.
func (b *SourceBuilder) Len() int {
	if b == nil {
		return 0
	}
	return len(b.files)
}

// Route is an HTTP route registration, located where the route reader found
// it. The graph marks the function that handles it as an entry point an
// outside request reaches.
type Route struct {
	Method, Path string
	File         string
	Line         int
	Reader       string
	// HandlerFile and HandlerFunc name a handler declared away from the
	// registration, when the route reader resolved it (Rails, Laravel).
	HandlerFile, HandlerFunc string
}

// routeHandlerWindow is how far below a registration the handler may be
// declared: the decorators and annotations stacked above a Flask, FastAPI,
// Spring, JAX-RS, NestJS or ASP.NET handler, or a callback whose header
// continues the registration's call.
const routeHandlerWindow = 8

// Build resolves the calls and returns the graph. routes marks the functions
// that handle them.
func (b *SourceBuilder) Build(routes []Route) *Graph {
	g := &Graph{
		funcs:          map[string]*Func{},
		callers:        map[string][]string{},
		limits:         map[reach.Limitation]bool{},
		intoPackage:    map[string][]string{},
		intoSymbol:     map[string][]string{},
		intoDependency: map[string][]string{},
		stmtOwner:      map[string]map[int]string{},
		analysis:       "source call graph (taint units)",
		buildID:        "syntactic, every language the taint extractor reads",
	}
	if b == nil {
		return g
	}
	files := append([]sourceFile(nil), b.files...)
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	for i := range files {
		if extra := b.loaded[files[i].eco]; len(extra) > 0 {
			files[i].imports = append(append([]string(nil), files[i].imports...), extra...)
		}
	}

	ix := newSourceIndex()
	keys := make([][]string, len(files))
	for fi := range files {
		f := &files[fi]
		ix.addFile(f)
		keys[fi] = make([]string, len(f.units))
		for ui := range f.units {
			u := &f.units[ui]
			key := g.uniqueKey(f.path, u)
			keys[fi][ui] = key
			kind, reason := sourceEntryPoint(f, u)
			fn := &Func{Key: key, Name: displayName(u), File: f.path, Line: u.Line, Kind: kind, EntryReason: reason}
			g.funcs[key] = fn
			owner := g.stmtOwner[f.path]
			if owner == nil {
				owner = map[int]string{}
				g.stmtOwner[f.path] = owner
			}
			for _, s := range u.Stmts {
				// The innermost scope wins: a callback's statements are its own,
				// and they are extracted after the line that opens it.
				owner[s.Line] = key
			}
			if u.FuncName != "" {
				ix.add(f, u.FuncName, key)
			}
		}
	}
	for fi := range files {
		f := &files[fi]
		for ui := range f.units {
			caller := g.funcs[keys[fi][ui]]
			for _, s := range f.units[ui].Stmts {
				for _, c := range s.Calls {
					g.resolveSourceCall(ix, f, caller, c, s.Calls)
				}
			}
		}
	}
	for k := range g.callers {
		g.callers[k] = sortedUnique(g.callers[k])
	}
	for k := range g.intoDependency {
		sort.Strings(g.intoDependency[k])
	}
	for _, fn := range g.funcs {
		fn.Calls = sortedUnique(fn.Calls)
	}
	g.markRouteHandlers(ix, routes)
	return g
}

// uniqueKey names a unit "<file>:<name>", disambiguated by its line when the
// file declares the name twice (overloads, the same method name in two
// classes) and always for a callback, which has no name of its own.
func (g *Graph) uniqueKey(file string, u *taint.Unit) string {
	switch {
	case u.FuncName == "" && u.Line == 0:
		return file + ":<module>"
	case u.FuncName == "":
		return file + ":<anonymous>@" + itoa(u.Line)
	}
	key := file + ":" + u.FuncName
	if _, taken := g.funcs[key]; taken {
		return key + "@" + itoa(u.Line)
	}
	return key
}

func displayName(u *taint.Unit) string {
	switch {
	case u.FuncName == "" && u.Line == 0:
		return "<module>"
	case u.FuncName == "":
		return "<anonymous>"
	}
	return u.FuncName
}

// scriptLanguages run their top-level code when the file is loaded, so the
// module unit is where execution begins, as a Go init function is.
var scriptLanguages = map[string]bool{
	"python": true, "javascript": true, "ruby": true, "php": true, "perl": true,
	"lua": true, "shell": true, "powershell": true, "elixir": true, "groovy": true,
}

// mainLanguages begin a program at a function named main (Main in C#).
var mainLanguages = map[string]bool{
	"java": true, "kotlin": true, "csharp": true, "rust": true, "cpp": true,
	"dart": true, "scala": true, "swift": true, "objc": true, "groovy": true,
}

// sourceEntryPoint is entryPoint for the other languages. The reason is
// recorded for the same cause: an operator can disagree with the set only if
// they can see why each member is in it.
func sourceEntryPoint(f *sourceFile, u *taint.Unit) (EntryKind, string) {
	lang := strings.ToLower(f.lang)
	module := u.FuncName == "" && u.Line == 0
	if f.test {
		if module || u.FuncName == "" || strings.HasPrefix(strings.ToLower(u.FuncName), "test") {
			return EntryTest, "the test runner runs it"
		}
		return NotAnEntry, ""
	}
	switch {
	case module && scriptLanguages[lang]:
		return EntryConcrete, "top-level code, which runs whenever the file is loaded"
	case mainLanguages[lang] && (u.FuncName == "main" || u.FuncName == "Main"):
		return EntryConcrete, "the program's entry function"
	}
	return NotAnEntry, ""
}

// isTestPath reports whether a file is test code by the conventions of the
// languages read here. Test code is real execution, but of the suite rather
// than of the program an attacker meets, so its entries are kept apart.
func isTestPath(p string) bool {
	p = "/" + strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	for _, dir := range []string{"/test/", "/tests/", "/spec/", "/specs/", "/__tests__/", "/testing/", "/t/"} {
		if strings.Contains(p, dir) {
			return true
		}
	}
	base := path.Base(p)
	stem := strings.TrimSuffix(base, path.Ext(base))
	return strings.HasPrefix(base, "test_") || strings.HasSuffix(stem, "_test") || strings.HasSuffix(stem, "_spec") ||
		strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".spec") ||
		strings.HasSuffix(stem, "test") && stem != "test" && !strings.HasSuffix(stem, "latest") ||
		strings.HasSuffix(stem, "tests")
}

// sourceIndex finds the functions a call may name.
type sourceIndex struct {
	// byFile maps a file to its named functions.
	byFile map[string]map[string][]string
	// byLang maps a language to the named functions of its non-test files.
	byLang map[string]map[string][]string
	// files lists every file by path, and stems maps a folded file stem to
	// the files carrying it, per language.
	files map[string]*sourceFile
	stems map[string]map[string][]string
}

func newSourceIndex() *sourceIndex {
	return &sourceIndex{
		byFile: map[string]map[string][]string{},
		byLang: map[string]map[string][]string{},
		files:  map[string]*sourceFile{},
		stems:  map[string]map[string][]string{},
	}
}

// addFile registers a file, whether or not it declares a named function.
func (ix *sourceIndex) addFile(f *sourceFile) {
	if _, seen := ix.files[f.path]; !seen {
		ix.files[f.path] = f
		st := ix.stems[f.lang]
		if st == nil {
			st = map[string][]string{}
			ix.stems[f.lang] = st
		}
		stem := foldName(strings.TrimSuffix(path.Base(f.path), path.Ext(f.path)))
		st[stem] = append(st[stem], f.path)
	}
}

func (ix *sourceIndex) add(f *sourceFile, name, key string) {
	m := ix.byFile[f.path]
	if m == nil {
		m = map[string][]string{}
		ix.byFile[f.path] = m
	}
	m[name] = append(m[name], key)
	if f.test {
		return
	}
	l := ix.byLang[f.lang]
	if l == nil {
		l = map[string][]string{}
		ix.byLang[f.lang] = l
	}
	l[name] = append(l[name], key)
}

// one returns the single key in keys, or false when there is none or more
// than one: two candidates are a call this graph cannot name.
func one(keys []string) (string, bool) {
	if len(keys) == 1 {
		return keys[0], true
	}
	return "", false
}

// selfQualifiers name the receiver's own class or module.
var selfQualifiers = map[string]bool{
	"self": true, "this": true, "cls": true, "super": true, "static": true, "@": true, "Self": true,
}

// resolveSourceCall binds one call. siblings are the other calls the same
// statement made, which carry the import expansion of a bare imported name.
func (g *Graph) resolveSourceCall(ix *sourceIndex, f *sourceFile, caller *Func, call string, siblings []string) {
	if dep, ok := dependencyOf(f, call); ok && !ix.isProjectModule(f, dep) {
		k := dependencyKey(f.eco, dep)
		g.intoDependency[k] = appendUnique(g.intoDependency[k], caller.Key)
		g.external++
		return
	}
	qual, name := splitCall(call)
	if name == "" {
		g.unresolvedCall()
		return
	}
	if qual == "" {
		// `from requests import get; get(u)` also arrives as requests.get,
		// which is resolved on its own; the bare name is the same call.
		for _, s := range siblings {
			if s != call && strings.HasSuffix(s, "."+name) {
				return
			}
		}
		if to, ok := one(ix.byFile[f.path][name]); ok {
			g.addEdge(caller, to)
			return
		}
		if len(ix.byFile[f.path][name]) == 0 {
			if to, ok := one(ix.byLang[f.lang][name]); ok {
				g.addEdge(caller, to)
				return
			}
		}
		g.unresolvedCall()
		return
	}
	if selfQualifiers[qual] || qual == "$this" {
		if to, ok := one(ix.byFile[f.path][name]); ok {
			g.addEdge(caller, to)
			return
		}
		g.unresolvedCall()
		return
	}
	if target, ok := ix.moduleFile(f, qual); ok {
		if to, ok := one(ix.byFile[target][name]); ok {
			g.addEdge(caller, to)
			return
		}
	}
	// A method on a value whose type is unknown here: the dispatch case.
	g.unresolvedCall()
}

// splitCall separates a call chain into its qualifier and the called name.
// Clojure separates a namespace with "/", everything else with ".".
func splitCall(call string) (qual, name string) {
	call = strings.TrimSpace(call)
	i := strings.LastIndexAny(call, "./")
	if i < 0 {
		return "", call
	}
	// A JavaScript relative specifier keeps its slashes in the qualifier:
	// "./lib/util.parse" is parse in ./lib/util.
	return call[:i], call[i+1:]
}

// moduleFile finds the one project file a qualifier names.
func (ix *sourceIndex) moduleFile(f *sourceFile, qual string) (string, bool) {
	dir := path.Dir(f.path)
	switch {
	case strings.HasPrefix(qual, "./") || strings.HasPrefix(qual, "../"):
		base := path.Join(dir, qual)
		for _, ext := range []string{"", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", "/index.js", "/index.ts"} {
			if _, ok := ix.files[base+ext]; ok {
				return base + ext, true
			}
		}
		// "./util.js" resolves without an extension added; a qualifier that
		// names a missing file is not a module this tree holds.
		return "", false
	case strings.EqualFold(f.lang, "python"):
		rel := strings.TrimLeft(qual, ".")
		p := strings.ReplaceAll(rel, ".", "/")
		var hits []string
		for _, cand := range []string{p + ".py", p + "/__init__.py"} {
			if strings.HasPrefix(qual, ".") {
				if _, ok := ix.files[path.Join(dir, cand)]; ok {
					hits = append(hits, path.Join(dir, cand))
				}
				continue
			}
			for fp := range ix.files {
				if fp == cand || strings.HasSuffix(fp, "/"+cand) {
					hits = append(hits, fp)
				}
			}
		}
		if len(hits) == 1 {
			return hits[0], true
		}
		if len(hits) > 1 {
			return "", false
		}
	}
	// A qualifier that is a file's stem: a Java, C# or Kotlin class, a Ruby
	// constant (UsersController in users_controller.rb), a PHP class.
	last := qual
	if i := strings.LastIndexAny(last, "./"); i >= 0 {
		last = last[i+1:]
	}
	cands := ix.stems[f.lang][foldName(last)]
	if len(cands) == 1 {
		return cands[0], true
	}
	for _, c := range cands {
		if path.Dir(c) == dir {
			return c, true
		}
	}
	return "", false
}

// isProjectModule reports whether an import names a module in this tree
// rather than a dependency: `from helpers import run_cmd` beside helpers.py.
// depimports lists every import, because it cannot see the tree.
func (ix *sourceIndex) isProjectModule(f *sourceFile, imp string) bool {
	if f.eco != "pypi" {
		// npm specifiers of the tree are relative and never listed; a Ruby
		// require of a project file names a path, not a gem constant.
		return false
	}
	p := strings.ReplaceAll(imp, ".", "/")
	for fp := range ix.files {
		if fp == p+".py" || strings.HasSuffix(fp, "/"+p+".py") ||
			strings.HasPrefix(fp, p+"/") || strings.Contains(fp, "/"+p+"/") {
			return true
		}
	}
	return false
}

// foldName compares names across naming conventions: UsersController,
// users_controller and users-controller are one name.
func foldName(s string) string {
	s = strings.ToLower(s)
	return strings.NewReplacer("_", "", "-", "", "::", "").Replace(s)
}

// dependencyOf reports which dependency the file imports that call enters.
func dependencyOf(f *sourceFile, call string) (string, bool) {
	if len(f.imports) == 0 {
		return "", false
	}
	if f.eco == "rubygems" {
		// Ruby calls a gem through its constant: Nokogiri::XML, RestClient.get.
		head, _, _ := strings.Cut(call, ".")
		fh := foldName(head)
		for _, imp := range f.imports {
			if foldName(imp) == fh {
				return imp, true
			}
		}
		return "", false
	}
	norm := call
	if f.eco == "pypi" || f.eco == "cargo" {
		norm = strings.ReplaceAll(strings.ToLower(norm), "-", "_")
	}
	best := ""
	for _, imp := range f.imports {
		if (norm == imp || strings.HasPrefix(norm, imp+".")) && len(imp) > len(best) {
			best = imp
		}
	}
	return best, best != ""
}

func dependencyKey(eco, name string) string { return eco + "\x00" + name }

// markRouteHandlers makes the function that handles each route an entry point
// a request reaches.
//
// A route is bound to (1) a function its registration names — Express's
// `app.post('/y', create)`, Django's `path('x/', views.detail)` — else (2) the
// first function declared within routeHandlerWindow lines below it: the
// decorated or annotated handler, or the callback opened on the registration
// line. A route that binds to nothing marks nothing.
func (g *Graph) markRouteHandlers(ix *sourceIndex, routes []Route) {
	for _, r := range routes {
		if r.HandlerFile != "" {
			if key, ok := one(ix.byFile[r.HandlerFile][r.HandlerFunc]); ok {
				g.markRoute(key, r)
			}
			continue
		}
		f, ok := ix.files[r.File]
		if !ok {
			continue
		}
		key, ok := g.namedHandler(ix, f, r.Line)
		if !ok {
			key, ok = g.handlerBelow(r.File, r.Line)
		}
		if !ok {
			continue
		}
		g.markRoute(key, r)
	}
}

func (g *Graph) markRoute(key string, r Route) {
	fn := g.funcs[key]
	if fn != nil && fn.Kind < EntryRoute {
		fn.Kind = EntryRoute
		fn.EntryReason = "handles " + strings.TrimSpace(r.Method+" "+r.Path) + " (" + r.Reader + ")"
	}
}

// namedHandler finds a function the statement on the registration line reads
// or calls by name, other than the registration call itself.
func (g *Graph) namedHandler(ix *sourceIndex, f *sourceFile, line int) (string, bool) {
	for _, u := range f.units {
		for _, s := range u.Stmts {
			if s.Line != line {
				continue
			}
			for _, ref := range append(append([]string(nil), s.Reads...), s.Chains...) {
				qual, name := splitCall(ref)
				if qual == "" {
					if k, ok := one(ix.byFile[f.path][name]); ok {
						return k, true
					}
					continue
				}
				if target, ok := ix.moduleFile(f, qual); ok {
					if k, ok := one(ix.byFile[target][name]); ok {
						return k, true
					}
				}
			}
		}
	}
	return "", false
}

// handlerBelow returns the first function declared at or within
// routeHandlerWindow lines below line in the same file.
func (g *Graph) handlerBelow(file string, line int) (string, bool) {
	best, bestLine := "", 0
	for k, fn := range g.funcs {
		if fn.File != file || fn.Line == 0 || fn.Line < line || fn.Line > line+routeHandlerWindow {
			continue
		}
		if best == "" || fn.Line < bestLine || (fn.Line == bestLine && k < best) {
			best, bestLine = k, fn.Line
		}
	}
	return best, best != ""
}

// CallersOfDependency returns the functions that call into a dependency, by
// its ecosystem and name as a lockfile names it, sorted. Like CallersOfPackage,
// empty is not evidence that no call exists.
func (g *Graph) CallersOfDependency(ecosystem, name string) []string {
	if g == nil {
		return nil
	}
	eco, _ := depimports.FileImports("x"+ecosystemExt(ecosystem), nil)
	if eco == "" {
		return nil
	}
	n := depimports.NormalizeName(ecosystem, name)
	var out []string
	for k, callers := range g.intoDependency {
		e, dep, _ := strings.Cut(k, "\x00")
		if e != eco {
			continue
		}
		if dep == n || (eco == "rubygems" && foldName(dep) == foldName(n)) {
			out = append(out, callers...)
		}
	}
	return sortedUnique(out)
}

// ecosystemExt names a source extension of an ecosystem, to reuse the
// extension table depimports keys ecosystems by.
func ecosystemExt(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return ".js"
	case "pypi", "pip", "python":
		return ".py"
	case "cargo", "crates.io", "rust":
		return ".rs"
	case "pub", "dart":
		return ".dart"
	case "rubygems", "gem", "ruby":
		return ".rb"
	}
	return ""
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return in
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Covers reports whether the source graph read file. A finding in a file it
// did not read is a question it cannot put, which is different from one it
// put and could not answer.
func (g *Graph) Covers(file string) bool {
	if g == nil {
		return false
	}
	_, ok := g.stmtOwner[file]
	return ok
}
