package callgraph

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/reach"
)

// maxSourceBytes bounds one file read. A Go file past this is generated or
// vendored data, and its call structure is not what anybody is asking about.
const maxSourceBytes = 4 << 20

// BuildGo parses every Go file under root and returns the call graph.
//
// Errors are absorbed rather than returned. A file that will not parse is a
// file this graph does not model, which is a limitation and not a failure —
// recorded as such, so a caller reading the scope can see that the search was
// narrower than it looks. Returning an error instead would make one
// unparseable file cost the answer for the whole module.
func BuildGo(root string) *Graph {
	g := &Graph{
		funcs:       map[string]*Func{},
		callers:     map[string][]string{},
		intoPackage: map[string][]string{},
		limits:      map[reach.Limitation]bool{},
		root:        root,
		module:      modulePath(root),
	}

	fset := token.NewFileSet()
	type parsed struct {
		file *ast.File
		dir  string
		path string
	}
	var files []parsed

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// vendor/ is somebody else's code and testdata/ is deliberately
			// broken by convention; neither is the program under analysis.
			switch d.Name() {
			case "vendor", "testdata", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > maxSourceBytes {
			g.limits[reach.BudgetExhausted] = true
			return nil
		}
		src, rerr := os.ReadFile(path) //nolint:gosec // caller-supplied scan root
		if rerr != nil {
			g.limits[reach.BudgetExhausted] = true
			return nil
		}
		f, perr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if perr != nil || f == nil {
			// A file nox could not read is a file whose calls are invisible.
			g.limits[reach.UnsupportedLanguage] = true
			return nil
		}
		rel, rerr2 := filepath.Rel(root, filepath.Dir(path))
		if rerr2 != nil {
			rel = filepath.Dir(path)
		}
		files = append(files, parsed{file: f, dir: filepath.ToSlash(rel), path: path})
		return nil
	})

	// Pass 1: declarations. Every call target must exist before edges are
	// resolved, or a function defined later in the walk would look unresolved.
	for _, p := range files {
		collectDecls(g, fset, p.file, p.dir, p.path)
	}
	// Pass 2: edges.
	for _, p := range files {
		collectCalls(g, p.file, p.dir)
	}

	for target, cs := range g.callers {
		sort.Strings(cs)
		g.callers[target] = cs
	}
	for pkg, cs := range g.intoPackage {
		sort.Strings(cs)
		g.intoPackage[pkg] = cs
	}
	for _, f := range g.funcs {
		sort.Strings(f.Calls)
	}
	return g
}

// declKey builds the unique identifier for a declaration. The directory rather
// than the package name, because one module can hold two packages called
// `util` and collapsing them would invent call edges between unrelated code.
func declKey(dir, recv, name string) string {
	// The module root is "." from filepath.Rel, and prefixing with it produced
	// keys like "..main". A key is read by people — it appears in the witness
	// path written onto a finding — so the root's functions are named bare.
	prefix := dir + "."
	if dir == "." || dir == "" {
		prefix = ""
	}
	if recv != "" {
		return prefix + "(" + recv + ")." + name
	}
	return prefix + name
}

// receiverName returns the bare type name of a method receiver, without
// pointer or type-parameter decoration.
func receiverName(fl *ast.FieldList) string {
	if fl == nil || len(fl.List) == 0 {
		return ""
	}
	return typeName(fl.List[0].Type)
}

func typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeName(t.X)
	case *ast.IndexExpr: // generic receiver: Foo[T]
		return typeName(t.X)
	case *ast.IndexListExpr:
		return typeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// collectDecls records every function and method, and decides which are entry
// points.
func collectDecls(g *Graph, fset *token.FileSet, f *ast.File, dir, path string) {
	pkg := f.Name.Name
	isTest := strings.HasSuffix(path, "_test.go")
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name == nil {
			continue
		}
		recv := receiverName(fd.Recv)
		key := declKey(dir, recv, fd.Name.Name)
		kind, reason := entryPoint(pkg, recv, fd.Name.Name, isTest)
		g.funcs[key] = &Func{
			Key:         key,
			Name:        fd.Name.Name,
			File:        path,
			Line:        fset.Position(fd.Pos()).Line,
			Kind:        kind,
			EntryReason: reason,
		}
	}
}

// entryPoint decides whether execution can begin at a declaration, and says
// why.
//
// The reason is recorded rather than implied because the set is a judgement an
// operator may disagree with, and one they cannot argue with is one they will
// distrust. An exported function in a library IS an entry point — somebody
// else's code calls it, and that code is not in this module — even though
// nothing here calls it.
func entryPoint(pkg, recv, name string, isTest bool) (kind EntryKind, reason string) {
	switch {
	case pkg == "main" && recv == "" && name == "main":
		return EntryConcrete, "package main's entry function"
	case recv == "" && name == "init":
		return EntryConcrete, "runs before main, whoever imports the package"
	case isTest && (strings.HasPrefix(name, "Test") ||
		strings.HasPrefix(name, "Benchmark") || strings.HasPrefix(name, "Fuzz")):
		return EntryTest, "the test runner calls it directly"
	case pkg != "main" && recv == "" && ast.IsExported(name):
		return EntryExported, "exported from a library package, so a caller outside this module could reach it"
	case pkg != "main" && recv != "" && ast.IsExported(name) && ast.IsExported(recv):
		return EntryExported, "an exported method on an exported type"
	}
	return NotAnEntry, ""
}

// collectCalls walks every function body and records the edges it can resolve.
//
// What it cannot resolve is counted, not ignored. A call through an interface,
// a function value or reflection is a real edge this graph does not have, and
// the count is what tells a reader how much of the program is missing — see
// Graph.Scope, which refuses to support a universal claim because of it.
func collectCalls(g *Graph, f *ast.File, dir string) {
	imports := importAliases(f)
	pkg := f.Name.Name

	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name == nil || fd.Body == nil {
			continue
		}
		from := declKey(dir, receiverName(fd.Recv), fd.Name.Name)
		caller, exists := g.funcs[from]
		if !exists {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch call := n.(type) {
			case *ast.CallExpr:
				g.resolveCall(caller, call, dir, pkg, imports)
			case *ast.SelectorExpr:
				// reflect and unsafe make calls nothing syntactic can follow.
				if id, ok := call.X.(*ast.Ident); ok {
					switch imports[id.Name] {
					case "reflect":
						g.limits[reach.Reflection] = true
					case "plugin":
						g.limits[reach.DynamicLoading] = true
					}
				}
			}
			return true
		})
	}
}

// resolveCall binds one call expression to a declaration where it can.
func (g *Graph) resolveCall(caller *Func, call *ast.CallExpr, dir, pkg string, imports map[string]string) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		// A bare name: a function in this package, or a local variable holding
		// a func. Only the first is resolvable from syntax.
		if to, ok := g.funcs[declKey(dir, "", fn.Name)]; ok {
			g.addEdge(caller, to.Key)
			return
		}
		g.unresolvedCall()
	case *ast.SelectorExpr:
		x, ok := fn.X.(*ast.Ident)
		if !ok {
			// Something like a.b.C() — a field or chained value. Not resolvable.
			g.unresolvedCall()
			return
		}
		if importPath, isImport := imports[x.Name]; isImport {
			// A call into another package. Within this module the import path
			// maps back to a directory, so the edge is resolvable; outside it
			// — the standard library, a dependency — the callee's source is not
			// here to bind to.
			//
			// An unresolvable stdlib call is NOT the same kind of gap as an
			// unresolved dispatch, and counting them together made the resolved
			// ratio meaningless: 21% on nox's own tree, almost all of it
			// fmt.Sprintf. So it is counted apart and does not add
			// UnresolvedDispatch, which is reserved for a call whose far end
			// could be anywhere.
			if dir, ok := g.moduleDir(importPath); ok {
				if to, found := g.funcs[declKey(dir, "", fn.Sel.Name)]; found {
					g.addEdge(caller, to.Key)
					return
				}
			}
			// A call OUT of the module. The callee's source is not here, so
			// there is no edge to build — but which of this module's functions
			// reaches for it is exactly the question a dependency advisory
			// poses, so the caller is recorded against the import path.
			g.intoPackage[importPath] = appendUnique(g.intoPackage[importPath], caller.Key)
			g.external++
			return
		}
		// A method call on a receiver whose type is unknown to us. This is the
		// interface-dispatch case and the reason this package never refutes:
		// the edge exists and we cannot name its far end.
		if to, ok := g.funcs[declKey(dir, x.Name, fn.Sel.Name)]; ok {
			g.addEdge(caller, to.Key)
			return
		}
		g.limits[reach.UnresolvedDispatch] = true
		g.unresolvedCall()
	case *ast.FuncLit:
		// An immediately-invoked literal. Its body was already walked by the
		// enclosing Inspect, so there is nothing to add and nothing lost.
	default:
		g.unresolvedCall()
	}
	_ = pkg
}

func (g *Graph) addEdge(from *Func, to string) {
	from.Calls = append(from.Calls, to)
	g.callers[to] = append(g.callers[to], from.Key)
	g.resolved++
}

func (g *Graph) unresolvedCall() {
	g.unresolved++
	g.limits[reach.UnresolvedDispatch] = true
}

// importAliases maps the identifier a file uses for each import to its path.
func importAliases(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		if imp.Path == nil {
			continue
		}
		path := strings.Trim(imp.Path.Value, `"`)
		name := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			name = path[i+1:]
		}
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = path
	}
	return out
}

// modulePath reads the module line from go.mod, or "" when there is none.
//
// Without it every cross-package call inside the module is unresolvable, which
// is most of a real program's call graph. It is read once rather than shelled
// out for, so the graph builds offline and without the toolchain.
func modulePath(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod")) //nolint:gosec // caller-supplied scan root
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// moduleDir maps an import path to the directory holding it, when it is inside
// this module.
func (g *Graph) moduleDir(importPath string) (string, bool) {
	if g.module == "" {
		return "", false
	}
	if importPath == g.module {
		return ".", true
	}
	rest, ok := strings.CutPrefix(importPath, g.module+"/")
	if !ok {
		return "", false
	}
	return rest, true
}

// appendUnique adds s to out if it is not already present. The lists are short
// — the functions in one module that call into one package — so a linear scan
// beats carrying a set alongside every slice.
func appendUnique(out []string, s string) []string {
	for _, v := range out {
		if v == s {
			return out
		}
	}
	return append(out, s)
}
