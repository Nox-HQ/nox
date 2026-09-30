package engine

import (
	"go/ast"
	"go/token"
	"strings"
)

// Receiver roles for the Go extractor.
//
// The Go catalog names its sources and sinks by receiver: `r.URL.Query`,
// `r.Header.Get`, `db.Query`, `w.Write`. Catalog lookups are exact, so those
// entries matched only when the variable was literally named r, db or w. A
// handler taking `req *http.Request`, a `conn *sql.DB`, a Beego controller
// reading `c.Ctx.Request.Header.Get(...)` or a Gin handler calling
// `c.Query("id")` was invisible: measured on the OWASP Benchmark port to Go,
// 6% of SQL injection cases and none of the XSS cases were found.
//
// The extractor has the AST, and with it every declared type in the file. A
// variable whose declared type is known gets a ROLE, and its name is rewritten
// to the role's canonical receiver before the catalog is consulted:
//
//	*http.Request                     -> r
//	http.ResponseWriter               -> w
//	*sql.DB, *sql.Tx, *sql.Conn, sqlx -> db
//	*gin.Context                      -> gin
//	echo.Context                      -> echo
//	*fiber.Ctx                        -> fiber
//	a struct embedding a Beego controller -> beego
//
// and a framework's request or response field is rewritten to the role it
// holds (`beego.Ctx.Request` -> r, `gin.Writer` -> w).
//
// Only a name with a KNOWN role is rewritten, so this adds matches and never
// removes one: a variable named r whose type is unknown still matches the
// `r.` entries exactly as before.
//
// Types come from what the file itself declares: parameters and receivers,
// `var x T`, composite literals and `new(T)`, the result of `sql.Open` and
// friends, and an assignment from an expression that already has a role
// (`response := c.Ctx.ResponseWriter`). No go/types, no imports followed.

// goTypeRoles maps a rendered type (pointer stripped) to its role.
var goTypeRoles = map[string]string{
	"http.Request":        "r",
	"http.ResponseWriter": "w",
	"sql.DB":              "db",
	"sql.Tx":              "db",
	"sql.Conn":            "db",
	"sqlx.DB":             "db",
	"sqlx.Tx":             "db",
	"gin.Context":         "gin",
	"echo.Context":        "echo",
	"fiber.Ctx":           "fiber",
}

// goRoleFields rewrites a framework field or accessor to the role it holds,
// after the head has been replaced by its role.
var goRoleFields = []struct{ from, to string }{
	{"beego.Ctx.Request", "r"},
	{"beego.Ctx.ResponseWriter", "w"},
	{"gin.Request", "r"},
	{"gin.Writer", "w"},
	{"echo.Request", "r"},
	{"echo.Response.Writer", "w"},
}

// goRoleConstructors are calls whose result has a role.
var goRoleConstructors = map[string]string{
	"sql.Open":     "db",
	"sql.OpenDB":   "db",
	"sqlx.Open":    "db",
	"sqlx.Connect": "db",
	"sqlx.NewDb":   "db",
	"db.Begin":     "db",
	"db.BeginTx":   "db",
	"db.Beginx":    "db",
	"db.Conn":      "db",
}

// goBeegoControllers are the embedded types that make a struct a Beego
// controller (beego v1 and v2).
var goBeegoControllers = map[string]bool{
	"web.Controller":   true,
	"beego.Controller": true,
}

// goRoles is the role environment: the file's package-level variables and the
// current function's locals.
type goRoles struct {
	file        map[string]string
	fn          map[string]string
	controllers map[string]bool
}

func newGoRoles(file *ast.File) *goRoles {
	g := &goRoles{file: map[string]string{}, fn: map[string]string{}, controllers: map[string]bool{}}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			for _, f := range st.Fields.List {
				if len(f.Names) == 0 && goBeegoControllers[goTypeName(f.Type)] {
					g.controllers[ts.Name.Name] = true
				}
			}
		}
	}
	for _, decl := range file.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
			g.declare(g.file, gd)
		}
	}
	return g
}

// goTypeName renders a type expression without its pointer: `*sql.DB` ->
// "sql.DB", `Ctrl` -> "Ctrl". Generic instantiations and other shapes render "".
func goTypeName(t ast.Expr) string {
	switch x := t.(type) {
	case *ast.StarExpr:
		return goTypeName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name + "." + x.Sel.Name
		}
	}
	return ""
}

// typeRole returns the role of a declared type, or "".
func (g *goRoles) typeRole(t ast.Expr) string {
	name := goTypeName(t)
	if r := goTypeRoles[name]; r != "" {
		return r
	}
	if g.controllers[name] {
		return "beego"
	}
	return ""
}

// enterFunc starts a function: its receiver and parameters seed the locals.
func (g *goRoles) enterFunc(d *ast.FuncDecl) {
	g.fn = map[string]string{}
	var fields []*ast.Field
	if d.Recv != nil {
		fields = append(fields, d.Recv.List...)
	}
	if d.Type != nil && d.Type.Params != nil {
		fields = append(fields, d.Type.Params.List...)
	}
	for _, f := range fields {
		role := g.typeRole(f.Type)
		for _, n := range f.Names {
			g.set(g.fn, n.Name, role)
		}
	}
}

// set binds name to role; an empty role clears a stale binding, so a name
// redeclared with an unknown type stops being rewritten.
func (g *goRoles) set(env map[string]string, name, role string) {
	if name == "" || name == "_" {
		return
	}
	if role == "" {
		delete(env, name)
		return
	}
	env[name] = role
}

// declare records `var x T` / `var x = expr` specs.
func (g *goRoles) declare(env map[string]string, gd *ast.GenDecl) {
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, n := range vs.Names {
			role := ""
			if vs.Type != nil {
				role = g.typeRole(vs.Type)
			} else if i < len(vs.Values) {
				role = g.exprRole(vs.Values[i])
			}
			g.set(env, n.Name, role)
		}
	}
}

// assign records the roles an assignment gives its left-hand side. A
// multi-value call (`db, err := sql.Open(...)`) gives its role to the first
// name.
func (g *goRoles) assign(lhs, rhs []ast.Expr) {
	for i, l := range lhs {
		id, ok := l.(*ast.Ident)
		if !ok {
			continue
		}
		role := ""
		switch {
		case len(rhs) == len(lhs):
			role = g.exprRole(rhs[i])
		case len(rhs) == 1 && i == 0:
			role = g.exprRole(rhs[0])
		}
		g.set(g.fn, id.Name, role)
	}
}

// exprRole returns the role an expression's value has.
func (g *goRoles) exprRole(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return g.exprRole(x.X)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return g.exprRole(x.X)
		}
	case *ast.CompositeLit:
		return g.typeRole(x.Type)
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
			return g.typeRole(x.Args[0])
		}
		chain := g.canon(renderCallChain(x.Fun))
		if r := goRoleConstructors[chain]; r != "" {
			return r
		}
		// An accessor returning a role (echo's c.Request()).
		if isGoRoleName(chain) {
			return chain
		}
	case *ast.Ident, *ast.SelectorExpr:
		if chain := g.canon(renderCallChain(x)); isGoRoleName(chain) {
			return chain
		}
	}
	return ""
}

func isGoRoleName(s string) bool {
	switch s {
	case "r", "w", "db", "gin", "echo", "fiber", "beego":
		return true
	}
	return false
}

// canon rewrites a dotted chain's head to its role, then a framework field to
// the role it holds. A chain whose head has no role is returned unchanged.
func (g *goRoles) canon(chain string) string {
	if chain == "" {
		return chain
	}
	head, rest, _ := strings.Cut(chain, ".")
	role := g.fn[head]
	if role == "" {
		role = g.file[head]
	}
	if role == "" {
		return chain
	}
	out := role
	if rest != "" {
		out += "." + rest
	}
	for _, f := range goRoleFields {
		if out == f.from || strings.HasPrefix(out, f.from+".") {
			return f.to + out[len(f.from):]
		}
	}
	return out
}

// canonStmt rewrites every call and chain a statement records.
func (g *goRoles) canonStmt(st *stmtDraft) {
	for i, c := range st.calls {
		st.calls[i] = g.canon(c)
	}
	for i, c := range st.chains {
		st.chains[i] = g.canon(c)
	}
	if len(st.sinkArgs) == 0 {
		return
	}
	out := make(map[string]sinkArgDraft, len(st.sinkArgs))
	for k, v := range st.sinkArgs {
		out[g.canon(k)] = v
	}
	st.sinkArgs = out
}
