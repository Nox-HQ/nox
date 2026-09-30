package hardening

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/nox-hq/nox/core/findings"
)

// scanGoCookies reports HARDEN-003 in one Go file, by the same rule as Python
// and Java: only the literal false, only as written.
//
//   - an http.Cookie literal with `Secure: false`;
//   - `c.Secure = false` where c is an http.Cookie the function declared or
//     built from a literal;
//   - gin's `c.SetCookie(name, value, maxAge, path, domain, false, httpOnly)`,
//     whose sixth argument is secure.
//
// An omitted Secure field is not reported, as for the other languages: the
// zero value is insecure, but whether that matters is decided by deployment.
func scanGoCookies(path string, content []byte) []findings.Finding {
	if !bytes.Contains(content, []byte("ecure")) && !bytes.Contains(content, []byte("SetCookie")) {
		return nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, content, parser.SkipObjectResolution)
	if file == nil || err != nil && len(file.Decls) == 0 {
		return nil
	}
	var out []findings.Finding
	report := func(pos token.Pos) {
		line := fset.Position(pos).Line
		out = append(out, findings.Finding{
			RuleID:     ruleInsecureCookie,
			Severity:   findings.SeverityMedium,
			Confidence: findings.ConfidenceHigh,
			Message:    "Cookie with its Secure flag set to false is sent over plain HTTP",
			Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
			Metadata:   map[string]string{"cwe": "CWE-614", "language": "go"},
		})
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		cookies := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if isHTTPCookieType(x.Type) {
					for _, e := range x.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok && isIdent(kv.Key, "Secure") && isIdent(kv.Value, "false") {
							report(kv.Pos())
						}
					}
				}
			case *ast.ValueSpec:
				if x.Type != nil && isHTTPCookieType(x.Type) {
					for _, id := range x.Names {
						cookies[id.Name] = true
					}
				}
			case *ast.AssignStmt:
				for i, l := range x.Lhs {
					if id, ok := l.(*ast.Ident); ok && i < len(x.Rhs) && isHTTPCookieValue(x.Rhs[i]) {
						cookies[id.Name] = true
					}
					sel, ok := l.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Secure" || i >= len(x.Rhs) || !isIdent(x.Rhs[i], "false") {
						continue
					}
					if recv, ok := sel.X.(*ast.Ident); ok && cookies[recv.Name] {
						report(x.Pos())
					}
				}
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetCookie" &&
					len(x.Args) == 7 && isIdent(x.Args[5], "false") {
					report(x.Args[5].Pos())
				}
			}
			return true
		})
	}
	return out
}

// isHTTPCookieType reports whether t is http.Cookie or *http.Cookie.
func isHTTPCookieType(t ast.Expr) bool {
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	sel, ok := t.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "http" && sel.Sel.Name == "Cookie"
}

// isHTTPCookieValue reports whether e builds an http.Cookie: a literal, its
// address, or new(http.Cookie).
func isHTTPCookieValue(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.CompositeLit:
		return isHTTPCookieType(x.Type)
	case *ast.UnaryExpr:
		return x.Op == token.AND && isHTTPCookieValue(x.X)
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
			return isHTTPCookieType(x.Args[0])
		}
	}
	return false
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
