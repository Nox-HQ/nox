package engine

import (
	"go/ast"
	"go/constant"
	"go/token"
)

// Element-sensitive slice literals for the Go extractor.
//
// Container taint is element-insensitive: `v := []string{"safe", param,
// "moresafe"}` taints v, so `bar = v[1]` reads as tainted whichever element it
// names. That is the right default and stays the default. It is refined only
// where the whole story is visible and constant: a slice built from a literal
// in one block, whose every other use in the function is, in that same block,
// a constant re-slice (`v = v[1:]`), an append of elements (`v = append(v, x)`)
// or a read at a constant index (`v[1]`). Then the block is walked with the
// slice's elements known, and each constant read is replaced by the element it
// names. Anything else -- passing v on, ranging over it, a variable index, a
// use in another block or a closure -- leaves v to the container model, as
// keyed.go does for maps. So a flow the container model finds can be lost only
// where the elements prove it cannot happen.

// goListOp classifies one statement of the block that defines a list.
type goListOp int

const (
	goListOther  goListOp = iota // uses v only through constant index reads
	goListDefine                 // v := []T{...}
	goListSlice                  // v = v[lo:hi]
	goListAppend                 // v = append(v, e...)
)

// eligibleLists returns the slice literals defined in stmts that qualify.
func (ex *goExtractor) eligibleLists(stmts []ast.Stmt, body *ast.BlockStmt) map[string]bool {
	out := map[string]bool{}
	for _, s := range stmts {
		name, ok := goListDefinition(s)
		if !ok {
			continue
		}
		inBlock := 0
		good := true
		for _, t := range stmts {
			op := ex.goListOpOf(t, name)
			n := countIdent(t, name)
			if op == goListOther && n != constIndexReads(t, name, ex.consts) {
				good = false
				break
			}
			inBlock += n
		}
		if good && inBlock == countIdent(body, name) {
			out[name] = true
		}
	}
	return out
}

// goListDefinition reports `v := []T{a, b, ...}` with plain elements.
func goListDefinition(s ast.Stmt) (string, bool) {
	a, ok := s.(*ast.AssignStmt)
	if !ok || a.Tok != token.DEFINE || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
		return "", false
	}
	id, ok := a.Lhs[0].(*ast.Ident)
	if !ok {
		return "", false
	}
	cl, ok := a.Rhs[0].(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	if at, ok := cl.Type.(*ast.ArrayType); !ok || at.Len != nil {
		return "", false
	}
	for _, e := range cl.Elts {
		if _, kv := e.(*ast.KeyValueExpr); kv {
			return "", false
		}
	}
	return id.Name, true
}

// goListOpOf classifies how statement s uses list name.
func (ex *goExtractor) goListOpOf(s ast.Stmt, name string) goListOp {
	if n, ok := goListDefinition(s); ok && n == name {
		return goListDefine
	}
	a, ok := s.(*ast.AssignStmt)
	if !ok || a.Tok != token.ASSIGN || len(a.Lhs) != 1 || len(a.Rhs) != 1 || !isIdentNamed(a.Lhs[0], name) {
		return goListOther
	}
	switch r := a.Rhs[0].(type) {
	case *ast.SliceExpr:
		if isIdentNamed(r.X, name) && !r.Slice3 && ex.constIndexOrNil(r.Low) && ex.constIndexOrNil(r.High) {
			return goListSlice
		}
	case *ast.CallExpr:
		if isIdentNamed(r.Fun, "append") && len(r.Args) >= 1 && isIdentNamed(r.Args[0], name) && !r.Ellipsis.IsValid() {
			for _, e := range r.Args[1:] {
				if countIdent(e, name) > 0 {
					return goListOther
				}
			}
			return goListAppend
		}
	}
	return goListOther
}

func (ex *goExtractor) constIndexOrNil(e ast.Expr) bool {
	if e == nil {
		return true
	}
	_, ok := goConstIndex(e, ex.consts)
	return ok
}

// goConstIndex evaluates a non-negative constant index.
func goConstIndex(e ast.Expr, env goConstEnv) (int, bool) {
	v, ok := evalGoConst(e, env)
	if !ok || v.Kind() != constant.Int {
		return 0, false
	}
	n, exact := constant.Int64Val(v)
	if !exact || n < 0 || n > 1<<20 {
		return 0, false
	}
	return int(n), true
}

func isIdentNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// countIdent counts the identifiers named name under n.
func countIdent(n ast.Node, name string) int {
	c := 0
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && id.Name == name {
			c++
		}
		return true
	})
	return c
}

// constIndexReads counts the reads `name[c]` under n with c constant.
func constIndexReads(n ast.Node, name string, env goConstEnv) int {
	c := 0
	ast.Inspect(n, func(x ast.Node) bool {
		if ix, ok := x.(*ast.IndexExpr); ok && isIdentNamed(ix.X, name) {
			if _, ok := goConstIndex(ix.Index, env); ok {
				c++
			}
		}
		return true
	})
	return c
}

// trackList updates the known elements of an eligible list for statement s,
// or replaces its constant reads in s with the elements they name.
func (ex *goExtractor) trackList(s ast.Stmt, lists map[string][]ast.Expr) {
	for name, elems := range lists {
		switch ex.goListOpOf(s, name) {
		case goListDefine:
			lists[name] = append([]ast.Expr(nil), s.(*ast.AssignStmt).Rhs[0].(*ast.CompositeLit).Elts...)
		case goListSlice:
			r := s.(*ast.AssignStmt).Rhs[0].(*ast.SliceExpr)
			lo, hi := 0, len(elems)
			if r.Low != nil {
				lo, _ = goConstIndex(r.Low, ex.consts)
			}
			if r.High != nil {
				hi, _ = goConstIndex(r.High, ex.consts)
			}
			if lo > hi || hi > len(elems) {
				// Out of range panics at run time; stop refining this list.
				delete(lists, name)
				continue
			}
			lists[name] = append([]ast.Expr(nil), elems[lo:hi]...)
		case goListAppend:
			lists[name] = append(append([]ast.Expr(nil), elems...), s.(*ast.AssignStmt).Rhs[0].(*ast.CallExpr).Args[1:]...)
		default:
			replaceConstReads(s, name, elems, ex.consts)
		}
	}
}

// replaceConstReads replaces each in-range `name[c]` under s with the element
// it names. An out-of-range read is left alone (it panics at run time).
func replaceConstReads(s ast.Node, name string, elems []ast.Expr, env goConstEnv) {
	pick := func(e ast.Expr) ast.Expr {
		ix, ok := e.(*ast.IndexExpr)
		if !ok || !isIdentNamed(ix.X, name) {
			return e
		}
		i, ok := goConstIndex(ix.Index, env)
		if !ok || i >= len(elems) {
			return e
		}
		return &ast.ParenExpr{Lparen: ix.Pos(), X: elems[i], Rparen: ix.End()}
	}
	ast.Inspect(s, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i := range x.Rhs {
				x.Rhs[i] = pick(x.Rhs[i])
			}
		case *ast.CallExpr:
			for i := range x.Args {
				x.Args[i] = pick(x.Args[i])
			}
		case *ast.BinaryExpr:
			x.X, x.Y = pick(x.X), pick(x.Y)
		case *ast.ReturnStmt:
			for i := range x.Results {
				x.Results[i] = pick(x.Results[i])
			}
		case *ast.ValueSpec:
			for i := range x.Values {
				x.Values[i] = pick(x.Values[i])
			}
		case *ast.ParenExpr:
			x.X = pick(x.X)
		}
		return true
	})
}
