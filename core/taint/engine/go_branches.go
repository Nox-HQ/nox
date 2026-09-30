package engine

import (
	"go/ast"
	"go/constant"
	"go/token"
	"sort"
)

// Branch model for the Go extractor.
//
// The Go extractor walked every branch body as straight-line code, so an
// assignment inside an `if` was a strong update: `p := r.FormValue("x"); if
// len(p) > 3 { p = "safe" }; db.Query("..." + p)` reported nothing, because the
// last assignment won whether or not its branch ran. That is a recall hole on
// the most ordinary validation shape there is.
//
// Now, as for Python (pydead.go) and Java (java_branches.go):
//
//   - a statement in an if/else arm, a loop body or a switch case is
//     Conditional (a weak update: it adds to what the variable may hold);
//   - an if whose condition is a constant is resolved: the arm that cannot run
//     is skipped, the arm that must run is not conditional;
//   - a switch whose tag is a constant runs only its matching case (or
//     default), unconditionally, unless a case falls through.
//
// Constants are evaluated with go/constant over the AST: literals, true/false,
// the file's constants, and locals the function assigns exactly once to a
// constant expression and never changes otherwise (no op-assign, ++/--,
// address taken or range variable). Anything else leaves the condition
// unknown, and an unknown condition changes nothing but the weak update.

// goConstEnv holds the constant value of every name that has one.
type goConstEnv map[string]constant.Value

// goFileConsts returns the file's package-level constants.
func goFileConsts(file *ast.File) goConstEnv {
	env := goConstEnv{}
	for _, decl := range file.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.CONST {
			addGoConstSpecs(env, gd)
		}
	}
	return env
}

func addGoConstSpecs(env goConstEnv, gd *ast.GenDecl) {
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, n := range vs.Names {
			if i < len(vs.Values) {
				if v, ok := evalGoConst(vs.Values[i], env); ok {
					env[n.Name] = v
				}
			}
		}
	}
}

// goFuncConsts returns base plus the function's single-assigned constant
// locals and local const declarations.
func goFuncConsts(body *ast.BlockStmt, base goConstEnv) goConstEnv {
	env := goConstEnv{}
	for k, v := range base {
		env[k] = v
	}
	if body == nil {
		return env
	}
	count := map[string]int{}
	never := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if id, ok := l.(*ast.Ident); ok {
					if x.Tok == token.DEFINE || x.Tok == token.ASSIGN {
						count[id.Name]++
					} else {
						never[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range x.Names {
				count[id.Name]++
			}
		case *ast.IncDecStmt:
			if id, ok := x.X.(*ast.Ident); ok {
				never[id.Name] = true
			}
		case *ast.UnaryExpr:
			if id, ok := x.X.(*ast.Ident); ok && x.Op == token.AND {
				never[id.Name] = true
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{x.Key, x.Value} {
				if id, ok := e.(*ast.Ident); ok {
					never[id.Name] = true
				}
			}
		}
		return true
	})
	// A local shadows a file constant of the same name.
	for name := range count {
		delete(env, name)
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) != len(x.Rhs) {
				return true
			}
			for i, l := range x.Lhs {
				id, ok := l.(*ast.Ident)
				if !ok || count[id.Name] != 1 || never[id.Name] {
					continue
				}
				if v, ok := evalGoConst(x.Rhs[i], env); ok {
					env[id.Name] = v
				}
			}
		case *ast.ValueSpec:
			for i, id := range x.Names {
				if count[id.Name] != 1 || never[id.Name] || i >= len(x.Values) {
					continue
				}
				if v, ok := evalGoConst(x.Values[i], env); ok {
					env[id.Name] = v
				}
			}
		}
		return true
	})
	return env
}

// evalGoConst evaluates a constant expression. ok is false for anything that
// is not provably constant.
func evalGoConst(e ast.Expr, env goConstEnv) (v constant.Value, ok bool) {
	defer func() {
		// go/constant panics on operand kinds an operator does not accept
		// (a string minus an int). Such an expression is not a constant we
		// can use, never a crash.
		if recover() != nil {
			v, ok = nil, false
		}
	}()
	return evalGoConstExpr(e, env)
}

func evalGoConstExpr(e ast.Expr, env goConstEnv) (constant.Value, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		v := constant.MakeFromLiteral(x.Value, x.Kind, 0)
		return v, v.Kind() != constant.Unknown
	case *ast.Ident:
		switch x.Name {
		case "true":
			return constant.MakeBool(true), true
		case "false":
			return constant.MakeBool(false), true
		}
		v, ok := env[x.Name]
		return v, ok
	case *ast.ParenExpr:
		return evalGoConstExpr(x.X, env)
	case *ast.IndexExpr:
		// A byte of a constant string: `guess[2]` with guess := "ABC".
		s, ok := evalGoConstExpr(x.X, env)
		if !ok || s.Kind() != constant.String {
			return nil, false
		}
		i, ok := evalGoConstExpr(x.Index, env)
		if !ok {
			return nil, false
		}
		n, exact := constant.Int64Val(i)
		str := constant.StringVal(s)
		if !exact || n < 0 || n >= int64(len(str)) {
			return nil, false
		}
		return constant.MakeInt64(int64(str[n])), true
	case *ast.CallExpr:
		// len of a constant string.
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "len" && len(x.Args) == 1 {
			s, ok := evalGoConstExpr(x.Args[0], env)
			if ok && s.Kind() == constant.String {
				return constant.MakeInt64(int64(len(constant.StringVal(s)))), true
			}
		}
	case *ast.UnaryExpr:
		v, ok := evalGoConstExpr(x.X, env)
		if !ok {
			return nil, false
		}
		switch x.Op {
		case token.SUB, token.ADD, token.NOT, token.XOR:
			r := constant.UnaryOp(x.Op, v, 0)
			return r, r.Kind() != constant.Unknown
		}
	case *ast.BinaryExpr:
		a, ok := evalGoConstExpr(x.X, env)
		if !ok {
			return nil, false
		}
		b, ok := evalGoConstExpr(x.Y, env)
		if !ok {
			return nil, false
		}
		switch x.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			return constant.MakeBool(constant.Compare(a, x.Op, b)), true
		case token.SHL, token.SHR:
			n, exact := constant.Uint64Val(b)
			if !exact || n > 64 {
				return nil, false
			}
			r := constant.Shift(a, x.Op, uint(n))
			return r, r.Kind() != constant.Unknown
		case token.QUO, token.REM:
			if constant.Sign(b) == 0 {
				return nil, false
			}
			op := x.Op
			if op == token.QUO && a.Kind() == constant.Int && b.Kind() == constant.Int {
				op = token.QUO_ASSIGN // go/constant's integer division
			}
			r := constant.BinaryOp(a, op, b)
			return r, r.Kind() != constant.Unknown
		default:
			r := constant.BinaryOp(a, x.Op, b)
			return r, r.Kind() != constant.Unknown
		}
	}
	return nil, false
}

// goTruth is a condition's constant truth: +1 always true, -1 always false,
// 0 unknown.
func goTruth(cond ast.Expr, env goConstEnv) int {
	v, ok := evalGoConst(cond, env)
	if !ok || v.Kind() != constant.Bool {
		return 0
	}
	if constant.BoolVal(v) {
		return 1
	}
	return -1
}

// walkIf walks an if statement under the branch model.
func (ex *goExtractor) walkIf(u *unitDraft, st *ast.IfStmt) {
	if st.Init != nil {
		ex.walkStmt(u, st.Init)
	}
	ex.emitGuard(u, st.Cond)
	switch goTruth(st.Cond, ex.consts) {
	case 1:
		if st.Body != nil {
			ex.walkBlock(u, st.Body.List)
		}
	case -1:
		if st.Else != nil {
			ex.walkStmt(u, st.Else)
		}
	default:
		if st.Body != nil && st.Else != nil {
			if arms := ifArms(st); arms != nil {
				ex.emitKills(u, definitelyAssigned(arms), ex.line(st.Pos()))
			}
		}
		ex.cond++
		if st.Body != nil {
			ex.walkBlock(u, st.Body.List)
		}
		if st.Else != nil {
			ex.walkStmt(u, st.Else)
		}
		ex.cond--
	}
}

// walkSwitch walks an expression switch under the branch model.
func (ex *goExtractor) walkSwitch(u *unitDraft, st *ast.SwitchStmt) {
	if st.Init != nil {
		ex.walkStmt(u, st.Init)
	}
	if st.Body == nil {
		return
	}
	if taken := ex.constCase(st); taken != nil {
		ex.walkBlock(u, taken.Body)
		return
	}
	if arms := switchArms(st); arms != nil {
		ex.emitKills(u, definitelyAssigned(arms), ex.line(st.Pos()))
	}
	ex.cond++
	ex.walkBlock(u, st.Body.List)
	ex.cond--
}

// constCase returns the one case a switch with a constant tag must take, or
// nil when that is not provable: the tag or a case expression before the
// match is not constant, or any case falls through.
func (ex *goExtractor) constCase(st *ast.SwitchStmt) *ast.CaseClause {
	if st.Tag == nil {
		return nil
	}
	tag, ok := evalGoConst(st.Tag, ex.consts)
	if !ok {
		return nil
	}
	var deflt, taken *ast.CaseClause
	for _, s := range st.Body.List {
		cc, ok := s.(*ast.CaseClause)
		if !ok {
			return nil
		}
		for _, b := range cc.Body {
			if br, ok := b.(*ast.BranchStmt); ok && br.Tok == token.FALLTHROUGH {
				return nil
			}
		}
		if cc.List == nil {
			deflt = cc
			continue
		}
		if taken != nil {
			continue
		}
		for _, e := range cc.List {
			v, ok := evalGoConst(e, ex.consts)
			if !ok {
				return nil
			}
			if goConstEqual(tag, v) {
				taken = cc
				break
			}
		}
	}
	if taken != nil {
		return taken
	}
	return deflt
}

func goConstEqual(a, b constant.Value) (eq bool) {
	defer func() {
		if recover() != nil {
			eq = false
		}
	}()
	return constant.Compare(a, token.EQL, b)
}

// Definite assignment across arms.
//
// A weak update keeps what a variable held before the branch, which is right
// when an arm may not assign it and wrong when every arm does:
// `if c { bar = "a" } else { bar = "b" }` overwrites bar whichever arm runs, so
// a tainted value bar held before cannot survive it. For each name every arm
// assigns, and no arm reads, the extractor emits a kill (an assignment of
// nothing) before walking the arms; the arms' weak updates then add exactly
// what they assign. An arm that cannot fall through (it returns, panics,
// breaks or continues) does not reach the code after the branch, so it counts
// as assigning everything.

// goArm is one arm's statements.
type goArm []ast.Stmt

// ifArms returns the arms of an if/else-if/else chain, or nil when the chain
// has no final else (then no arm is certain to run).
func ifArms(st *ast.IfStmt) []goArm {
	arms := []goArm{st.Body.List}
	switch e := st.Else.(type) {
	case *ast.BlockStmt:
		return append(arms, e.List)
	case *ast.IfStmt:
		if e.Init != nil {
			return nil
		}
		rest := ifArms(e)
		if rest == nil {
			return nil
		}
		return append(arms, rest...)
	}
	return nil
}

// switchArms returns a switch's case bodies, or nil when it has no default or
// a case falls through.
func switchArms(st *ast.SwitchStmt) []goArm {
	var arms []goArm
	deflt := false
	for _, s := range st.Body.List {
		cc, ok := s.(*ast.CaseClause)
		if !ok {
			return nil
		}
		if cc.List == nil {
			deflt = true
		}
		for _, b := range cc.Body {
			if br, ok := b.(*ast.BranchStmt); ok && br.Tok == token.FALLTHROUGH {
				return nil
			}
		}
		arms = append(arms, cc.Body)
	}
	if !deflt {
		return nil
	}
	return arms
}

// goArmTerminates reports whether an arm ends in a statement after which
// control does not reach the code following the branch.
func goArmTerminates(arm goArm) bool {
	if len(arm) == 0 {
		return false
	}
	switch x := arm[len(arm)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return x.Tok == token.BREAK || x.Tok == token.CONTINUE || x.Tok == token.GOTO
	case *ast.ExprStmt:
		if c, ok := x.X.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "panic" {
				return true
			}
		}
	}
	return false
}

// goArmAssigns returns the names an arm assigns with a plain top-level `=`.
func goArmAssigns(arm goArm) map[string]bool {
	out := map[string]bool{}
	for _, s := range arm {
		if a, ok := s.(*ast.AssignStmt); ok && a.Tok == token.ASSIGN {
			for _, l := range a.Lhs {
				if id, ok := l.(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
		}
	}
	return out
}

// goArmReads reports whether name is used in an arm other than as the plain
// target of an assignment.
func goArmReads(arm goArm, name string) bool {
	targets := map[*ast.Ident]bool{}
	for _, s := range arm {
		ast.Inspect(s, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok && a.Tok == token.ASSIGN {
				for _, l := range a.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						targets[id] = true
					}
				}
			}
			return true
		})
	}
	read := false
	for _, s := range arm {
		ast.Inspect(s, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == name && !targets[id] {
				read = true
			}
			return !read
		})
	}
	return read
}

// definitelyAssigned returns, in sorted order, the names every arm assigns
// and no arm reads. Arms that cannot fall through are ignored; at least one
// arm must fall through.
func definitelyAssigned(arms []goArm) []string {
	var live []goArm
	for _, a := range arms {
		if !goArmTerminates(a) {
			live = append(live, a)
		}
	}
	if len(live) == 0 {
		return nil
	}
	common := goArmAssigns(live[0])
	for _, a := range live[1:] {
		as := goArmAssigns(a)
		for n := range common {
			if !as[n] {
				delete(common, n)
			}
		}
	}
	var out []string
	for n := range common {
		reads := false
		for _, a := range arms {
			if goArmReads(a, n) {
				reads = true
				break
			}
		}
		if !reads {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// emitKills emits a strong assignment of nothing to each name, so what it held
// before the branch does not survive it.
func (ex *goExtractor) emitKills(u *unitDraft, names []string, line int) {
	for _, n := range names {
		u.stmts = append(u.stmts, stmtDraft{line: line, assigns: n, conditional: ex.cond > 0, sinkArgs: map[string]sinkArgDraft{}})
	}
}
