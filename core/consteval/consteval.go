// Package consteval answers whether an expression is a compile-time constant.
//
// # Why this exists
//
// `capability.ConstantEvaluation` has been declared since the capability model
// was written, `core/adjudicate` lists it as a question worth asking — "is this
// value a literal, or is it built from input?" — and until now nothing answered
// it. It appeared in exactly two places in the tree: its own declaration, and
// the list of things nox cannot do. `capability.Builtins()` even described nox
// as resolving "constants where a language engine exists", which was not true
// of any engine in the repository.
//
// A declared capability nobody provides is worse than an absent one. It reads
// as coverage in the matrix, and an operator cannot tell a question that was
// asked and answered from one that was never asked.
//
// # What it is for
//
// The distinction it draws is the one the AI rules actually care about, and the
// one lexical analysis cannot reach. `core/lexctx` answers "is this text or is
// it code?", which is enough to see that `fmt.Print("hello")` logs a literal.
// It is not enough for:
//
//	const bashCompletion = `# nox bash completion …`
//	fmt.Print(bashCompletion)
//
// Lexically, `bashCompletion` is an identifier — code, not text — so the
// lexical refiner correctly declines to call it constant text, and AI-006
// reports a prompt logged without redaction. It is a shell script. Four such
// waivers were hand-written in nox's own repository, each explaining to a human
// what a constant resolver could have established.
//
// Resolving the identifier to its `const` declaration answers it: a
// compile-time constant cannot hold a runtime prompt or a model response,
// because its value is fixed before the program runs.
//
// # Go only, and honest about it
//
// Go is the only language resolved here, for the same reason the taint engine
// modelled Go first: nox is written in Go, so `go/ast` is free, precise and
// deterministic, where every other language would need a parser this repository
// does not carry. Everything else answers "undetermined".
//
// That asymmetry is the whole safety argument. Every function here returns a
// DETERMINED flag beside its answer, and callers must refute only on
// (constant=true, determined=true). "I could not tell" and "it is not a
// constant" are different facts, and a refutation drops a finding — so reading
// the first as the second would hide real issues in every language without an
// engine, which is most of them.
//
// It is pure: no clock, no I/O, no network. Same bytes, same answer.
package consteval

import (
	"go/ast"
	"go/token"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/source"
)

// Result is what constant evaluation established about an expression.
type Result struct {
	// Constant reports that every non-literal name in the expression resolves
	// to a compile-time constant. Meaningless unless Determined.
	Constant bool
	// Determined reports that the question was actually answered. False means
	// the language has no engine here, the file did not parse, or a name could
	// not be resolved within this file — never that the answer is "no".
	Determined bool
	// Reason explains an undetermined answer, for the degradation channel.
	Reason string
}

// undetermined builds the "I could not tell" result.
func undetermined(reason string) Result { return Result{Reason: reason} }

// Supported reports whether a constant engine exists for a language.
//
// Callers use it to record capability coverage as Unsupported rather than
// NotEvaluated: a Python file is not a file where constant evaluation failed,
// it is a file where nox has no evaluator, and the matrix should say so.
func Supported(lang lexctx.Lang) bool { return lang == lexctx.LangGo }

// CallArgumentsAreConstant reports whether every argument of the call
// enclosing offset is a compile-time constant.
//
// This is the question a logging rule asks: `fmt.Print(x)` leaks a prompt only
// if x can hold one at runtime. A call whose arguments are all constants —
// literals, or names bound by `const` — cannot.
//
// `var` deliberately does NOT count. A package-level `var greeting = "hi"` is a
// literal today and a mutable slot forever after; anything may assign a model
// response to it before the log call runs. Constant is a claim about what the
// value CAN be, not about what it happens to be at the line being read.
func CallArgumentsAreConstant(path string, content []byte, offset int) Result {
	if !Supported(lexctx.LangFromPath(path)) {
		return undetermined("no constant evaluator for this language")
	}
	file, fset := source.ParseGoFile(path, content)
	if file == nil {
		return undetermined("file did not parse as Go")
	}

	call := enclosingCall(file, fset, offset)
	if call == nil {
		return undetermined("no call expression encloses the match")
	}
	if len(call.Args) == 0 {
		// A call with no arguments logs nothing that could carry a prompt. That
		// is a determinable fact, not an unknown.
		return Result{Constant: true, Determined: true}
	}

	consts := constNames(file)
	for _, arg := range call.Args {
		r := exprIsConstant(arg, consts)
		if !r.Determined || !r.Constant {
			return r
		}
	}
	return Result{Constant: true, Determined: true}
}

// enclosingCall returns the innermost call expression containing offset.
//
// Innermost matters: in `log.Print(fmt.Sprintf("%s", user))` the outer call's
// only argument is itself a call, and answering about the outer one would ask
// whether a function result is a constant — which it never is — while the
// question worth asking is about the arguments actually being formatted.
func enclosingCall(file *ast.File, fset *token.FileSet, offset int) *ast.CallExpr {
	target := fset.File(file.Pos())
	if target == nil {
		return nil
	}
	// token.Pos is 1-based over the file set's base.
	pos := target.Pos(min(max(offset, 0), target.Size()))

	var found *ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if n.Pos() > pos || n.End() <= pos {
			return false
		}
		if c, ok := n.(*ast.CallExpr); ok {
			found = c // keep descending; the last one wins, which is innermost
		}
		return true
	})
	return found
}

// constNames collects the names this file binds with `const`.
//
// Both package-level and function-local declarations are collected, and they
// are collected from THIS FILE only. A constant declared in another file of the
// same package is a real constant that this resolver cannot see, and the honest
// answer for it is undetermined rather than "not constant" — see
// exprIsConstant.
func constNames(file *ast.File) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, id := range vs.Names {
				if id.Name != "_" {
					names[id.Name] = true
				}
			}
		}
		return true
	})
	return names
}

// exprIsConstant decides one expression.
//
// The grammar it accepts is deliberately small — literals, constant names, and
// the operators that combine them — because every shape it does not recognise
// returns UNDETERMINED, and undetermined costs nothing but a finding that stays
// reported. Guessing, in this direction, drops findings.
func exprIsConstant(e ast.Expr, consts map[string]bool) Result {
	switch x := e.(type) {
	case *ast.BasicLit:
		// A literal is the base case: "text", 42, 'c', `raw`.
		return Result{Constant: true, Determined: true}

	case *ast.Ident:
		switch x.Name {
		case "true", "false", "iota":
			return Result{Constant: true, Determined: true}
		case "nil":
			// Untyped nil carries nothing and cannot be a prompt.
			return Result{Constant: true, Determined: true}
		}
		if consts[x.Name] {
			return Result{Constant: true, Determined: true}
		}
		// The name is not a constant IN THIS FILE. It may be a var, a
		// parameter, or a constant declared in another file of the package —
		// and those are different answers this resolver cannot separate, so it
		// separates none of them.
		return undetermined("name " + x.Name + " does not resolve to a constant in this file")

	case *ast.BinaryExpr:
		// Constant folding: "a" + b is constant when both halves are.
		if l := exprIsConstant(x.X, consts); !l.Determined || !l.Constant {
			return l
		}
		return exprIsConstant(x.Y, consts)

	case *ast.ParenExpr:
		return exprIsConstant(x.X, consts)

	case *ast.UnaryExpr:
		return exprIsConstant(x.X, consts)

	default:
		// Calls, selectors, indexes, slices, type assertions, composite
		// literals. Some are constant in Go's sense; none is worth guessing at,
		// because the cost of a wrong "constant" is a dropped finding.
		return undetermined("expression is not a literal or a constant name")
	}
}
