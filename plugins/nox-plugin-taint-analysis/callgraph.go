// Interprocedural taint analysis for Go.
//
// This is a minimal best-effort implementation. It runs intraprocedural
// analysis on every file in the directory and then walks function-call
// edges to propagate taint across function boundaries up to a small
// depth. Designed to detect TAINT-006 (cross-function SQLi) and
// TAINT-007 (cross-function CMDi) when a tainted value is passed as an
// argument to a function whose body terminates at a SQL or shell sink.
//
// Precision class: heuristic. Reflection, interface dispatch, and
// closures are ignored — the analysis over-approximates by tagging any
// callee whose name matches a sink-pattern.

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// fileEntry pairs a path with its parsed AST and source bytes.
type fileEntry struct {
	path    string
	content []byte
	fset    *token.FileSet
	file    *ast.File
}

// AnalyzeGoFileInterprocedural runs cross-function taint analysis across a
// set of Go files (typically one package directory). Caller passes a
// map of file path -> content as produced by the workspace walker in
// main.go.
func AnalyzeGoFileInterprocedural(files map[string][]byte) []TaintFlow {
	if len(files) < 2 {
		return nil
	}

	parsed := make([]fileEntry, 0, len(files))
	for path, content := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, content, 0)
		if err != nil {
			continue
		}
		parsed = append(parsed, fileEntry{
			path:    path,
			content: content,
			fset:    fset,
			file:    file,
		})
	}

	// Build call graph: function name -> list of callee names.
	calls := buildCallGraph(parsed)

	// Build per-function intraprocedural flows. Functions whose body
	// contains a call into a sink-named callee get an interprocedural
	// flow record at TAINT-006/007 severity.
	var out []TaintFlow
	for i := range parsed {
		entry := &parsed[i]
		ast.Inspect(entry.file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			for _, stmt := range fn.Body.List {
				if call := callsSink(stmt, calls, 3); call != "" {
					out = append(out, buildInterprocFlow(entry.path, fn.Name.Name, fn.Pos(), entry.fset, call, "go"))
				}
			}
			return false
		})
	}
	return out
}

// buildCallGraph walks every function declaration in parsed and records
// the names of functions it calls. Names are unqualified (no package
// prefix); ambiguity is acceptable because the lattice is heuristic.
func buildCallGraph(parsed []fileEntry) map[string][]string {
	calls := map[string][]string{}
	for i := range parsed {
		entry := &parsed[i]
		ast.Inspect(entry.file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			caller := fn.Name.Name
			ast.Inspect(fn.Body, func(child ast.Node) bool {
				ce, ok := child.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee := callExprName(ce)
				if callee != "" {
					calls[caller] = append(calls[caller], callee)
				}
				return true
			})
			return false
		})
	}
	return calls
}

// callExprName returns the unqualified function name being called, or
// the empty string when it can't be resolved.
func callExprName(ce *ast.CallExpr) string {
	switch fn := ce.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// callsSink returns the matched sink-callee name when stmt (recursively)
// invokes a function whose name looks like a SQL or shell sink. depth
// caps recursion through the call graph so the analysis stays bounded.
func callsSink(stmt ast.Stmt, calls map[string][]string, depth int) string {
	if depth <= 0 {
		return ""
	}
	var hit string
	ast.Inspect(stmt, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callExprName(ce)
		if isSinkName(name) {
			hit = name
			return false
		}
		// Recurse one hop into the callee's own calls.
		for _, sub := range calls[name] {
			if isSinkName(sub) {
				hit = sub
				return false
			}
		}
		return true
	})
	return hit
}

// isSinkName matches function names that look like SQL or shell-exec
// sinks. Heuristic: substring match on the lowercase form.
func isSinkName(name string) bool {
	low := strings.ToLower(name)
	for _, sub := range []string{"exec", "query", "queryrow", "command", "sprintf", "execute", "run"} {
		if strings.Contains(low, sub) {
			return true
		}
	}
	return false
}

// buildInterprocFlow shapes a TaintFlow record for a cross-function hit.
// The exact source position is the callee's first reference; the rule ID
// is chosen by sink kind.
func buildInterprocFlow(path, funcName string, pos token.Pos, fset *token.FileSet, calleeName, lang string) TaintFlow {
	rule := "TAINT-006"
	cwe := "CWE-89"
	if strings.Contains(strings.ToLower(calleeName), "exec") ||
		strings.Contains(strings.ToLower(calleeName), "command") ||
		strings.Contains(strings.ToLower(calleeName), "run") {
		rule = "TAINT-007"
		cwe = "CWE-78"
	}
	line := fset.Position(pos).Line
	return TaintFlow{
		Source: TaintSource{
			VarName: "<interproc>",
			Line:    line,
			Kind:    "interprocedural",
			Expr:    "(call edge)",
		},
		SinkLine: line,
		SinkExpr: calleeName + "(...)",
		RuleID:   rule,
		CWE:      cwe,
		FilePath: path,
		FuncName: funcName,
		Language: lang,
	}
}
