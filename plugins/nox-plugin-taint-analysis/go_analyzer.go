package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// AnalyzeGoFile performs intraprocedural taint analysis on a Go source file
// using the standard library's go/ast and go/parser packages.
func AnalyzeGoFile(filePath string, content []byte) []TaintFlow {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, content, 0)
	if err != nil {
		return nil
	}

	var flows []TaintFlow

	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if fn.Body == nil {
			return false
		}

		funcFlows := analyzeGoFunc(fset, filePath, fn)
		flows = append(flows, funcFlows...)
		return false
	})

	return flows
}

func analyzeGoFunc(fset *token.FileSet, filePath string, fn *ast.FuncDecl) []TaintFlow {
	state := NewTaintState()
	var flows []TaintFlow
	funcName := fn.Name.Name

	for _, stmt := range fn.Body.List {
		flows = append(flows, analyzeGoStmt(fset, filePath, funcName, stmt, state)...)
	}
	return flows
}

func analyzeGoStmt(fset *token.FileSet, filePath, funcName string, stmt ast.Stmt, state *TaintState) []TaintFlow {
	var flows []TaintFlow

	switch s := stmt.(type) {
	case *ast.AssignStmt:
		flows = append(flows, analyzeGoAssign(fset, filePath, funcName, s, state)...)

	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			flows = append(flows, analyzeGoCall(fset, filePath, funcName, call, state)...)
		}

	case *ast.ReturnStmt:
		// Check if tainted values are returned (could flow to sinks in callers)

	case *ast.IfStmt:
		// Analyze body statements (still intraprocedural, no branching logic)
		if s.Body != nil {
			for _, inner := range s.Body.List {
				flows = append(flows, analyzeGoStmt(fset, filePath, funcName, inner, state)...)
			}
		}
		if s.Else != nil {
			flows = append(flows, analyzeGoStmt(fset, filePath, funcName, s.Else, state)...)
		}

	case *ast.BlockStmt:
		for _, inner := range s.List {
			flows = append(flows, analyzeGoStmt(fset, filePath, funcName, inner, state)...)
		}

	case *ast.ForStmt:
		if s.Body != nil {
			for _, inner := range s.Body.List {
				flows = append(flows, analyzeGoStmt(fset, filePath, funcName, inner, state)...)
			}
		}

	case *ast.RangeStmt:
		if s.Body != nil {
			for _, inner := range s.Body.List {
				flows = append(flows, analyzeGoStmt(fset, filePath, funcName, inner, state)...)
			}
		}

	case *ast.DeclStmt:
		if genDecl, ok := s.Decl.(*ast.GenDecl); ok && genDecl.Tok == token.VAR {
			for _, spec := range genDecl.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for i, value := range vs.Values {
						chain := selectorChain(value)
						if kind, matched := MatchGoSource(chain); matched {
							if i < len(vs.Names) {
								varName := vs.Names[i].Name
								state.Mark(varName, TaintSource{
									VarName: varName,
									Line:    fset.Position(value.Pos()).Line,
									Kind:    kind,
									Expr:    chain,
								})
							}
						}
					}
				}
			}
		}
	}

	return flows
}

func analyzeGoAssign(fset *token.FileSet, filePath, funcName string, assign *ast.AssignStmt, state *TaintState) []TaintFlow {
	var flows []TaintFlow

	for i, rhs := range assign.Rhs {
		if i >= len(assign.Lhs) {
			break
		}

		lhsIdent, ok := assign.Lhs[i].(*ast.Ident)
		if !ok {
			continue
		}
		varName := lhsIdent.Name

		chain := selectorChain(rhs)

		// Check if RHS is a sanitizer — if so, clear taint.
		if IsGoSanitizer(chain) {
			state.Clear(varName)
			continue
		}

		// Check if RHS is a taint source.
		if kind, matched := MatchGoSource(chain); matched {
			state.Mark(varName, TaintSource{
				VarName: varName,
				Line:    fset.Position(rhs.Pos()).Line,
				Kind:    kind,
				Expr:    chain,
			})
			continue
		}

		// Check if RHS references a tainted variable (propagation).
		rhsIdents := extractIdents(rhs)
		for _, id := range rhsIdents {
			if src, tainted := state.Get(id); tainted {
				state.Mark(varName, TaintSource{
					VarName: varName,
					Line:    fset.Position(rhs.Pos()).Line,
					Kind:    src.Kind,
					Expr:    src.Expr,
				})
				break
			}
		}

		// Also check if LHS = sinkCall(taintedVar) — assignment with sink on RHS.
		if call, ok := rhs.(*ast.CallExpr); ok {
			callChain := selectorChain(call.Fun)
			if ruleID, cwe, matched := MatchGoSink(callChain); matched {
				argIdents := extractCallArgIdents(call)
				for _, argName := range argIdents {
					if src, tainted := state.Get(argName); tainted {
						flows = append(flows, TaintFlow{
							Source:   src,
							SinkLine: fset.Position(call.Pos()).Line,
							SinkExpr: callChain,
							RuleID:   ruleID,
							CWE:      cwe,
							FilePath: filePath,
							FuncName: funcName,
							Language: "go",
						})
					}
				}
			}
		}
	}

	return flows
}

func analyzeGoCall(fset *token.FileSet, filePath, funcName string, call *ast.CallExpr, state *TaintState) []TaintFlow {
	chain := selectorChain(call.Fun)

	ruleID, cwe, matched := MatchGoSink(chain)
	if !matched {
		return nil
	}

	var flows []TaintFlow
	argIdents := extractCallArgIdents(call)

	for _, argName := range argIdents {
		if src, tainted := state.Get(argName); tainted {
			flows = append(flows, TaintFlow{
				Source:   src,
				SinkLine: fset.Position(call.Pos()).Line,
				SinkExpr: chain,
				RuleID:   ruleID,
				CWE:      cwe,
				FilePath: filePath,
				FuncName: funcName,
				Language: "go",
			})
		}
	}

	// Also check for string concatenation in arguments that references tainted vars.
	for _, arg := range call.Args {
		if bin, ok := arg.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
			for _, id := range extractIdents(bin) {
				if src, tainted := state.Get(id); tainted {
					// Avoid duplicate if already found.
					found := false
					for i := range flows {
						if flows[i].Source.VarName == src.VarName {
							found = true
							break
						}
					}
					if !found {
						flows = append(flows, TaintFlow{
							Source:   src,
							SinkLine: fset.Position(call.Pos()).Line,
							SinkExpr: chain,
							RuleID:   ruleID,
							CWE:      cwe,
							FilePath: filePath,
							FuncName: funcName,
							Language: "go",
						})
					}
				}
			}
		}
	}

	return flows
}

// selectorChain flattens a Go expression into a dotted string.
// e.g., r.URL.Query().Get("id") → "r.URL.Query.Get"
func selectorChain(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name

	case *ast.SelectorExpr:
		parent := selectorChain(e.X)
		if parent != "" {
			return parent + "." + e.Sel.Name
		}
		return e.Sel.Name

	case *ast.CallExpr:
		return selectorChain(e.Fun)

	case *ast.IndexExpr:
		return selectorChain(e.X)

	case *ast.StarExpr:
		return selectorChain(e.X)

	case *ast.ParenExpr:
		return selectorChain(e.X)

	default:
		return ""
	}
}

// extractIdents pulls all identifier names from an expression tree.
func extractIdents(expr ast.Expr) []string {
	var idents []string

	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			idents = append(idents, id.Name)
		}
		return true
	})

	return idents
}

// extractCallArgIdents extracts all identifier names from the arguments of a call.
func extractCallArgIdents(call *ast.CallExpr) []string {
	var names []string
	for _, arg := range call.Args {
		names = append(names, extractIdents(arg)...)
	}
	return unique(names)
}

func unique(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// isGoTestFile reports whether the filename looks like a Go test file.
func isGoTestFile(name string) bool {
	return strings.HasSuffix(name, "_test.go")
}
