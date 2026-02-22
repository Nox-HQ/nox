package main

import (
	"regexp"
	"strings"
)

// Regexes for detecting function boundaries and variable assignments.
var (
	// Python function: def func_name(...):
	pyFuncDef = regexp.MustCompile(`^(\s*)def\s+(\w+)\s*\(`)
	// Python assignment: var = expr
	pyAssign = regexp.MustCompile(`^\s*(\w+)\s*=\s*(.+)$`)

	// JS/TS function patterns
	jsFuncDef     = regexp.MustCompile(`^\s*(?:async\s+)?function\s+(\w+)\s*\(`)
	jsArrowFunc   = regexp.MustCompile(`^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(`)
	jsMethodDef   = regexp.MustCompile(`^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{`)
	jsAssignConst = regexp.MustCompile(`^\s*(?:const|let|var)\s+(\w+)\s*=\s*(.+)$`)
	jsAssignBare  = regexp.MustCompile(`^\s*(\w+)\s*=\s*(.+)$`)
)

// AnalyzeTextFile performs taint analysis on Python, JavaScript, or TypeScript files
// using regex-based parsing with variable tracking.
func AnalyzeTextFile(filePath string, content []byte, lang string) []TaintFlow {
	lines := strings.Split(string(content), "\n")

	var allFlows []TaintFlow
	state := NewTaintState()
	funcName := "<module>"
	inFunc := false

	switch lang {
	case "python":
		allFlows = analyzePython(lines, filePath, state, funcName, inFunc)
	case "javascript", "typescript":
		allFlows = analyzeJS(lines, filePath, state, funcName, inFunc, lang)
	}

	return allFlows
}

func analyzePython(lines []string, filePath string, state *TaintState, funcName string, _ bool) []TaintFlow {
	var flows []TaintFlow
	var funcIndent int

	for lineNum, line := range lines {
		lineNo := lineNum + 1 // 1-based line numbers

		// Detect function boundaries.
		if m := pyFuncDef.FindStringSubmatch(line); m != nil {
			state.Reset()
			funcIndent = len(m[1])
			funcName = m[2]
			continue
		}

		// If we're in a function, check if line's indentation returned to func level.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lineIndent := len(line) - len(strings.TrimLeft(line, " \t"))
		if funcName != "<module>" && lineIndent <= funcIndent && !strings.HasPrefix(trimmed, "def ") {
			state.Reset()
			funcName = "<module>"
			funcIndent = lineIndent
		}

		// Check for variable assignment.
		if m := pyAssign.FindStringSubmatch(line); m != nil {
			varName := m[1]
			rhsExpr := m[2]

			// Check if RHS is a sanitizer.
			if IsTextSanitizer(rhsExpr, "python") {
				state.Clear(varName)
				continue
			}

			// Check if RHS is a taint source.
			if kind, matched := MatchTextSource(rhsExpr, "python"); matched {
				state.Mark(varName, TaintSource{
					VarName: varName,
					Line:    lineNo,
					Kind:    kind,
					Expr:    strings.TrimSpace(rhsExpr),
				})
				continue
			}

			// Check if RHS references a tainted variable.
			for _, tv := range state.TaintedVars() {
				if containsWord(rhsExpr, tv) {
					src, _ := state.Get(tv)
					state.Mark(varName, TaintSource{
						VarName: varName,
						Line:    lineNo,
						Kind:    src.Kind,
						Expr:    src.Expr,
					})
					break
				}
			}
		}

		// Check if line contains a sink with a tainted variable.
		if ruleID, cwe, matched := MatchTextSink(line, "python"); matched {
			for _, tv := range state.TaintedVars() {
				if containsWord(line, tv) {
					src, _ := state.Get(tv)
					flows = append(flows, TaintFlow{
						Source:   src,
						SinkLine: lineNo,
						SinkExpr: strings.TrimSpace(line),
						RuleID:   ruleID,
						CWE:      cwe,
						FilePath: filePath,
						FuncName: funcName,
						Language: "python",
					})
					break
				}
			}
		}
	}

	return flows
}

func analyzeJS(lines []string, filePath string, state *TaintState, funcName string, _ bool, lang string) []TaintFlow {
	var flows []TaintFlow
	braceDepth := 0

	for lineNum, line := range lines {
		lineNo := lineNum + 1

		// Detect function boundaries.
		if m := jsFuncDef.FindStringSubmatch(line); m != nil {
			state.Reset()
			funcName = m[1]
			braceDepth = 0
		} else if m := jsArrowFunc.FindStringSubmatch(line); m != nil {
			state.Reset()
			funcName = m[1]
			braceDepth = 0
		} else if m := jsMethodDef.FindStringSubmatch(line); m != nil {
			state.Reset()
			funcName = m[1]
			braceDepth = 0
		}

		// Track brace depth for function scope.
		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Check for variable assignment.
		var varName, rhsExpr string
		if m := jsAssignConst.FindStringSubmatch(line); m != nil {
			varName = m[1]
			rhsExpr = m[2]
		} else if m := jsAssignBare.FindStringSubmatch(line); m != nil {
			varName = m[1]
			rhsExpr = m[2]
		}

		if varName != "" {
			// Check if RHS is a sanitizer.
			if IsTextSanitizer(rhsExpr, lang) {
				state.Clear(varName)
				continue
			}

			// Check if RHS is a taint source.
			if kind, matched := MatchTextSource(rhsExpr, lang); matched {
				state.Mark(varName, TaintSource{
					VarName: varName,
					Line:    lineNo,
					Kind:    kind,
					Expr:    strings.TrimSpace(rhsExpr),
				})
				continue
			}

			// Check if RHS references a tainted variable.
			for _, tv := range state.TaintedVars() {
				if containsWord(rhsExpr, tv) {
					src, _ := state.Get(tv)
					state.Mark(varName, TaintSource{
						VarName: varName,
						Line:    lineNo,
						Kind:    src.Kind,
						Expr:    src.Expr,
					})
					break
				}
			}
		}

		// Check if line contains a sink with a tainted variable.
		if ruleID, cwe, matched := MatchTextSink(line, lang); matched {
			for _, tv := range state.TaintedVars() {
				if containsWord(line, tv) {
					src, _ := state.Get(tv)
					flows = append(flows, TaintFlow{
						Source:   src,
						SinkLine: lineNo,
						SinkExpr: strings.TrimSpace(line),
						RuleID:   ruleID,
						CWE:      cwe,
						FilePath: filePath,
						FuncName: funcName,
						Language: lang,
					})
					break
				}
			}
		}
	}

	return flows
}

// containsWord checks if a string contains a variable name as a distinct word.
// This prevents false matches where "id" matches "provider" or similar.
func containsWord(s, word string) bool {
	idx := 0
	for {
		i := strings.Index(s[idx:], word)
		if i < 0 {
			return false
		}
		pos := idx + i
		// Check boundaries: character before and after must not be alphanumeric or underscore.
		before := pos == 0 || !isIdentChar(s[pos-1])
		after := pos+len(word) >= len(s) || !isIdentChar(s[pos+len(word)])
		if before && after {
			return true
		}
		idx = pos + 1
	}
}

func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}
